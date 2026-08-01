package operator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

type Mode string

const (
	Backfill  Mode = "backfill"
	Reencrypt Mode = "reencrypt"
)

type Stats struct {
	Scanned    int64
	Updated    int64
	Unchanged  int64
	Conflicted int64
}

type Processor struct {
	Keyring *recordcrypt.Keyring
	Domain  string
}

func (p Processor) Transform(field policy.Field, value []byte, blindIndex []byte, mode Mode) (newValue, newBlind []byte, changed bool, err error) {
	if p.Keyring == nil || p.Domain == "" {
		return nil, nil, false, errors.New("operator: keyring and domain are required")
	}
	if value == nil {
		return nil, nil, false, nil
	}
	ctx := recordcrypt.Context{Domain: p.Domain, Schema: field.Schema, Table: field.Table, Column: field.Column}
	forceActive := mode == Reencrypt
	textMode := recordcrypt.TextRandom
	if field.Mode == policy.ModeDeterministic {
		textMode = recordcrypt.TextDeterministic
	}
	if len(field.JSONPaths) > 0 {
		rewritten, rewrittenChanged, err := p.Keyring.RewriteJSON(ctx, textMode, value, field.JSONPaths, forceActive)
		return rewritten, nil, rewrittenChanged, err
	}

	plaintext := value
	existing := false
	if strings.HasPrefix(string(value), recordcrypt.Prefix) {
		envelope, parseErr := recordcrypt.Parse(string(value))
		if parseErr != nil {
			return nil, nil, false, parseErr
		}
		plaintext, err = p.Keyring.Decrypt(ctx, string(value))
		if err != nil {
			return nil, nil, false, err
		}
		existing = true
		expectedMode := recordcrypt.ModeRandom
		if field.Mode == policy.ModeDeterministic {
			expectedMode = recordcrypt.ModeDeterministic
		}
		if envelope.Mode != expectedMode && !forceActive {
			return nil, nil, false, errors.New("operator: ciphertext mode is inconsistent with policy")
		}
		if envelope.Mode == expectedMode && (!forceActive || envelope.KeyID == p.Keyring.ActiveKeyID()) {
			newValue = append([]byte(nil), value...)
		}
	}
	if newValue == nil {
		encryptionInput := plaintext
		if field.Mode == policy.ModeDeterministic {
			encryptionInput, err = recordcrypt.Normalize(plaintext, recordcrypt.Normalizer(field.Normalize))
			if err != nil {
				return nil, nil, false, err
			}
		}
		encrypted, err := p.Keyring.EncryptText(ctx, textMode, encryptionInput)
		if err != nil {
			return nil, nil, false, err
		}
		newValue = []byte(encrypted)
	}
	if field.BlindIndex != "" {
		normalized, err := recordcrypt.Normalize(plaintext, recordcrypt.Normalizer(field.Normalize))
		if err != nil {
			return nil, nil, false, err
		}
		index, err := p.Keyring.BlindIndex(ctx, normalized)
		if err != nil {
			return nil, nil, false, err
		}
		newBlind = []byte(index)
	}
	changed = !existing || !bytesEqual(newValue, value) || !bytesEqualNullable(newBlind, blindIndex)
	return newValue, newBlind, changed, nil
}

type Engine struct {
	Connection *pgx.Conn
	Processor  Processor
	BatchSize  int
}

func (e *Engine) RunAndVerifyField(ctx context.Context, field policy.Field, mode Mode) (Stats, Verification, error) {
	stats, err := e.RunField(ctx, field, mode)
	if err != nil {
		return stats, Verification{}, err
	}
	verification, err := e.VerifyField(ctx, field)
	if err != nil {
		return stats, verification, fmt.Errorf("operator: verify %s.%s.%s after %s: %w", field.Schema, field.Table, field.Column, mode, err)
	}
	if !verification.Clean() {
		return stats, verification, fmt.Errorf(
			"operator: verification after %s failed for %s.%s.%s: plaintext=%d old_key=%d invalid=%d blind_mismatch=%d",
			mode, field.Schema, field.Table, field.Column, verification.PlaintextRows, verification.OldKeyRows, verification.InvalidRows, verification.BlindMismatch,
		)
	}
	return stats, verification, nil
}

func (e *Engine) RunField(ctx context.Context, field policy.Field, mode Mode) (Stats, error) {
	if e.Connection == nil {
		return Stats{}, errors.New("operator: PostgreSQL connection is required")
	}
	if mode != Backfill && mode != Reencrypt {
		return Stats{}, fmt.Errorf("operator: unsupported mode %q", mode)
	}
	batchSize := e.BatchSize
	if batchSize <= 0 {
		batchSize = 250
	}
	if batchSize > 10_000 {
		return Stats{}, errors.New("operator: batch size exceeds 10000")
	}
	table := pgx.Identifier{field.Schema, field.Table}.Sanitize()
	column := pgx.Identifier{field.Column}.Sanitize()
	var maximum *string
	if err := e.Connection.QueryRow(ctx, "SELECT max(ctid)::text FROM "+table+" WHERE "+column+" IS NOT NULL").Scan(&maximum); err != nil {
		return Stats{}, fmt.Errorf("operator: determine scan boundary for %s.%s.%s: %w", field.Schema, field.Table, field.Column, err)
	}
	if maximum == nil {
		return Stats{}, nil
	}
	cursor := "(0,0)"
	var stats Stats
	for {
		tx, err := e.Connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return stats, fmt.Errorf("operator: begin batch: %w", err)
		}
		batchStats, nextCursor, done, err := e.runBatch(ctx, tx, field, table, column, cursor, *maximum, batchSize, mode)
		if err != nil {
			_ = tx.Rollback(ctx)
			return stats, err
		}
		if err := tx.Commit(ctx); err != nil {
			return stats, fmt.Errorf("operator: commit batch: %w", err)
		}
		stats.Scanned += batchStats.Scanned
		stats.Updated += batchStats.Updated
		stats.Unchanged += batchStats.Unchanged
		stats.Conflicted += batchStats.Conflicted
		if done {
			return stats, nil
		}
		cursor = nextCursor
	}
}

type row struct {
	ctid  string
	value []byte
	blind []byte
}

func (e *Engine) runBatch(ctx context.Context, tx pgx.Tx, field policy.Field, table, column, cursor, maximum string, batchSize int, mode Mode) (Stats, string, bool, error) {
	selectColumns := "ctid::text, " + column + "::text"
	if field.BlindIndex != "" {
		selectColumns += ", " + pgx.Identifier{field.BlindIndex}.Sanitize() + "::text"
	}
	query := "SELECT " + selectColumns + " FROM " + table + " WHERE " + column + " IS NOT NULL AND ctid > $1::tid AND ctid <= $2::tid ORDER BY ctid LIMIT $3 FOR UPDATE SKIP LOCKED"
	rows, err := tx.Query(ctx, query, cursor, maximum, batchSize)
	if err != nil {
		return Stats{}, cursor, false, fmt.Errorf("operator: select batch for %s.%s.%s: %w", field.Schema, field.Table, field.Column, err)
	}
	batch := make([]row, 0, batchSize)
	for rows.Next() {
		var item row
		if field.BlindIndex != "" {
			if err := rows.Scan(&item.ctid, &item.value, &item.blind); err != nil {
				rows.Close()
				return Stats{}, cursor, false, fmt.Errorf("operator: scan batch: %w", err)
			}
		} else if err := rows.Scan(&item.ctid, &item.value); err != nil {
			rows.Close()
			return Stats{}, cursor, false, fmt.Errorf("operator: scan batch: %w", err)
		}
		batch = append(batch, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Stats{}, cursor, false, fmt.Errorf("operator: read batch: %w", err)
	}
	rows.Close()
	if len(batch) == 0 {
		return Stats{}, cursor, true, nil
	}
	stats := Stats{Scanned: int64(len(batch))}
	for _, item := range batch {
		newValue, newBlind, changed, err := e.Processor.Transform(field, item.value, item.blind, mode)
		if err != nil {
			return stats, cursor, false, fmt.Errorf("operator: transform %s.%s.%s at ctid %s: %w", field.Schema, field.Table, field.Column, item.ctid, err)
		}
		if !changed {
			stats.Unchanged++
			continue
		}
		command := "UPDATE " + table + " SET " + column + " = $1"
		arguments := []any{string(newValue)}
		if field.BlindIndex != "" {
			command += ", " + pgx.Identifier{field.BlindIndex}.Sanitize() + " = $2"
			arguments = append(arguments, string(newBlind))
		}
		arguments = append(arguments, item.ctid, string(item.value))
		ctidArg := len(arguments) - 1
		oldArg := len(arguments)
		command += fmt.Sprintf(" WHERE ctid = $%d::tid AND %s::text IS NOT DISTINCT FROM $%d", ctidArg, column, oldArg)
		result, err := tx.Exec(ctx, command, arguments...)
		if err != nil {
			return stats, cursor, false, fmt.Errorf("operator: update batch row: %w", err)
		}
		if result.RowsAffected() == 1 {
			stats.Updated++
		} else {
			stats.Conflicted++
		}
	}
	return stats, batch[len(batch)-1].ctid, len(batch) < batchSize, nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func bytesEqualNullable(a, b []byte) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return bytesEqual(a, b)
}
