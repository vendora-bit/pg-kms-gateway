package operator

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

type Verification struct {
	Scanned       int64
	PlaintextRows int64
	OldKeyRows    int64
	InvalidRows   int64
	BlindMismatch int64
}

func (v Verification) Clean() bool {
	return v.PlaintextRows == 0 && v.OldKeyRows == 0 && v.InvalidRows == 0 && v.BlindMismatch == 0
}

func (p Processor) Inspect(field policy.Field, value, blind []byte) (plaintext, oldKey, blindMismatch bool, err error) {
	if value == nil {
		return false, false, false, nil
	}
	ctx := recordcrypt.Context{Domain: p.Domain, Schema: field.Schema, Table: field.Table, Column: field.Column}
	mode := recordcrypt.TextRandom
	if field.Mode == policy.ModeDeterministic {
		mode = recordcrypt.TextDeterministic
	}
	if len(field.JSONPaths) > 0 {
		inspection, err := p.Keyring.InspectJSON(ctx, mode, value, field.JSONPaths)
		return inspection.PlaintextPaths > 0, inspection.OldKeyPaths > 0, false, err
	}
	if !strings.HasPrefix(string(value), recordcrypt.Prefix) {
		return true, false, field.BlindIndex != "" && blind != nil, nil
	}
	envelope, err := recordcrypt.Parse(string(value))
	if err != nil {
		return false, false, false, err
	}
	expectedMode := recordcrypt.ModeRandom
	if field.Mode == policy.ModeDeterministic {
		expectedMode = recordcrypt.ModeDeterministic
	}
	if envelope.Mode != expectedMode {
		return false, false, false, fmt.Errorf("operator: ciphertext mode is inconsistent with policy")
	}
	plain, err := p.Keyring.Decrypt(ctx, string(value))
	if err != nil {
		return false, false, false, err
	}
	if field.BlindIndex != "" {
		normalized, err := recordcrypt.Normalize(plain, recordcrypt.Normalizer(field.Normalize))
		if err != nil {
			return false, false, false, err
		}
		expected, err := p.Keyring.BlindIndex(ctx, normalized)
		if err != nil {
			return false, false, false, err
		}
		blindMismatch = blind == nil || !recordcrypt.VerifyBlindIndex(expected, string(blind))
	}
	return false, envelope.KeyID != p.Keyring.ActiveKeyID(), blindMismatch, nil
}

func (e *Engine) VerifyField(ctx context.Context, field policy.Field) (Verification, error) {
	if e.Connection == nil {
		return Verification{}, fmt.Errorf("operator: PostgreSQL connection is required")
	}
	batchSize := e.BatchSize
	if batchSize <= 0 {
		batchSize = 250
	}
	if batchSize > 10_000 {
		return Verification{}, fmt.Errorf("operator: batch size exceeds 10000")
	}
	table := pgx.Identifier{field.Schema, field.Table}.Sanitize()
	column := pgx.Identifier{field.Column}.Sanitize()
	var maximum *string
	if err := e.Connection.QueryRow(ctx, "SELECT max(ctid)::text FROM "+table+" WHERE "+column+" IS NOT NULL").Scan(&maximum); err != nil {
		return Verification{}, fmt.Errorf("operator: determine verification boundary: %w", err)
	}
	if maximum == nil {
		return Verification{}, nil
	}
	cursor := "(0,0)"
	var verification Verification
	for {
		selectColumns := "ctid::text, " + column + "::text"
		if field.BlindIndex != "" {
			selectColumns += ", " + pgx.Identifier{field.BlindIndex}.Sanitize() + "::text"
		}
		query := "SELECT " + selectColumns + " FROM " + table + " WHERE " + column + " IS NOT NULL AND ctid > $1::tid AND ctid <= $2::tid ORDER BY ctid LIMIT $3"
		rows, err := e.Connection.Query(ctx, query, cursor, *maximum, batchSize)
		if err != nil {
			return verification, fmt.Errorf("operator: select verification batch: %w", err)
		}
		count := 0
		for rows.Next() {
			var item row
			if field.BlindIndex != "" {
				err = rows.Scan(&item.ctid, &item.value, &item.blind)
			} else {
				err = rows.Scan(&item.ctid, &item.value)
			}
			if err != nil {
				rows.Close()
				return verification, fmt.Errorf("operator: scan verification row: %w", err)
			}
			count++
			cursor = item.ctid
			verification.Scanned++
			plaintext, oldKey, blindMismatch, inspectErr := e.Processor.Inspect(field, item.value, item.blind)
			if inspectErr != nil {
				verification.InvalidRows++
				continue
			}
			if plaintext {
				verification.PlaintextRows++
			}
			if oldKey {
				verification.OldKeyRows++
			}
			if blindMismatch {
				verification.BlindMismatch++
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return verification, fmt.Errorf("operator: read verification batch: %w", err)
		}
		rows.Close()
		if count < batchSize {
			return verification, nil
		}
	}
}
