package querymap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

func ApplyParameters(plan Plan, keyring *recordcrypt.Keyring, domain string, input [][]byte) ([][]byte, error) {
	if keyring == nil {
		return nil, errors.New("querymap: keyring is required")
	}
	if len(input) != plan.OriginalParameterCount {
		return nil, fmt.Errorf("querymap: bind has %d parameters, expected %d", len(input), plan.OriginalParameterCount)
	}
	output := make([][]byte, plan.ParameterCount)
	for i, value := range input {
		output[i] = appendNullable(value)
	}
	for _, rule := range plan.Parameters {
		if rule.Source <= 0 || rule.Source > len(input) || rule.Target <= 0 || rule.Target > len(output) {
			return nil, errors.New("querymap: compiled parameter rule is out of bounds")
		}
		plaintext := input[rule.Source-1]
		if plaintext == nil {
			output[rule.Target-1] = nil
			continue
		}
		ctx := fieldContext(domain, rule.Field)
		var transformed []byte
		switch rule.Op {
		case EncryptRandom, EncryptDeterministic:
			mode := recordcrypt.TextRandom
			value := plaintext
			if rule.Op == EncryptDeterministic {
				mode = recordcrypt.TextDeterministic
				normalized, err := recordcrypt.Normalize(plaintext, recordcrypt.Normalizer(rule.Field.Normalize))
				if err != nil {
					return nil, parameterError(rule, err)
				}
				value = normalized
			}
			if len(rule.Field.JSONPaths) > 0 {
				encrypted, err := keyring.EncryptJSON(ctx, mode, value, rule.Field.JSONPaths)
				if err != nil {
					return nil, parameterError(rule, err)
				}
				transformed = encrypted
			} else {
				var encrypted string
				var err error
				if rule.Op == EncryptDeterministic && rule.KeyID != "" {
					encrypted, err = keyring.EncryptDeterministicWithKeyID(ctx, rule.KeyID, value)
				} else {
					encrypted, err = keyring.EncryptText(ctx, mode, value)
				}
				if err != nil {
					return nil, parameterError(rule, err)
				}
				transformed = []byte(encrypted)
			}
		case ComputeBlindIndex:
			normalized, err := recordcrypt.Normalize(plaintext, recordcrypt.Normalizer(rule.Field.Normalize))
			if err != nil {
				return nil, parameterError(rule, err)
			}
			var index string
			if rule.KeyID != "" {
				index, err = keyring.BlindIndexWithKeyID(ctx, rule.KeyID, normalized)
			} else {
				index, err = keyring.BlindIndex(ctx, normalized)
			}
			if err != nil {
				return nil, parameterError(rule, err)
			}
			transformed = []byte(index)
		default:
			return nil, fmt.Errorf("querymap: unsupported parameter operation %q", rule.Op)
		}
		output[rule.Target-1] = transformed
	}
	return output, nil
}

func ApplyResults(rules []ResultRule, keyring *recordcrypt.Keyring, domain string, row [][]byte) ([][]byte, error) {
	if keyring == nil {
		return nil, errors.New("querymap: keyring is required")
	}
	output := make([][]byte, len(row))
	for i, value := range row {
		output[i] = appendNullable(value)
	}
	for _, rule := range rules {
		if rule.Ordinal < 0 || rule.Ordinal >= len(row) {
			return nil, errors.New("querymap: compiled result rule is out of bounds")
		}
		value := row[rule.Ordinal]
		if value == nil {
			continue
		}
		ctx := fieldContext(domain, rule.Field)
		if len(rule.Field.JSONPaths) > 0 {
			decrypted, err := keyring.DecryptJSONPartial(ctx, value, rule.Field.JSONPaths)
			if err != nil {
				return nil, resultError(rule, err)
			}
			output[rule.Ordinal] = decrypted
			continue
		}
		text := string(value)
		if !strings.HasPrefix(text, recordcrypt.Prefix) {
			// Online backfill permits ordinary plaintext. Reserved malformed values
			// are rejected by Decrypt below because they carry the full prefix.
			continue
		}
		plaintext, err := keyring.Decrypt(ctx, text)
		if err != nil {
			return nil, resultError(rule, err)
		}
		output[rule.Ordinal] = plaintext
	}
	return output, nil
}

func fieldContext(domain string, field policy.Field) recordcrypt.Context {
	return recordcrypt.Context{Domain: domain, Schema: field.Schema, Table: field.Table, Column: field.Column}
}

func parameterError(rule ParameterRule, err error) error {
	return fmt.Errorf("querymap: transform parameter $%d for %s.%s.%s: %w", rule.Source, rule.Field.Schema, rule.Field.Table, rule.Field.Column, err)
}

func resultError(rule ResultRule, err error) error {
	return fmt.Errorf("querymap: transform result column %d for %s.%s.%s: %w", rule.Ordinal, rule.Field.Schema, rule.Field.Table, rule.Field.Column, err)
}

func appendNullable(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
