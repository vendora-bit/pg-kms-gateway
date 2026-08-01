package recordcrypt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type TextMode string

const (
	TextRandom        TextMode = "random"
	TextDeterministic TextMode = "deterministic"
)

type Normalizer string

const (
	NormalizerNone          Normalizer = "none"
	NormalizerTrim          Normalizer = "trim"
	NormalizerLowercaseTrim Normalizer = "lowercase-trim"
)

func Normalize(value []byte, normalizer Normalizer) ([]byte, error) {
	if !utf8.Valid(value) {
		return nil, errors.New("recordcrypt: value is not valid UTF-8")
	}
	switch normalizer {
	case "", NormalizerNone:
		return append([]byte(nil), value...), nil
	case NormalizerTrim:
		return []byte(strings.TrimSpace(string(value))), nil
	case NormalizerLowercaseTrim:
		return []byte(strings.ToLower(strings.TrimSpace(string(value)))), nil
	default:
		return nil, fmt.Errorf("recordcrypt: unsupported normalizer %q", normalizer)
	}
}

func (k *Keyring) EncryptText(ctx Context, mode TextMode, plaintext []byte) (string, error) {
	switch mode {
	case TextRandom:
		return k.EncryptRandom(ctx, plaintext)
	case TextDeterministic:
		return k.EncryptDeterministic(ctx, plaintext)
	default:
		return "", fmt.Errorf("recordcrypt: unsupported text mode %q", mode)
	}
}

func (k *Keyring) EncryptJSON(ctx Context, mode TextMode, input []byte, paths []string) ([]byte, error) {
	root, err := decodeJSONObject(input)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		parent, key, err := jsonLocation(root, path)
		if err != nil {
			return nil, err
		}
		value, exists := parent[key]
		if !exists || value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("recordcrypt: JSON path %q must select a string or null", path)
		}
		pathContext := ctx
		pathContext.JSONPath = path
		encrypted, err := k.EncryptText(pathContext, mode, []byte(text))
		if err != nil {
			return nil, err
		}
		parent[key] = encrypted
	}
	return json.Marshal(root)
}

func (k *Keyring) DecryptJSON(ctx Context, input []byte, paths []string) ([]byte, error) {
	return k.decryptJSON(ctx, input, paths, true)
}

func (k *Keyring) DecryptJSONPartial(ctx Context, input []byte, paths []string) ([]byte, error) {
	return k.decryptJSON(ctx, input, paths, false)
}

func (k *Keyring) decryptJSON(ctx Context, input []byte, paths []string, requireEncrypted bool) ([]byte, error) {
	root, err := decodeJSONObject(input)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		parent, key, err := jsonLocation(root, path)
		if err != nil {
			return nil, err
		}
		value, exists := parent[key]
		if !exists || value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("recordcrypt: JSON path %q must select an encrypted string or null", path)
		}
		if !strings.HasPrefix(text, Prefix) {
			if requireEncrypted {
				return nil, fmt.Errorf("recordcrypt: JSON path %q contains unencrypted plaintext", path)
			}
			continue
		}
		pathContext := ctx
		pathContext.JSONPath = path
		plaintext, err := k.Decrypt(pathContext, text)
		if err != nil {
			return nil, fmt.Errorf("recordcrypt: JSON path %q: %w", path, err)
		}
		parent[key] = string(plaintext)
	}
	return json.Marshal(root)
}

func decodeJSONObject(input []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("recordcrypt: decode JSON object: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("recordcrypt: trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("recordcrypt: trailing JSON data: %w", err)
	}
	if root == nil {
		return nil, errors.New("recordcrypt: protected JSON value must be an object")
	}
	return root, nil
}

func jsonLocation(root map[string]any, path string) (map[string]any, string, error) {
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	if len(parts) == 0 || path == "" || !strings.HasPrefix(path, "$.") {
		return nil, "", fmt.Errorf("recordcrypt: invalid JSON path %q", path)
	}
	current := root
	for _, part := range parts[:len(parts)-1] {
		value, exists := current[part]
		if !exists || value == nil {
			return map[string]any{}, parts[len(parts)-1], nil
		}
		next, ok := value.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("recordcrypt: JSON path %q crosses a non-object value", path)
		}
		current = next
	}
	return current, parts[len(parts)-1], nil
}
