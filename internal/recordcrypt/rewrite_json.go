package recordcrypt

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RewriteJSON encrypts plaintext selected paths, verifies existing envelopes,
// and optionally rewrites decrypt-only key versions to the active key.
func (k *Keyring) RewriteJSON(ctx Context, mode TextMode, input []byte, paths []string, forceActive bool) ([]byte, bool, error) {
	root, err := decodeJSONObject(input)
	if err != nil {
		return nil, false, err
	}
	changed := false
	for _, path := range paths {
		parent, key, err := jsonLocation(root, path)
		if err != nil {
			return nil, false, err
		}
		value, exists := parent[key]
		if !exists || value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, false, fmt.Errorf("recordcrypt: JSON path %q must select a string or null", path)
		}
		pathContext := ctx
		pathContext.JSONPath = path
		if strings.HasPrefix(text, Prefix) {
			envelope, err := Parse(text)
			if err != nil {
				return nil, false, fmt.Errorf("recordcrypt: JSON path %q: %w", path, err)
			}
			plaintext, err := k.Decrypt(pathContext, text)
			if err != nil {
				return nil, false, fmt.Errorf("recordcrypt: JSON path %q: %w", path, err)
			}
			expectedMode := ModeRandom
			if mode == TextDeterministic {
				expectedMode = ModeDeterministic
			}
			if envelope.Mode != expectedMode && !forceActive {
				return nil, false, fmt.Errorf("recordcrypt: JSON path %q uses a mode inconsistent with policy", path)
			}
			if envelope.Mode == expectedMode && (!forceActive || envelope.KeyID == k.active) {
				continue
			}
			text = string(plaintext)
		}
		encrypted, err := k.EncryptText(pathContext, mode, []byte(text))
		if err != nil {
			return nil, false, err
		}
		parent[key] = encrypted
		changed = true
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, false, fmt.Errorf("recordcrypt: encode rewritten JSON: %w", err)
	}
	return encoded, changed, nil
}

type JSONInspection struct {
	PlaintextPaths int
	OldKeyPaths    int
}

func (k *Keyring) InspectJSON(ctx Context, mode TextMode, input []byte, paths []string) (JSONInspection, error) {
	root, err := decodeJSONObject(input)
	if err != nil {
		return JSONInspection{}, err
	}
	var inspection JSONInspection
	for _, path := range paths {
		parent, key, err := jsonLocation(root, path)
		if err != nil {
			return inspection, err
		}
		value, exists := parent[key]
		if !exists || value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return inspection, fmt.Errorf("recordcrypt: JSON path %q must select a string or null", path)
		}
		if !strings.HasPrefix(text, Prefix) {
			inspection.PlaintextPaths++
			continue
		}
		envelope, err := Parse(text)
		if err != nil {
			return inspection, err
		}
		expected := ModeRandom
		if mode == TextDeterministic {
			expected = ModeDeterministic
		}
		if envelope.Mode != expected {
			return inspection, fmt.Errorf("recordcrypt: JSON path %q uses a mode inconsistent with policy", path)
		}
		pathContext := ctx
		pathContext.JSONPath = path
		if _, err := k.Decrypt(pathContext, text); err != nil {
			return inspection, err
		}
		if envelope.KeyID != k.active {
			inspection.OldKeyPaths++
		}
	}
	return inspection, nil
}
