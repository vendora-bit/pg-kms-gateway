package recordcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	daeadsubtle "github.com/tink-crypto/tink-go/v2/daead/subtle"
)

const (
	Prefix            = "$PGXENC$"
	formatVersion     = "2"
	ModeRandom        = "r"
	ModeDeterministic = "d"
	BlindIndexPrefix  = "$PGXIDX$1:"

	maxPlaintextBytes = 16 << 20
)

var (
	ErrNotEnvelope       = errors.New("recordcrypt: value is not an encrypted envelope")
	ErrMalformedEnvelope = errors.New("recordcrypt: malformed encrypted envelope")
	ErrUnknownKey        = errors.New("recordcrypt: unknown data key")
	ErrContextMismatch   = errors.New("recordcrypt: authentication or context mismatch")
)

type Material struct {
	RandomKey        []byte
	DeterministicKey []byte
	BlindIndexKey    []byte
}

func (m Material) validate() error {
	if len(m.RandomKey) != 32 {
		return fmt.Errorf("recordcrypt: random key must be 32 bytes")
	}
	if len(m.DeterministicKey) != 64 {
		return fmt.Errorf("recordcrypt: deterministic key must be 64 bytes")
	}
	if len(m.BlindIndexKey) != 32 {
		return fmt.Errorf("recordcrypt: blind-index key must be 32 bytes")
	}
	return nil
}

func GenerateMaterial() (Material, error) {
	m := Material{
		RandomKey:        make([]byte, 32),
		DeterministicKey: make([]byte, 64),
		BlindIndexKey:    make([]byte, 32),
	}
	for _, target := range [][]byte{m.RandomKey, m.DeterministicKey, m.BlindIndexKey} {
		if _, err := io.ReadFull(rand.Reader, target); err != nil {
			return Material{}, fmt.Errorf("recordcrypt: generate key material: %w", err)
		}
	}
	return m, nil
}

type Keyring struct {
	active string
	keys   map[string]Material
}

func NewKeyring(active string, keys map[string]Material) (*Keyring, error) {
	if !validKeyID(active) {
		return nil, errors.New("recordcrypt: active key id is invalid")
	}
	copyKeys := make(map[string]Material, len(keys))
	for id, material := range keys {
		if !validKeyID(id) {
			return nil, fmt.Errorf("recordcrypt: key id %q is invalid", id)
		}
		if err := material.validate(); err != nil {
			return nil, fmt.Errorf("recordcrypt: key %q: %w", id, err)
		}
		copyKeys[id] = cloneMaterial(material)
	}
	if _, ok := copyKeys[active]; !ok {
		return nil, errors.New("recordcrypt: active key is absent")
	}
	return &Keyring{active: active, keys: copyKeys}, nil
}

func validKeyID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func cloneMaterial(m Material) Material {
	return Material{
		RandomKey:        append([]byte(nil), m.RandomKey...),
		DeterministicKey: append([]byte(nil), m.DeterministicKey...),
		BlindIndexKey:    append([]byte(nil), m.BlindIndexKey...),
	}
}

type Context struct {
	Domain   string
	Schema   string
	Table    string
	Column   string
	JSONPath string
}

func (c Context) validate() error {
	for label, value := range map[string]string{
		"domain": c.Domain, "schema": c.Schema, "table": c.Table, "column": c.Column,
	} {
		if value == "" {
			return fmt.Errorf("recordcrypt: context %s is required", label)
		}
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("recordcrypt: context %s contains NUL", label)
		}
	}
	if strings.ContainsRune(c.JSONPath, 0) {
		return errors.New("recordcrypt: context json path contains NUL")
	}
	return nil
}

func associatedData(c Context, mode string) []byte {
	parts := []string{"pgxenc", formatVersion, c.Domain, c.Schema, c.Table, c.Column, mode, c.JSONPath}
	var b strings.Builder
	for _, part := range parts {
		fmt.Fprintf(&b, "%d:%s", len(part), part)
	}
	return []byte(b.String())
}

func (k *Keyring) EncryptRandom(ctx Context, plaintext []byte) (string, error) {
	if err := validateInput(ctx, plaintext); err != nil {
		return "", err
	}
	material := k.keys[k.active]
	block, err := aes.NewCipher(material.RandomKey)
	if err != nil {
		return "", fmt.Errorf("recordcrypt: initialize AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("recordcrypt: initialize GCM: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("recordcrypt: generate nonce: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plaintext, associatedData(ctx, ModeRandom))
	payload := append(nonce, sealed...)
	return encodeEnvelope(ModeRandom, k.active, payload), nil
}

func (k *Keyring) EncryptDeterministic(ctx Context, plaintext []byte) (string, error) {
	return k.EncryptDeterministicWithKeyID(ctx, k.active, plaintext)
}

func (k *Keyring) EncryptDeterministicWithKeyID(ctx Context, keyID string, plaintext []byte) (string, error) {
	if err := validateInput(ctx, plaintext); err != nil {
		return "", err
	}
	material, exists := k.keys[keyID]
	if !exists {
		return "", fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	primitive, err := daeadsubtle.NewAESSIV(material.DeterministicKey)
	if err != nil {
		return "", fmt.Errorf("recordcrypt: initialize AES-SIV: %w", err)
	}
	sealed, err := primitive.EncryptDeterministically(plaintext, associatedData(ctx, ModeDeterministic))
	if err != nil {
		return "", fmt.Errorf("recordcrypt: deterministic encryption: %w", err)
	}
	return encodeEnvelope(ModeDeterministic, keyID, sealed), nil
}

func validateInput(ctx Context, plaintext []byte) error {
	if err := ctx.validate(); err != nil {
		return err
	}
	if len(plaintext) > maxPlaintextBytes {
		return fmt.Errorf("recordcrypt: plaintext exceeds %d bytes", maxPlaintextBytes)
	}
	if !utf8.Valid(plaintext) {
		return errors.New("recordcrypt: text plaintext is not valid UTF-8")
	}
	return nil
}

func encodeEnvelope(mode, keyID string, payload []byte) string {
	return Prefix + formatVersion + ":" + mode + ":" + keyID + ":" + base64.RawURLEncoding.EncodeToString(payload)
}

type Envelope struct {
	Mode    string
	KeyID   string
	Payload []byte
}

func Parse(value string) (Envelope, error) {
	if !strings.HasPrefix(value, Prefix) {
		return Envelope{}, ErrNotEnvelope
	}
	parts := strings.Split(value, ":")
	if len(parts) != 4 || parts[0] != Prefix+formatVersion || (parts[1] != ModeRandom && parts[1] != ModeDeterministic) || !validKeyID(parts[2]) || parts[3] == "" {
		return Envelope{}, ErrMalformedEnvelope
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(payload) == 0 {
		return Envelope{}, ErrMalformedEnvelope
	}
	return Envelope{Mode: parts[1], KeyID: parts[2], Payload: payload}, nil
}

func (k *Keyring) Decrypt(ctx Context, value string) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	envelope, err := Parse(value)
	if err != nil {
		return nil, err
	}
	material, ok := k.keys[envelope.KeyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, envelope.KeyID)
	}
	switch envelope.Mode {
	case ModeRandom:
		block, err := aes.NewCipher(material.RandomKey)
		if err != nil {
			return nil, fmt.Errorf("recordcrypt: initialize AES: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("recordcrypt: initialize GCM: %w", err)
		}
		if len(envelope.Payload) < aead.NonceSize()+aead.Overhead() {
			return nil, ErrMalformedEnvelope
		}
		nonce := envelope.Payload[:aead.NonceSize()]
		ciphertext := envelope.Payload[aead.NonceSize():]
		plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData(ctx, ModeRandom))
		if err != nil {
			return nil, ErrContextMismatch
		}
		return plaintext, nil
	case ModeDeterministic:
		if len(envelope.Payload) < 16 {
			return nil, ErrMalformedEnvelope
		}
		primitive, err := daeadsubtle.NewAESSIV(material.DeterministicKey)
		if err != nil {
			return nil, fmt.Errorf("recordcrypt: initialize AES-SIV: %w", err)
		}
		plaintext, err := primitive.DecryptDeterministically(envelope.Payload, associatedData(ctx, ModeDeterministic))
		if err != nil {
			return nil, ErrContextMismatch
		}
		return plaintext, nil
	default:
		return nil, ErrMalformedEnvelope
	}
}

func (k *Keyring) BlindIndex(ctx Context, normalized []byte) (string, error) {
	return k.BlindIndexWithKeyID(ctx, k.active, normalized)
}

func (k *Keyring) BlindIndexWithKeyID(ctx Context, keyID string, normalized []byte) (string, error) {
	if err := validateInput(ctx, normalized); err != nil {
		return "", err
	}
	material, exists := k.keys[keyID]
	if !exists {
		return "", fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	mac := hmac.New(sha256.New, material.BlindIndexKey)
	_, _ = mac.Write(associatedData(ctx, "i"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(normalized)
	return BlindIndexPrefix + keyID + ":" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyBlindIndex(expected, actual string) bool {
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func (k *Keyring) ActiveKeyID() string { return k.active }

func (k *Keyring) KeyIDs() []string {
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		if id != k.active {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return append([]string{k.active}, ids...)
}
