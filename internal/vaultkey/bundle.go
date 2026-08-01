package vaultkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

const (
	BundleVersion = 1
	materialSize  = 4 + 32 + 64 + 32
)

var materialMagic = [4]byte{'P', 'G', 'K', 1}

type Provider interface {
	Name() string
	Wrap(ctx context.Context, keyRef string, plaintext, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, keyRef string, ciphertext, aad []byte) ([]byte, error)
}

type Bundle struct {
	Version int     `json:"version"`
	Domain  string  `json:"domain"`
	Active  string  `json:"active"`
	Keys    []Entry `json:"keys"`
}

type Entry struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
	Provider  string    `json:"provider"`
	KeyRef    string    `json:"keyRef"`
	Wrapped   string    `json:"wrapped"`
}

type Target struct {
	Provider string
	KeyRef   string
}

func New(ctx context.Context, domain string, target Target, providers map[string]Provider, now time.Time) (Bundle, *recordcrypt.Keyring, error) {
	if err := validateDomain(domain); err != nil {
		return Bundle{}, nil, err
	}
	id, err := newKeyID(now)
	if err != nil {
		return Bundle{}, nil, err
	}
	material, err := recordcrypt.GenerateMaterial()
	if err != nil {
		return Bundle{}, nil, err
	}
	entry, err := wrapEntry(ctx, domain, id, "active", now, material, target, providers)
	if err != nil {
		return Bundle{}, nil, err
	}
	bundle := Bundle{Version: BundleVersion, Domain: domain, Active: id, Keys: []Entry{entry}}
	keyring, err := recordcrypt.NewKeyring(id, map[string]recordcrypt.Material{id: material})
	return bundle, keyring, err
}

func Open(ctx context.Context, bundle Bundle, providers map[string]Provider) (*recordcrypt.Keyring, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	materials := make(map[string]recordcrypt.Material, len(bundle.Keys))
	for _, entry := range bundle.Keys {
		provider, ok := providers[entry.Provider]
		if !ok || provider == nil {
			return nil, fmt.Errorf("vaultkey: provider %q is unavailable", entry.Provider)
		}
		if provider.Name() != entry.Provider {
			return nil, fmt.Errorf("vaultkey: provider registry mismatch for %q", entry.Provider)
		}
		wrapped, err := base64.RawStdEncoding.Strict().DecodeString(entry.Wrapped)
		if err != nil || len(wrapped) == 0 {
			return nil, fmt.Errorf("vaultkey: key %q has invalid wrapped material", entry.ID)
		}
		plaintext, err := provider.Unwrap(ctx, entry.KeyRef, wrapped, bundleAAD(bundle.Domain, entry))
		if err != nil {
			return nil, fmt.Errorf("vaultkey: unwrap key %q: %w", entry.ID, err)
		}
		material, err := decodeMaterial(plaintext)
		clear(plaintext)
		if err != nil {
			return nil, fmt.Errorf("vaultkey: key %q: %w", entry.ID, err)
		}
		materials[entry.ID] = material
	}
	return recordcrypt.NewKeyring(bundle.Active, materials)
}

func Rotate(ctx context.Context, current Bundle, target Target, providers map[string]Provider, now time.Time) (Bundle, *recordcrypt.Keyring, error) {
	keyring, err := Open(ctx, current, providers)
	if err != nil {
		return Bundle{}, nil, err
	}
	_ = keyring
	id, err := newKeyID(now)
	if err != nil {
		return Bundle{}, nil, err
	}
	material, err := recordcrypt.GenerateMaterial()
	if err != nil {
		return Bundle{}, nil, err
	}
	entry, err := wrapEntry(ctx, current.Domain, id, "active", now, material, target, providers)
	if err != nil {
		return Bundle{}, nil, err
	}
	next := cloneBundle(current)
	for i := range next.Keys {
		if next.Keys[i].ID == next.Active {
			next.Keys[i].State = "decrypt-only"
		}
	}
	next.Active = id
	next.Keys = append(next.Keys, entry)
	sort.Slice(next.Keys, func(i, j int) bool { return next.Keys[i].CreatedAt.Before(next.Keys[j].CreatedAt) })

	opened, err := Open(ctx, next, providers)
	if err != nil {
		return Bundle{}, nil, err
	}
	return next, opened, nil
}

func Rewrap(ctx context.Context, current Bundle, target Target, providers map[string]Provider) (Bundle, error) {
	if err := current.Validate(); err != nil {
		return Bundle{}, err
	}
	next := cloneBundle(current)
	for i, entry := range current.Keys {
		oldProvider, ok := providers[entry.Provider]
		if !ok || oldProvider == nil {
			return Bundle{}, fmt.Errorf("vaultkey: provider %q is unavailable", entry.Provider)
		}
		wrapped, err := base64.RawStdEncoding.Strict().DecodeString(entry.Wrapped)
		if err != nil {
			return Bundle{}, fmt.Errorf("vaultkey: key %q has invalid wrapped material", entry.ID)
		}
		plaintext, err := oldProvider.Unwrap(ctx, entry.KeyRef, wrapped, bundleAAD(current.Domain, entry))
		if err != nil {
			return Bundle{}, fmt.Errorf("vaultkey: unwrap key %q: %w", entry.ID, err)
		}
		newEntry, err := wrapRaw(ctx, current.Domain, entry, plaintext, target, providers)
		clear(plaintext)
		if err != nil {
			return Bundle{}, err
		}
		next.Keys[i] = newEntry
	}
	if _, err := Open(ctx, next, providers); err != nil {
		return Bundle{}, fmt.Errorf("vaultkey: verify rewrapped bundle: %w", err)
	}
	return next, nil
}

func (b Bundle) Validate() error {
	if b.Version != BundleVersion {
		return fmt.Errorf("vaultkey: unsupported bundle version %d", b.Version)
	}
	if err := validateDomain(b.Domain); err != nil {
		return err
	}
	if len(b.Keys) == 0 || len(b.Keys) > 32 {
		return errors.New("vaultkey: bundle must contain 1..32 keys; re-encrypt and prune old versions")
	}
	seen := make(map[string]struct{}, len(b.Keys))
	activeCount := 0
	for i, entry := range b.Keys {
		if !validToken(entry.ID) {
			return fmt.Errorf("vaultkey: keys[%d].id is invalid", i)
		}
		if _, exists := seen[entry.ID]; exists {
			return fmt.Errorf("vaultkey: duplicate key id %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		if entry.ID == b.Active {
			activeCount++
			if entry.State != "active" {
				return errors.New("vaultkey: active key state is inconsistent")
			}
		} else if entry.State != "decrypt-only" {
			return fmt.Errorf("vaultkey: non-active key %q must be decrypt-only", entry.ID)
		}
		if entry.CreatedAt.IsZero() || !validToken(entry.Provider) || strings.TrimSpace(entry.KeyRef) == "" || entry.Wrapped == "" {
			return fmt.Errorf("vaultkey: key %q metadata is incomplete", entry.ID)
		}
	}
	if activeCount != 1 {
		return errors.New("vaultkey: active must reference exactly one key")
	}
	return nil
}

func PruneDecryptOnly(current Bundle) (Bundle, int, error) {
	if err := current.Validate(); err != nil {
		return Bundle{}, 0, err
	}
	next := cloneBundle(current)
	next.Keys = next.Keys[:0]
	for _, entry := range current.Keys {
		if entry.ID == current.Active {
			next.Keys = append(next.Keys, entry)
		}
	}
	removed := len(current.Keys) - len(next.Keys)
	if err := next.Validate(); err != nil {
		return Bundle{}, 0, err
	}
	return next, removed, nil
}

func Parse(data []byte) (Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("vaultkey: decode bundle: %w", err)
	}
	if decoder.More() {
		return Bundle{}, errors.New("vaultkey: trailing JSON value")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Bundle{}, errors.New("vaultkey: trailing JSON value")
		}
		return Bundle{}, fmt.Errorf("vaultkey: trailing data: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func Marshal(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vaultkey: encode bundle: %w", err)
	}
	return append(data, '\n'), nil
}

func SaveAtomic(path string, bundle Bundle) error {
	data, err := Marshal(bundle)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".pgkms-bundle-*")
	if err != nil {
		return fmt.Errorf("vaultkey: create temporary bundle: %w", err)
	}
	name := temp.Name()
	ok := false
	defer func() {
		_ = temp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("vaultkey: chmod temporary bundle: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("vaultkey: write temporary bundle: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("vaultkey: sync temporary bundle: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("vaultkey: close temporary bundle: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("vaultkey: install bundle: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("vaultkey: open bundle directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return fmt.Errorf("vaultkey: sync bundle directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("vaultkey: close bundle directory: %w", err)
	}
	ok = true
	return nil
}

func wrapEntry(ctx context.Context, domain, id, state string, now time.Time, material recordcrypt.Material, target Target, providers map[string]Provider) (Entry, error) {
	entry := Entry{ID: id, State: state, CreatedAt: now.UTC()}
	plaintext := encodeMaterial(material)
	defer clear(plaintext)
	return wrapRaw(ctx, domain, entry, plaintext, target, providers)
}

func wrapRaw(ctx context.Context, domain string, entry Entry, plaintext []byte, target Target, providers map[string]Provider) (Entry, error) {
	provider, ok := providers[target.Provider]
	if !ok || provider == nil || provider.Name() != target.Provider {
		return Entry{}, fmt.Errorf("vaultkey: provider %q is unavailable", target.Provider)
	}
	if strings.TrimSpace(target.KeyRef) == "" {
		return Entry{}, errors.New("vaultkey: target key reference is required")
	}
	entry.Provider = target.Provider
	entry.KeyRef = target.KeyRef
	entry.Wrapped = ""
	wrapped, err := provider.Wrap(ctx, target.KeyRef, plaintext, bundleAAD(domain, entry))
	if err != nil {
		return Entry{}, fmt.Errorf("vaultkey: wrap key %q: %w", entry.ID, err)
	}
	if len(wrapped) == 0 {
		return Entry{}, errors.New("vaultkey: provider returned empty ciphertext")
	}
	entry.Wrapped = base64.RawStdEncoding.EncodeToString(wrapped)
	return entry, nil
}

func bundleAAD(domain string, entry Entry) []byte {
	// State is intentionally excluded: rotation changes active to decrypt-only
	// without touching the wrapped material. Identity, creation time and KEK
	// routing remain authenticated and immutable.
	fields := []string{"pgkms-bundle", "1", domain, entry.ID, entry.CreatedAt.UTC().Format(time.RFC3339Nano), entry.Provider, entry.KeyRef}
	var b strings.Builder
	for _, field := range fields {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(field)))
		b.WriteString(field)
	}
	return []byte(b.String())
}

func encodeMaterial(material recordcrypt.Material) []byte {
	out := make([]byte, 0, materialSize)
	out = append(out, materialMagic[:]...)
	out = append(out, material.RandomKey...)
	out = append(out, material.DeterministicKey...)
	out = append(out, material.BlindIndexKey...)
	return out
}

func decodeMaterial(data []byte) (recordcrypt.Material, error) {
	if len(data) != materialSize || !bytes.Equal(data[:4], materialMagic[:]) {
		return recordcrypt.Material{}, errors.New("wrapped material has invalid format")
	}
	return recordcrypt.Material{
		RandomKey: append([]byte(nil), data[4:36]...), DeterministicKey: append([]byte(nil), data[36:100]...), BlindIndexKey: append([]byte(nil), data[100:132]...),
	}, nil
}

func newKeyID(now time.Time) (string, error) {
	random := make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", fmt.Errorf("vaultkey: generate key id: %w", err)
	}
	return "dk-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func validateDomain(domain string) error {
	if strings.TrimSpace(domain) == "" || len(domain) > 256 || strings.ContainsRune(domain, 0) {
		return errors.New("vaultkey: domain is invalid")
	}
	return nil
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func cloneBundle(bundle Bundle) Bundle {
	next := bundle
	next.Keys = append([]Entry(nil), bundle.Keys...)
	return next
}
