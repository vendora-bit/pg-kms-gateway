package vaultkey

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

func providers(t *testing.T) map[string]Provider {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	provider, err := NewLocalProvider(map[string][]byte{"kek-a": key, "kek-b": key})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Provider{provider.Name(): provider}
}

func TestBundleLifecycle(t *testing.T) {
	ctx := context.Background()
	registry := providers(t)
	t0 := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	bundle, keyring, err := New(ctx, "tenant-a", Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, t0)
	if err != nil {
		t.Fatal(err)
	}
	context := recordcrypt.Context{Domain: "tenant-a", Schema: "public", Table: "users", Column: "email"}
	oldValue, err := keyring.EncryptRandom(context, []byte("old@example.com"))
	if err != nil {
		t.Fatal(err)
	}

	rotated, nextKeyring, err := Rotate(ctx, bundle, Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Active == bundle.Active || len(rotated.Keys) != 2 || rotated.Keys[0].State != "decrypt-only" {
		t.Fatalf("unexpected rotated bundle: %+v", rotated)
	}
	if plain, err := nextKeyring.Decrypt(context, oldValue); err != nil || string(plain) != "old@example.com" {
		t.Fatalf("old data did not survive rotation: %q, %v", plain, err)
	}

	rewrapped, err := Rewrap(ctx, rotated, Target{Provider: "local-dev", KeyRef: "kek-b"}, registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range rewrapped.Keys {
		if entry.KeyRef != "kek-b" {
			t.Fatalf("key was not rewrapped: %+v", entry)
		}
	}
	opened, err := Open(ctx, rewrapped, registry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Decrypt(context, oldValue); err != nil {
		t.Fatal(err)
	}
}

func TestBundleMetadataTamperingBreaksUnwrap(t *testing.T) {
	registry := providers(t)
	bundle, _, err := New(context.Background(), "tenant-a", Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle.Keys[0].CreatedAt = bundle.Keys[0].CreatedAt.Add(time.Second)
	if _, err := Open(context.Background(), bundle, registry); err == nil {
		t.Fatal("metadata tampering was accepted")
	}
}

func TestStrictParsingAndAtomicSave(t *testing.T) {
	registry := providers(t)
	bundle, _, err := New(context.Background(), "tenant-a", Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil || parsed.Active != bundle.Active {
		t.Fatalf("parse failed: %v", err)
	}
	if _, err := Parse(append(data[:len(data)-2], []byte(",\"unknown\":true}\n")...)); err == nil {
		t.Fatal("unknown field was accepted")
	}

	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := SaveAtomic(path, bundle); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode is %o", info.Mode().Perm())
	}
}

func TestCancellationAndWrongKEKFailClosed(t *testing.T) {
	registry := providers(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := New(ctx, "tenant-a", Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestPruneKeepsOnlyActiveVersion(t *testing.T) {
	registry := providers(t)
	bundle, _, err := New(context.Background(), "tenant-a", Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rotated, _, err := Rotate(context.Background(), bundle, Target{Provider: "local-dev", KeyRef: "kek-a"}, registry, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pruned, removed, err := PruneDecryptOnly(rotated)
	if err != nil || removed != 1 || len(pruned.Keys) != 1 || pruned.Keys[0].ID != pruned.Active {
		t.Fatalf("unexpected prune: %+v %d %v", pruned, removed, err)
	}
}
