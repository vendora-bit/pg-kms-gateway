package recordcrypt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	m, err := GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyring("dk-2026-08", map[string]Material{"dk-2026-08": m})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testContext() Context {
	return Context{Domain: "tenant-a", Schema: "public", Table: "users", Column: "email"}
}

func TestRandomRoundTripAndNonceUniqueness(t *testing.T) {
	k := testKeyring(t)
	a, err := k.EncryptRandom(testContext(), []byte("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.EncryptRandom(testContext(), []byte("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("random mode produced identical envelopes")
	}
	plain, err := k.Decrypt(testContext(), a)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "person@example.com" {
		t.Fatalf("got %q", plain)
	}
}

func TestDeterministicEqualityIsBoundToContext(t *testing.T) {
	k := testKeyring(t)
	a, err := k.EncryptDeterministic(testContext(), []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.EncryptDeterministic(testContext(), []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("deterministic mode produced different envelopes")
	}
	other := testContext()
	other.Column = "phone"
	if _, err := k.Decrypt(other, a); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("expected context mismatch, got %v", err)
	}
}

func TestTamperingFailsClosed(t *testing.T) {
	k := testKeyring(t)
	value, err := k.EncryptRandom(testContext(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload[len(envelope.Payload)-1] ^= 1
	tampered := encodeEnvelope(envelope.Mode, envelope.KeyID, envelope.Payload)
	if _, err := k.Decrypt(testContext(), tampered); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("expected authentication failure, got %v", err)
	}
}

func TestReservedPrefixNeverFallsBackToPlaintext(t *testing.T) {
	k := testKeyring(t)
	for _, value := range []string{"$PGXENC$", "$PGXENC$2:r:key:not base64", "$PGXENC$9:r:key:AA"} {
		if _, err := k.Decrypt(testContext(), value); !errors.Is(err, ErrMalformedEnvelope) {
			t.Fatalf("%q: expected malformed envelope, got %v", value, err)
		}
	}
	if _, err := k.Decrypt(testContext(), "ordinary"); !errors.Is(err, ErrNotEnvelope) {
		t.Fatalf("expected not-envelope, got %v", err)
	}
}

func TestBlindIndexUsesIndependentContextAndKeyVersion(t *testing.T) {
	k := testKeyring(t)
	a, err := k.BlindIndex(testContext(), []byte("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.BlindIndex(testContext(), []byte("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyBlindIndex(a, b) || !strings.HasPrefix(a, BlindIndexPrefix+k.ActiveKeyID()+":") {
		t.Fatalf("unexpected blind index %q", a)
	}
	other := testContext()
	other.Table = "accounts"
	c, err := k.BlindIndex(other, []byte("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal([]byte(a), []byte(c)) {
		t.Fatal("blind indexes leaked equality across contexts")
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	f.Add("$PGXENC$2:r:key:AA")
	f.Add("plaintext")
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = Parse(value)
	})
}
