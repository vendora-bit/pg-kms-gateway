package operator

import (
	"strings"
	"testing"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

func processor(t *testing.T) Processor {
	t.Helper()
	material, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := recordcrypt.NewKeyring("active", map[string]recordcrypt.Material{"active": material})
	if err != nil {
		t.Fatal(err)
	}
	return Processor{Keyring: keyring, Domain: "tenant"}
}

func TestBackfillIsIdempotentAndRepairsBlindIndex(t *testing.T) {
	processor := processor(t)
	field := policy.Field{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, Normalize: policy.NormalizeLowercaseTrim, BlindIndex: "email_bidx"}
	value, blind, changed, err := processor.Transform(field, []byte(" Person@Example.COM "), nil, Backfill)
	if err != nil || !changed || !strings.HasPrefix(string(value), recordcrypt.Prefix) || !strings.HasPrefix(string(blind), recordcrypt.BlindIndexPrefix) {
		t.Fatalf("unexpected transform: %q %q %v %v", value, blind, changed, err)
	}
	secondValue, secondBlind, changed, err := processor.Transform(field, value, blind, Backfill)
	if err != nil || changed || string(secondValue) != string(value) || string(secondBlind) != string(blind) {
		t.Fatalf("backfill was not idempotent: %v %v", changed, err)
	}
	_, repairedBlind, changed, err := processor.Transform(field, value, []byte("wrong"), Backfill)
	if err != nil || !changed || string(repairedBlind) != string(blind) {
		t.Fatalf("blind index was not repaired: %q %v %v", repairedBlind, changed, err)
	}
}

func TestPartialJSONBackfill(t *testing.T) {
	processor := processor(t)
	field := policy.Field{Schema: "public", Table: "profiles", Column: "data", Mode: policy.ModeRandom, JSONPaths: []string{"$.email", "$.phone"}}
	first, _, changed, err := processor.Transform(field, []byte(`{"email":"a@example.com","phone":"+1"}`), nil, Backfill)
	if err != nil || !changed {
		t.Fatal(err)
	}
	second, _, changed, err := processor.Transform(field, first, nil, Backfill)
	if err != nil || changed || string(second) != string(first) {
		t.Fatalf("JSON backfill was not idempotent: %s %v %v", second, changed, err)
	}
}

func TestInspectReportsPlaintextAndBlindMismatch(t *testing.T) {
	processor := processor(t)
	field := policy.Field{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, BlindIndex: "email_bidx"}
	plaintext, old, mismatch, err := processor.Inspect(field, []byte("plain@example.com"), []byte("stale"))
	if err != nil || !plaintext || old || !mismatch {
		t.Fatalf("unexpected inspection: %v %v %v %v", plaintext, old, mismatch, err)
	}
	value, blind, _, err := processor.Transform(field, []byte("plain@example.com"), nil, Backfill)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, old, mismatch, err = processor.Inspect(field, value, blind)
	if err != nil || plaintext || old || mismatch {
		t.Fatalf("valid row failed inspection: %v %v %v %v", plaintext, old, mismatch, err)
	}
}
