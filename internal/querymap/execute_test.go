package querymap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

func executionKeyring(t *testing.T) *recordcrypt.Keyring {
	t.Helper()
	material, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := recordcrypt.NewKeyring("dk-test", map[string]recordcrypt.Material{"dk-test": material})
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func TestApplyInsertParametersAndResult(t *testing.T) {
	plan, err := Analyze(`INSERT INTO users (email, external_id) VALUES ($1, $2) RETURNING email`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	keyring := executionKeyring(t)
	params, err := ApplyParameters(plan, keyring, "tenant-a", [][]byte{[]byte(" Person@Example.Com "), []byte("external-1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 3 || !strings.HasPrefix(string(params[0]), recordcrypt.Prefix) || !strings.HasPrefix(string(params[2]), recordcrypt.BlindIndexPrefix) {
		t.Fatalf("unexpected parameters: %q", params)
	}
	row, err := ApplyResults(plan.Results, keyring, "tenant-a", [][]byte{params[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(row[0], []byte(" Person@Example.Com ")) {
		t.Fatalf("got %q", row[0])
	}
}

func TestNullsAndPartialBackfill(t *testing.T) {
	plan, err := Analyze(`SELECT email FROM users WHERE external_id = $1`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	keyring := executionKeyring(t)
	params, err := ApplyParameters(plan, keyring, "tenant-a", [][]byte{nil})
	if err != nil || params[0] != nil {
		t.Fatalf("NULL was not preserved: %q, %v", params, err)
	}
	row, err := ApplyResults(plan.Results, keyring, "tenant-a", [][]byte{[]byte("not-yet-encrypted@example.com")})
	if err != nil || string(row[0]) != "not-yet-encrypted@example.com" {
		t.Fatalf("partial backfill read failed: %q, %v", row, err)
	}
}

func TestMalformedReservedResultFailsClosed(t *testing.T) {
	plan, err := Analyze(`SELECT email FROM users`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyResults(plan.Results, executionKeyring(t), "tenant-a", [][]byte{[]byte("$PGXENC$broken")})
	if err == nil {
		t.Fatal("malformed reserved value was returned")
	}
}

func TestEqualityExpandsAcrossDecryptableKeyVersions(t *testing.T) {
	oldMaterial, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	activeMaterial, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := recordcrypt.NewKeyring("active", map[string]recordcrypt.Material{"active": activeMaterial, "old": oldMaterial})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := AnalyzeWithKeyIDs(`SELECT email FROM users WHERE email = $1`, catalog(t), keyring.KeyIDs())
	if err != nil {
		t.Fatal(err)
	}
	if plan.ParameterCount != 2 || len(plan.Parameters) != 2 || !strings.Contains(plan.SQL, " OR ") {
		t.Fatalf("versioned equality was not expanded: %+v", plan)
	}
	params, err := ApplyParameters(plan, keyring, "tenant-a", [][]byte{[]byte("person@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 2 || string(params[0]) == string(params[1]) || !strings.Contains(string(params[0]), ":active:") || !strings.Contains(string(params[1]), ":old:") {
		t.Fatalf("unexpected versioned indexes: %q", params)
	}

	deterministic, err := AnalyzeWithKeyIDs(`SELECT external_id FROM users WHERE external_id = $1`, catalog(t), keyring.KeyIDs())
	if err != nil {
		t.Fatal(err)
	}
	deterministicParams, err := ApplyParameters(deterministic, keyring, "tenant-a", [][]byte{[]byte("external-1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(deterministicParams) != 2 || string(deterministicParams[0]) == string(deterministicParams[1]) {
		t.Fatalf("unexpected deterministic versions: %q", deterministicParams)
	}
}
