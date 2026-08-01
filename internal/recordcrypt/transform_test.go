package recordcrypt

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONPathRoundTripPreservesUnselectedData(t *testing.T) {
	k := testKeyring(t)
	ctx := Context{Domain: "tenant-a", Schema: "public", Table: "profiles", Column: "data"}
	input := []byte(`{"name":"Ada","address":{"email":"ADA@EXAMPLE.COM","zip":12345},"enabled":true}`)
	encrypted, err := k.EncryptJSON(ctx, TextRandom, input, []string{"$.address.email", "$.name"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("ADA@EXAMPLE.COM")) || bytes.Contains(encrypted, []byte(`"Ada"`)) {
		t.Fatalf("plaintext remained in JSON: %s", encrypted)
	}
	decrypted, err := k.DecryptJSON(ctx, encrypted, []string{"$.address.email", "$.name"})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(decrypted, &value); err != nil {
		t.Fatal(err)
	}
	if value["name"] != "Ada" || value["enabled"] != true {
		t.Fatalf("unexpected JSON: %s", decrypted)
	}
}

func TestJSONPlaintextAtProtectedPathFailsClosedOnRead(t *testing.T) {
	k := testKeyring(t)
	ctx := Context{Domain: "tenant-a", Schema: "public", Table: "profiles", Column: "data"}
	_, err := k.DecryptJSON(ctx, []byte(`{"email":"plaintext@example.com"}`), []string{"$.email"})
	if err == nil || !strings.Contains(err.Error(), "unencrypted plaintext") {
		t.Fatalf("expected plaintext rejection, got %v", err)
	}
}

func TestNormalize(t *testing.T) {
	value, err := Normalize([]byte("  PERSON@Example.Com \n"), NormalizerLowercaseTrim)
	if err != nil || string(value) != "person@example.com" {
		t.Fatalf("got %q, %v", value, err)
	}
}
