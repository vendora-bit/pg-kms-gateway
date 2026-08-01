package origin

import (
	"strings"
	"testing"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
)

func testCatalog(t *testing.T, field policy.Field) *policy.Catalog {
	t.Helper()
	doc := policy.Document{APIVersion: policy.APIVersion, Kind: "FieldEncryptionPolicy", Metadata: policy.Metadata{Name: "test"}, Spec: policy.Spec{KeyDomain: "tenant", Columns: []policy.Field{field}}}
	catalog, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestCompileValidatesAndResolvesOrigins(t *testing.T) {
	field := policy.Field{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, BlindIndex: "email_bidx"}
	resolver, err := Compile(testCatalog(t, field), []Column{
		{Schema: "public", Table: "users", Column: "email", TableOID: 42, AttributeNumber: 3, TypeName: "text"},
		{Schema: "public", Table: "users", Column: "email_bidx", TableOID: 42, AttributeNumber: 4, TypeName: "varchar"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, ok, err := resolver.Resolve(42, 3)
	if err != nil || !ok || resolved.Column != "email" {
		t.Fatalf("unexpected resolution: %+v, %v, %v", resolved, ok, err)
	}
	if _, ok, _ := resolver.Resolve(42, 4); ok {
		t.Fatal("blind-index storage was treated as a decryptable field")
	}
}

func TestCompileRejectsSchemaDrift(t *testing.T) {
	field := policy.Field{Schema: "public", Table: "profiles", Column: "data", Mode: policy.ModeRandom, JSONPaths: []string{"$.email"}}
	_, err := Compile(testCatalog(t, field), []Column{{Schema: "public", Table: "profiles", Column: "data", TableOID: 7, AttributeNumber: 2, TypeName: "text"}})
	if err == nil || !strings.Contains(err.Error(), "jsonPaths require") {
		t.Fatalf("expected JSON type mismatch, got %v", err)
	}
}
