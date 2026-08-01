package policy

import "testing"

func TestParseCompileAndLookup(t *testing.T) {
	raw := []byte(`apiVersion: pgkms.dev/v1
kind: FieldEncryptionPolicy
metadata:
  name: crm
spec:
  keyDomain: prod.crm
  columns:
    - schema: app
      table: customers
      column: email
      mode: deterministic
      normalize: lowercase-trim
      blindIndex: email_bidx
    - schema: app
      table: customers
      column: profile
      jsonPaths: [$.phone, $.address.street]
`)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got := catalog.KeyDomain(); got != "prod.crm" {
		t.Fatalf("domain = %q", got)
	}
	field, ok := catalog.Lookup(Identity{Schema: "app", Table: "customers", Column: "email"})
	if !ok || field.Mode != ModeDeterministic {
		t.Fatalf("unexpected field: %#v, %v", field, ok)
	}
	if got := len(catalog.Table("app", "customers")); got != 2 {
		t.Fatalf("table fields = %d", got)
	}
}

func TestParseRejectsUnknownAndUnsafeShape(t *testing.T) {
	tests := map[string]string{
		"unknown": `apiVersion: pgkms.dev/v1
kind: FieldEncryptionPolicy
metadata: {name: x}
spec: {keyDomain: x, columns: [], surprise: true}`,
		"duplicate": `apiVersion: pgkms.dev/v1
kind: FieldEncryptionPolicy
metadata: {name: x}
spec:
  keyDomain: x
  columns:
    - {table: users, column: email}
    - {table: users, column: email}`,
		"wildcard json": `apiVersion: pgkms.dev/v1
kind: FieldEncryptionPolicy
metadata: {name: x}
spec:
  keyDomain: x
  columns:
    - {table: users, column: profile, jsonPaths: [$.contacts.*]}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
