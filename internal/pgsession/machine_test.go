package pgsession

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

type fakeOrigins struct{ field policy.Field }

func (f fakeOrigins) Resolve(oid uint32, attribute uint16) (policy.Field, bool, error) {
	return f.field, oid == 42 && attribute == 7, nil
}

func machine(t *testing.T) *Machine {
	t.Helper()
	doc := policy.Document{APIVersion: policy.APIVersion, Kind: "FieldEncryptionPolicy", Metadata: policy.Metadata{Name: "test"}, Spec: policy.Spec{KeyDomain: "tenant-a", Columns: []policy.Field{
		{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, BlindIndex: "email_bidx"},
	}}}
	catalog, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	material, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := recordcrypt.NewKeyring("dk-test", map[string]recordcrypt.Material{"dk-test": material})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := New(catalog, keyring, fakeOrigins{field: doc.Spec.Columns[0]})
	if err != nil {
		t.Fatal(err)
	}
	return machine
}

func TestExtendedProtocolTransformsBindAndRow(t *testing.T) {
	m := machine(t)
	parsed, err := m.Frontend(&pgproto3.Parse{Name: "find", Query: `SELECT email FROM users WHERE email = $1`, ParameterOIDs: []uint32{25}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(parsed.(*pgproto3.Parse).Query, "email_bidx") {
		t.Fatalf("query was not rewritten: %s", parsed.(*pgproto3.Parse).Query)
	}
	if _, err := m.Backend(&pgproto3.ParseComplete{}); err != nil {
		t.Fatal(err)
	}
	bound, err := m.Frontend(&pgproto3.Bind{DestinationPortal: "p", PreparedStatement: "find", Parameters: [][]byte{[]byte("person@example.com")}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(bound.(*pgproto3.Bind).Parameters[0]), recordcrypt.BlindIndexPrefix) {
		t.Fatalf("parameter was not indexed: %q", bound.(*pgproto3.Bind).Parameters)
	}
	if _, err := m.Backend(&pgproto3.BindComplete{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Frontend(&pgproto3.Execute{Portal: "p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Backend(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("email"), Format: pgproto3.TextFormat}}}); err != nil {
		t.Fatal(err)
	}

	ctx := recordcrypt.Context{Domain: "tenant-a", Schema: "public", Table: "users", Column: "email"}
	ciphertext, err := m.keyring.EncryptRandom(ctx, []byte("person@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	backend, err := m.Backend(&pgproto3.DataRow{Values: [][]byte{[]byte(ciphertext)}})
	if err != nil {
		t.Fatal(err)
	}
	if string(backend.(*pgproto3.DataRow).Values[0]) != "person@example.com" {
		t.Fatalf("row was not decrypted: %q", backend.(*pgproto3.DataRow).Values)
	}
}

func TestRejectsBinaryProtectedFormats(t *testing.T) {
	m := machine(t)
	if _, err := m.Frontend(&pgproto3.Parse{Name: "find", Query: `SELECT email FROM users WHERE email = $1`}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Frontend(&pgproto3.Bind{PreparedStatement: "find", Parameters: [][]byte{[]byte("x")}, ParameterFormatCodes: []int16{pgproto3.BinaryFormat}})
	if !errors.Is(err, ErrProtocolSafety) {
		t.Fatalf("expected safety error, got %v", err)
	}
}

func TestFailedParseRollsBackProvisionalStatement(t *testing.T) {
	m := machine(t)
	if _, err := m.Frontend(&pgproto3.Parse{Name: "find", Query: `SELECT email FROM users`}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Backend(&pgproto3.ErrorResponse{Message: "server rejected parse"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Frontend(&pgproto3.Bind{PreparedStatement: "find"}); !errors.Is(err, ErrProtocolSafety) {
		t.Fatalf("failed Parse remained visible: %v", err)
	}
}

func TestParameterDescriptionPreservesClientContract(t *testing.T) {
	m := machine(t)
	if _, err := m.Frontend(&pgproto3.Parse{Name: "insert", Query: `INSERT INTO users (email) VALUES ($1)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Backend(&pgproto3.ParseComplete{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Frontend(&pgproto3.Describe{ObjectType: 'S', Name: "insert"}); err != nil {
		t.Fatal(err)
	}
	message, err := m.Backend(&pgproto3.ParameterDescription{ParameterOIDs: []uint32{25, 25}})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(message.(*pgproto3.ParameterDescription).ParameterOIDs); got != 1 {
		t.Fatalf("client saw %d parameters", got)
	}
}

func TestWildcardUsesOriginMetadata(t *testing.T) {
	m := machine(t)
	if _, err := m.Frontend(&pgproto3.Query{String: `SELECT * FROM users`}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Backend(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
		{Name: []byte("id"), TableOID: 42, TableAttributeNumber: 1, Format: pgproto3.TextFormat},
		{Name: []byte("email"), TableOID: 42, TableAttributeNumber: 7, Format: pgproto3.TextFormat},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := recordcrypt.Context{Domain: "tenant-a", Schema: "public", Table: "users", Column: "email"}
	ciphertext, err := m.keyring.EncryptRandom(ctx, []byte("wildcard@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	message, err := m.Backend(&pgproto3.DataRow{Values: [][]byte{[]byte("1"), []byte(ciphertext)}})
	if err != nil {
		t.Fatal(err)
	}
	if string(message.(*pgproto3.DataRow).Values[1]) != "wildcard@example.com" {
		t.Fatalf("wildcard field was not decrypted: %q", message.(*pgproto3.DataRow).Values)
	}
}

func TestEnvelopeCannotLeakFromUnprovenResult(t *testing.T) {
	m := machine(t)
	if _, err := m.Frontend(&pgproto3.Query{String: `SELECT title FROM posts`}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Backend(&pgproto3.DataRow{Values: [][]byte{[]byte(`copied $PGXENC$2:r:key:AA`)}})
	if !errors.Is(err, ErrProtocolSafety) {
		t.Fatalf("expected envelope leak rejection, got %v", err)
	}
}
