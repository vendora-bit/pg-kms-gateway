//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/vendora-bit/pg-kms-gateway/internal/gateway"
	"github.com/vendora-bit/pg-kms-gateway/internal/origin"
	"github.com/vendora-bit/pg-kms-gateway/internal/pgsession"
	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
)

func TestPostgreSQLWireEndToEnd(t *testing.T) {
	directDSN := os.Getenv("PGKMS_E2E_DSN")
	upstream := os.Getenv("PGKMS_E2E_ADDRESS")
	if directDSN == "" || upstream == "" {
		t.Skip("PGKMS_E2E_DSN and PGKMS_E2E_ADDRESS are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	document := policy.Document{APIVersion: policy.APIVersion, Kind: "FieldEncryptionPolicy", Metadata: policy.Metadata{Name: "e2e"}, Spec: policy.Spec{
		KeyDomain: "e2e", Columns: []policy.Field{
			{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, Normalize: policy.NormalizeLowercaseTrim, BlindIndex: "email_bidx"},
			{Schema: "public", Table: "users", Column: "external_id", Mode: policy.ModeDeterministic, Normalize: policy.NormalizeTrim},
		},
	}}
	catalog, err := policy.Compile(document)
	if err != nil {
		t.Fatal(err)
	}
	activeMaterial, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	oldMaterial, err := recordcrypt.GenerateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := recordcrypt.NewKeyring("dk-active", map[string]recordcrypt.Material{"dk-active": activeMaterial, "dk-old": oldMaterial})
	if err != nil {
		t.Fatal(err)
	}
	direct, err := pgx.Connect(ctx, directDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close(context.Background())
	resolver, err := origin.Discover(ctx, direct, catalog)
	if err != nil {
		t.Fatal(err)
	}
	emailContext := recordcrypt.Context{Domain: "e2e", Schema: "public", Table: "users", Column: "email"}
	// Build an old-version randomized envelope explicitly by temporarily opening
	// the same materials with the old key active.
	oldKeyring, err := recordcrypt.NewKeyring("dk-old", map[string]recordcrypt.Material{"dk-active": activeMaterial, "dk-old": oldMaterial})
	if err != nil {
		t.Fatal(err)
	}
	oldEmail, err := oldKeyring.EncryptRandom(emailContext, []byte("Old@Example.COM"))
	if err != nil {
		t.Fatal(err)
	}
	oldIndex, err := oldKeyring.BlindIndexWithKeyID(emailContext, "dk-old", []byte("old@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	externalContext := recordcrypt.Context{Domain: "e2e", Schema: "public", Table: "users", Column: "external_id"}
	oldExternal, err := oldKeyring.EncryptDeterministicWithKeyID(externalContext, "dk-old", []byte("old-external"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := direct.Exec(ctx, `INSERT INTO users (email, email_bidx, external_id) VALUES ($1,$2,$3)`, oldEmail, oldIndex, oldExternal); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.New(gateway.Config{
		UpstreamAddress: upstream,
		NewMachine: func() (*pgsession.Machine, error) {
			return pgsession.New(catalog, keyring, resolver)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(serverContext, listener) }()

	address := listener.Addr().(*net.TCPAddr)
	gatewayDSN := fmt.Sprintf("postgres://postgres:pgkms-test@127.0.0.1:%d/pgkms?sslmode=disable", address.Port)
	client, err := pgx.Connect(ctx, gatewayDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())

	var id int64
	err = client.QueryRow(ctx, `INSERT INTO users (email, external_id) VALUES ($1, $2) RETURNING id`, "Person@Example.COM", " ext-1 ").Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	var storedEmail, storedIndex, storedExternal string
	if err := direct.QueryRow(ctx, `SELECT email, email_bidx, external_id FROM users WHERE id=$1`, id).Scan(&storedEmail, &storedIndex, &storedExternal); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(storedEmail, recordcrypt.Prefix) || !strings.HasPrefix(storedIndex, recordcrypt.BlindIndexPrefix) || !strings.HasPrefix(storedExternal, recordcrypt.Prefix) {
		t.Fatalf("database contains unexpected values: %q %q %q", storedEmail, storedIndex, storedExternal)
	}
	if strings.Contains(storedEmail, "Person@Example.COM") || strings.Contains(storedExternal, "ext-1") {
		t.Fatal("database ciphertext leaked plaintext")
	}

	var email, externalID string
	if err := client.QueryRow(ctx, `SELECT email, external_id FROM users WHERE email = $1`, "person@example.com").Scan(&email, &externalID); err != nil {
		t.Fatal(err)
	}
	if email != "Person@Example.COM" || externalID != "ext-1" {
		t.Fatalf("gateway returned %q, %q", email, externalID)
	}
	if err := client.QueryRow(ctx, `SELECT email FROM users WHERE email = $1`, "old@example.com").Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "Old@Example.COM" {
		t.Fatalf("old blind-index key version was not searchable: %q", email)
	}
	if err := client.QueryRow(ctx, `SELECT external_id FROM users WHERE external_id = $1`, "old-external").Scan(&externalID); err != nil {
		t.Fatal(err)
	}
	if externalID != "old-external" {
		t.Fatalf("old deterministic key version was not searchable: %q", externalID)
	}

	stopServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not stop")
	}
}
