//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vendora-bit/pg-kms-gateway/internal/gateway"
	"github.com/vendora-bit/pg-kms-gateway/internal/operator"
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

	testPipeline(t, ctx, client, id)
	testPreparedStatement(t, ctx, client)
	testConnectionPool(t, ctx, gatewayDSN)
	testCancelRequest(t, client)
	testBackfillVerification(t, ctx, directDSN, direct, keyring)
	testTerminatedSCRAM(t, ctx, upstream, catalog, keyring, resolver, id)

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

func testBackfillVerification(t *testing.T, ctx context.Context, directDSN string, direct *pgx.Conn, keyring *recordcrypt.Keyring) {
	t.Helper()
	if _, err := direct.Exec(ctx, `DROP TABLE IF EXISTS backfill_users; CREATE TABLE backfill_users (id bigint PRIMARY KEY, email text, email_bidx text); INSERT INTO backfill_users VALUES (1, 'locked@example.com', NULL)`); err != nil {
		t.Fatal(err)
	}
	locker, err := pgx.Connect(ctx, directDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close(context.Background())
	transaction, err := locker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `SELECT id FROM backfill_users WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	field := policy.Field{Schema: "public", Table: "backfill_users", Column: "email", Mode: policy.ModeRandom, Normalize: policy.NormalizeLowercaseTrim, BlindIndex: "email_bidx"}
	engine := operator.Engine{Connection: direct, Processor: operator.Processor{Keyring: keyring, Domain: "e2e"}, BatchSize: 10}
	_, verification, err := engine.RunAndVerifyField(ctx, field, operator.Backfill)
	if err == nil || verification.PlaintextRows != 1 {
		t.Fatalf("locked row was not caught by mandatory verification: %+v, %v", verification, err)
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	_, verification, err = engine.RunAndVerifyField(ctx, field, operator.Backfill)
	if err != nil || !verification.Clean() {
		t.Fatalf("backfill did not recover after lock release: %+v, %v", verification, err)
	}
	if _, err := direct.Exec(ctx, `DROP TABLE backfill_users`); err != nil {
		t.Fatal(err)
	}
}

func testPipeline(t *testing.T, ctx context.Context, client *pgx.Conn, id int64) {
	t.Helper()
	pipeline := client.PgConn().StartPipeline(ctx)
	pipeline.SendQueryParams(`SELECT email FROM users WHERE email = $1`, [][]byte{[]byte("person@example.com")}, nil, nil, nil)
	pipeline.SendQueryParams(`SELECT external_id FROM users WHERE external_id = $1`, [][]byte{[]byte("ext-1")}, nil, nil, nil)
	if err := pipeline.Sync(); err != nil {
		t.Fatal(err)
	}
	for index, expected := range []string{"Person@Example.COM", "ext-1"} {
		result, err := pipeline.GetResults()
		if err != nil {
			t.Fatalf("pipeline result %d: %v", index, err)
		}
		reader, ok := result.(*pgconn.ResultReader)
		if !ok {
			t.Fatalf("pipeline result %d has type %T", index, result)
		}
		read := reader.Read()
		if read.Err != nil || len(read.Rows) != 1 || len(read.Rows[0]) != 1 || string(read.Rows[0][0]) != expected {
			t.Fatalf("pipeline result %d: rows=%q err=%v", index, read.Rows, read.Err)
		}
	}
	result, err := pipeline.GetResults()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.(*pgconn.PipelineSync); !ok {
		t.Fatalf("expected pipeline sync, got %T", result)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatal(err)
	}
	_ = id
}

func testPreparedStatement(t *testing.T, ctx context.Context, client *pgx.Conn) {
	t.Helper()
	if _, err := client.Prepare(ctx, "find-email", `SELECT email FROM users WHERE email = $1`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		var email string
		if err := client.QueryRow(ctx, "find-email", "person@example.com").Scan(&email); err != nil || email != "Person@Example.COM" {
			t.Fatalf("prepared statement reuse: email=%q err=%v", email, err)
		}
	}
}

func testConnectionPool(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 32)
	for worker := range 8 {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := range 10 {
				var email string
				if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE email = $1`, "person@example.com").Scan(&email); err != nil || email != "Person@Example.COM" {
					errorsChannel <- fmt.Errorf("worker %d iteration %d: email=%q err=%v", worker, iteration, email, err)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func testCancelRequest(t *testing.T, client *pgx.Conn) {
	t.Helper()
	queryContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Exec(queryContext, `SELECT pg_sleep(5)`)
		result <- err
	}()
	time.Sleep(250 * time.Millisecond)
	if err := client.PgConn().CancelRequest(queryContext); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "canceling statement") {
			t.Fatalf("cancel request did not cancel query: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel request was not forwarded")
	}
}

func testTerminatedSCRAM(t *testing.T, ctx context.Context, upstream string, catalog *policy.Catalog, keyring *recordcrypt.Keyring, resolver *origin.Resolver, id int64) {
	t.Helper()
	serverTLS, rootFile, clientCertFile, clientKeyFile := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.New(gateway.Config{
		UpstreamAddress: upstream, ClientTLS: serverTLS, RequireClientTLS: true,
		NewMachine: func() (*pgsession.Machine, error) { return pgsession.New(catalog, keyring, resolver) },
		TerminateAuth: &gateway.TerminationAuth{
			ClientUsername: "application", ClientPassword: "gateway-client-password",
			UpstreamUsername: "postgres", UpstreamPassword: "pgkms-test", UpstreamDatabase: "pgkms",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stop := context.WithCancel(context.Background())
	defer stop()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(serverContext, listener) }()
	port := listener.Addr().(*net.TCPAddr).Port
	dsn := fmt.Sprintf("postgres://application:gateway-client-password@127.0.0.1:%d/ignored?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s", port, urlQueryEscape(rootFile), urlQueryEscape(clientCertFile), urlQueryEscape(clientKeyFile))
	client, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var email string
	if err := client.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, id).Scan(&email); err != nil || email != "Person@Example.COM" {
		t.Fatalf("terminated SCRAM query: email=%q err=%v", email, err)
	}
	if err := client.Close(ctx); err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("terminated authentication gateway did not stop")
	}
}

func testCertificate(t *testing.T) (*tls.Config, string, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(rootFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	clientCertFile := filepath.Join(t.TempDir(), "client.crt")
	clientKeyFile := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(clientCertFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientKeyFile, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certificatePEM)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}, rootFile, clientCertFile, clientKeyFile
}

func urlQueryEscape(value string) string {
	return strings.ReplaceAll(value, " ", "%20")
}
