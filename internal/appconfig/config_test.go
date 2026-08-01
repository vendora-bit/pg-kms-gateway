package appconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadStrictConfigAndDuration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte(`listen: ":6432"
health: "127.0.0.1:8080"
upstream:
  address: "postgres:5432"
  tls: true
  serverName: "postgres.internal"
clientTLS:
  required: false
authentication:
  mode: relay
policyFile: "/etc/pgkms/policy.yaml"
bundleFile: "/etc/pgkms/bundle.json"
metadataDSNEnv: "PGKMS_METADATA_DSN"
kms:
  provider: vault-transit
  keyRef: "pgkms"
  vault:
    address: "https://vault.internal"
    tokenEnv: "VAULT_TOKEN"
limits:
  messageBytes: 8388608
  dialTimeout: 15s
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(config.Limits.DialTimeout) != 15*time.Second || config.Limits.MessageBytes != 8<<20 {
		t.Fatalf("unexpected limits: %+v", config.Limits)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`upstream: {address: "db:5432"}
policyFile: p
bundleFile: b
metadataDSNEnv: DSN
kms: {provider: vault-transit, keyRef: key, vault: {address: "https://vault", tokenEnv: TOKEN}}
surprise: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown key was accepted")
	}
}

func TestClientTLSIsRequiredByDefault(t *testing.T) {
	config := Config{
		Upstream: Upstream{Address: "db:5432"}, PolicyFile: "policy.yaml", BundleFile: "bundle.json", MetadataDSN: "DSN",
		KMS:            KMS{Provider: "vault-transit", KeyRef: "key", Vault: Vault{Address: "https://vault", TokenEnv: "TOKEN"}},
		Authentication: Authentication{Mode: "relay"},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("configuration without client TLS credentials was accepted")
	}
	allowPlaintext := false
	config.ClientTLS.Required = &allowPlaintext
	if err := config.Validate(); err != nil {
		t.Fatalf("explicit plaintext opt-out was rejected: %v", err)
	}
}

func TestTerminateSCRAMRequiresSeparateCredentials(t *testing.T) {
	required := true
	config := Config{
		Upstream: Upstream{Address: "db:5432"}, ClientTLS: ServerTLS{Required: &required, CertFile: "tls.crt", KeyFile: "tls.key"},
		Authentication: Authentication{Mode: "terminate-scram"},
		PolicyFile:     "policy.yaml", BundleFile: "bundle.json", MetadataDSN: "DSN",
		KMS: KMS{Provider: "vault-transit", KeyRef: "key", Vault: Vault{Address: "https://vault", TokenEnv: "TOKEN"}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("termination without independent credentials was accepted")
	}
}
