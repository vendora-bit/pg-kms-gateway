//go:build livekms

package integration

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	awssdkconfig "github.com/aws/aws-sdk-go-v2/config"
	awssvckms "github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/awskms"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/azurekms"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/gcpkms"
	"github.com/vendora-bit/pg-kms-gateway/internal/vaultkey/vaulttransit"
)

func TestLiveKMSProviders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	t.Run("vault-transit", func(t *testing.T) {
		address, keyRef := os.Getenv("PGKMS_LIVE_VAULT_ADDRESS"), os.Getenv("PGKMS_LIVE_VAULT_KEY")
		if address == "" || keyRef == "" || os.Getenv("PGKMS_LIVE_VAULT_TOKEN") == "" {
			t.Skip("live Vault address, token and key are not configured")
		}
		provider, err := vaulttransit.New(vaulttransit.Config{Address: address, Mount: os.Getenv("PGKMS_LIVE_VAULT_MOUNT"), Token: vaulttransit.EnvToken{Name: "PGKMS_LIVE_VAULT_TOKEN"}})
		if err != nil {
			t.Fatal(err)
		}
		liveKMSRoundTrip(t, ctx, provider, keyRef)
	})

	t.Run("aws-kms", func(t *testing.T) {
		region, keyRef := os.Getenv("PGKMS_LIVE_AWS_REGION"), os.Getenv("PGKMS_LIVE_AWS_KEY")
		if region == "" || keyRef == "" {
			t.Skip("live AWS region and KMS key are not configured")
		}
		config, err := awssdkconfig.LoadDefaultConfig(ctx, awssdkconfig.WithRegion(region))
		if err != nil {
			t.Fatal(err)
		}
		provider, err := awskms.New(awssvckms.NewFromConfig(config))
		if err != nil {
			t.Fatal(err)
		}
		liveKMSRoundTrip(t, ctx, provider, keyRef)
	})

	t.Run("gcp-kms", func(t *testing.T) {
		keyRef := os.Getenv("PGKMS_LIVE_GCP_KEY")
		if keyRef == "" {
			t.Skip("live Google Cloud KMS key is not configured")
		}
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		provider, err := gcpkms.New(client)
		if err != nil {
			t.Fatal(err)
		}
		liveKMSRoundTrip(t, ctx, provider, keyRef)
	})

	t.Run("azure-key-vault", func(t *testing.T) {
		vaultURL, keyRef := os.Getenv("PGKMS_LIVE_AZURE_VAULT_URL"), os.Getenv("PGKMS_LIVE_AZURE_KEY")
		if vaultURL == "" || keyRef == "" {
			t.Skip("live Azure vault URL and key are not configured")
		}
		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			t.Fatal(err)
		}
		client, err := azkeys.NewClient(vaultURL, credential, nil)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := azurekms.New(client, azkeys.EncryptionAlgorithmRSAOAEP256)
		if err != nil {
			t.Fatal(err)
		}
		liveKMSRoundTrip(t, ctx, provider, keyRef)
	})
}

func liveKMSRoundTrip(t *testing.T, ctx context.Context, provider vaultkey.Provider, keyRef string) {
	t.Helper()
	plaintext := []byte("pg-kms-gateway-live-provider-check")
	aad := []byte("pgkms-live-test-aad")
	ciphertext, err := provider.Wrap(ctx, keyRef, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := provider.Unwrap(ctx, keyRef, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("live KMS round trip returned different plaintext")
	}
}
