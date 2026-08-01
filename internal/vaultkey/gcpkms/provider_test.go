package gcpkms

import (
	"context"
	"hash/crc32"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeClient struct{}

func (fakeClient) Encrypt(_ context.Context, input *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	ciphertext := append([]byte("wrapped:"), input.Plaintext...)
	return &kmspb.EncryptResponse{
		Ciphertext: ciphertext, VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32.Checksum(ciphertext, castagnoli))),
	}, nil
}

func (fakeClient) Decrypt(_ context.Context, input *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	plaintext := input.Ciphertext[len("wrapped:"):]
	return &kmspb.DecryptResponse{Plaintext: plaintext, PlaintextCrc32C: wrapperspb.Int64(int64(crc32.Checksum(plaintext, castagnoli)))}, nil
}

func TestIntegrityCheckedRoundTrip(t *testing.T) {
	provider, err := New(fakeClient{})
	if err != nil {
		t.Fatal(err)
	}
	key := "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	wrapped, err := provider.Wrap(context.Background(), key, []byte("material"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := provider.Unwrap(context.Background(), key, wrapped, []byte("aad"))
	if err != nil || string(plaintext) != "material" {
		t.Fatalf("got %q, %v", plaintext, err)
	}
}
