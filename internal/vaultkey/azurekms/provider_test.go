package azurekms

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type fakeClient struct{ wrapped []byte }

func (f *fakeClient) WrapKey(_ context.Context, _, _ string, parameters azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	f.wrapped = append([]byte(nil), parameters.Value...)
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("ciphertext")}}, nil
}

func (f *fakeClient) UnwrapKey(_ context.Context, _, _ string, _ azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: append([]byte(nil), f.wrapped...)}}, nil
}

func TestRoundTripAndAADBinding(t *testing.T) {
	client := &fakeClient{}
	provider, err := New(client, azkeys.EncryptionAlgorithmA256KW)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := provider.Wrap(context.Background(), "pgkms/v1", []byte("material"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := provider.Unwrap(context.Background(), "pgkms/v1", wrapped, []byte("aad"))
	if err != nil || string(plaintext) != "material" {
		t.Fatalf("got %q, %v", plaintext, err)
	}
	if _, err := provider.Unwrap(context.Background(), "pgkms/v1", wrapped, []byte("other-aad")); err == nil {
		t.Fatal("AAD substitution was accepted")
	}
}
