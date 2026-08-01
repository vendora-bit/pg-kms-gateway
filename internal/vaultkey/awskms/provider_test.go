package awskms

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type fakeClient struct {
	encryptInput *kms.EncryptInput
	decryptInput *kms.DecryptInput
	err          error
}

func (f *fakeClient) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.encryptInput = input
	return &kms.EncryptOutput{CiphertextBlob: []byte("wrapped")}, f.err
}

func (f *fakeClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decryptInput = input
	return &kms.DecryptOutput{Plaintext: []byte("plain")}, f.err
}

func TestProviderBindsEncryptionContext(t *testing.T) {
	client := &fakeClient{}
	provider, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := provider.Wrap(context.Background(), "arn:aws:kms:region:account:key/id", []byte("plain"), []byte("aad"))
	if err != nil || string(wrapped) != "wrapped" {
		t.Fatal(err)
	}
	plain, err := provider.Unwrap(context.Background(), "arn:aws:kms:region:account:key/id", wrapped, []byte("aad"))
	if err != nil || string(plain) != "plain" {
		t.Fatal(err)
	}
	if client.encryptInput.EncryptionContext["pgkms-aad-sha256"] == "" || client.decryptInput.EncryptionContext["pgkms-aad-sha256"] != client.encryptInput.EncryptionContext["pgkms-aad-sha256"] {
		t.Fatal("AAD digest was not consistently bound")
	}
}

func TestProviderRedactsPlaintextFromErrors(t *testing.T) {
	client := &fakeClient{err: errors.New("access denied")}
	provider, _ := New(client)
	_, err := provider.Wrap(context.Background(), "key", []byte("secret-material"), []byte("aad"))
	if err == nil || err.Error() == "secret-material" {
		t.Fatalf("unexpected error: %v", err)
	}
}
