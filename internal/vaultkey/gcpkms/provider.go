package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type Client interface {
	Encrypt(context.Context, *kmspb.EncryptRequest, ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(context.Context, *kmspb.DecryptRequest, ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

type Provider struct{ client Client }

func New(client Client) (*Provider, error) {
	if client == nil {
		return nil, errors.New("gcp kms: client is required")
	}
	return &Provider{client: client}, nil
}

func (p *Provider) Name() string { return "gcp-kms" }

func (p *Provider) Wrap(ctx context.Context, keyRef string, plaintext, aad []byte) ([]byte, error) {
	if !validKeyRef(keyRef) {
		return nil, errors.New("gcp kms: key reference must be a CryptoKeyVersion resource name")
	}
	output, err := p.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name: keyRef, Plaintext: plaintext, AdditionalAuthenticatedData: aad,
		PlaintextCrc32C:                   wrapperspb.Int64(int64(crc32.Checksum(plaintext, castagnoli))),
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(crc32.Checksum(aad, castagnoli))),
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms: encrypt data key: %w", err)
	}
	if output == nil || len(output.Ciphertext) == 0 || !output.VerifiedPlaintextCrc32C || !output.VerifiedAdditionalAuthenticatedDataCrc32C {
		return nil, errors.New("gcp kms: encrypt response failed integrity verification")
	}
	if output.CiphertextCrc32C == nil || uint32(output.CiphertextCrc32C.Value) != crc32.Checksum(output.Ciphertext, castagnoli) {
		return nil, errors.New("gcp kms: encrypt ciphertext checksum mismatch")
	}
	return append([]byte(nil), output.Ciphertext...), nil
}

func (p *Provider) Unwrap(ctx context.Context, keyRef string, ciphertext, aad []byte) ([]byte, error) {
	if !validKeyRef(keyRef) || len(ciphertext) == 0 {
		return nil, errors.New("gcp kms: valid key reference and ciphertext are required")
	}
	output, err := p.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name: keyRef, Ciphertext: ciphertext, AdditionalAuthenticatedData: aad,
		CiphertextCrc32C:                  wrapperspb.Int64(int64(crc32.Checksum(ciphertext, castagnoli))),
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(crc32.Checksum(aad, castagnoli))),
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms: decrypt data key: %w", err)
	}
	if output == nil || len(output.Plaintext) == 0 || output.PlaintextCrc32C == nil || uint32(output.PlaintextCrc32C.Value) != crc32.Checksum(output.Plaintext, castagnoli) {
		return nil, errors.New("gcp kms: decrypt plaintext checksum mismatch")
	}
	return append([]byte(nil), output.Plaintext...), nil
}

func validKeyRef(value string) bool {
	return strings.HasPrefix(value, "projects/") && strings.Contains(value, "/locations/") && strings.Contains(value, "/keyRings/") && strings.Contains(value, "/cryptoKeys/")
}
