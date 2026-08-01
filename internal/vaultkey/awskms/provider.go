package awskms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type Client interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type Provider struct{ client Client }

func New(client Client) (*Provider, error) {
	if client == nil {
		return nil, errors.New("aws kms: client is required")
	}
	return &Provider{client: client}, nil
}

func (p *Provider) Name() string { return "aws-kms" }

func (p *Provider) Wrap(ctx context.Context, keyRef string, plaintext, aad []byte) ([]byte, error) {
	if strings.TrimSpace(keyRef) == "" {
		return nil, errors.New("aws kms: key reference is required")
	}
	if len(plaintext) > 4096 {
		return nil, errors.New("aws kms: plaintext exceeds KMS limit")
	}
	output, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId: &keyRef, Plaintext: plaintext, EncryptionContext: encryptionContext(aad),
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: encrypt data key: %w", err)
	}
	if output == nil || len(output.CiphertextBlob) == 0 {
		return nil, errors.New("aws kms: encrypt returned empty ciphertext")
	}
	return append([]byte(nil), output.CiphertextBlob...), nil
}

func (p *Provider) Unwrap(ctx context.Context, keyRef string, ciphertext, aad []byte) ([]byte, error) {
	if strings.TrimSpace(keyRef) == "" || len(ciphertext) == 0 {
		return nil, errors.New("aws kms: key reference and ciphertext are required")
	}
	output, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId: &keyRef, CiphertextBlob: ciphertext, EncryptionContext: encryptionContext(aad),
	})
	if err != nil {
		return nil, fmt.Errorf("aws kms: decrypt data key: %w", err)
	}
	if output == nil || len(output.Plaintext) == 0 {
		return nil, errors.New("aws kms: decrypt returned empty plaintext")
	}
	return append([]byte(nil), output.Plaintext...), nil
}

func encryptionContext(aad []byte) map[string]string {
	digest := sha256.Sum256(aad)
	return map[string]string{"pgkms-aad-sha256": hex.EncodeToString(digest[:])}
}
