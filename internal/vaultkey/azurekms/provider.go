package azurekms

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

var aadMagic = [4]byte{'P', 'G', 'A', 1}

type Client interface {
	WrapKey(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(context.Context, string, string, azkeys.KeyOperationParameters, *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

type Provider struct {
	client    Client
	algorithm azkeys.EncryptionAlgorithm
}

func New(client Client, algorithm azkeys.EncryptionAlgorithm) (*Provider, error) {
	if client == nil {
		return nil, errors.New("azure key vault: client is required")
	}
	if algorithm == "" {
		algorithm = azkeys.EncryptionAlgorithmRSAOAEP256
	}
	if algorithm != azkeys.EncryptionAlgorithmRSAOAEP256 && algorithm != azkeys.EncryptionAlgorithmA256KW {
		return nil, fmt.Errorf("azure key vault: unsupported wrap algorithm %q", algorithm)
	}
	return &Provider{client: client, algorithm: algorithm}, nil
}

func (p *Provider) Name() string { return "azure-key-vault" }

func (p *Provider) Wrap(ctx context.Context, keyRef string, plaintext, aad []byte) ([]byte, error) {
	name, version, err := parseKeyRef(keyRef)
	if err != nil {
		return nil, err
	}
	bound := bindAAD(plaintext, aad)
	output, err := p.client.WrapKey(ctx, name, version, azkeys.KeyOperationParameters{
		Algorithm: &p.algorithm, Value: bound, AdditionalAuthenticatedData: aad,
	}, nil)
	clear(bound)
	if err != nil {
		return nil, fmt.Errorf("azure key vault: wrap data key: %w", err)
	}
	if len(output.Result) == 0 {
		return nil, errors.New("azure key vault: wrap returned empty ciphertext")
	}
	return append([]byte(nil), output.Result...), nil
}

func (p *Provider) Unwrap(ctx context.Context, keyRef string, ciphertext, aad []byte) ([]byte, error) {
	name, version, err := parseKeyRef(keyRef)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("azure key vault: ciphertext is required")
	}
	output, err := p.client.UnwrapKey(ctx, name, version, azkeys.KeyOperationParameters{
		Algorithm: &p.algorithm, Value: ciphertext, AdditionalAuthenticatedData: aad,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure key vault: unwrap data key: %w", err)
	}
	plaintext, err := unbindAAD(output.Result, aad)
	clear(output.Result)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func parseKeyRef(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" || (len(parts) == 2 && parts[1] == "") {
		return "", "", errors.New("azure key vault: key reference must be name or name/version")
	}
	version := ""
	if len(parts) == 2 {
		version = parts[1]
	}
	return parts[0], version, nil
}

func bindAAD(plaintext, aad []byte) []byte {
	digest := sha256.Sum256(aad)
	result := make([]byte, 0, len(aadMagic)+len(digest)+len(plaintext))
	result = append(result, aadMagic[:]...)
	result = append(result, digest[:]...)
	result = append(result, plaintext...)
	return result
}

func unbindAAD(value, aad []byte) ([]byte, error) {
	if len(value) < len(aadMagic)+sha256.Size || subtle.ConstantTimeCompare(value[:len(aadMagic)], aadMagic[:]) != 1 {
		return nil, errors.New("azure key vault: unwrapped material format is invalid")
	}
	digest := sha256.Sum256(aad)
	if subtle.ConstantTimeCompare(value[len(aadMagic):len(aadMagic)+sha256.Size], digest[:]) != 1 {
		return nil, errors.New("azure key vault: unwrapped material AAD mismatch")
	}
	return append([]byte(nil), value[len(aadMagic)+sha256.Size:]...), nil
}
