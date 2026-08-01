package vaultkey

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// LocalProvider is intended for development and tests. Production deployments
// should use a remote provider whose KEK cannot be read by the gateway.
type LocalProvider struct {
	keys map[string][]byte
}

func NewLocalProvider(keys map[string][]byte) (*LocalProvider, error) {
	copyKeys := make(map[string][]byte, len(keys))
	for ref, key := range keys {
		if ref == "" || len(key) != 32 {
			return nil, errors.New("vaultkey: local KEK references must be non-empty and keys must be 32 bytes")
		}
		copyKeys[ref] = append([]byte(nil), key...)
	}
	return &LocalProvider{keys: copyKeys}, nil
}

func (p *LocalProvider) Name() string { return "local-dev" }

func (p *LocalProvider) Wrap(ctx context.Context, keyRef string, plaintext, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aead, err := p.aead(keyRef)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("vaultkey: generate local nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (p *LocalProvider) Unwrap(ctx context.Context, keyRef string, ciphertext, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aead, err := p.aead(keyRef)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("vaultkey: local ciphertext is truncated")
	}
	nonce := ciphertext[:aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, ciphertext[aead.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("vaultkey: local unwrap authentication failed")
	}
	return plaintext, nil
}

func (p *LocalProvider) aead(keyRef string) (cipher.AEAD, error) {
	key, ok := p.keys[keyRef]
	if !ok {
		return nil, fmt.Errorf("vaultkey: local KEK %q not found", keyRef)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: initialize local AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: initialize local GCM: %w", err)
	}
	return aead, nil
}
