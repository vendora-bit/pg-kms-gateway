package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const maxResponseBytes = 1 << 20

type TokenSource interface {
	Token(context.Context) (string, error)
}

type StaticToken string

func (s StaticToken) Token(context.Context) (string, error) {
	if strings.TrimSpace(string(s)) == "" {
		return "", errors.New("vault transit: token is empty")
	}
	return string(s), nil
}

type EnvToken struct{ Name string }

func (s EnvToken) Token(context.Context) (string, error) {
	if s.Name == "" {
		return "", errors.New("vault transit: token environment variable name is empty")
	}
	value, exists := os.LookupEnv(s.Name)
	if !exists || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("vault transit: token environment variable %s is unset or empty", s.Name)
	}
	return value, nil
}

type Config struct {
	Address   string
	Mount     string
	Namespace string
	Token     TokenSource
	Client    *http.Client
}

type Provider struct {
	base      *url.URL
	mount     string
	namespace string
	token     TokenSource
	client    *http.Client
}

func New(config Config) (*Provider, error) {
	base, err := url.Parse(config.Address)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("vault transit: address must be an absolute HTTP(S) URL without query or fragment")
	}
	if base.Scheme != "https" && !isLoopbackHost(base.Hostname()) {
		return nil, errors.New("vault transit: plaintext HTTP is allowed only for loopback development")
	}
	mount := strings.Trim(config.Mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if !validPath(mount) {
		return nil, errors.New("vault transit: mount path is invalid")
	}
	if config.Token == nil {
		return nil, errors.New("vault transit: token source is required")
	}
	client := config.Client
	if client == nil {
		client = http.DefaultClient
	}
	copyURL := *base
	copyURL.Path = strings.TrimSuffix(copyURL.Path, "/")
	return &Provider{base: &copyURL, mount: mount, namespace: config.Namespace, token: config.Token, client: client}, nil
}

func (p *Provider) Name() string { return "vault-transit" }

func (p *Provider) Wrap(ctx context.Context, keyRef string, plaintext, aad []byte) ([]byte, error) {
	if !validKeyName(keyRef) {
		return nil, errors.New("vault transit: key reference is invalid")
	}
	request := cryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
		Context:   base64.StdEncoding.EncodeToString(aad),
	}
	var response encryptResponse
	if err := p.call(ctx, "encrypt", keyRef, request, &response); err != nil {
		return nil, err
	}
	if response.Data.Ciphertext == "" || !strings.HasPrefix(response.Data.Ciphertext, "vault:v") {
		return nil, errors.New("vault transit: encrypt response has no ciphertext")
	}
	return []byte(response.Data.Ciphertext), nil
}

func (p *Provider) Unwrap(ctx context.Context, keyRef string, ciphertext, aad []byte) ([]byte, error) {
	if !validKeyName(keyRef) {
		return nil, errors.New("vault transit: key reference is invalid")
	}
	if !strings.HasPrefix(string(ciphertext), "vault:v") {
		return nil, errors.New("vault transit: ciphertext format is invalid")
	}
	request := cryptRequest{
		Ciphertext: string(ciphertext),
		Context:    base64.StdEncoding.EncodeToString(aad),
	}
	var response decryptResponse
	if err := p.call(ctx, "decrypt", keyRef, request, &response); err != nil {
		return nil, err
	}
	plaintext, err := base64.StdEncoding.Strict().DecodeString(response.Data.Plaintext)
	if err != nil {
		return nil, errors.New("vault transit: decrypt response has invalid plaintext")
	}
	return plaintext, nil
}

type cryptRequest struct {
	Plaintext  string `json:"plaintext,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Context    string `json:"context"`
}

type encryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

type decryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

type errorResponse struct {
	Errors []string `json:"errors"`
}

func (p *Provider) call(ctx context.Context, operation, keyRef string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("vault transit: encode %s request: %w", operation, err)
	}
	endpoint := *p.base
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/v1/" + p.mount + "/" + operation + "/" + url.PathEscape(keyRef)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vault transit: build %s request: %w", operation, err)
	}
	token, err := p.token.Token(ctx)
	if err != nil {
		return fmt.Errorf("vault transit: acquire token: %w", err)
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("vault transit: token source returned an empty token")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Token", token)
	if p.namespace != "" {
		request.Header.Set("X-Vault-Namespace", p.namespace)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("vault transit: %s request failed: %w", operation, err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("vault transit: read %s response: %w", operation, err)
	}
	if len(responseBody) > maxResponseBytes {
		return fmt.Errorf("vault transit: %s response exceeds limit", operation)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var details errorResponse
		_ = json.Unmarshal(responseBody, &details)
		message := "request rejected"
		if len(details.Errors) > 0 && details.Errors[0] != "" {
			message = details.Errors[0]
		}
		return fmt.Errorf("vault transit: %s failed with HTTP %d: %s", operation, response.StatusCode, message)
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("vault transit: decode %s response: %w", operation, err)
	}
	return nil
}

func validPath(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if !validKeyName(part) {
			return false
		}
	}
	return true
}

func validKeyName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
