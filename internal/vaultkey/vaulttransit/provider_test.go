package vaulttransit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestWrapAndUnwrap(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Vault-Token") != "test-token" || r.Header.Get("X-Vault-Namespace") != "team-a" {
			t.Error("missing Vault headers")
		}
		var body cryptRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch r.URL.Path {
		case "/v1/transit/encrypt/customer-key":
			if decoded, _ := base64.StdEncoding.DecodeString(body.Plaintext); string(decoded) != "material" {
				t.Errorf("unexpected plaintext %q", decoded)
			}
			return response(http.StatusOK, `{"data":{"ciphertext":"vault:v7:wrapped"}}`), nil
		case "/v1/transit/decrypt/customer-key":
			if body.Ciphertext != "vault:v7:wrapped" {
				t.Errorf("unexpected ciphertext %q", body.Ciphertext)
			}
			return response(http.StatusOK, `{"data":{"plaintext":"bWF0ZXJpYWw="}}`), nil
		default:
			return response(http.StatusNotFound, `{}`), nil
		}
	})}

	provider, err := New(Config{Address: "http://127.0.0.1", Token: StaticToken("test-token"), Namespace: "team-a", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := provider.Wrap(context.Background(), "customer-key", []byte("material"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := provider.Unwrap(context.Background(), "customer-key", wrapped, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "material" {
		t.Fatalf("got %q", plain)
	}
}

func TestRejectsInsecureRemoteAddress(t *testing.T) {
	if _, err := New(Config{Address: "http://vault.example.com", Token: StaticToken("x")}); err == nil {
		t.Fatal("insecure remote Vault address was accepted")
	}
}

func TestErrorDoesNotLeakRequestSecrets(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return response(http.StatusForbidden, `{"errors":["permission denied"]}`), nil
	})}
	provider, err := New(Config{Address: "http://127.0.0.1", Token: StaticToken("highly-secret-token"), Client: client})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Wrap(context.Background(), "customer-key", []byte("top-secret-material"), []byte("aad"))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "highly-secret") || strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("secret leaked in error: %v", err)
	}
}
