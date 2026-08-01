package gateway

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/vendora-bit/pg-kms-gateway/internal/pgsession"
)

func TestSecureConfigurationDefaults(t *testing.T) {
	_, err := New(Config{UpstreamAddress: "db:5432", RequireClientTLS: true, NewMachine: func() (*pgsession.Machine, error) { return nil, nil }})
	if err == nil {
		t.Fatal("required client TLS without a certificate was accepted")
	}
}

func TestAuthenticationType(t *testing.T) {
	tests := []struct {
		message  pgproto3.BackendMessage
		typeCode uint32
		respond  bool
	}{
		{&pgproto3.AuthenticationSASL{}, pgproto3.AuthTypeSASL, true},
		{&pgproto3.AuthenticationSASLContinue{}, pgproto3.AuthTypeSASLContinue, true},
		{&pgproto3.AuthenticationSASLFinal{}, pgproto3.AuthTypeSASLFinal, false},
		{&pgproto3.AuthenticationMD5Password{}, pgproto3.AuthTypeMD5Password, true},
	}
	for _, test := range tests {
		code, respond := authenticationType(test.message)
		if code != test.typeCode || respond != test.respond {
			t.Fatalf("unexpected auth mapping for %T", test.message)
		}
	}
}

func TestUpstreamTLSRequirementValidation(t *testing.T) {
	_, err := New(Config{UpstreamAddress: "db:5432", RequireUpstreamTLS: true, NewMachine: nil})
	if err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	_, err = New(Config{
		UpstreamAddress: "db:5432", RequireUpstreamTLS: true, UpstreamTLS: &tls.Config{MinVersion: tls.VersionTLS13},
		NewMachine: func() (*pgsession.Machine, error) { return nil, errors.New("unused") }, DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
}
