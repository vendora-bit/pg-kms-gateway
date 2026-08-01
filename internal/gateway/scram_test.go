package gateway

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSCRAMSHA256Conversation(t *testing.T) {
	server, err := newSCRAMServer("application", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	clientFirstBare := "n=,r=0123456789abcdef"
	serverFirstBytes, err := server.begin([]byte("y,," + clientFirstBare))
	if err != nil {
		t.Fatal(err)
	}
	serverFirst := string(serverFirstBytes)
	attributes, err := parseSCRAMAttributes(serverFirst)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := base64.StdEncoding.DecodeString(attributes["s"])
	if err != nil {
		t.Fatal(err)
	}
	clientFinalWithoutProof := "c=eSws,r=" + attributes["r"]
	authMessage := []byte(clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof)
	salted, err := pbkdf2.Key(sha256.New, "correct horse battery staple", salt, scramIterations, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := hmacSHA256(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	proof := xorBytes(clientKey, hmacSHA256(storedKey[:], authMessage))
	serverFinal, err := server.finish([]byte(clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(serverFinal), "v=") {
		t.Fatalf("missing server verifier: %q", serverFinal)
	}
}

func TestSCRAMRejectsInvalidProof(t *testing.T) {
	server, err := newSCRAMServer("application", "secret")
	if err != nil {
		t.Fatal(err)
	}
	serverFirst, err := server.begin([]byte("n,,n=application,r=0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := parseSCRAMAttributes(string(serverFirst))
	if err != nil {
		t.Fatal(err)
	}
	invalid := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if _, err := server.finish([]byte("c=biws,r=" + attributes["r"] + ",p=" + invalid)); err == nil {
		t.Fatal("invalid SCRAM proof was accepted")
	}
}
