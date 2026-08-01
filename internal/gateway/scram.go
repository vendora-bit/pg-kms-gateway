package gateway

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const scramIterations = 4096

type scramServer struct {
	username        string
	password        string
	clientFirstBare string
	serverFirst     string
	combinedNonce   string
	salt            []byte
	channelBinding  string
}

func newSCRAMServer(username, password string) (*scramServer, error) {
	if username == "" || password == "" {
		return nil, errors.New("gateway: SCRAM username and password are required")
	}
	if !printableASCII(username) || !printableASCII(password) {
		return nil, errors.New("gateway: SCRAM credentials must use printable ASCII")
	}
	return &scramServer{username: username, password: password}, nil
}

func printableASCII(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func (s *scramServer) begin(input []byte) ([]byte, error) {
	message := string(input)
	gs2Header := ""
	switch {
	case strings.HasPrefix(message, "n,,"):
		gs2Header = "n,,"
	case strings.HasPrefix(message, "y,,"):
		gs2Header = "y,,"
	default:
		return nil, errors.New("gateway: SCRAM channel binding and authorization identities are not supported")
	}
	bare := strings.TrimPrefix(message, gs2Header)
	attributes, err := parseSCRAMAttributes(bare)
	if err != nil {
		return nil, err
	}
	if attributes["n"] != "" && attributes["n"] != escapeSCRAMName(s.username) || len(attributes["r"]) < 16 {
		return nil, errors.New("gateway: SCRAM identity or nonce is invalid")
	}
	nonceBytes := make([]byte, 18)
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, fmt.Errorf("gateway: generate SCRAM nonce: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("gateway: generate SCRAM salt: %w", err)
	}
	s.clientFirstBare = bare
	s.combinedNonce = attributes["r"] + base64.RawStdEncoding.EncodeToString(nonceBytes)
	s.salt = salt
	s.channelBinding = base64.StdEncoding.EncodeToString([]byte(gs2Header))
	s.serverFirst = fmt.Sprintf("r=%s,s=%s,i=%d", s.combinedNonce, base64.StdEncoding.EncodeToString(salt), scramIterations)
	return []byte(s.serverFirst), nil
}

func (s *scramServer) finish(input []byte) ([]byte, error) {
	message := string(input)
	proofMarker := strings.LastIndex(message, ",p=")
	if proofMarker < 0 {
		return nil, errors.New("gateway: SCRAM client proof is missing")
	}
	withoutProof := message[:proofMarker]
	attributes, err := parseSCRAMAttributes(message)
	if err != nil {
		return nil, err
	}
	if attributes["c"] != s.channelBinding || attributes["r"] != s.combinedNonce {
		return nil, errors.New("gateway: SCRAM channel binding or nonce is invalid")
	}
	proof, err := base64.StdEncoding.Strict().DecodeString(attributes["p"])
	if err != nil || len(proof) != sha256.Size {
		return nil, errors.New("gateway: SCRAM client proof is invalid")
	}
	saltedPassword, err := pbkdf2.Key(sha256.New, s.password, s.salt, scramIterations, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("gateway: derive SCRAM verifier: %w", err)
	}
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	authMessage := []byte(s.clientFirstBare + "," + s.serverFirst + "," + withoutProof)
	clientSignature := hmacSHA256(storedKey[:], authMessage)
	recoveredClientKey := xorBytes(proof, clientSignature)
	recoveredStoredKey := sha256.Sum256(recoveredClientKey)
	if subtle.ConstantTimeCompare(storedKey[:], recoveredStoredKey[:]) != 1 {
		return nil, errors.New("gateway: SCRAM authentication failed")
	}
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	serverSignature := hmacSHA256(serverKey, authMessage)
	return []byte("v=" + base64.StdEncoding.EncodeToString(serverSignature)), nil
}

func parseSCRAMAttributes(message string) (map[string]string, error) {
	attributes := make(map[string]string)
	for _, item := range strings.Split(message, ",") {
		if len(item) < 2 || item[1] != '=' {
			return nil, errors.New("gateway: malformed SCRAM message")
		}
		key, value := item[:1], item[2:]
		if _, duplicate := attributes[key]; duplicate || value == "" && key != "n" {
			return nil, errors.New("gateway: malformed SCRAM attributes")
		}
		attributes[key] = value
	}
	return attributes, nil
}

func escapeSCRAMName(value string) string {
	return strings.NewReplacer("=", "=3D", ",", "=2C").Replace(value)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func xorBytes(left, right []byte) []byte {
	result := make([]byte, len(left))
	for i := range left {
		result[i] = left[i] ^ right[i]
	}
	return result
}
