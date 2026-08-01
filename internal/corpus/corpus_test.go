package corpus

import (
	"testing"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
)

func TestVerifyChecksOutcomeAndProtectedClassification(t *testing.T) {
	catalog, err := policy.Compile(policy.Document{APIVersion: policy.APIVersion, Kind: "FieldEncryptionPolicy", Metadata: policy.Metadata{Name: "test"}, Spec: policy.Spec{
		KeyDomain: "test", Columns: []policy.Field{{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, BlindIndex: "email_bidx"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	document := Document{Version: Version, Profile: "test", Statements: []Statement{
		{Name: "safe", SQL: `SELECT email FROM users WHERE email = $1`, Expected: "supported", TouchesProtected: true},
		{Name: "hidden", SQL: `SELECT id FROM users WHERE lower(email) = $1`, Expected: "rejected", TouchesProtected: true},
	}}
	report, err := Verify(document, catalog)
	if err != nil || report.Total != 2 || report.Supported != 1 || report.Rejected != 1 || report.Failed != 0 {
		t.Fatalf("unexpected report: %+v, %v", report, err)
	}
}
