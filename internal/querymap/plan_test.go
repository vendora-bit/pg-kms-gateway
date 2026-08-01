package querymap

import (
	"errors"
	"strings"
	"testing"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
)

func catalog(t *testing.T) *policy.Catalog {
	t.Helper()
	doc := policy.Document{
		APIVersion: policy.APIVersion,
		Kind:       "FieldEncryptionPolicy",
		Metadata:   policy.Metadata{Name: "test"},
		Spec: policy.Spec{KeyDomain: "tenant-a", Columns: []policy.Field{
			{Schema: "public", Table: "users", Column: "email", Mode: policy.ModeRandom, BlindIndex: "email_bidx"},
			{Schema: "public", Table: "users", Column: "external_id", Mode: policy.ModeDeterministic},
		}},
	}
	c, err := policy.Compile(doc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInsertAddsBlindIndexParameter(t *testing.T) {
	plan, err := Analyze(`INSERT INTO users (email, external_id) VALUES ($1, $2) RETURNING email`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if plan.OriginalParameterCount != 2 || plan.ParameterCount != 3 || len(plan.Parameters) != 3 || len(plan.Results) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if !strings.Contains(plan.SQL, "email_bidx") || !strings.Contains(plan.SQL, "$3") {
		t.Fatalf("SQL was not safely extended: %s", plan.SQL)
	}
}

func TestRandomEqualityRewritesToBlindIndex(t *testing.T) {
	plan, err := Analyze(`SELECT email FROM public.users AS u WHERE u.email = $1`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Parameters) != 1 || plan.Parameters[0].Op != ComputeBlindIndex || !strings.Contains(plan.SQL, "u.email_bidx") {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestUpdateDuplicatesConflictingParameter(t *testing.T) {
	plan, err := Analyze(`UPDATE users SET email = $1 WHERE email = $1 RETURNING *`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if plan.ParameterCount != 3 || !strings.Contains(plan.SQL, "email_bidx = $3") || !plan.ResolveResultOrigins {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestUnsafeProtectedFormsFailClosed(t *testing.T) {
	queries := []string{
		`INSERT INTO users (email) VALUES ('literal@example.com')`,
		`UPDATE users SET email = lower($1)`,
		`SELECT lower(email) FROM users`,
		`SELECT id FROM users WHERE lower(email) = $1`,
		`SELECT id FROM users WHERE coalesce(email, '') = $1`,
		`SELECT id FROM users WHERE $1 = trim(users.email)`,
		`SELECT id FROM users WHERE (email || '') = $1`,
		`SELECT id FROM users WHERE lower(public.users.email) = $1`,
		`SELECT email FROM users WHERE email LIKE $1`,
		`COPY users TO STDOUT`,
		`MERGE INTO users USING staged ON users.external_id = staged.id WHEN MATCHED THEN UPDATE SET email = staged.email`,
		`SELECT email FROM users; SELECT 1`,
		`ALTER TABLE users RENAME COLUMN email TO contact`,
		`CREATE VIEW leaked AS SELECT email FROM users`,
		`CALL process_users()`,
		`SELECT u.email FROM users u JOIN posts p ON p.user_id = u.id`,
		`SELECT email FROM (SELECT email FROM users) AS nested`,
	}
	for _, query := range queries {
		if _, err := Analyze(query, catalog(t)); !errors.Is(err, ErrUnsafeQuery) {
			t.Errorf("%q: expected unsafe-query error, got %v", query, err)
		}
	}
}

func TestSchemaQualifiedProtectedPredicate(t *testing.T) {
	plan, err := Analyze(`SELECT email FROM public.users WHERE public.users.email = $1`, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Parameters) != 1 || plan.Parameters[0].Op != ComputeBlindIndex || !strings.Contains(plan.SQL, "email_bidx") {
		t.Fatalf("schema-qualified predicate was not transformed: %+v", plan)
	}
}

func FuzzProtectedPredicateExpressionsFailClosed(f *testing.F) {
	wrappers := []func(string) string{
		func(column string) string { return "lower(" + column + ") = $1" },
		func(column string) string { return "coalesce(" + column + ", '') = $1" },
		func(column string) string { return "(" + column + " || '') = $1" },
		func(column string) string { return "length(" + column + ") = $1" },
		func(column string) string { return "$1 = trim(" + column + ")" },
		func(column string) string {
			return "CASE WHEN " + column + " IS NULL THEN '' ELSE " + column + " END = $1"
		},
	}
	for index := range wrappers {
		f.Add(uint8(index), index%2 == 0)
	}
	f.Fuzz(func(t *testing.T, wrapper uint8, qualified bool) {
		column := "email"
		if qualified {
			column = "public.users.email"
		}
		query := `SELECT id FROM users WHERE ` + wrappers[int(wrapper)%len(wrappers)](column)
		if _, parseErr := Analyze(query, catalog(t)); parseErr == nil {
			t.Fatalf("protected column hidden in predicate was accepted: %s", query)
		}
	})
}

func TestUnprotectedQueryPassesThrough(t *testing.T) {
	query := `SELECT title FROM posts WHERE id = $1`
	plan, err := Analyze(query, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if plan.SQL != query || plan.TouchesProtectedData || len(plan.Parameters) != 0 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestTransactionAndSessionControlPassThrough(t *testing.T) {
	for _, query := range []string{`BEGIN`, `COMMIT`, `SET application_name = 'gateway-client'`, `SHOW application_name`} {
		plan, err := Analyze(query, catalog(t))
		if err != nil || plan.SQL != query {
			t.Fatalf("%q: %+v, %v", query, plan, err)
		}
	}
}
