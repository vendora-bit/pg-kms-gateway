# Application conformance profiles

A generic PostgreSQL encryption policy proves field identity, but it does not prove that a particular application version emits only supported SQL. A conformance profile closes that gap with a versioned policy and sanitized SQL corpus.

## Corpus contract

Each entry records a stable name, parameterized SQL, expected `supported` or `rejected` outcome and whether the planner must classify the statement as touching protected data. `corpus-verify` fails on any behavior change.

```bash
pg-kms-gateway corpus-verify --policy policy.yaml --corpus corpus.json
```

Corpus capture must remove bind values and production literals. Prefer parser normalization and reviewed fixtures generated in a test environment. Never capture authentication messages, passwords or row results.

## Qualification workflow

1. Pin the exact application and PostgreSQL driver versions.
2. Export the generated schema and validate protected identities/types.
3. Exercise registration, authentication, CRUD, search, administration, background jobs and migrations in a test environment.
4. Deduplicate normalized SQL shapes and assign human-readable names.
5. Mark intentionally rejected shapes and ensure the application never depends on them at runtime.
6. Run wire E2E with TLS, terminated SCRAM, prepared statements, pooling, cancellation and pipeline/portal features used by the driver.
7. Review the corpus diff on every application upgrade.

Profiles do not weaken the core. There is no lenient runtime mode and no unknown-SQL passthrough for protected relations. Application-specific conditional encryption requires an explicit future policy feature, not hidden profile code.
