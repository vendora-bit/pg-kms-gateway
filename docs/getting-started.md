# Getting started with PostgreSQL field encryption

This guide deploys the gateway between an application and PostgreSQL, initializes KMS-wrapped data keys and migrates existing plaintext without downtime.

## Prerequisites

- PostgreSQL 14 or newer with SCRAM-SHA-256 enabled;
- a dedicated gateway PostgreSQL role and database;
- a separate application-to-gateway username and password;
- TLS certificates for the client-facing gateway and a trusted upstream PostgreSQL CA;
- one KEK in Vault Transit, AWS KMS, Google Cloud KMS or Azure Key Vault;
- a schema migration path that does not pass through the encrypted endpoint.

Create two network identities. The application credential must not exist in PostgreSQL. The PostgreSQL credential must be available only to the gateway. Deny application workloads direct network access to port 5432.

## 1. Choose fields and query semantics

Inventory every read, write and search involving the candidate column. Use randomized mode when equality lookup is unnecessary. Choose deterministic mode only when exact lookup is required and frequency leakage is acceptable. Prefer randomized encryption plus a dedicated blind-index column when the stored ciphertext itself should remain non-deterministic.

Add blind-index columns through the administrative connection:

```sql
ALTER TABLE public.users ADD COLUMN email_bidx text;
CREATE INDEX users_email_bidx_idx ON public.users (email_bidx);
```

## 2. Compile the policy

```bash
pg-kms-gateway policy-check --policy policy.yaml
```

Compilation rejects duplicate identities, unsupported modes, invalid JSON paths and unsafe blind-index configurations. Gateway startup additionally verifies the live PostgreSQL type, table OID and attribute number.

## 3. Initialize the key bundle

Give the gateway workload permission to wrap and unwrap only the configured KEK. Then run:

```bash
pg-kms-gateway keys-init --config config.yaml
```

Store `bundle.json` in a versioned secret store. It contains wrapped data keys, not plaintext keys, but it is still security-sensitive and must be integrity-protected, backed up and mounted read-only.

## 4. Start in strict mode

```bash
PGKMS_CLIENT_PASSWORD='application-only-secret' \
PGKMS_UPSTREAM_PASSWORD='postgres-role-secret' \
PGKMS_METADATA_DSN='postgres://pg_kms_gateway:...@postgres/app' \
VAULT_TOKEN='...' \
pg-kms-gateway serve --config config.yaml
```

Connect the application with its gateway username, password and TLS root. The database name supplied by the application is not trusted in terminated mode; the configured upstream database is used.

## 5. Migrate existing rows

Route all application writes through the gateway before backfill. Then run:

```bash
pg-kms-gateway backfill --config config.yaml --batch 250
```

The command succeeds only after a separate deep verification pass finds no plaintext, old-key envelopes, invalid envelopes or blind-index mismatches. A row skipped because another transaction held its lock is therefore reported instead of being silently missed. Re-run after the conflicting writer finishes.

## 6. Verify the database boundary

- Query through the gateway and confirm plaintext behavior.
- Query directly with the gateway PostgreSQL role and confirm ciphertext storage.
- Confirm the application credential cannot authenticate to PostgreSQL.
- Confirm NetworkPolicy/firewall rules block application-to-PostgreSQL traffic.
- Exercise prepared statements, connection pools, cancellation and the application corpus.

Do not expose the encrypted endpoint until these checks pass.
