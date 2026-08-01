# Operations, monitoring and troubleshooting

## Health and metrics

- `/livez` indicates that the process can serve HTTP.
- `/readyz` is available only after secure startup completed.
- `/metrics` exposes connection, session error, protected statement, parameter transformation and result-decryption counters.

Metrics contain no SQL, schema names, customer identifiers, bind values or ciphertext. Alert on readiness failure, increasing session errors, repeated restart loops and unexpected connection volume.

## Common failures

`statement type is not approved` means the encrypted endpoint received DDL, a procedure call, COPY/MERGE or another unapproved statement. Move migrations to the administrative path; do not add passthrough.

`protected predicate expression is unsupported` means a protected column appears inside a function, cast, boolean form or non-equality operator. Change the application query or policy/search design.

`encrypted envelope appeared in an unproven result column` indicates schema/query drift, a copied ciphertext value or a wire-plan mismatch. The connection closes. Preserve sanitized protocol metadata, not the row value, and treat this as a security incident.

`unknown data key` means the mounted bundle does not contain a key ID present in PostgreSQL. Restore the correct immutable bundle; do not edit ciphertext.

`verification after backfill failed` reports remaining plaintext, old-key rows, invalid envelopes or blind-index mismatch. Resolve locks/concurrent writers and re-run. Invalid envelopes require incident analysis and recovery from a trusted source.

## Performance

KMS latency affects startup and key operations, not each row. Per-value cost is AST planning, normalization, AES/HMAC and envelope encoding. Equality queries during rotation expand once per searchable key version, capped at 32; re-encrypt before allowing unbounded key accumulation.

Benchmark with the real driver, statement cache, pool size, row width and query corpus. Watch gateway CPU, allocation rate, PostgreSQL plan changes caused by blind-index predicates and index selectivity.

## Incident handling

Never log or attach plaintext, ciphertext, bind parameters, bundles or credentials. Record software digest, policy hash, bundle revision, KMS audit event IDs, sanitized SQL fingerprint and PostgreSQL error code. Rotate application/upstream credentials independently from data keys when exposure is suspected.
