# Architecture and security invariants

## Boundary

The gateway terminates a PostgreSQL v3 client connection and opens a separately authenticated PostgreSQL v3 server connection. It transforms only values whose schema, table and column identity is proven by a compiled policy and parsed SQL. Unknown or ambiguous protected operations fail before PostgreSQL receives them.

Production mode terminates client SCRAM-SHA-256 authentication and uses a different upstream SCRAM identity. A compatibility relay mode exists for controlled migrations, but it leaves bypass prevention entirely to network policy and is not the recommended production topology.

## Components

- `policy` decodes a strict declarative schema and compiles immutable lookup indexes.
- `vaultkey` provides a KMS-neutral KEK interface and versioned wrapped data-key bundles.
- `recordcrypt` implements authenticated field envelopes, normalization, JSON paths and blind indexes.
- `querymap` maps PostgreSQL parser ASTs to pure parameter and result transformation plans.
- `origin` validates protected columns and maps PostgreSQL table OIDs and attribute numbers.
- `pgsession` tracks statements, portals, descriptions, executions, synchronization boundaries and backend responses.
- `gateway` handles TLS, SCRAM termination, upstream authentication, cancellation and bounded relaying.
- `operator` performs restartable backfill, re-encryption and deep verification.
- `corpus` verifies application SQL contracts independently of sockets and databases.

Protocol code never parses policy YAML, KMS providers never inspect SQL and the query mapper does not own sockets. These boundaries keep security decisions testable as pure plans.

## Security invariants

1. A write involving a protected relation is forwarded only when every affected protected value is transformed from a bind parameter.
2. A protected predicate is accepted only as a direct equality between a proven protected column and a bind parameter.
3. Any nested expression that references a protected column but does not match an approved form is rejected.
4. A result carrying `$PGXENC$` is never returned from a column whose protected identity is unproven.
5. AEAD additional data binds format version, key domain, schema, table, column, mode and optional JSON path.
6. Data keys come from the operating-system CSPRNG, are wrapped outside PostgreSQL and remain plaintext only in gateway memory.
7. Random encryption is the default. Deterministic encryption and blind indexes require explicit policy choices and reveal equality.
8. Key rotation is additive. Old data keys remain decrypt-only until re-encryption and deep verification prove them unused.
9. Backfill and re-encryption use bounded transactions, row locks, compare-and-swap updates and mandatory post-run verification.
10. SQL, bind values, decrypted results, key material and ciphertext are never included in metrics or normal logs.

## Protocol state

Each frontend action appends an expected backend response to a FIFO queue. Parse, Bind and Close changes are provisional until their matching completion arrives. Describe results update shared statement/portal result metadata. Execute entries retain their own result rules, so later pipelined executions cannot overwrite an earlier result plan.

`ErrorResponse` rolls back unconfirmed changes and discards queued work only up to the next `Sync`/`ReadyForQuery` boundary. `PortalSuspended` completes one execution without deleting the portal or its proven result metadata. `NoData`, statement Describe, portal Describe, unnamed objects and repeated prepared execution have distinct tests.

## Encryption envelope

```text
$PGXENC$2:<mode>:<key-id>:<base64url(nonce-or-siv || ciphertext)>
```

The visible header selects the attempted decryption path but is trusted only after AEAD verification. Literal client plaintext beginning with the reserved prefix is encrypted normally. A malformed reserved envelope already stored in PostgreSQL is treated as corruption and fails closed.

## SQL qualification

The mapper accepts one PostgreSQL parser AST per request. Protected `INSERT`, `UPDATE`, equality predicates and projections use explicit allowlists. `COPY`, `MERGE`, DDL, multi-statements, protected literals, ambiguous relations and expressions hiding protected fields are rejected.

DDL is not forwarded through the encrypted endpoint. Operators use a separate administrative database path, apply the migration, validate the policy against the new schema and restart gateway replicas.

## Availability

KMS is required only to create, open, rotate or rewrap a bundle. A running replica does not call KMS per row. Every replica must mount the same immutable bundle revision. Startup fails before readiness if configuration, policy, bundle, KMS unwrap, TLS material or PostgreSQL origin discovery fails.
