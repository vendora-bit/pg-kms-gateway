# Independent design specification

This repository is a clean implementation of a policy-driven PostgreSQL field
encryption gateway. It does not share source files, Git history, package
layout, wire state machine, marker format, keyring format, or tests with any
previous proxy implementation.

## Boundary

The gateway terminates a PostgreSQL v3 client connection and opens a separate
authenticated PostgreSQL v3 server connection. It transforms only values whose
schema/table/column identity is proven by a compiled policy and parsed SQL.
Unknown or ambiguous protected writes fail before reaching PostgreSQL.

## Components

- `policy`: strict declarative schema and a compiled immutable lookup index.
- `vaultkey`: provider-neutral KEK interface and versioned wrapped data keys.
- `recordcrypt`: authenticated field envelopes, canonicalization and blind indexes.
- `querymap`: PostgreSQL AST analysis into parameter and result transformation plans.
- `pgsession`: protocol state machine, authentication, TLS and bounded relaying.
- `operator`: online backfill, verification, rotation and schema tooling.

These boundaries deliberately differ from the earlier repository. Protocol
code does not know policy YAML, cryptographic providers do not know SQL, and
the query mapper produces pure plans that are property-testable without a
socket.

## Security invariants

1. A write touching a protected relation is forwarded only when every affected
   protected value is either transformed or proven unchanged ciphertext.
2. A result value carrying the reserved envelope prefix is never returned if
   its relation/column identity cannot be proven.
3. AEAD additional data binds format version, key domain, schema, table,
   column, mode and optional JSON path.
4. Data keys are generated with the operating system CSPRNG, wrapped outside
   PostgreSQL and retained in plaintext only in process memory.
5. Equality support is opt-in. Random mode is the default. Blind-index keys
   are independent from field-encryption keys.
6. Key rotation is additive: old data-key versions remain decrypt-only until
   deep verification proves they are unused.
7. All migrations are restartable, compare-and-swap writes in bounded
   transactions, and never log plaintext.

## New envelope

Text values use:

```text
$PGXENC$2:<mode>:<key-id>:<base64url(nonce-or-siv || ciphertext)>
```

The authenticated header is not trusted until AEAD verification succeeds.
Literal plaintext starting with `$PGXENC$` is encrypted normally; there is no
escape/passthrough marker. Malformed reserved envelopes are fatal on reads.

## Query qualification

The query mapper accepts PostgreSQL parser ASTs and supports parameterized
`INSERT`, `UPDATE`, equality predicates and projection metadata. It rejects
`COPY`, `MERGE`, protected literals, dynamic SQL, ambiguous unqualified
relations and expressions that hide protected parameters. DDL is forwarded
but never interpreted as an encryption migration.

## Availability

KMS is needed only to create, open, rotate, or rewrap a key bundle. It is not
called per row. Multiple replicas mount the same immutable bundle revision;
readiness fails if policy or bundle compilation fails.
