# Cryptography and PostgreSQL protocol audit scope

This document defines the minimum scope for an external security assessment. Automated tests, CodeQL, staticcheck, govulncheck and maintainer review are defense-in-depth controls; they are not a substitute for an independent audit.

## Cryptographic review

Reviewers should verify:

- CSPRNG use and key-size separation for AES-GCM, AES-SIV and HMAC;
- AES-GCM nonce generation and payload parsing bounds;
- Tink AES-SIV use and deterministic normalization semantics;
- length-delimited AAD construction and domain separation;
- envelope parsing, unknown-key handling and constant-time blind-index comparison;
- bundle serialization, KMS wrapping context, rotation, rewrap and pruning;
- plaintext/key lifetime, copies, clearing opportunities, logging and crash behavior;
- JSON-path context binding and partial-backfill behavior;
- SCRAM-SHA-256 transcript parsing, proof verification, nonce/salt generation and TLS assumptions.

Use published AES-GCM, AES-SIV, HMAC, PBKDF2 and SCRAM test vectors in addition to repository tests. Fuzz every attacker-controlled parser and verify malformed reserved envelopes never fall back to plaintext.

## PostgreSQL protocol review

Review both frontend and backend directions for:

- SSLRequest, StartupMessage, CancelRequest and authentication transitions;
- named/unnamed Parse, Bind, Describe, Execute and Close lifetimes;
- FIFO ordering across multiple pipelined queries and Sync boundaries;
- statement and portal result-metadata caching;
- `PortalSuspended`, `NoData`, empty queries, errors and recovery;
- prepared statement replacement and failed provisional state rollback;
- text/binary format negotiation and transformed parameter counts;
- RowDescription origin proof and DataRow envelope-leak detection;
- COPY, replication, function calls, DDL and multi-statement rejection;
- message-size bounds, partial reads/writes, disconnects and concurrent relay shutdown.

Exercise pgx, pgjdbc and libpq with statement caching, pool resets, cancellation and pipeline mode. Compare packet traces only in synthetic environments without secrets or production row values.

## Deliverables

An audit report should identify the reviewed commit and container digest, threat model, tools/test vectors, findings with severity, exploitability, remediation and retest status. Public claims must link to a verifiable report or clearly state that the report is private and name the auditor and reviewed version.
