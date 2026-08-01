# Production security hardening checklist

## Identity and network

- Use `terminate-scram`; give the application and PostgreSQL different passwords.
- Require TLS 1.3 on both legs; use mTLS where workload identity is available.
- Deny application-to-PostgreSQL network traffic.
- Restrict gateway ingress to application namespaces and health ingress to monitoring.
- Restrict egress to DNS, PostgreSQL and the exact KMS path; keep unrestricted HTTPS disabled.
- Grant the upstream role least-privilege DML and required schema metadata access.

## Keys and runtime

- Mount a versioned bundle read-only and identically on every replica.
- Scope KMS authorization to one KEK and audit unwrap operations.
- Disable core dumps, debugging, process-memory inspection and swap where the platform permits.
- Run as non-root with a read-only root filesystem, no Linux capabilities and seccomp RuntimeDefault.
- Keep SQL, parameters, rows, ciphertext and secrets out of logs, traces and metrics.

## Data lifecycle

- Route all writers through the gateway before backfill.
- Require automatic post-backfill verification.
- Re-encrypt and deep-verify before pruning old data keys.
- Back up the bundle separately and test KEK disaster recovery.
- Run DDL only through a separate migration role/path and restart after schema changes.

## Software supply chain

- Pin container images by digest.
- Verify the Cosign identity and GitHub provenance attestation.
- Archive the SPDX SBOM and vulnerability scan for the deployed digest.
- Require pull requests, one approval, successful CI/security checks, conversation resolution and no force pushes on `main`.
- Obtain an external cryptographic and PostgreSQL protocol audit before making third-party assurance claims.
