# Security policy

Do not open public issues for suspected vulnerabilities. Report them through
GitHub private vulnerability reporting for the repository that publishes this
project. Include the affected version, reproduction, impact, and any proposed
mitigation. Maintainers will acknowledge a report within three business days.

Only the latest minor release receives security fixes. Ciphertext, key bundles,
KMS credentials, database credentials, query parameters, and decrypted values
must never be attached to a report.

The gateway reduces exposure of selected PostgreSQL fields at rest. It does not
replace database authorization, TLS, backups policy, host hardening, audit logs,
or application-layer access control. Deterministic encryption and blind indexes
leak equality and frequency by design and must be explicitly enabled.

Production deployments must require client and upstream TLS, use terminated
SCRAM with separate credentials, deny direct application-to-PostgreSQL access,
mount the key bundle read-only and restrict KMS authorization to the exact KEK.
Compatibility relay mode is outside the recommended production boundary.

No external cryptographic or PostgreSQL protocol audit is implied by automated
tests or maintainer review. Release notes will identify a third-party audit only
when a report and auditor can be independently verified.
