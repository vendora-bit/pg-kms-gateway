# Threat model

## Protected

The design protects selected field plaintext from database files, physical
snapshots, logical dumps taken directly from PostgreSQL, read-only SQL access
that does not also control the gateway, and accidental operator inspection.
Compromise of a KEK alone is insufficient without the bundle; compromise of the
bundle alone is insufficient without KMS authorization.

## Trusted

The gateway process necessarily sees plaintext and unwrapped data keys in
memory. The application authorization layer, gateway workload identity,
gateway host, release pipeline, policy, bundle and KMS authorization are
trusted. TLS endpoints see their respective plaintext protocol traffic.

## Not protected

The gateway does not defend against a compromised application, gateway process,
kernel, debugger, malicious database response combined with a gateway exploit,
or an administrator who controls both KMS and the running gateway. Equality
features reveal repetitions and frequency. Length is visible within AEAD
overhead. Access patterns, table names, non-protected columns, row counts, and
query timing remain visible to PostgreSQL.

Terminated SCRAM prevents the application from learning the PostgreSQL
credential. It does not replace NetworkPolicy or database authorization.
Relay mode assumes network controls alone prevent direct database access and
is outside the recommended production boundary.

## Failure behavior

Ambiguous SQL, unknown key versions, AEAD failures, malformed reserved values,
binary protected formats, schema drift, incomplete result origins, KMS errors,
and bundle-policy mismatches terminate or reject the affected operation. The
gateway never returns ciphertext carrying its reserved prefix as plaintext.
