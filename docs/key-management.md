# KMS providers and key rotation

The KEK wraps a small versioned data-key bundle. KMS is contacted for bundle lifecycle operations, not for each row.

## Provider configuration

- Vault Transit: token or workload-authenticated Vault client, mount and Transit key name.
- AWS KMS: default AWS credential chain, region and key ARN/alias.
- Google Cloud KMS: Application Default Credentials and CryptoKey resource name.
- Azure Key Vault: DefaultAzureCredential, vault URL, key identifier and RSA-OAEP-256 by default.

Grant only wrap/unwrap permissions for the selected KEK. Do not give the gateway key creation, deletion or broad KMS administration unless an operator workflow explicitly requires it.

## Data-key rotation

`keys-rotate` generates a new data-key version, marks the old version decrypt-only and writes a new bundle atomically. Deploy the exact new bundle revision to every replica before relying on new writes. During the transition, equality predicates expand across searchable key versions.

`reencrypt` rewrites values and blind indexes under the active data key in bounded transactions. Its automatic verification must pass. `keys-prune` repeats deep verification and refuses to remove decrypt-only versions while any old envelope remains.

## KEK rotation and rewrap

`keys-rewrap` unwraps each data-key entry with its current provider/key reference and wraps it with the configured target KEK. Row ciphertext and blind indexes do not change. Distribute and verify the new bundle before removing access to the old KEK.

## Rollback

Keep the previous immutable bundle revision until all replicas using it have stopped. A rollback is safe only while the selected bundle contains every data-key ID present in PostgreSQL. Never restore an older bundle after new writes use a key ID absent from it.

Back up the bundle independently from PostgreSQL and document the KEK recovery procedure. Losing either the bundle or authorization to every KEK version makes the data unrecoverable.

## Live provider qualification

Provider unit tests validate request shape and failure handling with controlled servers. Before approving a production KEK, run the opt-in live contract suite with workload credentials and the provider-specific `PGKMS_LIVE_*` key reference:

```bash
go test -tags=livekms -run TestLiveKMSProviders -v ./integration
```

The suite performs a real wrap/unwrap round trip without printing plaintext, ciphertext or credentials. Keep it in an isolated cloud project/subscription and audit the resulting KMS events.
