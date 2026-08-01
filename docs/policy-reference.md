# PostgreSQL encryption policy reference

Policy version `pgkms.dev/v1` maps exact `schema.table.column` identities to encryption behavior. It does not use regular expressions, inferred names or runtime passthrough rules.

```yaml
apiVersion: pgkms.dev/v1
kind: FieldEncryptionPolicy
metadata:
  name: customer_pii
spec:
  keyDomain: production.customer-pii
  columns:
    - schema: public
      table: users
      column: email
      mode: random
      normalize: lowercase-trim
      blindIndex: email_bidx
```

## Field options

`schema` defaults to `public`. `table` and `column` are required simple PostgreSQL identifiers.

`mode` is `random` or `deterministic`. Random mode uses a fresh nonce and is semantically secure under nonce uniqueness. Deterministic mode produces the same ciphertext for the same normalized value and context, revealing equality and frequency.

`normalize` is `none`, `trim` or `lowercase-trim`. Normalization affects deterministic ciphertext and blind indexes. It does not change randomized field plaintext. A randomized field may specify normalization only when it also has a blind index.

`blindIndex` names a separate text column. It cannot itself be protected or be shared by multiple fields. Create and index it before gateway startup.

`jsonPaths` protects selected string values inside a JSON object. Paths are bounded dotted keys such as `$.contact.email`. Arrays, wildcards, root selection and paths deeper than 16 keys are rejected. Whole-document normalization and blind indexing cannot be combined with partial JSON encryption.

## Equality queries

- deterministic field: `WHERE external_id = $1` encrypts the parameter under every searchable data-key version;
- random field with blind index: `WHERE email = $1` is rewritten to the blind-index column and computes one HMAC per searchable key version;
- random field without blind index: equality is rejected;
- partial JSON: equality is rejected.

Function wrapping, casts around columns, concatenation, `LIKE`, `ILIKE`, ranges, `IN`, `OR` and expression indexes are not approved in version 1. Casts around bind parameters are accepted only where the mapper can still prove the direct parameter.

## Policy changes

Treat policy changes like schema changes. Adding a field requires startup validation followed by backfill. Changing mode, normalization, key domain, blind-index identity or JSON paths changes cryptographic context and requires an explicit migration plan. Never edit a mounted policy in place while replicas run different revisions.
