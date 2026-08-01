# Encryption format and cryptographic design

## Data-key material

Each data-key version contains three independent keys:

- 256-bit AES-GCM key for randomized encryption;
- 512-bit AES-SIV key for deterministic authenticated encryption;
- 256-bit HMAC-SHA-256 key for blind indexes.

All bytes come from `crypto/rand`. The material is serialized into a key bundle entry and wrapped by the configured KEK provider. PostgreSQL stores only field envelopes and blind indexes; it never stores the bundle or KEK.

## Randomized encryption

Random mode uses AES-256-GCM with a fresh 96-bit nonce. The payload contains `nonce || ciphertext || tag`. Re-encrypting the same plaintext produces a different envelope. Nonce generation failure aborts the operation.

## Deterministic encryption

Deterministic mode uses AES-SIV from Google Tink. It tolerates nonce misuse by construction and requires no caller-provided nonce. Determinism reveals whether two normalized values are equal within the same cryptographic context and key version.

## Additional authenticated data

AAD is a length-delimited encoding of:

```text
pgxenc, format-version, key-domain, schema, table, column, mode, json-path
```

Copying ciphertext into another domain, table, column, mode or JSON path causes authentication failure. The visible envelope mode and key ID select a candidate key, but successful AEAD verification is the authority.

## Blind indexes

A blind index is HMAC-SHA-256 over AAD, a separator byte and normalized plaintext. It is not encryption and cannot be decrypted. It reveals equality and frequency and is vulnerable to offline guessing when the attacker also obtains the blind-index key. The blind-index key is independent of encryption keys so permissions and future rotation can be reasoned about separately.

## Limits

Ciphertext length, access patterns, table/column use and query timing remain visible. Deterministic encryption and blind indexes do not provide order or substring search. The gateway does not implement format-preserving encryption, searchable encryption for arbitrary predicates or homomorphic computation.
