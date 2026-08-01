# Application conformance profiles

Profiles are versioned policy and SQL-corpus packages kept outside the gateway core. A profile records the exact SQL shapes that an application release is expected to send through the encrypted endpoint. `corpus-verify` compiles every statement against the profile policy and fails when support or protected-data classification changes.

A profile is not a promise that every query emitted by an application is supported. Its `README.md` defines the tested scope, database changes, upgrade gate and known exclusions. Treat an application upgrade as incompatible until its schema and runtime corpus have been regenerated and reviewed.

Profile layout:

```text
profiles/<application>/<version>/
├── policy.yaml
├── corpus.json
└── README.md
```

Verify a profile before deployment:

```bash
pg-kms-gateway corpus-verify \
  --policy profiles/keycloak/26/policy.yaml \
  --corpus profiles/keycloak/26/corpus.json
```

Corpus files must contain parameterized SQL only. They must never contain captured bind values, credentials or production literals.
