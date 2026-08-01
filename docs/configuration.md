# Configuration reference

Configuration is strict YAML: unknown fields and multiple YAML documents are rejected. Secrets are referenced by environment-variable name and are never stored directly in the file.

## Listener and PostgreSQL upstream

```yaml
listen: ":6432"
health: "127.0.0.1:8080"
upstream:
  address: "postgres.database.svc:5432"
  tls: true
  serverName: "postgres.database.svc"
  caFile: "/etc/pgkms/upstream/ca.crt"
```

`listen` defaults to `:6432`. `health` defaults to loopback port `8080`; Kubernetes explicitly binds it inside the pod and limits access with NetworkPolicy. Upstream TLS requires a server name. TLS 1.3 is the minimum on both legs.

## Client TLS and optional mTLS

```yaml
clientTLS:
  required: true
  certFile: "/etc/pgkms/client/tls.crt"
  keyFile: "/etc/pgkms/client/tls.key"
  clientCAFile: "/etc/pgkms/client/ca.crt"
```

Client TLS is required when `required` is omitted. Supplying `clientCAFile` changes the listener to mTLS and requires a valid client certificate. Setting `required: false` is an explicit compatibility downgrade and cannot be combined with terminated SCRAM.

## Authentication modes

```yaml
authentication:
  mode: terminate-scram
  clientUsername: application
  clientPasswordEnv: PGKMS_CLIENT_PASSWORD
  upstreamUsername: pg_kms_gateway
  upstreamPasswordEnv: PGKMS_UPSTREAM_PASSWORD
  upstreamDatabase: app
```

`terminate-scram` is the default. The gateway acts as a SCRAM-SHA-256 server to the application and as an independent SCRAM-SHA-256 client to PostgreSQL. Use different random passwords. The upstream user needs only the SQL permissions required by the application and schema discovery.

Gateway-side SCRAM credentials currently require printable ASCII so client and server password normalization cannot diverge. Generate high-entropy base64url passwords rather than human phrases.

`mode: relay` forwards PostgreSQL authentication messages. It is provided for compatibility testing and depends entirely on network controls to prevent bypass.

## Policy, bundle and metadata connection

```yaml
policyFile: /etc/pgkms/policy/policy.yaml
bundleFile: /etc/pgkms/bundle/bundle.json
metadataDSNEnv: PGKMS_METADATA_DSN
```

The metadata DSN is used at startup and by operator commands for schema discovery and direct row migration. Keep it out of application environments.

## KMS

```yaml
kms:
  provider: vault-transit
  keyRef: pg-kms-gateway
  vault:
    address: https://vault.security.svc:8200
    mount: transit
    namespace: platform
    tokenEnv: VAULT_TOKEN
```

Provider values are `vault-transit`, `aws-kms`, `gcp-kms` and `azure-key-vault`. Cloud providers use their standard workload credential chains. `keyRef` is provider-specific and must identify one KEK.

## Resource limits

```yaml
limits:
  messageBytes: 67108864
  maxConnections: 1024
  dialTimeout: 10s
```

Message size must be between 1 MiB and 1 GiB. Concurrent sessions default to 1024 and are bounded to prevent unbounded authentication/relay goroutines. Dial timeout must be between one second and one minute. Field plaintext is independently limited to 16 MiB.
