# Kubernetes deployment with Helm

The chart defaults are intentionally restrictive: client TLS and terminated SCRAM are enabled, NetworkPolicy is on, client/upstream/KMS namespaces are explicit, health access has a separate selector and unrestricted HTTPS egress is disabled.

## Required secrets

Create:

- client-facing TLS secret (`tls.crt`, `tls.key`, and optional client CA);
- immutable key-bundle secret;
- credentials secret with metadata DSN, client password, upstream password and provider credential where applicable;
- upstream CA secret when the cluster trust store does not contain the PostgreSQL CA.

Do not store secret values in Helm values or rendered release metadata.

## Namespace and egress selectors

Override every example namespace label with the actual namespace:

```yaml
networkPolicy:
  ingressNamespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: applications}
  healthNamespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: monitoring}
  upstreamNamespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: database}
  kmsNamespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: security}
```

Cloud KMS endpoints normally require explicit `kmsCIDRs` or an egress gateway. `allowExternalHTTPS: true` opens TCP/443 to `0.0.0.0/0` and is an explicit security downgrade. Prefer a controlled egress proxy or provider-specific address policy.

## Bypass prevention

Use a separate PostgreSQL role for the gateway and ensure application pods cannot reach PostgreSQL. The application password should authenticate only to the gateway. Even with terminated credentials, deny direct network traffic as defense in depth.

## High availability

All replicas must mount the same policy and immutable bundle revision. The deployment uses rolling updates with zero unavailable replicas and a PodDisruptionBudget. Do not update a Secret in place and assume every mounted volume changes atomically; create a versioned Secret name and roll the deployment.

Readiness is reached only after policy/bundle loading, KMS unwrap, schema discovery, TLS initialization and listener startup. Keep health and metrics ports inaccessible to application namespaces unless required.
