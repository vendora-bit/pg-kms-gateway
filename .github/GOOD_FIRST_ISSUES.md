# Good first issues to open after the v0.1.0 release

Create these as GitHub issues with the good first issue label after the release
is public.

1. **Add a policy schema reference** — generate a concise field-by-field
   reference from the current validation model, including safe and rejected
   examples.
2. **Document a read-only client rollout** — describe how to route a staging
   application through the gateway before any backfill, with an explicit rollback.
3. **Add Prometheus scrape examples** — provide a small Kubernetes ServiceMonitor
   recipe that uses labels without customer, schema or SQL data.
4. **Improve unsupported SQL diagnostics** — add a test-led error hint for one
   intentionally rejected SQL shape without making the parser more permissive.
