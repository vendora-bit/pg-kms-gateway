# Contributing

Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and `gofmt` before a
change. Security-sensitive behavior requires negative tests. New SQL shapes are
rejected by default until the AST planner proves every protected parameter and
result origin. New cryptography must use a maintained standard library or a
reviewed upstream implementation; custom primitives are not accepted.

Commits must include a Developer Certificate of Origin sign-off (`git commit
-s`). Contributions must not copy code or history from another PostgreSQL
encryption proxy.
