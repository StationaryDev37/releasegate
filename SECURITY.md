# Security Policy

- Secrets are environment-injected and must never be committed.
- GitHub App and GitHub Marketplace webhook secrets are isolated; do not reuse them in production.
- Rotate any secret or ingest token immediately if exposure is suspected.
- Keep public request bodies bounded and terminate TLS before ReleaseGate.
- Back up SQLite or move to Postgres before multi-instance deployment.
- v0.1 returns `INDETERMINATE`; it does not claim independent provenance/artifact verification.
- Do not promote a receipt to `VERIFIED` until the verifier independently retrieves and cryptographically validates the relevant evidence.
