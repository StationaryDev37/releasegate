# ReleaseGate v0.1 Status

Evidence categories follow a strict no-inflation rule.

| Gate | Status | Evidence |
|---|---|---|
| Source tree | IMPLEMENTED | Rust service, migration, fixtures, CI, docs present |
| Cargo.toml parse | PASSED | Python `tomllib` |
| Fixture JSON parse | PASSED | Python `json` |
| SQLite migration | PASSED | Executed against in-memory SQLite |
| GitHub HMAC known vector | PASSED | Independent Python HMAC-SHA256 check |
| Receipt deterministic vector | PASSED | Independent Python implementation |
| Rust formatting | UNEXECUTED | `rustfmt` unavailable in authoring runtime |
| Rust compilation | UNEXECUTED | `rustc`/Cargo unavailable in authoring runtime |
| Clippy | UNEXECUTED | Cargo unavailable |
| Rust tests | UNEXECUTED | Cargo unavailable |
| Live GitHub App webhook | BLOCKED | Requires registered GitHub App + deployed HTTPS endpoint + secret |
| Live Marketplace purchase | BLOCKED | Requires eligible verified publisher/listing/financial onboarding |
| Independent provenance verification | PLANNED | Next gate; v0.1 deliberately returns INDETERMINATE |
| Production release | BLOCKED | Requires all Rust and live integration gates above |
