# ReleaseGate v0.3 Policy Gate Status

Evidence categories follow a strict no-inflation rule.

| Gate | Status | Evidence |
|---|---|---|
| v0.1 immutable baseline | VERIFIED | tag `v0.1-static-gate`; source SHA-256 `bf23924a358ace274a0e4bdc79e18d4d41608b850f5b2a2a187e70c09d5680a0` |
| v0.2 provenance source | IMPLEMENTED | GitHub App JWT, installation token, bounded attestation retrieval, fail-closed Sigstore verifier |
| v0.3 policy resolver | IMPLEMENTED | immutable policy version -> authenticated source context -> exact `ProvenanceExpectation` |
| Cargo.toml parse | PASSED | Python `tomllib` |
| Fixture JSON parse | PASSED | Python `json` |
| SQLite migration chain | PASSED | migrations 0001-0004 executed against in-memory SQLite with foreign keys enabled |
| GitHub HMAC known vector | PASSED | independent Python HMAC-SHA256 check |
| Receipt deterministic vector | PASSED | independent Python implementation |
| Policy deterministic vector | PASSED | independent Python implementation; SHA-256 `6bc707d83af54b493743d2f7ba4eb287302d8ce5cdfab99550421fb0880cefc1` |
| Cross-repository policy activation | PASSED | SQLite composite foreign key rejects mismatched repo activation |
| Trusted source selection | PASSED | exact installation + repo + commit + ref lookup in static gate |
| Rust formatting | UNEXECUTED | `rustfmt` unavailable in authoring runtime |
| Rust compilation | UNEXECUTED | `rustc`/Cargo unavailable in authoring runtime |
| Clippy | UNEXECUTED | Cargo unavailable |
| Rust tests | UNEXECUTED | Cargo unavailable |
| Live GitHub App webhook roundtrip | BLOCKED | requires registered GitHub App + deployed HTTPS endpoint + secret |
| Live installation-token roundtrip | BLOCKED | requires live GitHub App credentials/installation |
| Live attestation verification | BLOCKED | requires live installation plus real attested artifact |
| Production release | BLOCKED | Rust compile/test and live integration predicates are not yet closed |

## v0.3 decision boundary

v0.3 does **not** trust repository/ref/commit values supplied by an arbitrary verification request. It records those facts only after GitHub App webhook HMAC authentication, then resolves an active immutable organization policy against an exact `(installation_id, repository_id, commit, ref)` source record.

A permitted source produces a `ProvenanceExpectation`. A ref explicitly outside policy is `REJECTED`. Missing, malformed, or identity-mismatched trust context is `INDETERMINATE`.

No GitHub Check Run, SBOM commitment, receipt integration, or new metering behavior is claimed in this gate.
