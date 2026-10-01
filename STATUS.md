# ReleaseGate v0.3.2 silicon-lock status

| Gate | Status | Evidence |
|---|---|---|
| v0.1 immutable baseline | VERIFIED | historical tag `v0.1-static-gate`; source SHA-256 `bf23924a358ace274a0e4bdc79e18d4d41608b850f5b2a2a187e70c09d5680a0` |
| v0.2 provenance design | IMPLEMENTED | GitHub App JWT/token path, bounded bundle evidence, fail-closed Sigstore verifier |
| v0.3 policy design | IMPLEMENTED | immutable policy + authenticated exact source context |
| Truth/authorization/release split | IMPLEMENTED | custom closed 3×3 decision law |
| Durable webhook recovery | IMPLEMENTED | persisted authenticated bytes + digest + signature; lease/reclaim/backoff; recovery re-hash/HMAC; 12-attempt terminal budget |
| Evaluation freeze | IMPLEMENTED | deterministic context binds source/policy/artifact/trust/executing-binary identities |
| Rekor trust selection | IMPLEMENTED | exact log-id/SPKI SHA-256 match; no vector-position trust |
| Bundle egress hardening | IMPLEMENTED | exact hostname + public DNS validation + address pin + no redirect |
| Authority split / secret redaction | IMPLEMENTED | webhook/control/evaluator/auditor separation; redacted secret type |
| Critical verifier dependency pin | IMPLEMENTED | `attestation-verify = "=0.1.0"` |
| Silicon lock / affinity attestation | IMPLEMENTED | host-specific content-addressed topology lock; deterministic housekeeping/IRQ/runtime CPU placement; startup verifies lock bytes and `/proc/self/status` affinity |
| Silicon independent gate | PASSED | `scripts/silicon_gate.py` proves lock creation, validation, tamper rejection and affinity execution |
| Bedrock independent static gate | PASSED | `scripts/static_gate.py` -> `BEDROCK_STATIC_GATE_PASS` |
| SQLite migration chain 0001-0007 | PASSED | executed in-memory with foreign keys enabled by static gate |
| Lease/recovery adversarial vectors | PASSED | independent SQLite/Python vectors prove non-steal-before-expiry, reclaim-after-expiry, backoff enforcement, retry-budget terminalization, durable payload digest/HMAC re-auth, and terminal applied state |
| Evaluation identity vector | PASSED | `rge_1f6f385e648dfa4c7d2eca4478bb88e8fba7adf28686313fd751e2e8204c2183` |
| Rekor key identity vector | PASSED | independent SHA-256(SPKI) equals Rekor `logId` |
| Git diff whitespace gate | PASSED | `git diff --check` |
| Rust formatting | BLOCKED | `rustfmt` absent in this execution runtime |
| Rust compilation | BLOCKED | `rustc`/Cargo absent; runtime DNS cannot resolve Rust distribution host |
| Clippy | BLOCKED | Rust toolchain unavailable |
| Rust tests | BLOCKED | Rust toolchain unavailable |
| `Cargo.lock` | BLOCKED | cannot truthfully generate dependency lock without Cargo resolution |
| Production release | BLOCKED | `scripts/rust_gate.sh` has not reported `RUST_GATE_PASS`; live GitHub roundtrips remain unexecuted |

No compile/test status is inferred from static analysis.
