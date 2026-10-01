# ReleaseGate v0.4 commercial-loop status

This file distinguishes implemented source from executed evidence. Static gates do not imply Rust compilation.

| Gate | Status | Evidence |
|---|---|---|
| v0.1 immutable baseline | VERIFIED | historical source SHA-256 `bf23924a358ace274a0e4bdc79e18d4d41608b850f5b2a2a187e70c09d5680a0` |
| v0.2 provenance kernel | IMPLEMENTED | GitHub App auth, bounded attestation retrieval, fail-closed Sigstore path |
| v0.3 immutable policy/source binding | IMPLEMENTED | exact authenticated repo/ref/commit + immutable policy versions |
| v0.3.1 bedrock hardening | IMPLEMENTED | truth/auth/release split, durable webhook recovery, explicit trust/evaluation identity |
| v0.3.2 silicon lock | IMPLEMENTED | content-addressed host topology / runtime-affinity evidence; excluded from release truth |
| EvaluationContext v2 | IMPLEMENTED | adds receipt-key identity to frozen evaluation commitment |
| Deterministic decision commitment | IMPLEMENTED | custom domain-separated canonical encoding with independent fixture |
| Independent receipt authority | IMPLEMENTED | separate RS256 keypair, startup self-test, public verification endpoint |
| Atomic commercial finalization | IMPLEMENTED | decision + per-bundle outcomes + exactly-one usage event + Check outbox in one transaction |
| Least-privilege GitHub token scopes | IMPLEMENTED | separate `attestations:read` and `checks:write` installation tokens |
| Durable GitHub Check projection | IMPLEMENTED | lease/reclaim/backoff/dead-letter + external-id recovery before POST |
| Bedrock static gate | PASSED | `scripts/static_gate.py` → `BEDROCK_STATIC_GATE_PASS` |
| Commercial-loop independent gate | PASSED | `scripts/commercial_gate.py` → `COMMERCIAL_LOOP_GATE_PASS` |
| Python script syntax | PASSED | `python3 -m py_compile scripts/*.py` |
| Git whitespace gate | PASSED | `git diff --check` |
| Migration chain 0001–0008 | PASSED | exercised fresh and as v0.3.2→v0.4 upgrade by independent gate |
| Evaluation v2 canonical vector | PASSED | fixture identity reproduced independently |
| Attestation-set commitment vector | PASSED | order-independent fixture commitment reproduced independently |
| Decision commitment vector | PASSED | independent Python implementation matches fixture |
| Exactly-one metering invariant | PASSED | duplicate evaluation charge rejected by DB identity |
| Check outbox lease/reclaim invariant | PASSED | independent SQLite adversarial path |
| Placeholder/demo source rejection | PASSED | commercial gate rejects TODO/unimplemented/placeholder/mock/demo production source |
| Rust formatting | BLOCKED | no `rustfmt` in this execution runtime |
| Rust compilation | BLOCKED | no `rustc`/Cargo in this execution runtime |
| Clippy | BLOCKED | Rust toolchain unavailable here |
| Rust tests | BLOCKED | Rust toolchain unavailable here |
| `Cargo.lock` | BLOCKED | authoritative dependency resolution requires Cargo; gate refuses to invent it |
| Live GitHub App roundtrip | UNEXECUTED | requires registered App, installation, repository and live secrets |
| Live Check Run publication | UNEXECUTED | requires the same live GitHub installation |
| Production release | BLOCKED | requires `scripts/rust_gate.sh` → `RUST_GATE_PASS` plus live GitHub roundtrip evidence |

No compile, test, Check delivery, Marketplace collection, or production status is inferred from source inspection.
