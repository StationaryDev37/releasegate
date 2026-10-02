# ReleaseGate v0.5 production-candidate status

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

## v0.5 production-candidate closure

The production-host boundary is now implemented and audit-hardened on branch `v0.5-production-rc1-fix`:

- hardened systemd runtime service and dedicated Caddy HTTPS edge;
- create-once host materialization with generated scoped tokens/webhook secrets and a distinct RSA-3072 receipt key;
- exact GitHub App contract and content-addressed runtime manifest;
- silicon lock enforced at process exec;
- SQLite online backup with post-backup integrity/foreign-key verification;
- decision-derived operational snapshot instead of a generic dashboard;
- exact Rust 1.90.0/Cargo 1.90.0 enforcement in the authoritative Rust gate;
- repaired `github.rs` duplicate Check parameter and malformed bundle-client call discovered during production source review;
- repaired `RecoveredDelivery.attempt` compile blocker and locked recovery logging to the persisted retry count;
- serialized SQLite write transitions through one connection with a bounded busy timeout;
- bound the package/User-Agent identity to `0.5.0` from `CARGO_PKG_VERSION`;
- made receipt public-key identity reject concatenated PEM keyrings;
- prevented systemd restart storms for launcher exits `40`/`41`;
- encoded target-runtime silicon-lock generation and webhook-secret rotation semantics in the production contract.

Static, commercial, silicon, production, SQLite integrity, backup and Git-history gates are executed and passing. Rust format/check/Clippy/tests/release build remain **BLOCKED** in this runtime because `rustc`/Cargo are absent. Production release is therefore **NOT CLAIMED**.

## v0.5 RC2 hardening

The RC2 hardening branch adds three release-specific invariants discovered during the post-RC1 adversarial review: invariant-critical recovery and GitHub Check workers are process-supervised so silent worker death forces service shutdown/restart; ambiguous Check-run recovery is bound to ReleaseGate's exact GitHub App ID in addition to the evaluation `external_id`; and bundle egress rejects IPv4-mapped/reserved IPv6 forms before DNS-pinned retrieval. These changes do not promote Rust execution status: the authoritative Rust gate remains required.
