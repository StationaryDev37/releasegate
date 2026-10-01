# ReleaseGate v0.4 — commercial release-decision loop

ReleaseGate is a fail-closed GitHub release-control kernel. It converts authenticated source events, immutable release policy, GitHub artifact provenance, and a frozen trust snapshot into one deterministic release decision, then emits independently verifiable evidence, a durable GitHub Check projection, and one idempotent usage event.

It is not a generic webhook service, CI dashboard, policy CRUD application, or attestation generator.

## Closed execution law

```text
GitHub HMAC event
      ↓
authenticated durable source event
      ↓
immutable active policy + exact source/ref/commit
      ↓
frozen EvaluationContext v2
      ↓
GitHub attestation retrieval
      ↓
Sigstore provenance verification
      ↓
EvidenceTruth × PolicyAuthorization
      ↓
ReleaseDecision
      ↓
deterministic DecisionCommitment
      ↓
RS256 signed receipt
      ↓
atomic finalization
   ├── release decision
   ├── per-bundle evidence outcomes
   ├── exactly-one usage event
   └── durable GitHub Check outbox
      ↓
idempotent GitHub Check publication
```

Only `VERIFIED + ALLOW` produces `RELEASE`. Everything else becomes `BLOCK` or `HOLD`; missing or unsupported evidence can never be promoted into release truth.

## Kernel invariants

1. **Truth, authorization, and release are different state machines.** Cryptographic invalidity cannot be confused with policy denial.
2. **Evaluation facts freeze before verification.** Repository/source/ref/commit, policy, artifact, trust snapshot, executing verifier binary, and receipt-key identity are committed into `EvaluationContext v2`.
3. **Receipts bind decisions, not mutable presentation.** The custom decision commitment is deterministic and excludes issuance time; receipt identity is `rgr_<decision_commitment>`.
4. **Receipt authority is separate from GitHub authority.** GitHub App RSA credentials cannot sign ReleaseGate receipts. Receipt key rotation changes evaluation identity.
5. **Metering is transaction-coupled to finalization.** A finalized evaluation creates exactly one `release_evaluation_v1` usage event or none. Duplicate billing for the same evaluation is rejected by storage identity.
6. **GitHub Check delivery is an outbox projection, not part of truth.** A transient GitHub outage cannot roll back or reinterpret an already-finalized decision.
7. **Check publication is recoverably idempotent.** The evaluation ID is GitHub `external_id`; recovery queries the exact commit/check name before retrying POST.
8. **Installation tokens are least-privilege by operation.** Attestation reads receive only `attestations:read`; Check publication receives only `checks:write`.
9. **Webhook bytes remain evidence.** Authenticated payload bytes are persisted before side effects and are re-hashed/re-authenticated during recovery.
10. **No hardware optimization establishes truth.** Silicon lock/affinity is operational evidence only.

## Runtime surface

- `POST /webhooks/github/app` — GitHub App HMAC ingress.
- `POST /webhooks/github/marketplace` — separately authenticated entitlement ingress.
- `POST /v1/policies/active` — control authority; creates/activates immutable policy.
- `POST /v1/evaluations` — evaluator authority; executes or idempotently returns one frozen release evaluation.
- `GET /v1/evaluations/:id` — auditor authority; returns completed decision, signed receipt, and Check projection state.
- `GET /v1/receipt-key` — public verification material for ReleaseGate receipts.
- `GET /healthz`, `GET /readyz` — liveness/readiness only.

No dashboard, ORM, generic repository layer, generic message bus, placeholder API, fake integration, or example production secret is shipped.

## Durable finalization boundary

The decision row, attestation outcomes, billable usage event, and GitHub Check outbox entry are committed in one SQLite transaction. The Check worker owns a finite lease and retry budget; success records the returned Check Run ID, retryable failures back off, permanent failures dead-letter with a stable error code.

A GitHub Check failure therefore means **projection failure**, not loss of release truth.

## Evidence gates

- `scripts/static_gate.py` — bedrock migrations, replay/recovery, trust identity, state law and canonical evaluation vectors.
- `scripts/commercial_gate.py` — v0.4 schema upgrade, deterministic receipt/evidence vectors, one-charge law, Check outbox recovery, least-privilege source assertions, and placeholder rejection.
- `scripts/silicon_gate.py` — hardware lock/affinity invariants.
- `scripts/rust_gate.sh` — authoritative Rust format/check/Clippy/test/release-build gate. It refuses to report PASS without a reviewed `Cargo.lock` and a clean source tree.
- `scripts/termux_rust_gate.sh` — phone-native toolchain/bootstrap path for the same authoritative Rust gate.

`STATUS.md` records executed evidence without inferring compiler success from static analysis.
