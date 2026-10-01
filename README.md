# ReleaseGate — silicon-locked bedrock

ReleaseGate is a fail-closed release-decision kernel for GitHub artifacts. Its job is narrow: bind authenticated source facts to immutable policy, retrieve supported GitHub provenance, establish cryptographic truth, and compose that truth with authorization without conflating the two.

## Bedrock invariants

1. **Truth is not authorization.** `EvidenceTruth`, `PolicyAuthorization`, and `ReleaseDecision` are separate state machines. Only `VERIFIED + ALLOW` can produce `RELEASE`.
2. **Webhook evidence is durable before side effects.** After HMAC authentication, the exact payload, digest, event identity, and validated signature header are persisted in a recoverable inbox. Recovery re-hashes and re-verifies HMAC before dispatch; expired leases are reclaimed internally, retryable failures use bounded exponential backoff, and the retry budget is finite.
3. **Replay is identity-bound.** `(ingress source, delivery id)` may never be rebound to different authenticated bytes or a different event type.
4. **Policy is immutable.** Policy content is deterministically hashed; activation changes only a pointer.
5. **Evaluation facts freeze.** Source delivery, repository/ref/commit, policy hash, artifact digest, trust snapshot, and executing binary hash are committed into a deterministic evaluation identity before provenance execution.
6. **Trust is selected by identity, never list position.** The supported Rekor v1 log is matched by the exact SHA-256 identity shared by its `logId` and SPKI.
7. **Bundle egress is pinned.** Bundle URLs must use the configured exact hostname, HTTPS, no credentials, no redirect, and a DNS result containing only public addresses; the validated address is pinned into the request client.
8. **Authority is split.** Webhook secrets, control authority, evaluator authority, and auditor authority are distinct secrets with redacted debug behavior.
9. **Silicon is constrained, never trusted for truth.** A content-addressed host lock binds NIC/CPU topology to IRQ/runtime placement. Runtime startup re-attests the exact lock bytes and actual process CPU affinity. Hardware placement is operational evidence only and cannot alter evaluation identity.
10. **No optimistic release.** Missing/unsupported/uncertain evidence is `INDETERMINATE`; it cannot release.

## Runtime surface

- `POST /webhooks/github/app` — authenticated installation/push ingress.
- `POST /webhooks/github/marketplace` — separately authenticated subscription ingress.
- `POST /v1/policies/active` — control authority; stores and activates immutable policy.
- `POST /v1/evaluations` — evaluator authority; freezes context, retrieves supported provenance, verifies it, and composes the release decision.
- `GET /v1/evaluations/:id` — auditor authority; reads frozen evaluation facts.
- `GET /healthz`, `GET /readyz` — process/database liveness only.

No dashboard, generic CRUD surface, placeholder verification endpoint, or example secret file is shipped.

## Verification gates

`scripts/static_gate.py` is an independent non-Rust gate for migrations, canonical vectors, state laws, replay/recovery semantics, trust identity, and source invariants. `scripts/silicon_gate.py` separately proves lock generation, host validation, tamper rejection, and deterministic placement.

`scripts/rust_gate.sh` is the executable Rust release gate. It refuses to claim PASS without Rust/Cargo/rustfmt/Clippy and a reviewed `Cargo.lock`.

See `STATUS.md` for executed evidence. Configuration is defined in `CONFIGURATION.md`; no secret values are supplied by the repository.
