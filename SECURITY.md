# ReleaseGate v0.4 security boundary

ReleaseGate is fail-closed. Unsupported evidence, ambiguous identity, unavailable trust, failed cryptographic verification, or unresolved policy cannot become a release authorization.

## Authority separation

- GitHub App webhook HMAC secret — GitHub App ingress authentication only.
- Marketplace webhook HMAC secret — entitlement ingress only.
- Control token — immutable policy creation/activation only.
- Evaluator token — release evaluation execution only.
- Auditor token — completed evaluation evidence reads only.
- GitHub App RSA key — short-lived GitHub App JWT signing only.
- Receipt RSA key — ReleaseGate decision-receipt signing only; never reused for GitHub authentication.

All secret-bearing configuration uses the custom redacted `Secret` type. `Config` does not implement `Debug`.

## Durable webhook ingress

A webhook body is HMAC-authenticated before parsing. The exact authenticated bytes, digest, event identity, and validated signature header are persisted before event side effects.

Processing follows the ReleaseGate lease law:

`received -> leased -> applied | rejected`

Retryable failures return to `received` with bounded exponential backoff. Immediate redelivery cannot bypass backoff. Expired leases are reclaimable. Recovery recomputes the persisted body SHA-256 and re-verifies the stored GitHub HMAC under the current ingress secret before parsing or dispatch. Corrupt/no-longer-authentic evidence becomes terminal `rejected` with `durable_authentication_failed`.

A delivery ID cannot be rebound to another event type or authenticated payload digest. Recovery has a finite attempt budget; exhausted work becomes terminal rather than looping indefinitely.

## Frozen evaluation boundary

`EvaluationContext v2` binds:

- installation and numeric repository identity,
- authenticated source delivery/ref/commit,
- immutable policy SHA-256,
- artifact SHA-256,
- exact trust-snapshot SHA-256,
- SHA-256 of the executing ReleaseGate binary,
- canonical receipt public-key SHA-256.

Database foreign keys bind source and policy facts to the same repository identity. Policy or receipt-key rotation cannot reinterpret a previously frozen evaluation.

## Provenance truth

The supported verification path is GitHub `actions/attest-build-provenance` / SLSA provenance v1 under exactly pinned `attestation-verify = "=0.1.0"`. Rekor v1 trust is selected by exact log-id/SPKI SHA-256 identity, never trust-store vector position.

Bundle retrieval accepts only the operator-configured exact HTTPS hostname, forbids credentials/redirects/private or reserved DNS addresses, and pins the validated address into the TLS client.

Attestation installation tokens request only `attestations:read`.

## Decision / receipt boundary

`EvidenceTruth`, `PolicyAuthorization`, and `ReleaseDecision` are distinct types. Only `VERIFIED + ALLOW` maps to `RELEASE`.

The custom `DecisionCommitment v1` is domain-separated and deterministically commits frozen evaluation facts, truth, authorization, release result, stable reasons, and the order-independent attestation-set commitment. Receipt identity is derived from this decision commitment; issuance time is not allowed to change the underlying decision identity.

Receipts are RS256-signed with a dedicated ReleaseGate keypair. Startup signs and verifies a probe so mismatched configured keys fail before service readiness. `/v1/receipt-key` exposes public verification material only.

## Atomic commercial finalization

One SQLite transaction commits:

- the final release evaluation,
- per-bundle verification outcomes,
- exactly one usage event keyed to the evaluation,
- one GitHub Check outbox projection.

If the transaction does not commit, none of those effects exist. This prevents “billed but no decision” and “decision but no projection intent” split states.

## GitHub Check boundary

Check publication is a projection of already-established truth; GitHub availability cannot rewrite release truth. Check tokens request only `checks:write`.

The outbox uses ownership-bound leases, bounded retry/backoff and terminal dead-letter state. Before creating a Check Run after an ambiguous failure, ReleaseGate queries the exact commit/check name and reuses an existing run whose `external_id` equals the evaluation ID. This prevents duplicate Check Runs from changing the protocol identity.

## Release predicate

Production release is forbidden until `scripts/rust_gate.sh` reports `RUST_GATE_PASS`, the generated `Cargo.lock` has been reviewed and committed, and live GitHub webhook/attestation/Check/receipt vectors pass. Static evidence alone is never promoted into production-release status.
