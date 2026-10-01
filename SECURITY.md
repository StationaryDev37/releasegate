# ReleaseGate security boundary

ReleaseGate is fail-closed. Unsupported evidence, ambiguous identity, unavailable trust, or failed cryptographic verification never becomes a release authorization.

## Authority separation

- GitHub App webhook HMAC secret: GitHub App ingress authentication only.
- Marketplace webhook HMAC secret: Marketplace ingress authentication only.
- Control token: immutable policy creation/activation only.
- Evaluator token: evaluation execution only.
- Auditor token: frozen evaluation reads only.
- GitHub App RSA key: short-lived GitHub App JWT signing only.

All secret-bearing configuration uses the custom redacted `Secret` type. `Config` does not implement `Debug`.

## Durable ingress

A webhook body is HMAC-authenticated before parsing. The exact authenticated bytes, digest, event identity, and validated signature header are persisted before event side effects.

Processing is governed by a ReleaseGate-specific lease state machine:

`received -> leased -> applied | rejected`

Retryable failures return to `received` with bounded exponential backoff. Immediate redelivery cannot bypass the backoff. Expired leases are reclaimable. Recovery recomputes the persisted payload SHA-256 and re-verifies the stored GitHub HMAC under the current ingress secret before parsing or dispatching the body. Corrupt or no-longer-authentic durable evidence becomes terminal `rejected` with `durable_authentication_failed`.

A delivery id already associated with a different event type or payload digest is a hard conflict. Recovery is bounded to 12 processing attempts; an exhausted record becomes terminal `rejected` with `retry_budget_exhausted` instead of looping forever.

## Evaluation boundary

A frozen evaluation context binds:

- installation and numeric repository identity,
- authenticated source delivery/ref/commit,
- immutable policy hash,
- artifact SHA-256,
- exact trust-snapshot SHA-256,
- SHA-256 of the executing ReleaseGate binary.

Database foreign keys bind source facts and policy facts to the same repository identity. Policy rotation cannot reinterpret an already frozen context.

## Provenance boundary

The current supported path is GitHub `actions/attest-build-provenance` / SLSA provenance v1 under the exact `attestation-verify = "=0.1.0"` verifier dependency. The supported Rekor v1 public log is selected by exact log-id/SPKI SHA-256 identity; trust-store vector position is irrelevant.

Bundle fetches accept only the operator-configured exact HTTPS hostname, reject credentials and non-443 explicit ports, reject redirects, reject private/link-local/documentation/multicast/reserved DNS results, and pin the validated public address into the TLS request client.

## Release predicate

A production release is forbidden until `scripts/rust_gate.sh` reports `RUST_GATE_PASS`, `Cargo.lock` is reviewed and committed, and live GitHub integration vectors pass. Static evidence alone is not a production release claim.
