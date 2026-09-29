# ReleaseGate

ReleaseGate is a fail-closed verification and entitlement service designed to sit inside GitHub release workflows.

**Commercial loop:** INSTALL → ENTITLE → VERIFY → RECEIPT → METER → REPEAT.

## Implemented slices

### v0.1 — ingress / entitlement / receipt / meter

- GitHub App and Marketplace webhook HMAC verification.
- installation + subscription persistence.
- deterministic evidence/receipt commitments.
- idempotent usage ledger.
- SQLite WAL persistence.

### v0.2 — provenance gate

- GitHub App RS256 JWT minting.
- repository-scoped installation-token exchange/cache.
- bounded artifact-attestation retrieval with raw transport evidence.
- fail-closed supported GitHub/Sigstore provenance verification.

### v0.3 — policy gate

- immutable, content-addressed release-policy versions.
- active policy pointer per installation/repository.
- authenticated GitHub push source ledger.
- exact `(installation, repo, commit, ref)` source resolution.
- deterministic policy -> `ProvenanceExpectation` generation.

## Current security boundary

`VERIFIED` is reserved for evidence that completes the supported cryptographic provenance chain under an exact trusted identity expectation. v0.3 does not let a verification request invent repository/ref/commit or signer policy: source facts come from HMAC-authenticated GitHub push deliveries and signer requirements come from immutable organization policy. Unsupported or incomplete trust remains fail-closed.

## Build

```bash
cp .env.example .env
# export variables from .env using your preferred secret manager
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo run --release
```

## GitHub App webhook

Point the GitHub App webhook URL at:

`https://YOUR_HOST/webhooks/github/app`

Use `application/json`, configure a high-entropy App webhook secret, and subscribe to `installation` and `push`. Configure the Marketplace listing webhook separately at `https://YOUR_HOST/webhooks/github/marketplace` with its own high-entropy secret for `marketplace_purchase` events.

GitHub sends webhook signatures in `X-Hub-Signature-256`; ReleaseGate rejects deliveries that do not authenticate.

## Evidence request

```bash
curl -fsS http://127.0.0.1:8080/v1/verify \
  -H 'content-type: application/json' \
  -H "x-releasegate-token: $RELEASEGATE_INGEST_TOKEN" \
  -d '{
    "request_id": "build-20260929-0001",
    "installation_id": 12345,
    "repository": "acme/widget",
    "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "artifact_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "policy_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  }'
```

An active installation + active Marketplace subscription must already exist, otherwise verification fails closed.

## Revenue model

GitHub Marketplace can supply free, flat-rate, and per-unit plans. ReleaseGate stores plan state from Marketplace events and uses the usage ledger for internal quota enforcement/analytics. Payment-card handling stays outside ReleaseGate. Paid Marketplace plans require an eligible verified publisher organization and financial onboarding, so live paid billing remains an external release gate.

## Current closure status

See `STATUS.md` for the evidence table. Rust format/compile/Clippy/tests remain **UNEXECUTED** in the authoring runtime because no Rust toolchain is installed. Live GitHub integration remains blocked on real App credentials, installation, deployed HTTPS ingress, and a real attested artifact.

See `docs/ARCHITECTURE.md`, `docs/V0_3_POLICY_GATE.md`, `docs/PRODUCT.md`, and `docs/NEXT_GATE.md`.
