# ReleaseGate

ReleaseGate is a fail-closed verification and entitlement service designed to sit inside GitHub release workflows.

**Commercial loop:** INSTALL → ENTITLE → VERIFY → RECEIPT → METER → REPEAT.

## v0.1 implemented slice

- GitHub webhook endpoint with raw-body HMAC-SHA256 verification.
- Delivery-id idempotency ledger.
- GitHub App installation lifecycle persistence.
- GitHub Marketplace `marketplace_purchase` entitlement state.
- Authenticated evidence verification API.
- Deterministic evidence commitment and receipt digest.
- Idempotent usage meter.
- SQLite WAL persistence and migrations.
- Health/readiness endpoints.
- Strict 1 MiB request-body limit.
- JSON structured logs.

## Security boundary

v0.1 returns **`INDETERMINATE`** after structurally validating and deterministically committing the submitted evidence tuple. It deliberately does **not** return `VERIFIED` until ReleaseGate independently retrieves and verifies build evidence. The next gate is GitHub App installation-token authentication + artifact retrieval + provenance/SBOM verification. This distinction is intentional; status is not inflated.

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

Use `application/json`, configure a high-entropy App webhook secret, and subscribe to `installation`. Configure the Marketplace listing webhook separately at `https://YOUR_HOST/webhooks/github/marketplace` with its own high-entropy secret for `marketplace_purchase` events.

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

| Gate | Status |
|---|---|
| Source implementation | IMPLEMENTED |
| Static fixture validation | IMPLEMENTED |
| Rust format | UNEXECUTED in authoring runtime |
| Compile | UNEXECUTED in authoring runtime |
| Clippy | UNEXECUTED in authoring runtime |
| Rust tests | UNEXECUTED in authoring runtime |
| GitHub App live delivery | BLOCKED on external App registration/secret |
| GitHub Marketplace paid billing | BLOCKED on publisher/listing approval |
| Release | BLOCKED until compile/test gates pass |

See `docs/ARCHITECTURE.md`, `docs/PRODUCT.md`, and `docs/NEXT_GATE.md`.
