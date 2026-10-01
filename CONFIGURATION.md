# ReleaseGate v0.4 configuration

ReleaseGate ships no example credentials and no fallback authority values. Missing security-critical inputs fail startup.

## GitHub authority

- `RELEASEGATE_GITHUB_APP_ID` — numeric GitHub App ID used as JWT issuer.
- `RELEASEGATE_GITHUB_APP_PRIVATE_KEY_PEM` — RSA private key used only for GitHub App JWTs.
- `RELEASEGATE_GITHUB_APP_WEBHOOK_SECRET` — HMAC secret used only for GitHub App webhook ingress.
- `RELEASEGATE_GITHUB_MARKETPLACE_WEBHOOK_SECRET` — independent HMAC secret used only for Marketplace entitlement ingress.
- `RELEASEGATE_GITHUB_BUNDLE_HOST` — exact allowed attestation-bundle hostname. Retrieval requires HTTPS, no credentials, no redirects, public DNS addresses only, and pins the validated addresses.

GitHub installation tokens are minted per repository and per operation. Attestation retrieval requests only `attestations:read`. Check projection requests only `checks:write`.

## ReleaseGate authority

- `RELEASEGATE_CONTROL_TOKEN` — create/activate immutable policy versions.
- `RELEASEGATE_EVALUATOR_TOKEN` — freeze/execute release evaluations.
- `RELEASEGATE_AUDITOR_TOKEN` — read completed evaluation evidence.

These authorities are intentionally not interchangeable.

## Receipt authority

- `RELEASEGATE_RECEIPT_PRIVATE_KEY_PEM` — RSA private key used only to sign ReleaseGate decision receipts.
- `RELEASEGATE_RECEIPT_PUBLIC_KEY_PEM` — matching public key returned by `/v1/receipt-key` for independent verification.
- `RELEASEGATE_RECEIPT_KEY_ID` — operator-assigned stable key identifier; validated for bounded ASCII identity syntax.

Startup signs and verifies an internal key probe. A mismatched receipt keypair fails startup. The evaluation context binds the canonical public-key SHA-256, so key rotation cannot silently reuse an old evaluation identity.

## Persistence / leases

- `RELEASEGATE_DATABASE_URL` — defaults to `sqlite://releasegate.db?mode=rwc`.
- `RELEASEGATE_DELIVERY_LEASE_SECONDS` — webhook lease duration; default `120`, accepted `30..900`.
- `RELEASEGATE_CHECK_LEASE_SECONDS` — GitHub Check outbox lease duration; default `120`, accepted `30..900`.

Webhook recovery and Check projection both use ownership-bound leases with bounded retries. A durable final release decision is never rewritten because a Check delivery failed.

## Runtime / silicon

- `RELEASEGATE_BIND` — defaults to `127.0.0.1:8080`.
- `RELEASEGATE_LOG` — tracing filter.
- `RELEASEGATE_SILICON_LOCK_PATH`
- `RELEASEGATE_SILICON_LOCK_SHA256`
- `RELEASEGATE_SILICON_FINGERPRINT`
- `RELEASEGATE_RUNTIME_CPUSET`
- `TOKIO_WORKER_THREADS`

Silicon settings are operational constraints, not release evidence. `scripts/silicon_ctl.py exec` is the intended injector because it also applies process affinity and verifies the host lock.

Secret-bearing configuration is wrapped in ReleaseGate's redacted `Secret` type. The configuration object itself does not derive `Debug`.
