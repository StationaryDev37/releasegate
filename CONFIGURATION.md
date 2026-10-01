# ReleaseGate bedrock configuration

ReleaseGate intentionally ships no example secrets and no default authority credentials.

Required runtime inputs:

- `RELEASEGATE_GITHUB_APP_ID` — numeric GitHub App identity used as the JWT issuer.
- `RELEASEGATE_GITHUB_APP_PRIVATE_KEY_PEM` — RSA private key used only for short-lived GitHub App JWTs.
- `RELEASEGATE_GITHUB_APP_WEBHOOK_SECRET` — HMAC secret used only by GitHub App webhook ingress.
- `RELEASEGATE_GITHUB_MARKETPLACE_WEBHOOK_SECRET` — separate HMAC secret used only by Marketplace ingress.
- `RELEASEGATE_CONTROL_TOKEN` — authority to create/activate immutable release policy versions.
- `RELEASEGATE_EVALUATOR_TOKEN` — authority to freeze evaluation contexts.
- `RELEASEGATE_AUDITOR_TOKEN` — read-only authority for frozen evaluation evidence.
- `RELEASEGATE_GITHUB_BUNDLE_HOST` — exact DNS hostname accepted for attestation bundle egress.

Optional operational inputs:

- `RELEASEGATE_BIND` — defaults to `127.0.0.1:8080`.
- `RELEASEGATE_DATABASE_URL` — defaults to `sqlite://releasegate.db?mode=rwc`.
- `RELEASEGATE_DELIVERY_LEASE_SECONDS` — defaults to 120; accepted range 30..900.
- `RELEASEGATE_LOG` — tracing filter.

Every secret-bearing value is stored in a redacted `Secret` type. No configuration structure derives `Debug`.
