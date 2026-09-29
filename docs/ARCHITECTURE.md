# Architecture

## Trust boundaries

1. **GitHub → webhook ingress: GitHub App and Marketplace use isolated endpoints/secrets**: authenticate the exact raw request bytes using HMAC-SHA256 and the configured webhook secret.
2. **Delivery ledger**: claim `(ingress source, X-GitHub-Delivery)` before side effects. Retries/duplicates are acknowledged without replaying billing or installation state.
3. **Entitlement**: installation identity is mapped to the GitHub account; subscription state is mapped to the same GitHub account. Verification fails closed unless both are active.
4. **Evidence ingress**: separately authenticated by a high-entropy service token in v0.1. Per-installation tokens/OIDC replace this global token at the next gate.
5. **Receipt**: a length-prefixed SHA-256 commitment avoids ambiguous concatenation and JSON map-order dependence.
6. **Meter**: `(installation_id, metric, source_key)` uniqueness makes usage recording idempotent.

## Data flow

```text
GitHub App + Marketplace
        |
        | isolated HMAC-authenticated ingress
        v
/webhooks/github/{app,marketplace} ---> webhook_deliveries
        |                 |
        +--> installations |
        +--> subscriptions |
                          v
CI evidence ---> /v1/verify ---> entitlement join
                                  |
                                  v
                          verification_receipts
                                  |
                                  v
                             usage_events
```

## Fail-closed rules

- Missing/invalid signature: reject.
- Missing delivery/event headers: reject.
- Duplicate delivery: acknowledge, no repeated side effects.
- Unknown/unentitled installation: reject evidence.
- Malformed repository/commit/digests: reject.
- Database failure: 500, do not fabricate success.

## Explicit v0.1 non-goals

- No custody or movement of customer funds.
- No card/payment processing.
- No claim of reproducible-build verification yet.
- No silent GitHub repository mutation.
- No dynamic code execution from webhook payloads.
