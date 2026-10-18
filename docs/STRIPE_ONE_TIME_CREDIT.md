# ReleaseGate — one-time purchase gate candidate

Status: **SOURCE CANDIDATE, NOT RELEASED OR SELLABLE**. This patch carries the existing cryptographic verification core unchanged. No new infrastructure. The existing historical `HOLD` remains immutable.

Stripe live product `prod_VSoCZ9WVPoaaKe` and one-time price `price_1URsZxRXXpFV7W9nbuqMuGkV` ($29) remain **inactive**. Do not activate until CI, customer onboarding, webhook deployment, checkout configuration, and live end-to-end fulfillment prove that a buyer receives one receipt.

This branch introduces isolated webhook authenticity checks, a signed GitHub-installation binding in a Payment Link `client_reference_id`, a durable one-purchase/one-use ledger, refund/dispute revocation of unused credits, paid-policy setup for repositories observed through authenticated GitHub events, and atomic credit consumption in the same transaction as signed receipt finalization.

It does not claim the live customer experience is complete. Before launch, the system requires a confirmed GitHub App installation workflow, verified Stripe webhook endpoint and signing secret configured on Railway, an activated one-time Stripe Payment Link with no discounts/tax surprises, a buyer-facing policy-and-evaluation form, a Checkout success return URL `https://releasegate-production.up.railway.app/receipt#session_id={CHECKOUT_SESSION_ID}` (Stripe substitution must be verified) and production webhook delivery, and real production end-to-end receipt delivery. Source compilation and independent review are mandatory.

## Technical constraints

- Only Stripe `checkout.session.completed` or `checkout.session.async_payment_succeeded` with `payment_status=paid` can grant a credit; delayed/unpaid sessions cannot.
- The event must carry a valid Stripe HMAC, a timestamp within 300 seconds, the expected Payment Link identity, amount exactly 2900 cents, live mode, and a claim HMAC binding the credited installation ID.
- Each paid Checkout Session and PaymentIntent grants at most one credit; signature replay and concurrent evaluation consumption are fail-closed.
- Checkout Session ID is treated as a bearer capability. Never put one in logs, referral headers, public URLs outside Stripe's explicit return mechanism, or analytics events.
- Authenticated GitHub installation and trusted source events remain prerequisites. A payment never proves code provenance or grants a `RELEASE` verdict.
- Stripe webhook secrets, claim signing key and Payment Link settings are all-or-nothing optional configuration; no Stripe checkout routes activate without all four.
- If a refund occurs after a receipt was issued, historical cryptographic evidence stays immutable. Unused credits can be revoked.

## Deployment gate

Do not deploy this patch to production until the new branch passes full Rust compilation, Clippy and unit tests and the existing 205+ verifier regressions. Independently review the access and refund cases. Keep merchant checkout inactive until one real paid end-to-end receipt is delivered automatically, without intervention.
