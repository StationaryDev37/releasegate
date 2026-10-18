-- A paid Checkout Session is one durable prepaid release verification, not a subscription.
-- Decisions already signed by ReleaseGate are immutable regardless of later refunds.
CREATE TABLE stripe_one_time_credits (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) >= 10 AND length(session_id) <= 256),
    payment_intent TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL,
    installation_id INTEGER NOT NULL REFERENCES installations(installation_id),
    state TEXT NOT NULL CHECK (state IN ('paid','revoked')),
    created_at TEXT NOT NULL,
    consumed_evaluation_id TEXT UNIQUE REFERENCES evaluation_contexts(evaluation_id),
    consumed_at TEXT
);
CREATE INDEX stripe_paid_install_idx ON stripe_one_time_credits(installation_id,state,consumed_evaluation_id);
