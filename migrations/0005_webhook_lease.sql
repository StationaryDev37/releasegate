ALTER TABLE webhook_deliveries
ADD COLUMN state TEXT NOT NULL DEFAULT 'applied'
CHECK(state IN ('received','leased','applied','rejected'));

ALTER TABLE webhook_deliveries
ADD COLUMN lease_token TEXT;

ALTER TABLE webhook_deliveries
ADD COLUMN lease_expires_unix INTEGER;

ALTER TABLE webhook_deliveries
ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 1 CHECK(attempt_count >= 1);

ALTER TABLE webhook_deliveries
ADD COLUMN last_error_code TEXT;

ALTER TABLE webhook_deliveries
ADD COLUMN completed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_webhook_reclaim
ON webhook_deliveries(state, lease_expires_unix);
