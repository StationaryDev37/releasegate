ALTER TABLE webhook_deliveries
ADD COLUMN signature_header TEXT;

CREATE INDEX IF NOT EXISTS idx_webhook_terminal
ON webhook_deliveries(state, completed_at);
