PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    source TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY(source, delivery_id)
);

CREATE TABLE IF NOT EXISTS installations (
    installation_id INTEGER PRIMARY KEY,
    github_account_id INTEGER NOT NULL,
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_installations_account ON installations(github_account_id);

CREATE TABLE IF NOT EXISTS subscriptions (
    github_account_id INTEGER PRIMARY KEY,
    account_login TEXT NOT NULL,
    plan_id INTEGER,
    plan_name TEXT,
    billing_cycle TEXT,
    unit_count INTEGER,
    status TEXT NOT NULL CHECK(status IN ('active','cancelled','pending','unknown')),
    effective_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_receipts (
    receipt_id TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    repository TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    evidence_commitment TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(outcome IN ('VERIFIED','REJECTED','INDETERMINATE')),
    reason_code TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE(installation_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_receipts_installation_created ON verification_receipts(installation_id, created_at);

CREATE TABLE IF NOT EXISTS usage_events (
    usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id INTEGER NOT NULL,
    metric TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK(quantity > 0),
    source_key TEXT NOT NULL,
    repository TEXT,
    occurred_at TEXT NOT NULL,
    UNIQUE(installation_id, metric, source_key)
);
CREATE INDEX IF NOT EXISTS idx_usage_installation_time ON usage_events(installation_id, occurred_at);
