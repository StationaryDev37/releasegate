CREATE TABLE IF NOT EXISTS attestation_bundles (
    bundle_sha256 TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    repository TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    source_url_sha256 TEXT NOT NULL,
    raw_json BLOB NOT NULL,
    fetched_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attestation_lookup
ON attestation_bundles(installation_id, repository_id, artifact_sha256, fetched_at);
