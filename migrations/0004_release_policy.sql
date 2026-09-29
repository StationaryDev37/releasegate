CREATE TABLE IF NOT EXISTS release_policy_versions (
    policy_sha256 TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL CHECK(installation_id > 0),
    repository_id INTEGER NOT NULL CHECK(repository_id > 0),
    repository TEXT NOT NULL,
    ref_rule TEXT NOT NULL CHECK(ref_rule IN ('exact','prefix')),
    ref_value TEXT NOT NULL,
    signer_repository TEXT NOT NULL,
    signer_workflow_path TEXT NOT NULL,
    signer_revision_sha TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(policy_sha256, installation_id, repository_id),
    FOREIGN KEY(installation_id) REFERENCES installations(installation_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_release_policy_repo
ON release_policy_versions(installation_id, repository_id, created_at);

CREATE TABLE IF NOT EXISTS active_release_policies (
    installation_id INTEGER NOT NULL CHECK(installation_id > 0),
    repository_id INTEGER NOT NULL CHECK(repository_id > 0),
    policy_sha256 TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    PRIMARY KEY(installation_id, repository_id),
    FOREIGN KEY(policy_sha256, installation_id, repository_id)
        REFERENCES release_policy_versions(policy_sha256, installation_id, repository_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS trusted_source_events (
    delivery_id TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL CHECK(installation_id > 0),
    repository_id INTEGER NOT NULL CHECK(repository_id > 0),
    repository TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    source_commit_sha TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES installations(installation_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_trusted_source_lookup
ON trusted_source_events(installation_id, repository_id, source_commit_sha, observed_at);
