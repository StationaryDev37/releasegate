CREATE TABLE IF NOT EXISTS evaluation_contexts (
    evaluation_id TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL CHECK(installation_id > 0),
    repository_id INTEGER NOT NULL CHECK(repository_id > 0),
    repository TEXT NOT NULL,
    source_delivery_id TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    source_commit_sha TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    trust_snapshot_sha256 TEXT NOT NULL,
    verifier_build_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(installation_id, repository_id, source_delivery_id, policy_sha256, artifact_sha256,
           trust_snapshot_sha256, verifier_build_sha256),
    FOREIGN KEY(source_delivery_id) REFERENCES trusted_source_events(delivery_id) ON DELETE RESTRICT,
    FOREIGN KEY(policy_sha256, installation_id, repository_id)
      REFERENCES release_policy_versions(policy_sha256, installation_id, repository_id)
      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_evaluation_repo_created
ON evaluation_contexts(installation_id, repository_id, created_at);
