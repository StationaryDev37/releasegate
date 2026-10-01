CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_source_identity
ON trusted_source_events(delivery_id,installation_id,repository_id,repository,source_ref,source_commit_sha);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_repository_identity
ON release_policy_versions(policy_sha256,installation_id,repository_id,repository);

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
    FOREIGN KEY(source_delivery_id, installation_id, repository_id, repository, source_ref, source_commit_sha)
      REFERENCES trusted_source_events(delivery_id, installation_id, repository_id, repository, source_ref, source_commit_sha)
      ON DELETE RESTRICT,
    FOREIGN KEY(policy_sha256, installation_id, repository_id, repository)
      REFERENCES release_policy_versions(policy_sha256, installation_id, repository_id, repository)
      ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_evaluation_repo_created
ON evaluation_contexts(installation_id, repository_id, created_at);
