ALTER TABLE evaluation_contexts RENAME TO evaluation_contexts_v1;

CREATE TABLE evaluation_contexts (
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
    receipt_key_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(installation_id, repository_id, source_delivery_id, policy_sha256, artifact_sha256,
           trust_snapshot_sha256, verifier_build_sha256, receipt_key_sha256),
    FOREIGN KEY(source_delivery_id, installation_id, repository_id, repository, source_ref, source_commit_sha)
      REFERENCES trusted_source_events(delivery_id, installation_id, repository_id, repository, source_ref, source_commit_sha)
      ON DELETE RESTRICT,
    FOREIGN KEY(policy_sha256, installation_id, repository_id, repository)
      REFERENCES release_policy_versions(policy_sha256, installation_id, repository_id, repository)
      ON DELETE RESTRICT
);

INSERT INTO evaluation_contexts(
    evaluation_id,installation_id,repository_id,repository,source_delivery_id,source_ref,
    source_commit_sha,policy_sha256,artifact_sha256,trust_snapshot_sha256,
    verifier_build_sha256,receipt_key_sha256,created_at
)
SELECT evaluation_id,installation_id,repository_id,repository,source_delivery_id,source_ref,
       source_commit_sha,policy_sha256,artifact_sha256,trust_snapshot_sha256,
       verifier_build_sha256,'legacy-unbound',created_at
FROM evaluation_contexts_v1;

DROP TABLE evaluation_contexts_v1;

CREATE INDEX idx_evaluation_repo_created
ON evaluation_contexts(installation_id, repository_id, created_at);

DROP TABLE IF EXISTS verification_receipts;

CREATE TABLE release_evaluations (
    evaluation_id TEXT PRIMARY KEY,
    evidence_truth TEXT NOT NULL CHECK(evidence_truth IN ('VERIFIED','INVALID','INDETERMINATE')),
    policy_authorization TEXT NOT NULL CHECK(policy_authorization IN ('ALLOW','DENY','INDETERMINATE')),
    release_decision TEXT NOT NULL CHECK(release_decision IN ('RELEASE','BLOCK','HOLD')),
    policy_reason TEXT NOT NULL,
    provenance_reason TEXT NOT NULL,
    attestation_set_sha256 TEXT NOT NULL,
    decision_commitment TEXT NOT NULL UNIQUE,
    receipt_id TEXT NOT NULL UNIQUE,
    receipt_key_id TEXT NOT NULL,
    receipt_key_sha256 TEXT NOT NULL,
    receipt_jws TEXT NOT NULL,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    completed_at TEXT NOT NULL,
    FOREIGN KEY(evaluation_id) REFERENCES evaluation_contexts(evaluation_id) ON DELETE RESTRICT
);

CREATE TABLE evaluation_attestation_outcomes (
    evaluation_id TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    evidence_truth TEXT NOT NULL CHECK(evidence_truth IN ('VERIFIED','INVALID','INDETERMINATE')),
    reason_code TEXT NOT NULL,
    PRIMARY KEY(evaluation_id, bundle_sha256),
    FOREIGN KEY(evaluation_id) REFERENCES release_evaluations(evaluation_id) ON DELETE RESTRICT,
    FOREIGN KEY(bundle_sha256) REFERENCES attestation_bundles(bundle_sha256) ON DELETE RESTRICT
);

CREATE TABLE github_check_outbox (
    evaluation_id TEXT PRIMARY KEY,
    installation_id INTEGER NOT NULL CHECK(installation_id > 0),
    repository_id INTEGER NOT NULL CHECK(repository_id > 0),
    repository TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    check_name TEXT NOT NULL,
    external_id TEXT NOT NULL UNIQUE,
    conclusion TEXT NOT NULL CHECK(conclusion IN ('success','failure','action_required')),
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','leased','sent','dead')),
    lease_token TEXT,
    lease_expires_unix INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    next_attempt_unix INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    check_run_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(evaluation_id) REFERENCES release_evaluations(evaluation_id) ON DELETE RESTRICT
);

CREATE INDEX idx_github_check_dispatch
ON github_check_outbox(state, next_attempt_unix, lease_expires_unix);
