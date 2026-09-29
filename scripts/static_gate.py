#!/usr/bin/env python3
"""Non-Rust preflight checks. This does NOT replace cargo fmt/clippy/test."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest_join(parts: list[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        b = part.encode()
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)
    return h.hexdigest()


def policy_hash(spec: dict[str, object]) -> str:
    parts = [
        "1",
        str(spec["installation_id"]),
        str(spec["repository_id"]),
        str(spec["repository"]),
        str(spec["ref_rule"]),
        str(spec["ref_value"]),
        str(spec["signer_repository"]),
        str(spec["signer_workflow_path"]),
        str(spec["signer_revision_sha"]).lower(),
    ]
    return digest_join(parts)


def main() -> None:
    tomllib.loads((ROOT / "Cargo.toml").read_text())
    for path in sorted((ROOT / "fixtures" / "github").glob("*.json")):
        json.loads(path.read_text())
    policy_fixture = json.loads((ROOT / "fixtures" / "policy" / "release-policy.json").read_text())
    push_fixture = json.loads((ROOT / "fixtures" / "github" / "push-source.json").read_text())

    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys = ON")
    for migration in sorted((ROOT / "migrations").glob("*.sql")):
        con.executescript(migration.read_text())
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {
        "webhook_deliveries",
        "installations",
        "subscriptions",
        "verification_receipts",
        "usage_events",
        "attestation_bundles",
        "release_policy_versions",
        "active_release_policies",
        "trusted_source_events",
    }
    assert required <= tables, (required - tables)

    secret = b"It's a Secret to Everybody"
    payload = b"Hello, World!"
    expected = "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    assert hmac.new(secret, payload, hashlib.sha256).hexdigest() == expected

    request_id = "job-123"
    installation_id = 42
    repo = "acme/widget"
    commit = "a" * 40
    artifact = "b" * 64
    manifest = "c" * 64
    policy = "d" * 64
    evidence = digest_join([repo, commit, artifact, manifest, policy])
    identity = digest_join([str(installation_id), request_id])
    receipt_id = "rg_" + identity[:24]
    receipt_sha = digest_join([
        receipt_id,
        str(installation_id),
        request_id,
        repo,
        commit,
        artifact,
        manifest,
        policy,
        evidence,
        "INDETERMINATE",
        "EVIDENCE_COMMITTED_NOT_INDEPENDENTLY_VERIFIED",
        "2026-09-29T20:00:00Z",
    ])
    assert receipt_id == "rg_0adf57dc816e6f82a95057ca"
    assert evidence == "da35d57fa5e32595f427895268b5d8565225ec4524e08392838287a6d4e74272"
    assert receipt_sha == "605d67c26e1353b5573bcbdf7d7fd27198bcca5c261d758dbbeef5fd8db2bac3"

    # Independent v0.3 policy commitment and persistence checks.
    p_hash = policy_hash(policy_fixture)
    assert p_hash == "5962169627530d699a347e46b229c57988ed91ce778d1effaf6ffb189ff7e202"
    con.execute(
        """INSERT INTO release_policy_versions(
           policy_sha256,installation_id,repository_id,repository,ref_rule,ref_value,
           signer_repository,signer_workflow_path,signer_revision_sha,created_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            p_hash,
            policy_fixture["installation_id"],
            policy_fixture["repository_id"],
            policy_fixture["repository"],
            policy_fixture["ref_rule"],
            policy_fixture["ref_value"],
            policy_fixture["signer_repository"],
            policy_fixture["signer_workflow_path"],
            policy_fixture["signer_revision_sha"],
            "2026-09-29T22:00:00Z",
        ),
    )
    con.execute(
        "INSERT INTO active_release_policies VALUES(?,?,?,?)",
        (42, 99, p_hash, "2026-09-29T22:00:01Z"),
    )
    con.execute(
        """INSERT INTO trusted_source_events(
           delivery_id,installation_id,repository_id,repository,source_ref,source_commit_sha,observed_at
           ) VALUES(?,?,?,?,?,?,?)""",
        (
            "delivery-1",
            push_fixture["installation"]["id"],
            push_fixture["repository"]["id"],
            push_fixture["repository"]["full_name"],
            push_fixture["ref"],
            push_fixture["after"],
            "2026-09-29T22:00:02Z",
        ),
    )
    row = con.execute(
        """SELECT p.ref_rule,p.ref_value,p.signer_repository,p.signer_workflow_path,p.signer_revision_sha,
                  s.repository,s.source_ref,s.source_commit_sha
           FROM active_release_policies a
           JOIN release_policy_versions p ON p.policy_sha256=a.policy_sha256
           JOIN trusted_source_events s ON s.installation_id=a.installation_id
             AND s.repository_id=a.repository_id
           WHERE a.installation_id=42 AND a.repository_id=99
             AND s.source_commit_sha=? AND s.source_ref=?""",
        (push_fixture["after"], push_fixture["ref"]),
    ).fetchone()
    assert row is not None
    ref_rule, ref_value, signer_repo, workflow_path, signer_sha, source_repo, source_ref, source_sha = row
    assert ref_rule == "prefix" and source_ref.startswith(ref_value)
    assert source_repo == "acme/widget"
    assert source_sha == "b" * 40
    assert signer_repo == "acme/release-workflows"
    assert workflow_path == ".github/workflows/release.yml"
    assert signer_sha == "a" * 40

    # DB-level policy scoping must reject cross-repository activation.
    try:
        con.execute(
            "INSERT INTO active_release_policies VALUES(?,?,?,?)",
            (42, 100, p_hash, "2026-09-29T22:00:03Z"),
        )
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("cross-repository policy activation was accepted")

    print("STATIC_GATE_PASS")


if __name__ == "__main__":
    main()
