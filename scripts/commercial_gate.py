#!/usr/bin/env python3
"""Independent v0.4 commercial-loop gate. Does not substitute for Rust compilation."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def push_text(out: bytearray, value: str) -> None:
    raw = value.encode()
    out.extend(len(raw).to_bytes(4, "big"))
    out.extend(raw)


def digest_join(parts: list[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        raw = part.encode()
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
    return h.hexdigest()


def evaluation_id(v: dict[str, object]) -> str:
    return "rge_" + digest_join([
        str(v["schema"]),
        str(v["installation_id"]),
        str(v["repository_id"]),
        str(v["repository"]),
        str(v["source_delivery_id"]),
        str(v["source_ref"]),
        str(v["source_commit_sha"]).lower(),
        str(v["policy_sha256"]).lower(),
        str(v["artifact_sha256"]).lower(),
        str(v["trust_snapshot_sha256"]).lower(),
        str(v["verifier_build_sha256"]).lower(),
        str(v["receipt_key_sha256"]).lower(),
    ])


def attestation_set_commitment(outcomes: list[dict[str, str]]) -> str:
    out = bytearray(b"ReleaseGate\x00AttestationSet\x00v1")
    ordered = sorted(outcomes, key=lambda item: item["bundle_sha256"])
    out.extend(len(ordered).to_bytes(4, "big"))
    for item in ordered:
        push_text(out, item["bundle_sha256"])
        push_text(out, item["truth"])
        push_text(out, item["reason"])
    return hashlib.sha256(out).hexdigest()


def decision_commitment(ev: dict[str, object], decision: dict[str, object]) -> str:
    out = bytearray(b"ReleaseGate\x00DecisionCommitment\x00v1")
    out.extend(int(ev["installation_id"]).to_bytes(8, "big", signed=True))
    out.extend(int(ev["repository_id"]).to_bytes(8, "big", signed=True))
    for value in [
        ev["evaluation_id"],
        ev["repository"],
        ev["source_delivery_id"],
        ev["source_ref"],
        ev["source_commit_sha"],
        ev["policy_sha256"],
        ev["artifact_sha256"],
        ev["trust_snapshot_sha256"],
        ev["verifier_build_sha256"],
        ev["receipt_key_sha256"],
        decision["evidence_truth"],
        decision["policy_authorization"],
        decision["release_decision"],
        decision["policy_reason"],
        decision["provenance_reason"],
        decision["attestation_set_sha256"],
    ]:
        push_text(out, str(value))
    return hashlib.sha256(out).hexdigest()


def apply_migrations(con: sqlite3.Connection, paths: list[Path]) -> None:
    con.execute("PRAGMA foreign_keys = ON")
    for path in paths:
        con.executescript(path.read_text())


def main() -> None:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    assert cargo["package"]["version"] == "0.5.0"
    assert cargo["dependencies"]["attestation-verify"] == "=0.1.0"
    assert cargo["dependencies"]["jsonwebtoken"]["version"] == "=11.1.0"

    migrations = sorted((ROOT / "migrations").glob("*.sql"))
    assert migrations[-1].name == "0008_commercial_loop.sql"

    # Prove upgrade from the locked v0.3.2 schema does not discard an existing frozen context.
    legacy = sqlite3.connect(":memory:")
    apply_migrations(legacy, migrations[:-1])
    legacy.execute(
        "INSERT INTO installations VALUES(?,?,?,?,?,?)",
        (42, 7001, "acme", "Organization", 1, "2026-09-30T00:00:00Z"),
    )
    policy_hash = "6bc707d83af54b493743d2f7ba4eb287302d8ce5cdfab99550421fb0880cefc1"
    legacy.execute(
        """INSERT INTO release_policy_versions VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (policy_hash,42,99,"acme/widget","prefix","refs/tags/v","acme/release-workflows",
         ".github/workflows/release.yml","a"*40,"2026-09-30T00:00:01Z"),
    )
    legacy.execute(
        """INSERT INTO trusted_source_events VALUES(?,?,?,?,?,?,?)""",
        ("delivery-legacy",42,99,"acme/widget","refs/tags/v1.2.3","b"*40,"2026-09-30T00:00:02Z"),
    )
    legacy.execute(
        """INSERT INTO evaluation_contexts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("rge_legacy",42,99,"acme/widget","delivery-legacy","refs/tags/v1.2.3","b"*40,
         policy_hash,"c"*64,"d"*64,"e"*64,"2026-09-30T00:00:03Z"),
    )
    legacy.executescript(migrations[-1].read_text())
    upgraded = legacy.execute(
        "SELECT receipt_key_sha256 FROM evaluation_contexts WHERE evaluation_id='rge_legacy'"
    ).fetchone()
    assert upgraded == ("legacy-unbound",)
    assert legacy.execute("PRAGMA foreign_key_check").fetchall() == []

    # New schema and custom canonical vectors.
    con = sqlite3.connect(":memory:")
    apply_migrations(con, migrations)
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "release_evaluations",
        "evaluation_attestation_outcomes",
        "github_check_outbox",
        "usage_events",
    } <= tables
    assert "verification_receipts" not in tables

    ev = json.loads((ROOT / "fixtures/adversarial/evaluation-context.json").read_text())
    dec = json.loads((ROOT / "fixtures/adversarial/release-decision.json").read_text())
    assert evaluation_id(ev) == ev["evaluation_id"]
    assert attestation_set_commitment(dec["attestation_outcomes"]) == dec["attestation_set_sha256"]
    assert decision_commitment(ev, dec) == dec["decision_commitment"]
    assert dec["receipt_id"] == "rgr_" + dec["decision_commitment"]
    assert attestation_set_commitment(list(reversed(dec["attestation_outcomes"]))) == dec["attestation_set_sha256"]

    # Build the minimum parent state for the frozen evaluation.
    con.execute(
        "INSERT INTO installations VALUES(?,?,?,?,?,?)",
        (42,7001,"acme","Organization",1,"2026-09-30T00:00:00Z"),
    )
    con.execute(
        """INSERT INTO release_policy_versions VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (ev["policy_sha256"],42,99,"acme/widget","prefix","refs/tags/v","acme/release-workflows",
         ".github/workflows/release.yml","a"*40,"2026-09-30T00:00:01Z"),
    )
    con.execute(
        """INSERT INTO trusted_source_events VALUES(?,?,?,?,?,?,?)""",
        (ev["source_delivery_id"],42,99,"acme/widget",ev["source_ref"],ev["source_commit_sha"],
         "2026-09-30T00:00:02Z"),
    )
    con.execute(
        """INSERT INTO evaluation_contexts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ev["evaluation_id"],42,99,"acme/widget",ev["source_delivery_id"],ev["source_ref"],
         ev["source_commit_sha"],ev["policy_sha256"],ev["artifact_sha256"],ev["trust_snapshot_sha256"],
         ev["verifier_build_sha256"],ev["receipt_key_sha256"],"2026-09-30T00:00:03Z"),
    )

    # One finalized decision creates exactly one billable usage event and one durable Check projection.
    with con:
        con.execute(
            """INSERT INTO release_evaluations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev["evaluation_id"],dec["evidence_truth"],dec["policy_authorization"],dec["release_decision"],
             dec["policy_reason"],dec["provenance_reason"],dec["attestation_set_sha256"],
             dec["decision_commitment"],dec["receipt_id"],"receipt-key-1",ev["receipt_key_sha256"],
             "signed-jws-fixture","0"*64,"2026-09-30T00:00:04Z"),
        )
        con.execute(
            """INSERT INTO usage_events(installation_id,metric,quantity,source_key,repository,occurred_at)
               VALUES(42,'release_evaluation_v1',1,?,'acme/widget','2026-09-30T00:00:04Z')""",
            (ev["evaluation_id"],),
        )
        con.execute(
            """INSERT INTO github_check_outbox(
               evaluation_id,installation_id,repository_id,repository,head_sha,check_name,external_id,
               conclusion,title,summary,state,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?)""",
            (ev["evaluation_id"],42,99,"acme/widget",ev["source_commit_sha"],
             "ReleaseGate "+ev["evaluation_id"][4:],ev["evaluation_id"],"success",
             "Release authorized","receipt="+dec["receipt_id"],"2026-09-30T00:00:04Z","2026-09-30T00:00:04Z"),
        )
    assert con.execute(
        "SELECT COUNT(*) FROM usage_events WHERE source_key=? AND metric='release_evaluation_v1'",
        (ev["evaluation_id"],),
    ).fetchone()[0] == 1
    try:
        con.execute(
            """INSERT INTO usage_events(installation_id,metric,quantity,source_key,repository,occurred_at)
               VALUES(42,'release_evaluation_v1',1,?,'acme/widget','2026-09-30T00:00:05Z')""",
            (ev["evaluation_id"],),
        )
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("usage metering accepted a duplicate evaluation charge")

    # Check outbox lease/reclaim is ownership-bound.
    assert con.execute(
        "UPDATE github_check_outbox SET state='leased',lease_token='lease-1',lease_expires_unix=200,attempt_count=1 WHERE evaluation_id=? AND state='pending'",
        (ev["evaluation_id"],),
    ).rowcount == 1
    assert con.execute(
        "UPDATE github_check_outbox SET lease_token='stolen' WHERE evaluation_id=? AND state='leased' AND lease_expires_unix<=199",
        (ev["evaluation_id"],),
    ).rowcount == 0
    assert con.execute(
        "UPDATE github_check_outbox SET lease_token='lease-2',lease_expires_unix=400,attempt_count=2 WHERE evaluation_id=? AND state='leased' AND lease_expires_unix<=200",
        (ev["evaluation_id"],),
    ).rowcount == 1
    assert con.execute(
        "UPDATE github_check_outbox SET state='sent',lease_token=NULL,lease_expires_unix=NULL,check_run_id=1234 WHERE evaluation_id=? AND state='leased' AND lease_token='lease-2'",
        (ev["evaluation_id"],),
    ).rowcount == 1
    assert con.execute(
        "SELECT state,check_run_id FROM github_check_outbox WHERE evaluation_id=?",
        (ev["evaluation_id"],),
    ).fetchone() == ("sent",1234)

    # Source law: least-privilege tokens, signed receipt, deterministic finalization, durable check outbox.
    source = "\n".join(path.read_text() for path in sorted((ROOT / "src").glob("*.rs")))
    must_have = [
        "TokenScope::AttestationRead",
        "TokenScope::CheckWrite",
        "checks: Some(\"write\")",
        "attestations: Some(\"read\")",
        "ReceiptSigner",
        "decision_commitment",
        "release_evaluation_v1",
        "github_check_outbox",
        "publish_check_run",
        "external_id",
        "receipt_key_sha256",
        "release result is bound to a different frozen evaluation context",
    ]
    for token in must_have:
        assert token in source, token
    for token in ["todo!", "unimplemented!", "placeholder", "mock server", "demo mode"]:
        assert token.lower() not in source.lower(), token
    assert "attestations: Some(\"read\"),\n                checks: Some(\"write\")" not in source
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []

    print("COMMERCIAL_LOOP_GATE_PASS")


if __name__ == "__main__":
    main()
