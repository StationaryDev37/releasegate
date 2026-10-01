#!/usr/bin/env python3
"""Independent non-Rust bedrock gate. It never substitutes for rust_gate.sh."""
from __future__ import annotations

import base64
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
        raw = part.encode()
        h.update(len(raw).to_bytes(8, "big"))
        h.update(raw)
    return h.hexdigest()


def policy_hash(spec: dict[str, object]) -> str:
    return digest_join([
        "1",
        str(spec["installation_id"]),
        str(spec["repository_id"]),
        str(spec["repository"]),
        str(spec["ref_rule"]),
        str(spec["ref_value"]),
        str(spec["signer_repository"]),
        str(spec["signer_workflow_path"]),
        str(spec["signer_revision_sha"]).lower(),
    ])


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


def compose(truth: str, authorization: str) -> str:
    if truth == "VERIFIED" and authorization == "ALLOW":
        return "RELEASE"
    if truth == "INVALID" or authorization == "DENY":
        return "BLOCK"
    return "HOLD"


def push_text(out: bytearray, value: str) -> None:
    raw = value.encode()
    out.extend(len(raw).to_bytes(4, "big"))
    out.extend(raw)


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
        ev["evaluation_id"], ev["repository"], ev["source_delivery_id"], ev["source_ref"],
        ev["source_commit_sha"], ev["policy_sha256"], ev["artifact_sha256"],
        ev["trust_snapshot_sha256"], ev["verifier_build_sha256"], ev["receipt_key_sha256"],
        decision["evidence_truth"], decision["policy_authorization"], decision["release_decision"],
        decision["policy_reason"], decision["provenance_reason"], decision["attestation_set_sha256"],
    ]:
        push_text(out, str(value))
    return hashlib.sha256(out).hexdigest()


def main() -> None:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())
    assert cargo["package"]["version"] == "0.4.0"
    assert cargo["dependencies"]["attestation-verify"] == "=0.1.0"
    assert not (ROOT / ".env.example").exists()

    for path in sorted((ROOT / "fixtures").rglob("*.json")):
        json.loads(path.read_text())

    con = sqlite3.connect(":memory:")
    con.execute("PRAGMA foreign_keys = ON")
    for migration in sorted((ROOT / "migrations").glob("*.sql")):
        con.executescript(migration.read_text())

    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {
        "webhook_deliveries",
        "installations",
        "subscriptions",
        "attestation_bundles",
        "release_policy_versions",
        "active_release_policies",
        "trusted_source_events",
        "evaluation_contexts",
        "release_evaluations",
        "evaluation_attestation_outcomes",
        "usage_events",
        "github_check_outbox",
    }
    assert "verification_receipts" not in tables
    assert required <= tables, required - tables

    # GitHub webhook HMAC reference vector.
    secret = b"It's a Secret to Everybody"
    payload = b"Hello, World!"
    expected = "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    computed_signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    assert computed_signature == expected
    signature_header = f"sha256={computed_signature}"
    assert hmac.compare_digest(signature_header, f"sha256={expected}")

    # Exact Rekor v1 log id must equal SHA-256(SPKI), preventing list-order trust.
    log_id = base64.b64decode("wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=")
    spki = base64.b64decode(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
    )
    assert hashlib.sha256(spki).digest() == log_id
    assert log_id.hex() == "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"

    # Closed 3x3 decision law: exactly one state may RELEASE.
    truths = ["VERIFIED", "INVALID", "INDETERMINATE"]
    policies = ["ALLOW", "DENY", "INDETERMINATE"]
    releases = [(t, p) for t in truths for p in policies if compose(t, p) == "RELEASE"]
    assert releases == [("VERIFIED", "ALLOW")]
    assert compose("INDETERMINATE", "DENY") == "BLOCK"
    assert compose("VERIFIED", "INDETERMINATE") == "HOLD"

    policy_fixture = json.loads((ROOT / "fixtures/policy/release-policy.json").read_text())
    p_hash = policy_hash(policy_fixture)
    assert p_hash == "6bc707d83af54b493743d2f7ba4eb287302d8ce5cdfab99550421fb0880cefc1"

    con.execute(
        "INSERT INTO installations VALUES(?,?,?,?,?,?)",
        (42, 7001, "acme", "Organization", 1, "2026-09-30T00:00:00Z"),
    )
    con.execute(
        """INSERT INTO release_policy_versions(
           policy_sha256,installation_id,repository_id,repository,ref_rule,ref_value,
           signer_repository,signer_workflow_path,signer_revision_sha,created_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            p_hash, 42, 99, "acme/widget", "prefix", "refs/tags/v",
            "acme/release-workflows", ".github/workflows/release.yml", "a" * 40,
            "2026-09-30T00:00:01Z",
        ),
    )
    con.execute(
        "INSERT INTO active_release_policies VALUES(?,?,?,?)",
        (42, 99, p_hash, "2026-09-30T00:00:02Z"),
    )
    con.execute(
        """INSERT INTO trusted_source_events(
           delivery_id,installation_id,repository_id,repository,source_ref,source_commit_sha,observed_at
           ) VALUES(?,?,?,?,?,?,?)""",
        ("delivery-1", 42, 99, "acme/widget", "refs/tags/v1.2.3", "b" * 40, "2026-09-30T00:00:03Z"),
    )

    # Immutable evaluation identity vector and FK-scoped freeze.
    ev = json.loads((ROOT / "fixtures/adversarial/evaluation-context.json").read_text())
    assert evaluation_id(ev) == ev["evaluation_id"]
    con.execute(
        """INSERT INTO evaluation_contexts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ev["evaluation_id"], 42, 99, "acme/widget", "delivery-1", "refs/tags/v1.2.3",
            "b" * 40, p_hash, "c" * 64, "d" * 64, "e" * 64, "f" * 64,
            "2026-09-30T00:00:04Z",
        ),
    )
    try:
        con.execute(
            """INSERT INTO evaluation_contexts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "rge_bad_scope", 42, 100, "acme/other", "delivery-1", "refs/tags/v1.2.3",
                "b" * 40, p_hash, "c" * 64, "d" * 64, "e" * 64, "f" * 64,
                "2026-09-30T00:00:05Z",
            ),
        )
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("evaluation context accepted cross-repository evidence")

    # Canonical commercial decision commitment: order-independent attestation set + frozen facts.
    decision = json.loads((ROOT / "fixtures/adversarial/release-decision.json").read_text())
    assert attestation_set_commitment(decision["attestation_outcomes"]) == decision["attestation_set_sha256"]
    assert decision_commitment(ev, decision) == decision["decision_commitment"]
    assert decision["receipt_id"] == "rgr_" + decision["decision_commitment"]

    # Final decision, metering, and GitHub Check projection are one durable transaction boundary.
    con.execute(
        """INSERT INTO release_evaluations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ev["evaluation_id"], decision["evidence_truth"], decision["policy_authorization"],
            decision["release_decision"], decision["policy_reason"], decision["provenance_reason"],
            decision["attestation_set_sha256"], decision["decision_commitment"], decision["receipt_id"],
            "receipt-key-1", "f" * 64, "signed-jws-fixture", "0" * 64,
            "2026-09-30T00:00:05Z",
        ),
    )
    con.execute(
        """INSERT INTO usage_events(installation_id,metric,quantity,source_key,repository,occurred_at)
           VALUES(42,'release_evaluation_v1',1,?,'acme/widget','2026-09-30T00:00:05Z')""",
        (ev["evaluation_id"],),
    )
    con.execute(
        """INSERT INTO github_check_outbox(
           evaluation_id,installation_id,repository_id,repository,head_sha,check_name,external_id,
           conclusion,title,summary,state,created_at,updated_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?)""",
        (
            ev["evaluation_id"],42,99,"acme/widget","b"*40,"ReleaseGate fixture",ev["evaluation_id"],
            "success","Release authorized","fixture summary","2026-09-30T00:00:05Z","2026-09-30T00:00:05Z",
        ),
    )
    assert con.execute(
        "SELECT COUNT(*) FROM usage_events WHERE metric='release_evaluation_v1' AND source_key=?",
        (ev["evaluation_id"],),
    ).fetchone()[0] == 1
    assert con.execute(
        "SELECT state FROM github_check_outbox WHERE evaluation_id=?", (ev["evaluation_id"],)
    ).fetchone()[0] == "pending"

    # Check projection lease is non-stealable, reclaimable, and bounded.
    changed = con.execute(
        """UPDATE github_check_outbox SET state='leased',lease_token='check-lease-1',
           lease_expires_unix=200,attempt_count=attempt_count+1
           WHERE evaluation_id=? AND state='pending'""",
        (ev["evaluation_id"],),
    ).rowcount
    assert changed == 1
    assert con.execute(
        "UPDATE github_check_outbox SET lease_token='stolen' WHERE evaluation_id=? AND state='leased' AND lease_expires_unix<=199",
        (ev["evaluation_id"],),
    ).rowcount == 0
    assert con.execute(
        """UPDATE github_check_outbox SET lease_token='check-lease-2',lease_expires_unix=400,
           attempt_count=attempt_count+1 WHERE evaluation_id=? AND state='leased' AND lease_expires_unix<=200""",
        (ev["evaluation_id"],),
    ).rowcount == 1

    # Delivery lease/reclaim law at the persistence boundary.
    lease = json.loads((ROOT / "fixtures/adversarial/webhook-lease.json").read_text())
    durable_payload = b'{"zen":"Keep it logically awesome."}'
    durable_hash = hashlib.sha256(durable_payload).hexdigest()
    durable_signature = "sha256=" + hmac.new(secret, durable_payload, hashlib.sha256).hexdigest()
    con.execute(
        """INSERT INTO webhook_deliveries(
           source,delivery_id,event_type,payload_sha256,received_at,payload_bytes,signature_header,state,attempt_count
           ) VALUES(?,?,?,?,?,?,?,'received',0)""",
        (lease["source"], lease["delivery_id"], lease["event_type"], durable_hash,
         "2026-09-30T00:00:06Z", durable_payload, durable_signature),
    )
    stored = con.execute(
        "SELECT payload_sha256,payload_bytes,signature_header FROM webhook_deliveries WHERE delivery_id=?",
        (lease["delivery_id"],),
    ).fetchone()
    assert hashlib.sha256(stored[1]).hexdigest() == stored[0]
    assert hmac.compare_digest(
        stored[2], "sha256=" + hmac.new(secret, stored[1], hashlib.sha256).hexdigest()
    )
    first_token = "lease-token-1"
    changed = con.execute(
        """UPDATE webhook_deliveries SET state='leased',lease_token=?,lease_expires_unix=?,attempt_count=attempt_count+1
           WHERE source=? AND delivery_id=? AND state='received'""",
        (first_token, lease["first_lease_unix"] + lease["lease_seconds"], lease["source"], lease["delivery_id"]),
    ).rowcount
    assert changed == 1
    assert con.execute("SELECT attempt_count FROM webhook_deliveries WHERE delivery_id=?", (lease["delivery_id"],)).fetchone()[0] == 1

    # Before expiry: second worker cannot steal the lease.
    changed = con.execute(
        """UPDATE webhook_deliveries SET lease_token='stolen',attempt_count=attempt_count+1
           WHERE source=? AND delivery_id=? AND state='leased' AND lease_expires_unix <= ?""",
        (lease["source"], lease["delivery_id"], lease["first_lease_unix"] + 60),
    ).rowcount
    assert changed == 0

    # After expiry: exactly one reclaim is allowed and attempt counter advances.
    changed = con.execute(
        """UPDATE webhook_deliveries SET lease_token='lease-token-2',lease_expires_unix=?,attempt_count=attempt_count+1
           WHERE source=? AND delivery_id=? AND state='leased' AND lease_expires_unix <= ?""",
        (lease["reclaim_unix"] + lease["lease_seconds"], lease["source"], lease["delivery_id"], lease["reclaim_unix"]),
    ).rowcount
    assert changed == 1
    assert con.execute("SELECT attempt_count FROM webhook_deliveries WHERE delivery_id=?", (lease["delivery_id"],)).fetchone()[0] == 2

    # Retry backoff cannot be bypassed by immediate redelivery.
    con.execute(
        """UPDATE webhook_deliveries SET state='received',lease_token=NULL,lease_expires_unix=NULL,next_attempt_unix=?
           WHERE source=? AND delivery_id=?""",
        (lease["reclaim_unix"] + 300, lease["source"], lease["delivery_id"]),
    )
    changed = con.execute(
        """UPDATE webhook_deliveries SET state='leased',lease_token='too-early'
           WHERE source=? AND delivery_id=? AND attempt_count < 12
             AND state='received' AND next_attempt_unix <= ?""",
        (lease["source"], lease["delivery_id"], lease["reclaim_unix"] + 1),
    ).rowcount
    assert changed == 0

    # Exhausted retry budget becomes terminal rather than looping forever.
    con.execute(
        """UPDATE webhook_deliveries SET state='received',attempt_count=12,next_attempt_unix=?
           WHERE source=? AND delivery_id=?""",
        (lease["reclaim_unix"], lease["source"], lease["delivery_id"]),
    )
    changed = con.execute(
        """UPDATE webhook_deliveries
           SET state='rejected',last_error_code='retry_budget_exhausted',completed_at=?
           WHERE source=? AND delivery_id=? AND attempt_count >= 12
             AND state='received' AND next_attempt_unix <= ?""",
        ("2026-09-30T00:00:07Z", lease["source"], lease["delivery_id"], lease["reclaim_unix"]),
    ).rowcount
    assert changed == 1
    terminal = con.execute(
        "SELECT state,last_error_code FROM webhook_deliveries WHERE delivery_id=?",
        (lease["delivery_id"],),
    ).fetchone()
    assert terminal == ("rejected", "retry_budget_exhausted")

    # Reset to an owned lease to verify terminal applied semantics separately.
    con.execute(
        """UPDATE webhook_deliveries SET state='leased',attempt_count=2,lease_token='lease-token-2',
           lease_expires_unix=?,next_attempt_unix=0,last_error_code=NULL,completed_at=NULL
           WHERE source=? AND delivery_id=?""",
        (lease["reclaim_unix"] + lease["lease_seconds"], lease["source"], lease["delivery_id"]),
    )

    # Applied deliveries are terminal and no longer reclaimable.
    con.execute(
        """UPDATE webhook_deliveries SET state='applied',lease_token=NULL,lease_expires_unix=NULL,completed_at=?
           WHERE source=? AND delivery_id=? AND lease_token='lease-token-2'""",
        ("2026-09-30T00:00:07Z", lease["source"], lease["delivery_id"]),
    )
    assert con.execute(
        "UPDATE webhook_deliveries SET state='leased' WHERE source=? AND delivery_id=? AND state='received'",
        (lease["source"], lease["delivery_id"]),
    ).rowcount == 0

    # Source scan for banned unfinished paths / old authority model.
    source_text = "\n".join(path.read_text() for path in sorted((ROOT / "src").glob("*.rs")))
    banned = [
        "RELEASEGATE_INGEST_TOKEN",
        "authorize_ingest",
        "claim_delivery(",
        ".tlogs.first()",
        "todo!",
        "unimplemented!",
        "replace-with-high-entropy",
    ]
    for token in banned:
        assert token not in source_text, token
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    assert "lease_delivery(" in source_text
    assert "durable_authentication_failed" in source_text
    assert "retry_budget_exhausted" in source_text
    assert "signature_header" in source_text
    assert "freeze_evaluation_context(" in source_text
    assert "finalize_release_evaluation(" in source_text
    assert "publish_check_run(" in source_text
    assert "ReceiptSigner" in source_text
    assert "release_evaluation_v1" in source_text
    assert "PolicyAuthorization" in source_text and "EvidenceTruth" in source_text
    evaluation_text = (ROOT / "src/evaluation.rs").read_text()
    assert "silicon" not in evaluation_text.lower(), "silicon must not enter evaluation identity"
    assert (ROOT / "src/silicon.rs").exists()

    print("BEDROCK_STATIC_GATE_PASS")


if __name__ == "__main__":
    main()
