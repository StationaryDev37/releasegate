#!/usr/bin/env python3
"""Emit ReleaseGate operational truth directly from durable decision state."""
from __future__ import annotations
import argparse, json, sqlite3
from pathlib import Path


def scalar(db: sqlite3.Connection, q: str):
    return db.execute(q).fetchone()[0]


def grouped(db: sqlite3.Connection, table: str, column: str) -> dict[str, int]:
    return {str(k): int(v) for k, v in db.execute(f"SELECT {column}, COUNT(*) FROM {table} GROUP BY {column}")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=Path("/var/lib/releasegate/releasegate.db"))
    args = ap.parse_args()
    uri = f"file:{args.db}?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.execute("PRAGMA foreign_keys=ON")
    integrity = scalar(db, "PRAGMA integrity_check")
    out = {
        "schema": "releasegate.ops-snapshot.v1",
        "database_integrity": integrity,
        "foreign_key_violations": scalar(db, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        "evaluations_total": scalar(db, "SELECT COUNT(*) FROM release_evaluations"),
        "release_decisions": grouped(db, "release_evaluations", "release_decision"),
        "evidence_truth": grouped(db, "release_evaluations", "evidence_truth"),
        "policy_authorization": grouped(db, "release_evaluations", "policy_authorization"),
        "usage_events_total": scalar(db, "SELECT COUNT(*) FROM usage_events"),
        "check_dispatch": grouped(db, "github_check_outbox", "state"),
        "webhook_delivery": grouped(db, "webhook_deliveries", "state"),
    }
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))
    return 0 if integrity == "ok" and out["foreign_key_violations"] == 0 else 2

if __name__ == "__main__":
    raise SystemExit(main())
