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


def main() -> None:
    tomllib.loads((ROOT / "Cargo.toml").read_text())
    for path in sorted((ROOT / "fixtures" / "github").glob("*.json")):
        json.loads(path.read_text())

    con = sqlite3.connect(":memory:")
    con.executescript((ROOT / "migrations" / "0001_init.sql").read_text())
    tables = {
        r[0]
        for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    required = {
        "webhook_deliveries",
        "installations",
        "subscriptions",
        "verification_receipts",
        "usage_events",
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

    print("STATIC_GATE_PASS")


if __name__ == "__main__":
    main()
