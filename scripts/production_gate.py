#!/usr/bin/env python3
from __future__ import annotations

import sqlite3
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def must(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"PRODUCTION_GATE_FAIL {message}")


def main() -> int:
    required = [
        ROOT / "deploy/releasegate.service",
        ROOT / "deploy/releasegate-edge.service",
        ROOT / "deploy/releasegate-launch",
        ROOT / "scripts/production_materialize.py",
        ROOT / "scripts/ops_snapshot.py",
        ROOT / "scripts/sqlite_snapshot.py",
    ]
    for path in required:
        must(path.is_file(), f"missing={path.relative_to(ROOT)}")

    subprocess.run(
        [
            "python3",
            "-m",
            "py_compile",
            str(ROOT / "scripts/production_materialize.py"),
            str(ROOT / "scripts/ops_snapshot.py"),
            str(ROOT / "scripts/sqlite_snapshot.py"),
        ],
        check=True,
    )

    service = (ROOT / "deploy/releasegate.service").read_text()
    must(
        all(
            token in service
            for token in [
                "User=releasegate",
                "NoNewPrivileges=yes",
                "ProtectSystem=strict",
                "ReadWritePaths=/var/lib/releasegate",
            ]
        ),
        "systemd_kernel_hardening",
    )
    edge = (ROOT / "deploy/releasegate-edge.service").read_text()
    must("DynamicUser=yes" in edge and "CAP_NET_BIND_SERVICE" in edge, "edge_privilege_boundary")
    launcher = (ROOT / "deploy/releasegate-launch").read_text()
    must(
        'exec /usr/bin/python3 "$CTL" exec --lock "$LOCK" -- "$BIN"' in launcher,
        "launcher_silicon_exec",
    )

    production_text = "\n".join(path.read_text(errors="ignore").lower() for path in required)
    for forbidden in ["changeme", "example-secret", "dummy-token", "todo!", "unimplemented!"]:
        must(forbidden not in production_text, f"forbidden_token={forbidden}")

    # The production migration chain must remain executable independently of Rust.
    with tempfile.TemporaryDirectory() as tmp:
        database = sqlite3.connect(Path(tmp) / "gate.db")
        database.execute("PRAGMA foreign_keys=ON")
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            database.executescript(migration.read_text())
        must(database.execute("PRAGMA foreign_key_check").fetchall() == [], "migration_fk")
        must(database.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "migration_integrity")

    toolchain = (ROOT / "rust-toolchain.toml").read_text()
    rust_gate = (ROOT / "scripts/rust_gate.sh").read_text()
    must('channel = "1.90.0"' in toolchain, "toolchain_pin")
    must("expected_rustc=1.90.0" in rust_gate and "expected_cargo=1.90.0" in rust_gate, "toolchain_enforcement")

    # The two compiler defects that escaped the older static gate must never regress.
    github = (ROOT / "src/github.rs").read_text()
    must("check_name: &str,\n        check_name: &str," not in github, "duplicate_check_parameter")
    must("let response = self\n            bundle_client" not in github, "malformed_bundle_client_call")

    print("PRODUCTION_GATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
