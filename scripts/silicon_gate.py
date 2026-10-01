#!/usr/bin/env python3
from __future__ import annotations
import json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CTL = ROOT / "scripts" / "silicon_ctl.py"

def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(CTL), *args], text=True, capture_output=True)

with tempfile.TemporaryDirectory() as td:
    lock = Path(td) / "silicon.lock.json"
    p = run("probe", "--out", str(lock))
    if p.returncode != 0:
        print(p.stdout, p.stderr, end="")
        raise SystemExit("SILICON_GATE_FAIL probe")
    data = json.loads(lock.read_text())
    assert data["schema"] == "releasegate.silicon.lock/v1"
    assert data["placement"]["runtime_cpus"]
    assert data["placement"]["irq_cpus"]
    assert data["placement"]["tokio_worker_threads"] == len(data["placement"]["runtime_cpus"])

    p = run("validate", "--lock", str(lock))
    if p.returncode != 0 or "SILICON_LOCK_PASS" not in p.stdout:
        print(p.stdout, p.stderr, end="")
        raise SystemExit("SILICON_GATE_FAIL validate")

    # Lock tampering must be detected before host validation.
    tampered = dict(data)
    tampered["placement"] = dict(data["placement"])
    tampered["placement"]["runtime_cpus"] = [999999]
    lock.write_text(json.dumps(tampered, separators=(",", ":"), sort_keys=True) + "\n")
    p = run("validate", "--lock", str(lock))
    if p.returncode == 0 or "SILICON_LOCK_INVALID fingerprint" not in (p.stdout + p.stderr):
        print(p.stdout, p.stderr, end="")
        raise SystemExit("SILICON_GATE_FAIL tamper")

print("SILICON_GATE_PASS")
