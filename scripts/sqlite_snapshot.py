#!/usr/bin/env python3
"""Create a transactionally consistent ReleaseGate SQLite backup and verify it."""
from __future__ import annotations
import argparse, hashlib, os, sqlite3
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=Path("/var/lib/releasegate/releasegate.db"))
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_name(args.out.name + ".tmp")
    if tmp.exists(): tmp.unlink()
    src = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    dst = sqlite3.connect(tmp)
    src.backup(dst)
    dst.commit()
    integrity = dst.execute("PRAGMA integrity_check").fetchone()[0]
    fk = list(dst.execute("PRAGMA foreign_key_check"))
    dst.close(); src.close()
    if integrity != "ok" or fk:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"SQLITE_SNAPSHOT_FAILED integrity={integrity} fk={len(fk)}")
    os.chmod(tmp, 0o600)
    os.replace(tmp, args.out)
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print(f"SQLITE_SNAPSHOT_PASS sha256={digest} path={args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
