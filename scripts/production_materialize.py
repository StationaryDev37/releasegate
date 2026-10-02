#!/usr/bin/env python3
"""Materialize one ReleaseGate production host from verified build inputs.

This command creates only host-specific state that ReleaseGate mechanically needs.
It is create-once: existing authority material causes a hard stop rather than a
silent key/token rotation.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


def die(msg: str) -> None:
    raise SystemExit(f"PRODUCTION_MATERIALIZE_BLOCKED {msg}")


def run(*argv: str, input_bytes: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            argv,
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"")
        raise SystemExit(
            f"PRODUCTION_MATERIALIZE_BLOCKED command={' '.join(argv)} "
            f"detail={detail.decode(errors='replace').strip()}"
        ) from exc
    return proc.stdout


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def token() -> str:
    return secrets.token_hex(32)


def validate_public_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
    ):
        die("public_base_url_must_be_plain_https_origin")
    return value.rstrip("/"), parsed.hostname


def validate_hostname(value: str) -> None:
    if len(value) > 253 or not re.fullmatch(
        r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+",
        value,
    ):
        die("bundle_host_invalid")


def create_releasegate_user() -> tuple[int, int]:
    try:
        user = pwd.getpwnam("releasegate")
    except KeyError:
        run(
            "useradd",
            "--system",
            "--home",
            "/var/lib/releasegate",
            "--shell",
            "/usr/sbin/nologin",
            "releasegate",
        )
        user = pwd.getpwnam("releasegate")
    return user.pw_uid, grp.getgrnam("releasegate").gr_gid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--releasegate-binary", type=Path, required=True)
    parser.add_argument("--github-app-id", type=int, required=True)
    parser.add_argument("--github-app-private-key", type=Path, required=True)
    parser.add_argument("--public-base-url", required=True)
    parser.add_argument("--bundle-host", required=True)
    parser.add_argument("--nic", default=None)
    args = parser.parse_args()

    if args.github_app_id <= 0:
        die("github_app_id_must_be_positive")
    if not args.releasegate_binary.is_file():
        die("releasegate_binary_missing")
    if not args.github_app_private_key.is_file():
        die("github_app_private_key_missing")
    base_url, public_host = validate_public_url(args.public_base_url)
    validate_hostname(args.bundle_host)
    if args.bundle_host.casefold() == public_host.casefold():
        die("bundle_host_must_not_point_to_releasegate")

    root = args.root.resolve()
    opt = root / "opt/releasegate"
    etc = root / "etc/releasegate"
    state = root / "var/lib/releasegate"
    bin_dir = opt / "bin"
    lib_dir = opt / "lib"
    secrets_dir = etc / "secrets"
    systemd_dir = root / "etc/systemd/system"

    if secrets_dir.exists() and any(secrets_dir.iterdir()):
        die("authority_material_already_exists")

    for directory, mode in [
        (bin_dir, 0o755),
        (lib_dir, 0o755),
        (etc, 0o750),
        (secrets_dir, 0o700),
        (state, 0o700),
        (systemd_dir, 0o755),
    ]:
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, mode)

    project_root = Path(__file__).resolve().parents[1]
    binary_bytes = args.releasegate_binary.read_bytes()
    binary_sha256 = sha256_bytes(binary_bytes)
    binary = bin_dir / "releasegate"
    atomic_write(binary, binary_bytes, 0o755)

    shutil.copy2(project_root / "scripts/silicon_ctl.py", lib_dir / "silicon_ctl.py")
    os.chmod(lib_dir / "silicon_ctl.py", 0o755)
    shutil.copy2(project_root / "deploy/releasegate-launch", bin_dir / "releasegate-launch")
    os.chmod(bin_dir / "releasegate-launch", 0o755)
    shutil.copy2(project_root / "deploy/releasegate.service", systemd_dir / "releasegate.service")
    shutil.copy2(project_root / "deploy/releasegate-edge.service", systemd_dir / "releasegate-edge.service")

    app_key = args.github_app_private_key.read_bytes()
    if b"BEGIN" not in app_key or b"PRIVATE KEY" not in app_key:
        die("github_app_private_key_not_pem")
    # OpenSSL parses the real key before it can become installed authority.
    run("openssl", "pkey", "-noout", input_bytes=app_key)
    atomic_write(secrets_dir / "github-app-private-key.pem", app_key, 0o600)

    receipt_private = run(
        "openssl",
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:3072",
    )
    receipt_public = run("openssl", "pkey", "-pubout", input_bytes=receipt_private)
    atomic_write(secrets_dir / "receipt-private-key.pem", receipt_private, 0o600)
    atomic_write(secrets_dir / "receipt-public-key.pem", receipt_public, 0o600)
    for name in [
        "github-app-webhook-secret",
        "marketplace-webhook-secret",
        "control-token",
        "evaluator-token",
        "auditor-token",
    ]:
        atomic_write(secrets_dir / name, (token() + "\n").encode(), 0o600)

    runtime_env = "\n".join(
        [
            "RELEASEGATE_BIND=127.0.0.1:8080",
            "RELEASEGATE_DATABASE_URL=sqlite:///var/lib/releasegate/releasegate.db?mode=rwc",
            f"RELEASEGATE_GITHUB_APP_ID={args.github_app_id}",
            f"RELEASEGATE_GITHUB_BUNDLE_HOST={args.bundle_host}",
            "RELEASEGATE_RECEIPT_KEY_ID=releasegate-production-rsa3072-v1",
            "RELEASEGATE_DELIVERY_LEASE_SECONDS=120",
            "RELEASEGATE_CHECK_LEASE_SECONDS=120",
            "RELEASEGATE_LOG=releasegate=info,tower_http=warn",
            "",
        ]
    )
    atomic_write(etc / "runtime.env", runtime_env.encode(), 0o640)

    lock = etc / "silicon.lock"
    ctl = lib_dir / "silicon_ctl.py"
    probe = [sys.executable, str(ctl), "probe", "--out", str(lock)]
    if args.nic:
        probe.extend(["--nic", args.nic])
    run(*probe)
    os.chmod(lock, 0o640)
    silicon_lock_sha256 = sha256_bytes(lock.read_bytes())

    app_contract = {
        "schema": "releasegate.github-app-contract.v1",
        "app_id": args.github_app_id,
        "webhooks": {
            "github_app": f"{base_url}/webhooks/github/app",
            "marketplace": f"{base_url}/webhooks/github/marketplace",
        },
        "repository_permissions": {
            "attestations": "read",
            "checks": "write",
            "contents": "read",
            "metadata": "read",
        },
        "events": ["installation", "push"],
        "secrets": {
            "github_app_webhook_secret_file": "/etc/releasegate/secrets/github-app-webhook-secret",
            "marketplace_webhook_secret_file": "/etc/releasegate/secrets/marketplace-webhook-secret",
        },
    }
    atomic_write(
        etc / "github-app-contract.json",
        (json.dumps(app_contract, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        0o640,
    )

    caddyfile = (
        f"{public_host} {{\n"
        "    @releasegate path /webhooks/github/app /webhooks/github/marketplace "
        "/v1/policies/active /v1/evaluations /v1/evaluations/* /v1/receipt-key /healthz /readyz\n"
        "    handle @releasegate {\n"
        "        reverse_proxy 127.0.0.1:8080\n"
        "    }\n"
        "    respond 404\n"
        "}\n"
    )
    atomic_write(etc / "Caddyfile", caddyfile.encode(), 0o640)

    runtime_manifest = {
        "schema": "releasegate.runtime-manifest.v1",
        "releasegate_binary_sha256": binary_sha256,
        "receipt_public_key_sha256": sha256_bytes(receipt_public),
        "silicon_lock_sha256": silicon_lock_sha256,
        "github_app_id": args.github_app_id,
        "public_base_url": base_url,
        "bundle_host": args.bundle_host,
    }
    atomic_write(
        etc / "runtime-manifest.json",
        (json.dumps(runtime_manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        0o640,
    )

    if root == Path("/"):
        if os.geteuid() != 0:
            die("root_required_for_live_install")
        if shutil.which("caddy") != "/usr/bin/caddy":
            die("caddy_required_at_/usr/bin/caddy")
        uid, gid = create_releasegate_user()
        os.chown(state, uid, gid)
        for path in secrets_dir.iterdir():
            os.chown(path, 0, gid)
            os.chmod(path, 0o640)
        for path in [
            etc / "runtime.env",
            etc / "silicon.lock",
            etc / "github-app-contract.json",
            etc / "runtime-manifest.json",
        ]:
            os.chown(path, 0, gid)
            os.chmod(path, 0o640)
        os.chmod(etc / "Caddyfile", 0o644)

    print(
        f"PRODUCTION_MATERIALIZE_PASS root={root} app_id={args.github_app_id} "
        f"binary_sha256={binary_sha256} public={base_url}"
    )
    print(f"GITHUB_APP_CONTRACT={etc / 'github-app-contract.json'}")
    print(f"RUNTIME_MANIFEST={etc / 'runtime-manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
