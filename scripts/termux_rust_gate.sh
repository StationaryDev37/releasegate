#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

pkg install -y rust clang pkg-config openssl
python3 scripts/static_gate.py
python3 scripts/commercial_gate.py

if [[ ! -f Cargo.lock ]]; then
  cargo generate-lockfile
  sha256sum Cargo.lock
  printf '%s\n' 'LOCKFILE_CREATED: review Cargo.lock, commit it, then rerun scripts/termux_rust_gate.sh.'
  exit 21
fi

./scripts/rust_gate.sh
