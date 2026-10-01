#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 scripts/static_gate.py
python3 scripts/commercial_gate.py

for tool in rustc cargo rustfmt clippy-driver; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'RUST_GATE_BLOCKED missing=%s\n' "$tool" >&2
    exit 20
  }
done

printf 'rustc=%s\n' "$(rustc --version)"
printf 'cargo=%s\n' "$(cargo --version)"

if [[ ! -f Cargo.lock ]]; then
  cargo generate-lockfile
  printf '%s\n' 'RUST_GATE_STOP: Cargo.lock was generated. Review and commit the lockfile, then rerun this gate with the tree clean.' >&2
  exit 21
fi

if ! git diff --quiet -- Cargo.lock 2>/dev/null; then
  printf '%s\n' 'RUST_GATE_STOP: Cargo.lock has uncommitted changes.' >&2
  exit 22
fi

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  printf '%s\n' 'RUST_GATE_STOP: source tree is not clean.' >&2
  git status --short >&2
  exit 23
fi

cargo fmt --all -- --check
RUSTFLAGS='-D warnings' cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
RUSTFLAGS='-D warnings' cargo build --locked --release
sha256sum target/release/releasegate
printf '%s\n' 'RUST_GATE_PASS'
