# Next closure gate

Do not add SBOM, Check Runs, dashboard, billing expansion, or another provider yet.

The next gate is execution closure for this bedrock branch:

1. Produce and review `Cargo.lock` using the pinned Rust toolchain.
2. `cargo fmt --all -- --check`.
3. `RUSTFLAGS='-D warnings' cargo check --locked --all-targets --all-features`.
4. `cargo clippy --locked --all-targets --all-features -- -D warnings`.
5. `cargo test --locked --all-targets --all-features`.
6. `cargo build --locked --release` and record binary SHA-256.
7. Execute a signed GitHub push webhook, force a mid-delivery process kill, restart, and prove the durable inbox re-hashes + re-verifies HMAC before idempotently applying the event and reaching one terminal state.
8. Execute a live installation-token + attestation retrieval + supported provenance verification roundtrip.

Only after those predicates pass does SBOM commitment become the next engineering slice.
