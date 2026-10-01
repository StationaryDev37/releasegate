# Next closure gate

v0.4 source closes the commercial decision loop in code. Do not add another provider, dashboard, generic queue, SBOM feature, or billing surface before execution closure.

The next gate is evidence, not architecture:

1. Produce and review `Cargo.lock` under the pinned Rust 1.90.0 toolchain.
2. `cargo fmt --all -- --check`.
3. `RUSTFLAGS='-D warnings' cargo check --locked --all-targets --all-features`.
4. `cargo clippy --locked --all-targets --all-features -- -D warnings`.
5. `cargo test --locked --all-targets --all-features`.
6. `cargo build --locked --release`; record the ReleaseGate binary SHA-256 used by evaluation identity.
7. Register/install the GitHub App with the minimum permissions required by the implemented loop.
8. Execute one signed push webhook through durable ingress and prove crash/restart recovery reaches exactly one terminal application.
9. Execute one live installation-token → attestation retrieval → supported provenance verification evaluation.
10. Prove one finalized evaluation creates exactly one usage event and one GitHub Check Run whose `external_id` equals the frozen evaluation ID.
11. Verify the emitted receipt independently with `/v1/receipt-key` material and reproduce its deterministic decision commitment from stored evidence.

Only after these predicates pass is v0.4 eligible for a production-release tag. The next engineering slice, if evidence justifies it, is SBOM/dependency commitment—not broader application scaffolding.
