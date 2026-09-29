# Next Gate: v0.4 verification orchestration + SBOM commitment

v0.1 is immutable. v0.2 verifies GitHub provenance. v0.3 generates the verifier expectation from trusted source context and immutable organization policy.

The next gate closes the live decision path without adding UI or billing scope:

1. Wire GitHub App credentials/API client into application state.
2. Resolve exact trusted source `(installation, repo, commit, ref)` and active policy.
3. Generate `ProvenanceExpectation` from v0.3 policy resolution.
4. Retrieve/store attestation bundles using the v0.2 bounded GitHub path.
5. Run v0.2 provenance verification with the v0.3 expectation.
6. Parse supported SBOM evidence (CycloneDX/SPDX) with strict size/resource limits.
7. Produce a deterministic canonical SBOM/dependency commitment.
8. Compose provenance + SBOM + policy into the release decision input.

Stop there.

Still out of scope for this gate:

- GitHub Check Runs
- receipt signing/integration changes
- Marketplace/AWS billing changes
- dashboard/UI
- generalized multi-provider provenance

Release predicate remains: `cargo fmt --check` + compile + Clippy `-D warnings` + Rust tests + static gate + live signed webhook roundtrip + live installation-token/attestation roundtrip.
