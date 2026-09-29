# Next Gate: cryptographically strong automated release verification

The next release must close these items in this order:

1. GitHub App JWT using the App private key.
2. Exchange JWT for installation access token.
3. Resolve commit SHA and fetch the selected workflow artifact from GitHub API.
4. Stream artifact hashing with bounded decompression / archive traversal protections.
5. Ingest SLSA provenance / GitHub artifact attestation when present.
6. Parse SBOM (CycloneDX/SPDX) and compute canonical dependency commitment.
7. Policy engine producing VERIFIED / REJECTED / INDETERMINATE.
8. Post a GitHub Check result and immutable receipt URL.
9. Replace global ingest token with GitHub OIDC or per-installation scoped credentials.
10. Quota enforcement derived from Marketplace plan state.

Release predicate: format + compile + clippy + unit/integration tests + live signed webhook fixture + live GitHub installation roundtrip.
