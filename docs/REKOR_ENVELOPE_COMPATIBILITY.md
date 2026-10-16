# Rekor original-envelope hash interoperability (2026-10-15)

Pinned dependency: attestation-verify 0.1.0, re-vendored from crates.io
using the exact SHA-256 recorded in the original Cargo.lock.

## Failure observed

The production ReleaseGate evaluation rge_4d4de7ff35804e1491f199be41af747961340982392bae23ec5542c362d09478
returned HOLD with evidence INDETERMINATE and reason `content_binding`.
The independently read production evidence matched its artifact subject,
Rekor kind/version, DSSE signature bytes, certificate and decoded payload hash.
The only local equality that failed was the reconstructed `envelopeHash`.

Rekor v1 dsse/0.0.1 `envelopeHash` hashes the original submitted JSON bytes,
not a canonical encoding of the parsed envelope. The bundle does not retain
those original bytes. Checking a freshly reserialized version is invalid.

## Security invariant

The patch does NOT alter ReleaseGate's fail-closed policy or skip DSSE,
certificate, source/signer identity, trust root, Rekor SET, Merkle inclusion,
checkpoint, timestamp, signature, or decoded payload hash verification.
The logged envelope hash field remains strict-hex parsed and authenticated
as part of the transparency-log body. A tampered logged hash must fail the
signed entry timestamp or inclusion checks. No production evaluation is
re-written, and no RELEASE is claimed on the basis of this patch.

The CI workflow tests the vendored verifier (including adversarial tests)
and runs the ReleaseGate authoritative Rust gate. No merge or Railway deploy
is part of this patch's publication.
