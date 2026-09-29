# v0.3 Policy Gate

## Purpose

Turn organization-controlled release policy plus authenticated GitHub source facts into the exact identity expectation consumed by the v0.2 provenance verifier.

## Trust inputs

**Authenticated source facts** are recorded only after the GitHub App webhook raw body passes HMAC-SHA256 verification:

- installation id
- repository id
- repository owner/name
- exact git ref
- exact commit SHA
- GitHub delivery id

**Organization policy** is versioned immutably and supplies:

- installation/repository scope
- allowed source ref rule (`exact` or literal `prefix`)
- signer repository
- signer workflow path
- exact signer workflow revision SHA

The active policy pointer is separate from the immutable policy version. Changing policy therefore creates a new policy hash instead of rewriting history.

## Resolution law

```text
active policy + exact trusted source record
                  |
                  +-- identity mismatch/malformed -> INDETERMINATE
                  +-- ref outside allowed rule    -> REJECTED
                  +-- allowed                     -> ELIGIBLE
                                                     |
                                                     v
                                           ProvenanceExpectation
                                           - source repo + numeric id
                                           - exact source ref
                                           - exact source commit
                                           - signer repo
                                           - workflow path
                                           - workflow revision SHA
```

The resolver never copies signer policy from an attestation bundle.

## Canonical policy identity

`policy_sha256` is SHA-256 over length-prefixed UTF-8 fields in this exact order:

1. policy version (`1`)
2. installation id
3. repository id
4. repository owner/name
5. ref rule kind
6. ref rule value
7. signer repository
8. signer workflow path
9. lowercase signer revision SHA

Fixture vector:

```text
6bc707d83af54b493743d2f7ba4eb287302d8ce5cdfab99550421fb0880cefc1
```

## Deliberate limits

- One active release policy per installation/repository in this slice.
- Ref matching supports exact or literal prefix only; no regex/glob ambiguity.
- Source lookup requires exact commit **and** ref so a commit reachable from multiple refs cannot select the wrong release policy context.
- Policy provisioning still uses the existing v0.1 control-plane ingest token; per-installation/OIDC control-plane authorization remains future work.
- This gate creates the verifier expectation but does not yet orchestrate attestation retrieval + policy resolution + provenance verification in one live endpoint.
