# Bedrock architecture

```text
GitHub raw webhook bytes
        |
        | HMAC-SHA256 before parsing
        v
durable authenticated webhook inbox
 payload + digest + validated signature
              |
              v
received -> leased -> applied
    ^         |
    |         +----> rejected (permanent/auth/retry-budget)
    |
    +-- bounded backoff -- retryable failure

expired lease -> reclaim -> re-hash + HMAC re-verify -> dispatch

GitHub push facts --------------------+
                                      |
immutable policy ---------------------+--> frozen EvaluationContext
                                      |      source delivery/ref/commit
trust snapshot fingerprint -----------+      policy/artifact/trust/build hashes
executing binary SHA-256 -------------+
                                             |
                                             v
                                     ProvenanceExpectation
                                             |
                     exact Rekor/Fulcio/Sigstore verification
                                             |
                                      EvidenceTruth
                                             |
PolicyAuthorization -------------------------+
                                             v
                                      ReleaseDecision
```

## State law

`EvidenceTruth = VERIFIED | INVALID | INDETERMINATE`

`PolicyAuthorization = ALLOW | DENY | INDETERMINATE`

`ReleaseDecision = RELEASE | BLOCK | HOLD`

Only `(VERIFIED, ALLOW)` maps to `RELEASE`. Cryptographic invalidity always blocks. Explicit policy denial blocks even if cryptographic truth is not yet established. Every other uncertain combination holds.

## Persistence law

SQLite WAL is intentional for the single-process kernel. The schema is shaped around ReleaseGate identities rather than generic entities. Multi-writer deployment is unsupported until a separate consistency design exists; there is no silent database substitution path.
