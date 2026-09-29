# Architecture

## Trust boundaries

1. **GitHub -> webhook ingress**: GitHub App and Marketplace use isolated endpoints/secrets. Authenticate the exact raw request bytes using HMAC-SHA256 before parsing.
2. **Delivery ledger**: claim `(ingress source, X-GitHub-Delivery)` to prevent replayed side effects.
3. **Installation/entitlement**: installation identity maps to the GitHub account; subscription state maps to the same account. Existing verification remains fail-closed unless both are active.
4. **Trusted source ledger (v0.3)**: source repo id/name, exact ref and exact commit are persisted only from an authenticated GitHub App `push` delivery belonging to a known active installation.
5. **Immutable release policy (v0.3)**: policy versions are content-addressed by deterministic SHA-256. A separate active pointer chooses one version per installation/repository; history is not mutated.
6. **Policy resolver (v0.3)**: only the intersection of trusted source facts and active policy can create a `ProvenanceExpectation`. Signer repo/workflow/revision never come from the candidate attestation.
7. **Provenance verifier (v0.2)**: validates supported GitHub/Sigstore bundles through DSSE, Rekor/Fulcio trust material and exact GitHub identity policy. Unsupported/uncertain evidence remains `INDETERMINATE`.
8. **Receipt/meter (v0.1)**: existing deterministic receipt and idempotent usage ledger remain unchanged by v0.3.

## v0.3 data flow

```text
GitHub signed push webhook
        |
        | raw-body HMAC-SHA256
        v
trusted_source_events
        |
        | exact installation + repo + commit + ref
        |
        +---------------------------+
                                    |
control-plane policy ---> release_policy_versions
                                    |
                           active_release_policies
                                    |
                                    v
                              policy resolver
                                    |
                           ProvenanceExpectation
                                    |
                                    v
                         v0.2 provenance verifier
```

## Fail-closed rules

- Missing/invalid webhook signature: reject ingress.
- Unknown/inactive installation: do not create trusted source context or activate new policy.
- Repository identity mismatch: `INDETERMINATE`.
- Malformed trusted source context: `INDETERMINATE`.
- Source ref outside explicit organization policy: `REJECTED`.
- Missing active policy/source record: no verifier expectation is produced.
- Cross-repository policy activation: database foreign key rejects it.
- Unsupported/uncertain cryptographic provenance: `INDETERMINATE`.

## Explicit non-goals through v0.3

- No custody or movement of customer funds.
- No card/payment processing.
- No GitHub repository mutation or Check Run yet.
- No SBOM security claim yet.
- No dynamic code execution from webhook payloads.
