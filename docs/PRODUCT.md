# Product Positioning

## What ReleaseGate is

ReleaseGate is an auditable policy-decision layer for software releases. It consumes trusted build/provenance evidence, evaluates organization policy, records a deterministic decision receipt, and exposes that decision to CI/CD and audit systems.

## What ReleaseGate is not

- Not another provenance-signing system.
- Not a replacement for GitHub Artifact Attestations or Sigstore.
- Not a vulnerability scanner pretending provenance means security.
- Not a payment processor or custodian of customer funds.

## Commercial wedge

Native provenance systems answer: **where/how was this artifact built?**

ReleaseGate must answer: **given provenance + SBOM + repository + organization policy, may this exact artifact be released, and can we prove later why the decision was made?**

The paid value is the decision/audit layer across repositories and environments:

- centralized policy
- deterministic receipts
- deployment/release gating
- audit retention/export
- organization-level reporting
- eventually multi-provider evidence (GitHub, GitLab, registries, cloud build systems)

## Billing shape

GitHub Marketplace is suitable for discovery and subscription billing. Current Marketplace plan types are free, flat-rate, or per-unit; the v0.1 `usage_events` table is therefore an internal quota/analytics meter, not a claim that GitHub bills per verification.

Initial commercial packaging should favor flat-rate tiers by repository/organization size. True usage-based billing can be added through a billing rail that explicitly supports metered consumption.
