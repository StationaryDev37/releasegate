use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceTruth {
    Verified,
    Invalid,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyAuthorization {
    Allow,
    Deny,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseDecision {
    Release,
    Block,
    Hold,
}

#[must_use]
pub const fn compose(truth: EvidenceTruth, authorization: PolicyAuthorization) -> ReleaseDecision {
    use EvidenceTruth::{Indeterminate as TruthUnknown, Invalid, Verified};
    use PolicyAuthorization::{Allow, Deny, Indeterminate as PolicyUnknown};
    use ReleaseDecision::{Block, Hold, Release};

    match (truth, authorization) {
        (Verified, Allow) => Release,
        (Invalid, _) | (_, Deny) => Block,
        (Verified, PolicyUnknown)
        | (TruthUnknown, Allow)
        | (TruthUnknown, PolicyUnknown) => Hold,
    }
}

#[cfg(test)]
mod tests {
    use super::{compose, EvidenceTruth, PolicyAuthorization, ReleaseDecision};

    #[test]
    fn only_verified_and_allowed_releases() {
        let truths = [
            EvidenceTruth::Verified,
            EvidenceTruth::Invalid,
            EvidenceTruth::Indeterminate,
        ];
        let policies = [
            PolicyAuthorization::Allow,
            PolicyAuthorization::Deny,
            PolicyAuthorization::Indeterminate,
        ];
        let mut releases = 0;
        for truth in truths {
            for policy in policies {
                if compose(truth, policy) == ReleaseDecision::Release {
                    releases += 1;
                    assert_eq!(truth, EvidenceTruth::Verified);
                    assert_eq!(policy, PolicyAuthorization::Allow);
                }
            }
        }
        assert_eq!(releases, 1);
    }

    #[test]
    fn explicit_denial_blocks_even_when_truth_is_unknown() {
        assert_eq!(
            compose(EvidenceTruth::Indeterminate, PolicyAuthorization::Deny),
            ReleaseDecision::Block
        );
    }
}
