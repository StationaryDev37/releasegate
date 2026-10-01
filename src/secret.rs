use std::fmt;

use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(value: String) -> Result<Self, &'static str> {
        let bytes = value.into_bytes();
        if bytes.len() < 32 {
            return Err("secret must be at least 32 bytes");
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        let expected = sha2::Sha256::digest(self.as_bytes());
        let provided = sha2::Sha256::digest(candidate.as_bytes());
        bool::from(expected.ct_eq(&provided))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

use sha2::Digest as _;
