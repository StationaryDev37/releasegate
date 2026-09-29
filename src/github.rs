use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_webhook_signature(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.strip_prefix("sha256=") else { return false; };
    let Ok(provided) = hex::decode(hex_sig) else { return false; };
    if provided.len() != 32 { return false; }

    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else { return false; };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::verify_webhook_signature;

    #[test]
    fn accepts_known_github_vector() {
        let secret = b"It's a Secret to Everybody";
        let payload = b"Hello, World!";
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(verify_webhook_signature(secret, payload, sig));
    }

    #[test]
    fn rejects_modified_payload() {
        let secret = b"It's a Secret to Everybody";
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(!verify_webhook_signature(secret, b"Hello, World?", sig));
    }
}
