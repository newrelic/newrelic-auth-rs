use rcgen::{KeyPair as RcKeyPair, PKCS_RSA_SHA512, RsaKeySize};

use crate::key::creator::{KeyPair, KeyType};

/// Generates an RSA key pair based on the specified key type.
///
/// Returns the generated `KeyPair` or an error if key generation fails.
pub fn rsa(key_type: &KeyType) -> Result<KeyPair, Box<dyn std::error::Error>> {
    let key_size = match key_type {
        KeyType::Rsa4096 => RsaKeySize::_4096,
    };

    let rsa = RcKeyPair::generate_rsa_for(&PKCS_RSA_SHA512, key_size)?;

    Ok(KeyPair {
        private_key: rsa.serialize_pem().into_bytes(),
        public_key: rsa.public_key_pem().into_bytes(),
    })
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;

    #[test]
    fn test_rsa_key_generation() {
        let key_pair = rsa(&KeyType::Rsa4096).expect("Failed to generate RSA key pair");
        // Assert on private and public key content
        let priv_key = String::from_utf8(key_pair.private_key.clone()).expect("invalid utf8");
        assert!(
            is_private_key_content(priv_key.as_str()),
            "invalid private key content"
        );

        let pub_key = String::from_utf8(key_pair.public_key.clone()).expect("invalid utf8");
        assert!(
            is_public_key_content(pub_key.as_str()),
            "invalid public key content"
        );
    }

    pub(crate) fn is_private_key_content(content: &str) -> bool {
        let trimmed = content.trim_end();
        trimmed.starts_with("-----BEGIN PRIVATE KEY-----")
            && trimmed.ends_with("-----END PRIVATE KEY-----")
    }

    pub(crate) fn is_public_key_content(content: &str) -> bool {
        let trimmed = content.trim_end();
        trimmed.starts_with("-----BEGIN PUBLIC KEY-----")
            && trimmed.ends_with("-----END PUBLIC KEY-----")
    }
}
