pub struct KeyPair {
    pub_key: String,
    // Should we add private key related info to use this?
    // private_key_path:
    // vendored_key_info: {}
}

/// Generates Key Pairs returning the Public Key
pub trait KeyPairGenerator {
    fn generate(&self) -> Result<KeyPair, KeyPairGeneratorError>;
}
pub trait KeyPairGeneratorBuilder {
    fn build(&self, config: &KeyPairGeneratorConfigImpl) -> Result<KeyPair, KeyPairGeneratorError>;
}

pub enum KeyPairGeneratorConfigImpl {
    Local(KeyPairGeneratorLocalConfig),
    // Vault(KeyPairGeneratorVaultConfig)
}

pub struct KeyPairGeneratorLocalConfig();

#[derive(thiserror::Error, Debug)]
pub enum KeyPairGeneratorError {
    #[error("TBD: `{0}`")]
    KeyPairGenerationError(String),
}
