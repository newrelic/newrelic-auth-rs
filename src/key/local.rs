use crate::key::creator::{Creator, KeyPair, KeyType, PublicKeyPem};
use rcgen::KeyPair as RcKeyPair;
use rcgen::{RsaKeySize, PKCS_RSA_SHA512};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::debug;

/// Errors that can occur during local key creation.
#[derive(Error, Debug)]
pub enum LocalKeyCreationError {
    /// Error that occurs when path to store the key is invalid.
    #[error("invalid path: `{0}`")]
    InvalidPath(String),
    /// Error that occurs when key generation fails.
    #[error("unable to generate key: `{0}`")]
    UnableToGenerateKey(String),
    /// Error that occurs when the private key file cannot be created.
    #[error("unable to create private key file: `{0}`")]
    UnableToCreatePrivateKeyFile(String),
    /// Error that occurs when writing the private key fails.
    #[error("unable to write private key: `{0}`")]
    UnableToWritePrivateKey(String),
}

/// Options for creating a cryptographic key.
#[derive(Debug)]
pub struct KeyPairGeneratorLocalConfig {
    /// The type of key to be created.
    pub key_type: KeyType,
    /// The name associated with the key.
    pub name: String,
    /// The file path where the private key will be stored.
    pub path: PathBuf,
}

/// A creator for generating and managing cryptographic keys locally.
#[derive(Debug)]
pub struct LocalCreator {
    /// The type of key to be created.
    key_type: KeyType,
    /// The name associated with the key.
    name: String,
    /// The file path where the private key will be stored.
    path: PathBuf,
}

impl Creator for LocalCreator {
    type Error = LocalKeyCreationError;
    /// Creates a cryptographic key based on the provided options and stores the private key locally.
    ///
    /// Returns the public key in PEM format, or an error if key creation fails.
    fn create(&self) -> Result<PublicKeyPem, Self::Error> {
        let key_pair = match self.key_type {
            KeyType::Rsa4096 => rsa(&self.key_type)?,
        };

        self.persist_private_key(&key_pair.private_key)?;

        Ok(key_pair.public_key)
    }
}

impl LocalCreator {
    pub fn new(config: KeyPairGeneratorLocalConfig) -> Self {
        Self {
            key_type: config.key_type,
            name: config.name,
            path: config.path,
        }
    }

    /// Persists the private key to the specified file path.
    fn persist_private_key(&self, key: &[u8]) -> Result<(), LocalKeyCreationError> {
        debug!(
            "persisting local private key in {}",
            self.path.as_path().display()
        );
        Self::validate_path(self.path.as_path())?;

        let mut file = File::create(self.path.join(&self.name).as_path())
            .map_err(|e| LocalKeyCreationError::UnableToCreatePrivateKeyFile(e.to_string()))?;
        file.write_all(key)
            .map_err(|e| LocalKeyCreationError::UnableToWritePrivateKey(e.to_string()))?;
        Ok(())
    }

    fn validate_path(path: &Path) -> Result<(), LocalKeyCreationError> {
        if !path.exists() {
            return Err(LocalKeyCreationError::InvalidPath(String::from(
                "local key path does not exist",
            )));
        }
        if path.is_file() {
            return Err(LocalKeyCreationError::InvalidPath(String::from(
                "local key path needs to be a directory",
            )));
        }
        Ok(())
    }
}

/// Generates an RSA key pair based on the specified key type.
///
/// Returns the generated `KeyPair` or an error if key generation fails.
fn rsa(key_type: &KeyType) -> Result<KeyPair, LocalKeyCreationError> {
    let key_size = match key_type {
        KeyType::Rsa4096 => RsaKeySize::_4096,
    };

    let rsa = RcKeyPair::generate_rsa_for(&PKCS_RSA_SHA512, key_size)
        .map_err(|e| LocalKeyCreationError::UnableToGenerateKey(e.to_string()))?;

    Ok(KeyPair {
        private_key: rsa.serialize_pem().into_bytes(),
        public_key: rsa.public_key_pem().into_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use assert_matches::assert_matches;
    use tempfile::{NamedTempFile, TempDir};

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

    #[test]
    fn test_local_creator_create_invalid_path_non_existent() {
        let key_path = PathBuf::from("/tmp/non-existent-path");
        let config = KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            name: "key".to_string(),
            path: key_path.clone(),
        };
        let creator = LocalCreator::new(config);
        let result = creator.create();
        assert_matches!(
            result,
            Err(LocalKeyCreationError::InvalidPath(error_message)) => {
                assert_eq!(error_message, String::from("local key path does not exist"));
            }
        );
    }

    #[test]
    fn test_local_creator_create_invalid_path_file() {
        let tmp_file = NamedTempFile::new().unwrap();
        let config = KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            name: "key".to_string(),
            path: tmp_file.path().to_path_buf(),
        };
        let creator = LocalCreator::new(config);
        let result = creator.create();
        assert_matches!(
            result,
            Err(LocalKeyCreationError::InvalidPath(error_message)) => {
                assert_eq!(error_message, String::from("local key path needs to be a directory"));
            }
        );
    }

    #[test]
    fn test_local_creator_create() {
        let tmp_dir = TempDir::new().expect("Failed to create temp directory");
        let key_path = tmp_dir.path();

        let key_name = String::from("key");
        let config = KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            name: key_name.clone(),
            path: key_path.to_path_buf(),
        };

        let creator = LocalCreator::new(config);

        let pub_key = creator.create().expect("Failed to create key pair");
        let pub_key_content =
            String::from_utf8(pub_key.clone()).expect("Public key is not valid UTF-8");
        assert!(
            is_public_key_content(pub_key_content.as_str()),
            "invalid public key content"
        );

        let private_key_content: String =
            fs::read_to_string(key_path.join(key_name)).expect("Failed to load private key file");
        assert!(
            is_private_key_content(private_key_content.as_str()),
            "invalid private key content"
        );
    }

    fn is_private_key_content(content: &str) -> bool {
        content.starts_with("-----BEGIN PRIVATE KEY-----")
            && content.ends_with("-----END PRIVATE KEY-----\n")
    }

    fn is_public_key_content(content: &str) -> bool {
        content.starts_with("-----BEGIN PUBLIC KEY-----")
            && content.ends_with("-----END PUBLIC KEY-----\n")
    }
}
