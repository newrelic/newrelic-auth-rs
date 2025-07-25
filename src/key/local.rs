use crate::key::creator::{Creator, KeyPair, KeyType, PublicKeyPem};
use rcgen::KeyPair as RcKeyPair;
use rcgen::{PKCS_RSA_SHA512, RsaKeySize};
use std::fs::{self, File};
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
    /// The file path where the private key will be stored.
    pub file_path: PathBuf,
}

/// A creator for generating and managing cryptographic keys locally.
#[derive(Debug)]
pub struct LocalCreator {
    /// The type of key to be created.
    key_type: KeyType,
    /// The file path where the private key will be stored.
    file_path: PathBuf,
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

impl From<KeyPairGeneratorLocalConfig> for LocalCreator {
    fn from(
        KeyPairGeneratorLocalConfig {
            key_type,
            file_path: path,
        }: KeyPairGeneratorLocalConfig,
    ) -> Self {
        Self {
            key_type,
            file_path: path,
        }
    }
}

impl LocalCreator {
    /// Persists the private key to the specified file path.
    fn persist_private_key(&self, key: &[u8]) -> Result<(), LocalKeyCreationError> {
        Self::validate_path(&self.file_path)?;

        debug!(
            "persisting local private key in {}",
            self.file_path.display()
        );
        let parent_dir = self.file_path.parent().ok_or_else(|| {
            LocalKeyCreationError::InvalidPath(String::from(
                "local key path parent directory does not exist or is not a directory",
            ))
        })?;
        fs::create_dir_all(parent_dir)
            .map_err(|e| LocalKeyCreationError::UnableToCreatePrivateKeyFile(e.to_string()))?;

        let mut file = File::create(&self.file_path)
            .map_err(|e| LocalKeyCreationError::UnableToCreatePrivateKeyFile(e.to_string()))?;
        file.write_all(key)
            .map_err(|e| LocalKeyCreationError::UnableToWritePrivateKey(e.to_string()))
    }

    fn validate_path(path: &Path) -> Result<(), LocalKeyCreationError> {
        // Filename should not exist already
        if path.exists() {
            Err(LocalKeyCreationError::InvalidPath(String::from(
                "local key path already exists",
            )))
        } else {
            Ok(())
        }
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
    use tempfile::{NamedTempFile, TempDir, tempdir};

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
    fn test_local_creator_create_path_on_non_existent_parent_dir() {
        let tmp_dir = tempdir().unwrap();
        let key_path = tmp_dir.path().join("ad-hoc-dir").join("key-filename");

        let config = KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            file_path: key_path,
        };
        let creator = LocalCreator::from(config);
        let result = creator.create();
        assert!(result.is_ok());
    }

    #[test]
    fn test_local_creator_create_file_already_exists() {
        let tmp_file = NamedTempFile::new().unwrap();
        let config = KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            file_path: tmp_file.path().to_path_buf(),
        };
        let creator = LocalCreator::from(config);
        let result = creator.create();
        assert_matches!(
            result,
            Err(LocalKeyCreationError::InvalidPath(error_message)) => {
                assert_eq!(error_message, String::from("local key path already exists"));
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
            file_path: key_path.join(&key_name),
        };

        let creator = LocalCreator::from(config);

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
