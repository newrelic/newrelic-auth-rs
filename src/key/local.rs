use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use rcgen::KeyPair as RcKeyPair;
use rcgen::{RsaKeySize, PKCS_RSA_SHA512};
use thiserror::Error;

use crate::key::creator::{CreationError, Creator, KeyPair, KeyType, Options, PublicKeyPem};

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

/// A creator for generating and managing cryptographic keys locally.
#[derive(Debug)]
pub struct LocalCreator {
    /// The file path where the private key will be stored.
    path: PathBuf,
}

impl Creator for LocalCreator {
    /// Creates a cryptographic key based on the provided options and stores the private key locally.
    ///
    /// Returns the public key in PEM format, or an error if key creation fails.
    fn create(&self, options: Options) -> Result<PublicKeyPem, CreationError> {
        let key_pair = match options.key_type {
            KeyType::Rsa4096 => rsa(options.key_type)?,
        };

        self.persist_private_key(options.name.as_str(), &key_pair.private_key)?;

        Ok(key_pair.public_key)
    }
}

impl TryFrom<PathBuf> for LocalCreator {
    type Error = LocalKeyCreationError;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        if !value.exists() {
            return Err(LocalKeyCreationError::InvalidPath(String::from(
                "local key path does not exist",
            )));
        }
        if value.is_file() {
            return Err(LocalKeyCreationError::InvalidPath(String::from(
                "local key path needs to be a directory",
            )));
        }
        Ok(LocalCreator { path: value })
    }
}

impl LocalCreator {
    /// Persists the private key to the specified file path.
    fn persist_private_key(&self, name: &str, key: &[u8]) -> Result<(), LocalKeyCreationError> {
        let mut file = File::create(&self.path.join(name).as_path())
            .map_err(|e| LocalKeyCreationError::UnableToCreatePrivateKeyFile(e.to_string()))?;
        file.write_all(key)
            .map_err(|e| LocalKeyCreationError::UnableToWritePrivateKey(e.to_string()))?;
        Ok(())
    }
}

impl From<LocalKeyCreationError> for CreationError {
    fn from(value: LocalKeyCreationError) -> Self {
        CreationError::UnableToCreateKey(value.to_string())
    }
}

/// Generates an RSA key pair based on the specified key type.
///
/// Returns the generated `KeyPair` or an error if key generation fails.
fn rsa(key_type: KeyType) -> Result<KeyPair, CreationError> {
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
        let key_pair = rsa(KeyType::Rsa4096).expect("Failed to generate RSA key pair");
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
        let creator = LocalCreator::try_from(key_path).unwrap_err();
        assert_matches!(
            creator,
            LocalKeyCreationError::InvalidPath(error_message) => {
                assert_eq!(error_message, String::from("local key path does not exist"));
            }
        );
    }

    #[test]
    fn test_local_creator_create_invalid_path_file() {
        let tmp_fie = NamedTempFile::new().unwrap();
        let creator = LocalCreator::try_from(tmp_fie.path().to_path_buf()).unwrap_err();
        assert_matches!(
            creator,
            LocalKeyCreationError::InvalidPath(error_message) => {
                assert_eq!(error_message, String::from("local key path needs to be a directory"));
            }
        );
    }

    #[test]
    fn test_local_creator_create() {
        let key_path = TempDir::new()
            .expect("Failed to create temp directory")
            .into_path();

        let creator =
            LocalCreator::try_from(key_path.clone()).expect("Failed to create local creator");

        let key_name = String::from("key");
        let options = Options {
            key_type: KeyType::Rsa4096,
            name: key_name.clone(),
        };

        let pub_key = creator.create(options).expect("Failed to create key pair");
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

    #[test]
    fn test_create_should_fail_on_persist() {
        let key_path = PathBuf::from("/tmp/non-existent-path/private.pem");

        let creator = LocalCreator {
            path: key_path.clone(),
        };

        let options = Options {
            key_type: KeyType::Rsa4096,
            name: "test_key".to_string(),
        };

        let result = creator.create(options).unwrap_err();

        assert_matches!(
            result,
            CreationError::UnableToCreateKey(error_message) => {
                assert_eq!(error_message, String::from("unable to create private key file: `No such file or directory (os error 2)`"));
            }
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
