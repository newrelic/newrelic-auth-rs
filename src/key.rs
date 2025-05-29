use crate::jwt::signer::local::{LocalPrivateKeySigner, LocalPrivateKeySignerError};

pub mod creator;
pub mod local;

/// Represents a PEM-encoded private key "byte string".
#[derive(Clone, PartialEq)]
pub struct PrivateKeyPem(Vec<u8>);

impl<S: AsRef<[u8]>> From<S> for PrivateKeyPem {
    fn from(key: S) -> Self {
        PrivateKeyPem(key.as_ref().to_vec())
    }
}

impl TryFrom<PrivateKeyPem> for LocalPrivateKeySigner {
    type Error = LocalPrivateKeySignerError;
    fn try_from(value: PrivateKeyPem) -> Result<Self, Self::Error> {
        Self::try_from(value.0.as_slice())
    }
}

impl TryFrom<&PrivateKeyPem> for LocalPrivateKeySigner {
    type Error = LocalPrivateKeySignerError;
    fn try_from(value: &PrivateKeyPem) -> Result<Self, Self::Error> {
        Self::try_from(value.0.as_slice())
    }
}
