use std::fmt;

use serde::{Deserialize, Serialize};

use crate::jwt::signer::local::{LocalPrivateKeySigner, LocalPrivateKeySignerError};

/// Represents the supported authentication methods with which a System Identity can be created.
#[derive(Clone, PartialEq)]
pub enum AuthMethod {
    ClientSecret(ClientSecret), // L1 method
    PrivateKey(PrivateKeyPem),  // L2 method
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::ClientSecret(_) => write!(f, "ClientSecret: redacted"),
            AuthMethod::PrivateKey(_) => write!(f, "FromLocal: redacted"),
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientSecret(String); // TODO is String the correct inner representation and input type?

impl<S: AsRef<str>> From<S> for ClientSecret {
    fn from(secret: S) -> Self {
        ClientSecret(secret.as_ref().to_string())
    }
}

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
