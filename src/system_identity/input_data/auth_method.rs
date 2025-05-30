use std::fmt;

use serde::{Deserialize, Serialize};

use crate::key::PrivateKeyPem;

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

impl fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientSecret: redacted")
    }
}
