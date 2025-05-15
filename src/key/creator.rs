use thiserror::Error;

/// Represents the type of cryptographic key to be created.
pub enum KeyType {
    /// RSA key with a size of 4096 bits.
    Rsa4096,
}

/// Options for creating a cryptographic key.
pub struct Options {
    /// The type of key to be created.
    pub key_type: KeyType,
    /// The name associated with the key.
    pub name: String,
}

/// A PEM-encoded public key.
pub type PublicKeyPem = Vec<u8>;

/// A PEM-encoded private key.
pub type PrivateKeyPem = Vec<u8>;

/// A pair of cryptographic keys, consisting of a private key and a public key.
pub struct KeyPair {
    /// The private key in PEM format.
    pub private_key: PrivateKeyPem,
    /// The public key in PEM format.
    pub public_key: PublicKeyPem,
}

/// Errors that can occur during key creation.
#[derive(Error, Debug)]
pub enum CreationError {
    /// Indicates that the key could not be created, with a specific error message.
    #[error("unable to create key: `{0}`")]
    UnableToCreateKey(String),
}

/// A trait for creating cryptographic keys.
pub trait Creator {
    /// Creates a cryptographic key based on the provided options.
    ///
    /// Return created public key in PEM format, or an error if key creation fails.
    fn create(&self, options: Options) -> Result<PublicKeyPem, CreationError>;
}
