/// Represents the type of cryptographic key to be created.
#[derive(Debug)]
pub enum KeyType {
    /// RSA key with a size of 4096 bits.
    Rsa4096,
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

/// A trait for creating cryptographic keys.
pub trait Creator {
    type Error;
    /// Creates and persists a cryptographic key based on the provided options. The created private
    /// key will not be accessible/exposed. Depending on the implementation it could be accessible
    /// (i.e. Local key pair) but others like Vault, KMS... will not. In any case, the private key
    /// will not be exposed.
    ///
    /// Return created public key in PEM format, or an error if key creation fails.
    fn create(&self) -> Result<PublicKeyPem, Self::Error>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::mock;

    mock! {
        pub Creator {}
        impl Creator for Creator {
            type Error = String;
            fn create(&self) -> Result<PublicKeyPem, String>;
        }
    }
}
