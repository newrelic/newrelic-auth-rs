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
