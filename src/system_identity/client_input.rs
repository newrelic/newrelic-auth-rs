use super::environment::SystemIdentityCreationEnvironment;

/// Represents the input data required to create a System Identity.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationMetadata {
    pub name: String,
    pub organization_id: String,
    pub client_id: String,
    pub auth_method: AuthMethod,
    pub environment: SystemIdentityCreationEnvironment,
}

type ClientSecret = String; // TODO type better
type PrivateKeyPem = Vec<u8>; // TODO Type better

#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    ClientSecret(ClientSecret),         // L1 method
    FromLocalPrivateKey(PrivateKeyPem), // L2 method
}
