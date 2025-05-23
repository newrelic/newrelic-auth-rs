use thiserror::Error;

use crate::key::creator::Creator as KeyCreator;

use super::{
    iam_client::{response_data::SystemIdentityCreationResponseData, IAMClient},
    SystemIdentity,
};

#[derive(Debug, Clone, Error)]
pub enum SystemIdentityGenerationError {
    // This should probably leverage associated types for the involved traits, so we
    // can gain automatic conversions via #[from] annotations...
    #[error("error creating key pair: `{0}`")]
    KeyPairCreator(String),
    #[error("error retrieving the system identity: `{0}`")]
    IAMClient(String),
}

pub struct SystemIdentityGenerator<K, I>
where
    K: KeyCreator,
    I: IAMClient,
{
    pub(super) key_creator: K,
    pub(super) iam_client: I,
}

impl<K, I> SystemIdentityGenerator<K, I>
where
    K: KeyCreator,
    I: IAMClient,
{
    pub fn generate(self) -> Result<SystemIdentity, SystemIdentityGenerationError> {
        let pub_key = self.key_creator.create().map_err(|_| {
            SystemIdentityGenerationError::KeyPairCreator(String::from(
                "Could not obtain public key",
            ))
        })?; // FIXME Creator::Error does not implement std::error::Error, should be convertible to something we can work with
        let SystemIdentityCreationResponseData { client_id, name } = self
            .iam_client
            .create_system_identity(pub_key.as_slice())
            .map_err(|e| SystemIdentityGenerationError::IAMClient(e.to_string()))?;

        Ok(SystemIdentity {
            name,
            client_id,
            pub_key,
        })
    }
}
