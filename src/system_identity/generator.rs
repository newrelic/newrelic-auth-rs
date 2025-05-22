use thiserror::Error;

use crate::{key::creator::Creator as KeyCreator, TokenRetriever};

use super::{
    iam_client::{IAMClient, SystemIdentityCreationResponseData},
    SystemIdentity,
};

#[derive(Debug, Clone, Error)]
pub enum SystemIdentityGenerationError {
    // This should probably leverage associated types for the involved traits, so we
    // can gain automatic conversions via #[from] annotations...
    #[error("error retrieving token: `{0}`")]
    TokenRetriever(String),
    #[error("error creating key pair: `{0}`")]
    KeyPairCreator(String),
    #[error("error retrieving the system identity: `{0}`")]
    IAMClient(String),
}

pub struct SystemIdentityGenerator<K, T, I>
where
    K: KeyCreator,
    T: TokenRetriever,
    I: IAMClient,
{
    pub(super) key_creator: K,
    pub(super) token_retriever: T,
    pub(super) iam_client: I,
}

impl<K, T, I> SystemIdentityGenerator<K, T, I>
where
    K: KeyCreator,
    T: TokenRetriever,
    I: IAMClient,
{
    pub fn generate(self) -> Result<SystemIdentity, SystemIdentityGenerationError> {
        let token = self
            .token_retriever
            .retrieve()
            .map_err(|e| SystemIdentityGenerationError::TokenRetriever(e.to_string()))?;
        let pub_key = self.key_creator.create().map_err(|_| {
            SystemIdentityGenerationError::KeyPairCreator(String::from(
                "Could not obtain public key",
            ))
        })?; // FIXME Creator::Error does not implement std::error::Error, should be convertible to something we can work with
        let SystemIdentityCreationResponseData { client_id, name } = self
            .iam_client
            .create_system_identity(token.access_token(), pub_key.as_slice())
            .map_err(|e| SystemIdentityGenerationError::IAMClient(e.to_string()))?;

        Ok(SystemIdentity {
            name,
            client_id,
            pub_key,
        })
    }
}
