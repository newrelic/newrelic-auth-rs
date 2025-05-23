use std::fmt;

use thiserror::Error;

use crate::key::creator::Creator as KeyCreator;

use super::{
    iam_client::{response_data::SystemIdentityCreationResponseData, IAMClient},
    SystemIdentity,
};

#[derive(Error)]
pub enum SystemIdentityGenerationError<K, I>
where
    K: KeyCreator,
    I: IAMClient,
{
    #[error("error creating key pair: `{0}`")]
    KeyPairCreator(K::Error),
    #[error("error retrieving the system identity: `{0}`")]
    IAMClient(I::Error),
}

impl<K, I> fmt::Debug for SystemIdentityGenerationError<K, I>
where
    K: KeyCreator,
    I: IAMClient,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemIdentityGenerationError::KeyPairCreator(err) => f
                .debug_tuple("SystemIdentityGenerationError::KeyPairCreator")
                .field(err)
                .finish(),
            SystemIdentityGenerationError::IAMClient(err) => f
                .debug_tuple("SystemIdentityGenerationError::IAMClient")
                .field(err)
                .finish(),
        }
    }
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
    pub fn generate(self) -> Result<SystemIdentity, SystemIdentityGenerationError<K, I>> {
        let pub_key = self
            .key_creator
            .create()
            .map_err(SystemIdentityGenerationError::KeyPairCreator)?; // FIXME Creator::Error does not implement std::error::Error, should be convertible to something we can work with
        let SystemIdentityCreationResponseData { client_id, name } = self
            .iam_client
            .create_system_identity(pub_key.as_slice())
            .map_err(SystemIdentityGenerationError::IAMClient)?;

        Ok(SystemIdentity {
            name,
            client_id,
            pub_key,
        })
    }
}
