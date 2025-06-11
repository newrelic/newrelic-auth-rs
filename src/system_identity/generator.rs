use std::fmt;

use thiserror::Error;

use crate::{key::creator::Creator as KeyCreator, token::Token};

use super::{
    SystemIdentity,
    identity_creator::{L1IdentityCreator, L2IdentityCreator},
};

/// This type is responsible for generating a System Identity and its associated key pair.
pub struct L2SystemIdentityGenerator<K, I>
where
    K: KeyCreator,
    I: L2IdentityCreator,
{
    pub key_creator: K,
    pub iam_client: I,
}

impl<K, I> L2SystemIdentityGenerator<K, I>
where
    K: KeyCreator,
    I: L2IdentityCreator,
{
    pub fn generate(
        &self,
        token: &Token,
    ) -> Result<SystemIdentity, SystemIdentityGenerationError<K, I>> {
        let pub_key = self
            .key_creator
            .create()
            .map_err(SystemIdentityGenerationError::KeyPairCreator)?;

        self.iam_client
            .create_l2_system_identity(token, pub_key.as_slice())
            .map_err(SystemIdentityGenerationError::IAMClient)
    }
}

pub struct L1SystemIdentityGenerator<I: L1IdentityCreator> {
    pub iam_client: I,
}

impl<I: L1IdentityCreator> L1SystemIdentityGenerator<I> {
    pub fn generate(&self, token: &Token) -> Result<SystemIdentity, I::Error> {
        self.iam_client.create_l1_system_identity(token)
    }
}

#[derive(Error)]
pub enum SystemIdentityGenerationError<K, I>
where
    K: KeyCreator,
    I: L2IdentityCreator,
{
    #[error("error creating key pair: `{0}`")]
    KeyPairCreator(K::Error),
    #[error("error retrieving the system identity: `{0}`")]
    IAMClient(I::Error),
}

impl<K, I> fmt::Debug for SystemIdentityGenerationError<K, I>
where
    K: KeyCreator,
    I: L2IdentityCreator,
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
