use super::{
    SystemIdentity,
    iam_client::http::IAMAuthCredential,
    identity_creator::{L1IdentityCreator, L2IdentityCreator},
};
use crate::key::creator::Creator as KeyCreator;
use std::fmt;
use thiserror::Error;

/// This type is responsible for generating a System Identity and its associated key pair.
pub struct L2SystemIdentityGenerator<'a, K, I>
where
    K: KeyCreator,
    I: L2IdentityCreator,
{
    pub key_creator: K,
    pub iam_client: &'a I,
}

impl<K, I> L2SystemIdentityGenerator<'_, K, I>
where
    K: KeyCreator,
    I: L2IdentityCreator,
{
    pub fn generate(
        &self,
        auth_credential: &IAMAuthCredential,
    ) -> Result<SystemIdentity, SystemIdentityGenerationError<K, I>> {
        let pub_key = self
            .key_creator
            .create()
            .map_err(SystemIdentityGenerationError::KeyPairCreator)?;

        self.iam_client
            .create_l2_system_identity(auth_credential, pub_key.as_slice())
            .map_err(SystemIdentityGenerationError::IAMClient)
    }
}

pub struct L1SystemIdentityGenerator<'a, I: L1IdentityCreator> {
    pub iam_client: &'a I,
}

impl<I: L1IdentityCreator> L1SystemIdentityGenerator<'_, I> {
    pub fn generate(
        &self,
        auth_credential: &IAMAuthCredential,
    ) -> Result<SystemIdentity, I::Error> {
        self.iam_client.create_l1_system_identity(auth_credential)
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
