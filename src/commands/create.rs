use crate::http_client::HttpClient;
use crate::key::creator::KeyType;
use crate::key::local::{KeyPairGeneratorLocalConfig, LocalCreator};
use crate::system_identity::generator::{L1SystemIdentityGenerator, L2SystemIdentityGenerator};
use crate::system_identity::iam_client::http_impl::HttpIAMClient;
use crate::system_identity::input_data::output_platform::OutputPlatform;
use crate::system_identity::input_data::SystemIdentityCreationMetadata;
use crate::system_identity::SystemIdentity;
use crate::token::Token;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CreateError {
    #[error("creation error: `{0}`")]
    CreateError(String),
}

pub struct CreateCommand<C>
where
    C: HttpClient + Clone,
{
    http_client: C,
}
impl<C> CreateCommand<C>
where
    C: HttpClient + Clone,
{
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }

    pub fn create_l1_system_identity(
        &self,
        metadata: &SystemIdentityCreationMetadata,
        token: Token,
    ) -> Result<SystemIdentity, CreateError> {
        let iam_client = HttpIAMClient::new(self.http_client.clone(), metadata.to_owned());

        let system_identity_generator = L1SystemIdentityGenerator { iam_client };
        let identity = system_identity_generator
            .generate(&token)
            .map_err(|e| CreateError::CreateError(e.to_string()))?;
        Ok(identity)
    }
    pub fn create_l2_system_identity(
        &self,
        metadata: &SystemIdentityCreationMetadata,
        token: Token,
    ) -> Result<SystemIdentity, CreateError> {
        let iam_client = HttpIAMClient::new(self.http_client.clone(), metadata.to_owned());
        let output_key_path: &PathBuf;
        match &metadata.output_platform {
            OutputPlatform::LocalPrivateKeyPath(path) => {
                output_key_path = path;
            }
        }
        let key_creator = LocalCreator::from(KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            name: metadata.name.clone().unwrap_or_default(),
            path: output_key_path.to_path_buf(),
        });

        let system_identity_generator = L2SystemIdentityGenerator {
            iam_client,
            key_creator,
        };
        let identity = system_identity_generator
            .generate(&token)
            .map_err(|e| CreateError::CreateError(e.to_string()))?;
        Ok(identity)
    }
}
