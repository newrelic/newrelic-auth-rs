use crate::http_client::HttpClient;
use crate::key::creator::KeyType;
use crate::key::local::{KeyPairGeneratorLocalConfig, LocalCreator};
use crate::system_identity::client_input::{AuthMethod, SystemIdentityCreationMetadata};
use crate::system_identity::generator::{L1SystemIdentityGenerator, L2SystemIdentityGenerator};
use crate::system_identity::iam_client::http_iam_client::HttpIAMClient;
use crate::system_identity::iam_client::http_token_retriever::HttpTokenRetriever;
use crate::system_identity::iam_client::l1_creator::L1IdentityCreator;
use crate::system_identity::iam_client::l2_creator::L2IdentityCreator;
use crate::system_identity::output_platform::AuthOutputPlatform;
use std::path::PathBuf;

pub struct CreateCommand<C>
where
    C: HttpClient,
{
    http_client: C,
}
impl<C> CreateCommand<C>
where
    C: HttpClient,
{
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }

    pub fn create(
        &self,
        metadata: &SystemIdentityCreationMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let http_token_retriever = HttpTokenRetriever::new(&self.http_client, &metadata);

        let iam_client =
            HttpIAMClient::new(&self.http_client, http_token_retriever, metadata.to_owned());
        if matches!(metadata.auth_method, AuthMethod::ClientSecret(_)) {
            let system_identity_generator = L1SystemIdentityGenerator { iam_client };
            system_identity_generator.generate()?
        } else {
            let output_key_path: &PathBuf;
            match &metadata.output_platform {
                AuthOutputPlatform::LocalPrivateKeyPath(path) => {
                    output_key_path = path;
                }
            }
            let key_creator = LocalCreator::from(KeyPairGeneratorLocalConfig {
                key_type: KeyType::Rsa4096,
                name: metadata.name.to_string(),
                path: output_key_path.to_path_buf(),
            });

            let system_identity_generator = L2SystemIdentityGenerator {
                iam_client,
                key_creator,
            };

            system_identity_generator.generate()?
        }
    }
}
