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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
//     use crate::system_identity::input_data::environment::NewRelicEnvironment;
//     use crate::system_identity::input_data::output_platform::OutputPlatform;
//     use crate::system_identity::input_data::{SystemIdentityCreationMetadata, SystemIdentityInput};
//     use crate::token::{Token, TokenType};
//     use std::path::PathBuf;
//     use chrono::{Duration, Utc};
//     use crate::http_client::tests::MockHttpClient;
//     use crate::key::PrivateKeyPem;
// 
//     fn create_test_metadata(
//         auth_method_type: &str,
//         output_path_str: Option<&str>,
//         name: Option<String>,
//     ) -> SystemIdentityCreationMetadata {
//         let auth_method = if auth_method_type == "secret" {
//             AuthMethod::ClientSecret(ClientSecret::from("test_secret_value".to_string()))
//         } else {
//             AuthMethod::PrivateKey(PrivateKeyPem::from("test_pem_data".as_bytes().to_vec()))
//         };
// 
//         let output_platform = OutputPlatform::LocalPrivateKeyPath(
//             PathBuf::from(output_path_str.unwrap_or("./mp"))
//         );
// 
//         SystemIdentityCreationMetadata {
//             system_identity_input: SystemIdentityInput {
//                 organization_id: "org-id".to_string(),
//                 auth_method,
//                 client_id: "test_client_id".to_string(),
//             },
//             name: name.or_else(|| Some("default_test_name".to_string())),
//             environment: NewRelicEnvironment::US,
//             output_platform,
//         }
//     }
// 
//     fn dummy_token() -> Token {
//         Token::new("dummy-test-token".to_string(),TokenType::Bearer,Utc::now() + Duration::minutes(10))
//     }
// 
//     #[test]
//     fn test_create_l1_system_identity_success() {
//         let mock_http_client = MockHttpClient::new();
//         let command = CreateCommand::new(mock_http_client);
//         let metadata = create_test_metadata("secret", None, Some("l1_identity_test".to_string()));
//         let token = dummy_token();
//         let result = command.create_l1_system_identity(&metadata, token);
// 
//         if let Err(e) = &result {
//             eprintln!("L1 Success Test Failed: {:?}", e);
//         }
//         assert!(result.is_ok());
//     }
// 
//     #[test]
//     fn test_create_l2_system_identity_success() {
//         let mock_http_client = MockHttpClient::new();
//         let command = CreateCommand::new(mock_http_client);
//         let metadata = create_test_metadata("key", Some("/tmp/test_l2_output.pem"), Some("l2_identity_test".to_string()));
//         let token = dummy_token();
// 
//         let result = command.create_l2_system_identity(&metadata, token);
//         if let Err(e) = &result {
//             eprintln!("L2 Success Test Failed: {:?}", e);
//         }
//         assert!(result.is_ok());
//     }
// }