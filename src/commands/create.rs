use crate::http_client::HttpClient;
use crate::key::creator::KeyType;
use crate::key::local::{KeyPairGeneratorLocalConfig, LocalCreator};
use crate::system_identity::SystemIdentity;
use crate::system_identity::generator::{L1SystemIdentityGenerator, L2SystemIdentityGenerator};
use crate::system_identity::iam_client::http::HttpIAMClient;
use crate::system_identity::input_data::SystemIdentityCreationMetadata;
use crate::system_identity::input_data::output_platform::OutputPlatform;
use crate::token::Token;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CreateError {
    #[error("creation error: `{0}`")]
    CreateError(String),
}

pub struct CreateCommand<C>
where
    C: HttpClient,
{
    iam_client: HttpIAMClient<C>,
}

impl<C> CreateCommand<C>
where
    C: HttpClient,
{
    pub fn new(iam_client: HttpIAMClient<C>) -> Self {
        Self { iam_client }
    }

    pub fn create_l1_system_identity(self, token: Token) -> Result<SystemIdentity, CreateError> {
        L1SystemIdentityGenerator {
            iam_client: self.iam_client,
        }
        .generate(&token)
        .map_err(|e| CreateError::CreateError(e.to_string()))
    }
    pub fn create_l2_system_identity(
        self,
        metadata: &SystemIdentityCreationMetadata,
        token: Token,
    ) -> Result<SystemIdentity, CreateError> {
        let output_key_path = match &metadata.output_platform {
            OutputPlatform::LocalPrivateKeyPath(path) => path,
        }
        .to_path_buf();

        let key_creator = LocalCreator::from(KeyPairGeneratorLocalConfig {
            key_type: KeyType::Rsa4096,
            path: output_key_path,
        });

        L2SystemIdentityGenerator {
            key_creator,
            iam_client: self.iam_client,
        }
        .generate(&token)
        .map_err(|e| CreateError::CreateError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::create::CreateError::CreateError;
    use crate::http_client::tests::MockHttpClient;
    use crate::system_identity::input_data::environment::NewRelicEnvironment;
    use crate::system_identity::input_data::output_platform::OutputPlatform;
    use crate::system_identity::input_data::{SystemIdentityCreationMetadata, SystemIdentityInput};
    use crate::system_identity::{ClientSecret, SystemIdentityType};
    use crate::token::{Token, TokenType};
    use chrono::{Duration, Utc};
    use http::Response;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn create_test_metadata(
        output_path: PathBuf,
        name: Option<String>,
    ) -> SystemIdentityCreationMetadata {
        let output_platform = OutputPlatform::LocalPrivateKeyPath(output_path);

        SystemIdentityCreationMetadata {
            system_identity_input: SystemIdentityInput {
                organization_id: "org-id".to_string(),
                client_id: "test_client_id".to_string(),
            },
            name: name.or_else(|| Some("default_test_name".to_string())),
            environment: NewRelicEnvironment::Staging,
            output_platform,
        }
    }

    fn dummy_token() -> Token {
        Token::new(
            "dummy-test-token".to_string(),
            TokenType::Bearer,
            Utc::now() + Duration::minutes(10),
        )
    }

    fn setup_mock_http_client(expected_response: &'static str) -> MockHttpClient {
        let response_body_bytes = expected_response.as_bytes().to_vec();
        let mut mock_http_client = MockHttpClient::default();
        mock_http_client.expect_send().once().returning(move |_| {
            let response = Response::builder()
                .status(200)
                .body(response_body_bytes.clone())
                .unwrap();
            Ok(response)
        });
        mock_http_client
    }

    #[test]
    fn test_create_l1_system_identity_success() {
        let metadata =
            create_test_metadata(PathBuf::default(), Some("l1_identity_test".to_string()));
        let expected_identity = SystemIdentity {
            id: "identity-123".to_string(),
            name: Some("test-identity".to_string()),
            client_id: "client-abc-789".to_string(),
            organization_id: "org-xyz-456".to_string(),
            identity_type: SystemIdentityType::L1 {
                client_secret: ClientSecret::from("ssh-rsa".to_string()),
                credential_expiration: "2025-12-31T23:59:59Z".to_string(),
            },
        };

        let full_expected_response = r#"
        {
          "data": {
            "systemIdentityCreate": {
              "clientId": "client-abc-789",
              "id": "identity-123",
              "name": "test-identity",
              "organizationId": "org-xyz-456",
              "clientSecret": "ssh-rsa",
              "credentialExpiration": "2025-12-31T23:59:59Z"
            }
          }
        }
        "#;

        let mock_http_client = setup_mock_http_client(full_expected_response);
        let iam_client = HttpIAMClient::new(mock_http_client, metadata.clone());
        let command = CreateCommand::new(iam_client);
        let token = dummy_token();
        let result = command.create_l1_system_identity(token);
        assert!(
            result.is_ok(),
            "L1 creation failed when it should have succeeded. Error: {:?}",
            result.err()
        );

        assert_eq!(result.unwrap(), expected_identity);
    }
    #[test]
    fn test_create_l2_system_identity_success() {
        let tmp_dir = tempdir().unwrap();
        let metadata = create_test_metadata(
            tmp_dir.path().join("test-key"),
            Some("l2_identity_test".to_string()),
        );
        let expected_identity = SystemIdentity {
            id: "identity-123".to_string(),
            name: Some("test-identity".to_string()),
            client_id: "client-abc-789".to_string(),
            organization_id: "org-xyz-456".to_string(),
            identity_type: SystemIdentityType::L2 {
                pub_key: "cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==".to_string(),
            },
        };

        let full_expected_response = r#"
        {
          "data": {
            "systemIdentityCreate": {
              "clientId": "client-abc-789",
              "publicKey": "cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==",
              "id": "identity-123",
              "name": "test-identity",
              "organizationId": "org-xyz-456"
            }
          }
        }
        "#;

        let mock_http_client = setup_mock_http_client(full_expected_response);
        let iam_client = HttpIAMClient::new(mock_http_client, metadata.clone());
        let command = CreateCommand::new(iam_client);
        let token = dummy_token();

        let result = command.create_l2_system_identity(&metadata, token);
        assert!(
            result.is_ok(),
            "L2 creation failed when it should have succeeded. Error: {:?}",
            result.err()
        );

        assert_eq!(result.unwrap(), expected_identity);
    }
    #[test]
    fn test_create_l2_system_identity_malformed_response() {
        let tmp_dir = tempdir().unwrap();
        let metadata = create_test_metadata(
            tmp_dir.path().join("test-key"),
            Some("l2_identity_test".to_string()),
        );
        let malformed_response = "{ invalid json }";

        let mock_http_client = setup_mock_http_client(malformed_response);
        let iam_client = HttpIAMClient::new(mock_http_client, metadata.clone());
        let command = CreateCommand::new(iam_client);
        let token = dummy_token();
        let result = command.create_l2_system_identity(&metadata, token);

        assert!(
            matches!(result, Err(CreateError(_))),
            "Expected a CreateError."
        );
    }
    #[test]
    fn test_create_identity_with_empty_metadata() {
        let tmp_dir = tempdir().unwrap();
        let metadata = create_test_metadata(tmp_dir.path().join("test-key"), None);
        let mock_http_client = setup_mock_http_client("");
        let iam_client = HttpIAMClient::new(mock_http_client, metadata.clone());
        let command = CreateCommand::new(iam_client);
        let token = dummy_token();

        let result_l1 = command.create_l1_system_identity(token.clone());
        assert!(
            result_l1.is_err(),
            "Expected error with empty metadata for L1"
        );
    }
}
