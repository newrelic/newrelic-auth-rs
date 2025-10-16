use crate::authenticator::Authenticator;
use crate::jwt::signer::JwtSignerImpl;
use crate::jwt::signer::local::LocalPrivateKeySigner;
use crate::system_identity::input_data::SystemTokenCreationMetadata;
use crate::system_identity::input_data::auth_method::AuthMethod;
use crate::token::Token;
use crate::token_retriever::TokenRetrieverWithCache;
use crate::{TokenRetriever, TokenRetrieverError};

pub struct RetrieveTokenCommand<A>
where
    A: Authenticator,
{
    authenticator: A,
}

impl<A> RetrieveTokenCommand<A>
where
    A: Authenticator,
{
    pub fn new(authenticator: A) -> Self {
        Self { authenticator }
    }

    pub fn retrieve_token(
        self,
        metadata: &SystemTokenCreationMetadata,
    ) -> Result<Token, TokenRetrieverError> {
        let token_result = match &metadata.auth_method {
            AuthMethod::ClientSecret(client_secret) => {
                let retriever = TokenRetrieverWithCache::new_with_secret(
                    metadata.client_id.to_owned(),
                    self.authenticator,
                    client_secret.to_owned(),
                );
                retriever.retrieve()
            }
            AuthMethod::PrivateKey(private_key_pem) => {
                let jwt_signer = JwtSignerImpl::Local(
                    LocalPrivateKeySigner::try_from(private_key_pem)
                        .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?,
                );
                let retriever = TokenRetrieverWithCache::new_with_jwt_signer(
                    metadata.client_id.to_owned(),
                    self.authenticator,
                    jwt_signer,
                );
                retriever.retrieve()
            }
        };

        token_result.map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::authenticator::HttpAuthenticator;
    use crate::commands::retrieve_token::RetrieveTokenCommand;
    use crate::http_client::HttpClientError;
    use crate::http_client::tests::MockHttpClient;
    use crate::jwt::signer::local::test::RS256_PRIVATE_KEY;
    use crate::system_identity::input_data::SystemTokenCreationMetadata;
    use crate::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
    use crate::system_identity::input_data::environment::NewRelicEnvironment;
    use http::Response;
    use mockall::predicate::*;

    fn create_test_metadata(auth_method_type: &str) -> SystemTokenCreationMetadata {
        let auth_method = if auth_method_type == "secret" {
            AuthMethod::ClientSecret(ClientSecret::from("test_secret_value".to_string()))
        } else {
            AuthMethod::PrivateKey(crate::key::PrivateKeyPem::from(
                RS256_PRIVATE_KEY.as_bytes().to_vec(),
            ))
        };

        SystemTokenCreationMetadata {
            client_id: "test_client_id".to_string(),
            environment: NewRelicEnvironment::US,
            auth_method,
        }
    }

    #[test]
    fn test_retrieve_token_with_client_secret_success() {
        let mut mock_http_client = MockHttpClient::default();
        mock_http_client.expect_send().times(1).returning(|_| {
            let json_body =
                r#"{"access_token":"retrieved_secret_token","token_type":"Bearer","expires_in":1749662727}"#;
            let response = Response::builder()
                .status(200)
                .body(json_body.as_bytes().to_vec())
                .unwrap();
            Ok(response)
        });
        let metadata = create_test_metadata("secret");
        let http_authenticator = HttpAuthenticator::new(
            mock_http_client,
            metadata.environment.token_renewal_endpoint(),
        );
        let command = RetrieveTokenCommand::new(http_authenticator);

        let result = command.retrieve_token(&metadata);

        assert!(result.is_ok(), "Token retrieval should succeed");
        let token = result.unwrap();
        assert_eq!(token.access_token(), "retrieved_secret_token");
    }

    #[test]
    fn test_retrieve_token_with_private_key_success() {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client.expect_send().times(1).returning(|_| {
            let json_body =
                r#"{"access_token":"retrieved_jwt_token","token_type":"Bearer","expires_in":1749662727}"#;
            let response = Response::builder()
                .status(200)
                .body(json_body.as_bytes().to_vec())
                .unwrap();
            Ok(response)
        });
        let metadata = create_test_metadata("key");
        let http_authenticator = HttpAuthenticator::new(
            mock_http_client,
            metadata.environment.token_renewal_endpoint(),
        );
        let command = RetrieveTokenCommand::new(http_authenticator);

        let result = command.retrieve_token(&metadata);

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.access_token(), "retrieved_jwt_token");
    }

    #[test]
    fn test_retrieve_token_fails_when_private_key_is_invalid() {
        let mock_http_client = MockHttpClient::new();
        let mut metadata = create_test_metadata("key");
        let http_authenticator = HttpAuthenticator::new(
            mock_http_client,
            metadata.environment.token_renewal_endpoint(),
        );
        let command = RetrieveTokenCommand::new(http_authenticator);

        metadata.auth_method = AuthMethod::PrivateKey(crate::key::PrivateKeyPem::from(vec![]));

        let result = command.retrieve_token(&metadata);

        assert!(
            result.is_err(),
            "Expected token retrieval to fail due to invalid key"
        );
        let error_string = result.unwrap_err().to_string();
        assert!(error_string.contains("InvalidKeyFormat"));
    }

    #[test]
    fn test_retrieve_token_fails_on_http_error() {
        let mut mock_http_client = MockHttpClient::new();
        mock_http_client.expect_send().times(1).returning(|_| {
            Err(HttpClientError::TransportError(
                "Connection refused".to_string(),
            ))
        });
        let metadata = create_test_metadata("secret");
        let http_authenticator = HttpAuthenticator::new(
            mock_http_client,
            metadata.environment.token_renewal_endpoint(),
        );
        let command = RetrieveTokenCommand::new(http_authenticator);

        let result = command.retrieve_token(&metadata);

        assert!(result.is_err());
        let error_string = result.unwrap_err().to_string();
        assert!(error_string.contains("Connection refused"));
    }
}
