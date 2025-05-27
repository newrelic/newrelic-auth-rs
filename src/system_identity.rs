//! Module containing the types and logic in charge of generating System Identities for New Relic.
//!
//! Refer to the submodules for more information.
pub mod client_input;
pub mod environment;
pub mod generator;
pub mod iam_client;
pub mod output_platform;

/// System identity information.
#[derive(Debug, Clone, Default)]
pub struct SystemIdentity {
    pub name: String,
    pub client_id: String,
    pub pub_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mockall::Sequence;
    use rstest::rstest;

    use crate::system_identity::iam_client::http_token_retriever::HttpTokenRetriever;
    use crate::{
        http_client::tests::MockHttpClient,
        jwt::signer::local::test::RS256_PRIVATE_KEY,
        key::creator::tests::MockCreator,
        system_identity::{
            client_input::{AuthMethod, ClientSecret, SystemIdentityCreationMetadata},
            generator::L2SystemIdentityGenerator,
            iam_client::{
                http_iam_client::HttpIAMClient, l2_creator::tests::MockL2IAMClient,
                response_data::SystemIdentityCreationResponseData,
            },
            output_platform::AuthOutputPlatform,
        },
    };

    use super::environment::SystemIdentityCreationEnvironment;

    // The idea here is emulate what would be the flow of a CLI call to create a system identity.
    // The CLI would parse the command line arguments into a type with the actual concretions
    // required to perform the operation. Here we test mocking only the HTTP client and the
    // key creator. The rest are concretions that receive these as generics.
    #[rstest]
    #[case(AuthMethod::ClientSecret(ClientSecret::from("client-secret")))]
    #[case(AuthMethod::PrivateKey(RS256_PRIVATE_KEY.as_bytes().into()))]
    fn http_client_create_system_identity_from_client_secret(#[case] auth_method: AuthMethod) {
        let cli_input = SystemIdentityCreationMetadata {
            name: "test".to_string(),
            organization_id: "org-id".to_string(),
            client_id: "client-id".to_string(),
            auth_method,
            environment: SystemIdentityCreationEnvironment::Staging,
            output_platform: AuthOutputPlatform::LocalPrivateKeyPath(PathBuf::default()),
        };

        let mut token_retriever_http_client = MockHttpClient::new();
        // 1. Sign the token
        token_retriever_http_client
            .expect_send()
            .once()
            .withf({
                let env = cli_input.environment.clone();
                move |req| {
                    req.method().eq(&http::Method::POST)
                        && req.uri().eq(&env.token_renewal_endpoint())
                        && req
                            .headers()
                            .get("Content-Type")
                            .is_some_and(|v| v == "application/json")
                }
            })
            .returning(|_| {
                let response = http::Response::builder()
                    .status(200)
                    .body(
                        serde_json::to_string(&serde_json::json!({
                            "access_token": "some-access-token",
                            "expires_in": 3600,
                            "token_type": "Bearer",
                        }))
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                    )
                    .unwrap();
                Ok(response)
            });

        let mut iam_client_http_client = MockHttpClient::new();
        iam_client_http_client
            .expect_send()
            .once()
            .withf({
                let env = cli_input.environment.clone();
                move |req| {
                    req.method().eq(&http::Method::POST)
                        && req.uri().eq(&env.identity_creation_endpoint())
                        && req
                            .headers()
                            .get("Content-Type")
                            .is_some_and(|v| v == "application/json")
                }
            })
            .returning(|_| {
                let response = http::Response::builder()
                    .status(200)
                    .body(
                        serde_json::to_string(&serde_json::json!({
                          "data": {
                            "systemIdentityCreate": {
                              "clientId": "client-id",
                              "name": "test",
                            }
                          }
                        }))
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                    )
                    .unwrap();
                Ok(response)
            });

        // More mocks, this time for the key creator
        let mut key_creator = MockCreator::new();
        key_creator
            .expect_create()
            .once()
            .returning(|| Ok(vec![1, 2, 3]));

        let http_token_retriever =
            HttpTokenRetriever::new(token_retriever_http_client, &cli_input).unwrap();

        // IAMClient from HttpClient
        let iam_client = HttpIAMClient::new(
            iam_client_http_client,
            http_token_retriever,
            cli_input.to_owned(), // I compare with this value later on, so we keep it here
        );

        // As we are creating concretions, we only need to set expectations for the key creator
        // (which could be just abstracting the filesystem) and the HTTP client.
        // However, the final structures that we create are actually generic over
        // `IAMClient`s and `KeyCreator`s, so that makes it extensible for other, non-HTTP-based
        // implementations.
        let system_identity_generator = L2SystemIdentityGenerator {
            key_creator,
            iam_client,
        };

        let result = system_identity_generator.generate();
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.name, cli_input.name);
        assert_eq!(result.client_id, cli_input.client_id);
        assert_eq!(result.pub_key, vec![1, 2, 3]);
    }

    #[test]
    fn create_system_identity_mocked() {
        let mut key_creator = MockCreator::new();
        let mut iam_client = MockL2IAMClient::new();
        let mut sequence = Sequence::new();

        key_creator
            .expect_create()
            .once()
            .in_sequence(&mut sequence)
            .returning(|| Ok(vec![1, 2, 3]));
        iam_client
            .expect_create_l2_system_identity()
            .once()
            .in_sequence(&mut sequence)
            .returning(|_| {
                Ok(SystemIdentityCreationResponseData {
                    client_id: "client-id".to_string(),
                    name: "test".to_string(),
                })
            });

        let system_identity_generator = L2SystemIdentityGenerator {
            key_creator,
            iam_client,
        };
        let result = system_identity_generator.generate();
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.name, "test");
        assert_eq!(result.client_id, "client-id");
        assert_eq!(result.pub_key, vec![1, 2, 3]);
    }
}
