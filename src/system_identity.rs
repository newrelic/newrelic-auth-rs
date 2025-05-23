mod client_input;
mod environment;
mod generator;
mod iam_client;
mod output_platform;

#[derive(Debug, Clone, Default)]
pub struct SystemIdentity {
    pub name: String,
    pub client_id: String, // TODO type better
    pub pub_key: Vec<u8>,  // TODO type better
}

#[cfg(test)]
mod tests {
    use mockall::Sequence;

    use crate::{
        http_client::tests::MockHttpClient,
        jwt::signer::local::test::RS256_PRIVATE_KEY,
        key::creator::tests::MockCreator,
        system_identity::{
            client_input::{AuthMethod, SystemIdentityCreationMetadata},
            generator::SystemIdentityGenerator,
            iam_client::{
                http_iam_client::HttpIAMClient, http_token_retriever::HttpTokenRetriever,
                response_data::SystemIdentityCreationResponseData, tests::MockIAMClient,
            },
        },
    };

    use super::environment::SystemIdentityCreationEnvironment;

    // The idea here is emulate what would be the flow of a CLI call to create a system identity.
    // The CLI would parse the command line arguments into a type with the actual concretions
    // required to perform the operation. Here we test mocking only the HTTP client and the
    // key creator. The rest are concretions that receive these as generics.
    #[test]
    fn http_client_create_system_identity_from_client_secret() {
        let cli_input = SystemIdentityCreationMetadata {
            name: "test".to_string(),
            organization_id: "org-id".to_string(),
            client_id: "client-id".to_string(),
            auth_method: AuthMethod::ClientSecret("client-secret".to_string()),
            environment: SystemIdentityCreationEnvironment::Staging,
        };

        // When creating a system identity from a client secret, the HTTP client implementation
        // that we use will be called two times. One to retrieve the token and another to
        // create the system identity itself.
        let mut http_client = MockHttpClient::new();
        let mut request_sequence = Sequence::new();
        // Mock the HTTP client to expect a request to the token retrieval endpoint
        // 1. Token retrieval
        http_client
            .expect_send()
            .once()
            .in_sequence(&mut request_sequence)
            .withf({
                let env = cli_input.environment.clone();
                move |req| {
                    req.method().eq(&http::Method::POST)
                        && req.uri().eq(env.token_renewal_endpoint())
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
        // 2. System identity creation
        http_client
            .expect_send()
            .once()
            .in_sequence(&mut request_sequence)
            .withf({
                let env = cli_input.environment.clone();
                move |req| {
                    req.method().eq(&http::Method::POST)
                        && req.uri().eq(env.identity_creation_endpoint())
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

        let http_token_retriever = HttpTokenRetriever::from_auth_method(
            &http_client,
            &cli_input.auth_method,
            cli_input.environment.token_renewal_endpoint(),
            cli_input.client_id.to_owned(),
        )
        .unwrap();

        // IAMClient from HttpClient
        let iam_client = HttpIAMClient::new(
            &http_client,
            http_token_retriever,
            cli_input.to_owned(), // I compare with this value later, keep it around
        );

        // As we are creating concretions, we only need to set expectations for the key creator
        // (which could be just abstracting the filesystem) and the HTTP client.
        // However, the final structures that I create are actually generic over
        // `IAMClient`s and `KeyCreator`s, so that makes it extensible for other, non-HTTP-based
        // implementations.
        let system_identity_generator = SystemIdentityGenerator {
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
    fn http_client_create_system_identity_from_private_key() {
        let cli_input = SystemIdentityCreationMetadata {
            name: "test".to_string(),
            organization_id: "org-id".to_string(),
            client_id: "client-id".to_string(),
            auth_method: AuthMethod::FromLocalPrivateKey(RS256_PRIVATE_KEY.as_bytes().into()),
            environment: SystemIdentityCreationEnvironment::Staging,
        };

        // When creating a system identity from a private key, the HTTP client implementation
        // that we use will be called two times: One to sign the token via and another to
        // create the system identity itself.
        let mut http_client = MockHttpClient::new();
        let mut sequence = Sequence::new();
        // 1. Sign the token
        http_client
            .expect_send()
            .once()
            .in_sequence(&mut sequence)
            .withf({
                let env = cli_input.environment.clone();
                move |req| {
                    req.method().eq(&http::Method::POST)
                        && req.uri().eq(env.token_renewal_endpoint())
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
        http_client
            .expect_send()
            .once()
            .in_sequence(&mut sequence)
            .withf({
                let env = cli_input.environment.clone();
                move |req| {
                    req.method().eq(&http::Method::POST)
                        && req.uri().eq(env.identity_creation_endpoint())
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

        let http_token_retriever = HttpTokenRetriever::from_auth_method(
            &http_client,
            &cli_input.auth_method,
            cli_input.environment.token_renewal_endpoint(),
            cli_input.client_id.to_owned(),
        )
        .unwrap();

        // IAMClient from HttpClient
        let iam_client = HttpIAMClient::new(
            &http_client,
            http_token_retriever,
            cli_input.to_owned(), // I compare with this value later, keep it around
        );

        // As we are creating concretions, we only need to set expectations for the key creator
        // (which could be just abstracting the filesystem) and the HTTP client.
        // However, the final structures that I create are actually generic over
        // `IAMClient`s and `KeyCreator`s, so that makes it extensible for other, non-HTTP-based
        // implementations.
        let system_identity_generator = SystemIdentityGenerator {
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
        let mut iam_client = MockIAMClient::new();
        let mut sequence = Sequence::new();

        key_creator
            .expect_create()
            .once()
            .in_sequence(&mut sequence)
            .returning(|| Ok(vec![1, 2, 3]));
        iam_client
            .expect_create_system_identity()
            .once()
            .in_sequence(&mut sequence)
            .returning(|_| {
                Ok(SystemIdentityCreationResponseData {
                    client_id: "client-id".to_string(),
                    name: "test".to_string(),
                })
            });

        let system_identity_generator = SystemIdentityGenerator {
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
