use std::fmt;
use std::fmt::Debug;

pub mod creation_response;
pub mod generator;
pub mod iam_client;
pub mod identity_creator;
pub mod input_data;

/// System identity information. Final output of the System Identity creation process.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentity {
    pub id: String,
    pub name: Option<String>,
    pub client_id: String,
    pub organization_id: String,
    pub identity_type: SystemIdentityType,
}

/// Represents the type of system identity being created.
///
/// If the request was to create an L1, the `SystemIdentityType` will contain the client secret and
/// its expiration.
///
/// If the request was to create an L2, the `SystemIdentityType` will contain the public key
/// in Base64 format. This is the same public key that was used in the request to create the
/// system identity.
#[derive(Debug, Clone, PartialEq)]
pub enum SystemIdentityType {
    L1 {
        client_secret: ClientSecret,
        credential_expiration: String,
    },
    L2 {
        pub_key: Base64PublicKey,
    },
}

type Base64PublicKey = String; // For L2 System Identity.

#[derive(Clone, PartialEq)]
pub struct ClientSecret(String); // For L1 System Identity.
impl Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientSecret: redacted")
    }
}
impl From<String> for ClientSecret {
    fn from(secret: String) -> Self {
        Self(secret)
    }
}
impl ClientSecret {
    pub fn reveal(self) -> String {
        self.0
    }
}
impl fmt::Display for SystemIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let identity_type = match &self.identity_type {
            SystemIdentityType::L1 {
                client_secret,
                credential_expiration,
            } => {
                format!(
                    "L1(client_secret: {}, credential_expiration: {})",
                    client_secret.clone().reveal(),
                    credential_expiration
                )
            }
            SystemIdentityType::L2 { pub_key } => format!("L2(pub_key: {})", pub_key),
        };
        write!(
            f,
            "SystemIdentity(id: {}, name: {}, client_id: {}, organization_id: {}, identity_type: {})",
            self.id,
            self.name.clone().unwrap_or_else(|| "None".to_string()),
            self.client_id,
            self.organization_id,
            identity_type,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::input_data::auth_method::AuthMethod;
    use crate::system_identity::input_data::SystemTokenCreationMetadata;
    use chrono::Utc;
    use mockall::Sequence;
    use std::clone::Clone;
    use std::convert::{Into, TryFrom};
    use std::default::Default;
    use std::option::Option::Some;
    use std::path::PathBuf;

    use crate::system_identity::SystemIdentityType;
    use crate::{
        http_client::tests::MockHttpClient,
        jwt::signer::local::{LocalPrivateKeySigner, test::RS256_PRIVATE_KEY},
        key::creator::tests::MockCreator,
        system_identity::{
            ClientSecret, SystemIdentity,
            generator::L2SystemIdentityGenerator,
            iam_client::http::HttpIAMClient,
            identity_creator::tests::MockL2IAMClient,
            input_data::{
                SystemIdentityCreationMetadata, SystemIdentityInput,
                auth_method::ClientSecret as AuthClientSecret, environment::NewRelicEnvironment,
                output_platform::OutputPlatform,
            },
        },
        token::{Token, TokenType},
        token_retriever::TokenRetrieverWithCache,
    };
    use rstest::{Context, rstest};
    use std::result::Result::Ok;
    use std::string::{String, ToString};

    // The idea here is emulate what would be the flow of a CLI call to create a system identity.
    // The CLI would parse the command line arguments into a type with the actual concretions
    // required to perform the operation. Here we test mocking only the HTTP client and the
    // key creator. The rest are concretions that receive these as generics.
    #[rstest]
    #[case(AuthMethod::ClientSecret(AuthClientSecret::from("client-secret")))]
    #[case(AuthMethod::PrivateKey(RS256_PRIVATE_KEY.as_bytes().into()))]
    fn http_client_create_system_identity_from_client_secret(
        #[context] ctx: Context,
        #[case] auth_method: AuthMethod,
    ) {
        use crate::{TokenRetriever, authenticator::HttpAuthenticator, jwt::signer::JwtSignerImpl};

        let cli_token_input = SystemTokenCreationMetadata {
            client_id: format!("{}-client-id", ctx.name),
            environment: NewRelicEnvironment::Staging,
            auth_method,
        };

        let cli_input = SystemIdentityCreationMetadata {
            system_identity_input: SystemIdentityInput {
                organization_id: "org-id".to_string(),
                client_id: format!("{}-client-id", ctx.name),
            },
            name: ctx.name.to_string().into(),
            environment: NewRelicEnvironment::Staging,
            output_platform: OutputPlatform::LocalPrivateKeyPath(PathBuf::default()),
        };
        let expected_client_id = cli_input.system_identity_input.client_id.to_owned();
        let expected_name = cli_input.name.to_owned();

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
            .returning(move |_| {
                let response = http::Response::builder()
                    .status(200)
                    .body(
                        serde_json::to_string(&serde_json::json!({
                          "data": {
                            "systemIdentityCreate": {
                              "clientId": format!("{}-client-id", ctx.name),
                              "name": ctx.name,
                              "publicKey": String::from_utf8_lossy(&[1u8, 2u8, 3u8]), // "cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==",
                              "id": "some-granted-id",
                              "organizationId": "org-id",
                              // "clientSecret": "c2VjcmV0LWNsaWVudC1zZWNyZXQtc2VjcmV0",
                              // "credentialExpiration": "2023-10-01T00:00:00Z"
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

        let authenticator = HttpAuthenticator::new(
            token_retriever_http_client,
            cli_input.environment.token_renewal_endpoint(),
        );
        let client_id = cli_input.system_identity_input.client_id.to_owned();
        let token_retriever = match cli_token_input.auth_method.to_owned() {
            AuthMethod::ClientSecret(client_secret) => {
                TokenRetrieverWithCache::new_with_secret(client_id, authenticator, client_secret)
            }
            AuthMethod::PrivateKey(private_key_pem) => {
                let signer = LocalPrivateKeySigner::try_from(private_key_pem).unwrap();
                let jwt_signer = JwtSignerImpl::Local(signer);
                TokenRetrieverWithCache::new_with_jwt_signer(client_id, authenticator, jwt_signer)
            }
        };

        // IAMClient from HttpClient
        let iam_client = HttpIAMClient::new(
            iam_client_http_client,
            cli_input, // I compare with this value later on, so we keep it here
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

        let token = token_retriever.retrieve().unwrap();
        let result = system_identity_generator.generate(&token);
        assert!(
            result.is_ok(),
            "Failed to generate system identity: {:?}",
            result
        );

        let result = result.unwrap();
        assert_eq!(result.name, expected_name);
        assert_eq!(result.client_id, expected_client_id);
        assert!(matches!(
            result.identity_type,
            super::SystemIdentityType::L2 { pub_key } if pub_key == String::from_utf8_lossy(&[1u8, 2u8, 3u8])
        ));
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
            .returning(|_, _| {
                Ok(SystemIdentity {
                    client_id: "client-id".to_string(),
                    name: "test".to_string().into(),
                    identity_type: super::SystemIdentityType::L2 {
                        pub_key: String::from_utf8_lossy(&[1u8, 2u8, 3u8]).to_string(),
                    },
                    id: "id".to_string(),
                    organization_id: "org-id".to_string(),
                })
            });

        let system_identity_generator = L2SystemIdentityGenerator {
            key_creator,
            iam_client,
        };

        let token = Token::new("test-token".to_string(), TokenType::Bearer, Utc::now());
        let result = system_identity_generator.generate(&token);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.name, Some("test".to_string()));
        assert_eq!(result.client_id, "client-id");
        assert!(matches!(
            result.identity_type,
            super::SystemIdentityType::L2 { pub_key } if pub_key == String::from_utf8_lossy(&[1u8, 2u8, 3u8])
        ));
    }
    #[test]
    fn test_system_identity_display_l1() {
        let system_identity = SystemIdentity {
            id: "identity-123".to_string(),
            name: Some("test-identity".to_string()),
            client_id: "client-abc-789".to_string(),
            organization_id: "org-xyz-456".to_string(),
            identity_type: SystemIdentityType::L1 {
                client_secret: ClientSecret::from("supersecret".to_string()),
                credential_expiration: "2025-12-31T23:59:59Z".to_string(),
            },
        };

        let display_str = format!("{}", system_identity);
        let expected_str = "SystemIdentity(id: identity-123, name: test-identity, client_id: client-abc-789, organization_id: org-xyz-456, identity_type: L1(client_secret: supersecret, credential_expiration: 2025-12-31T23:59:59Z))";

        assert_eq!(display_str, expected_str);
    }

    #[test]
    fn test_system_identity_display_l2() {
        let system_identity = SystemIdentity {
            id: "identity-456".to_string(),
            name: None,
            client_id: "client-xyz-123".to_string(),
            organization_id: "org-abc-789".to_string(),
            identity_type: SystemIdentityType::L2 {
                pub_key: "cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==".to_string(),
            },
        };

        let display_str = format!("{}", system_identity);
        let expected_str = "SystemIdentity(id: identity-456, name: None, client_id: client-xyz-123, organization_id: org-abc-789, identity_type: L2(pub_key: cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==))";

        assert_eq!(display_str, expected_str);
    }
}
