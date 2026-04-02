use super::error::IAMClientError;
use crate::{
    http_client::HttpClient,
    system_identity::{
        SystemIdentity,
        creation_response::SystemIdentityCreationResponse,
        identity_creator::{L1IdentityCreator, L2IdentityCreator},
        input_data::SystemIdentityCreationMetadata,
    },
};
use base64::{Engine, engine::general_purpose};
use http::{
    HeaderName, HeaderValue, Request,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use serde_json::{Value, json};
use std::str::FromStr;

const API_KEY_HEADER: &str = "Api-Key";

/// Authentication credential for creating system identities
#[derive(Debug, Clone)]
pub enum IAMAuthCredential {
    /// Bearer token from OAuth authentication
    BearerToken(String),
    /// New Relic User API Key
    ApiKey(String),
}

/// The name of the System Identity Group that grants the ability to create more identities.
/// Identities added to this group receive the organization.create.system_identities capability.
pub const NR_CONTROL_GROUP_NAME: &str = "NR Control Group";

/// Implementation of the IAMClient trait for a generic HTTP client.
pub struct HttpIAMClient<C>
where
    C: HttpClient,
{
    http_client: C,
    metadata: SystemIdentityCreationMetadata,
}

impl<C> HttpIAMClient<C>
where
    C: HttpClient,
{
    pub fn new(http_client: C, metadata: SystemIdentityCreationMetadata) -> Self {
        Self {
            http_client,
            metadata,
        }
    }

    fn get_auth_header(
        auth_credential: &IAMAuthCredential,
    ) -> Result<(HeaderName, HeaderValue), IAMClientError> {
        match auth_credential {
            IAMAuthCredential::BearerToken(token) => {
                let mut bearer_token_header = HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|_| {
                    IAMClientError::Transport(
                        "invalid HTTP header value set for Authorization".to_string(),
                    )
                })?;
                bearer_token_header.set_sensitive(true);
                Ok((AUTHORIZATION, bearer_token_header))
            }
            IAMAuthCredential::ApiKey(api_key) => {
                let mut api_key_header = HeaderValue::from_str(api_key).map_err(|_| {
                    IAMClientError::Transport(
                        "invalid HTTP header value set for Api-Key".to_string(),
                    )
                })?;
                api_key_header.set_sensitive(true);
                let header_name = HeaderName::from_str(API_KEY_HEADER).map_err(|e| {
                    IAMClientError::Transport(format!(
                        "invalid HTTP header name set for Api-Key {API_KEY_HEADER}: {e}"
                    ))
                })?;
                Ok((header_name, api_key_header))
            }
        }
    }

    fn create_system_identity(
        &self,
        auth_credentials: &IAMAuthCredential,
        maybe_pub_key: Option<&[u8]>,
    ) -> Result<SystemIdentity, IAMClientError> {
        let pub_key_b64 = maybe_pub_key.map(|k| general_purpose::STANDARD.encode(k));
        let json_body = assemble_create_identity_json_value(
            self.metadata.name.as_ref(),
            self.metadata.organization_id.as_str(),
            pub_key_b64,
        );

        let json = self.perform_graphql_request(auth_credentials, json_body)?;

        let system_identity_response: SystemIdentityCreationResponse =
                    serde_json::from_value(json.clone()).map_err(|e| {
                        IAMClientError::Decoder(format!(
                            "Failed to decode JSON response for system identity creation: {e}. Response body: {json}"
                        ))
                    })?;

        let system_identity = system_identity_response
            .data()
            .to_owned()
            .try_into()
            .map_err(|e| {
                IAMClientError::Decoder(format!(
                    "Failed to convert response to a valid system identity: {e}"
                ))
            })?;
        Ok(system_identity)
    }

    /// Find a system identity group_id by name. Returns the first match.
    pub fn find_system_identity_group_id_by_name(
        &self,
        group_name: &str,
        auth_credentials: &IAMAuthCredential,
    ) -> Result<String, IAMClientError> {
        let query = json!({"query": format!(
            "query {{ customerAdministration {{ systemIdentityGroups(filter: {{ organizationId: {{ eq: \"{}\" }}, name: {{ eq: \"{}\" }} }}) {{ items {{ id }} }} }} }}",
            self.metadata.organization_id, group_name
        )});

        let json = self.perform_graphql_request(auth_credentials, query)?;

        let items = json
            .get("data")
            .and_then(|d| d.get("customerAdministration"))
            .and_then(|ca| ca.get("systemIdentityGroups"))
            .and_then(|sig| sig.get("items"))
            .and_then(|items| items.as_array())
            .ok_or_else(|| {
                IAMClientError::Decoder(format!(
                    "Failed to extract groups from response. Body: {json}"
                ))
            })?;

        items
            .first()
            .and_then(|group| group.get("id"))
            .and_then(|id| id.as_str())
            .map(String::from)
            .ok_or_else(|| {
                IAMClientError::IAMClient(format!(
                    "{} not found in organization",
                    NR_CONTROL_GROUP_NAME
                ))
            })
    }

    pub fn add_identity_to_group_by_id(
        &self,
        identity_id: &str,
        group_id: &str,
        auth_credentials: &IAMAuthCredential,
    ) -> Result<(), IAMClientError> {
        let query = json!({"query": format!(
            "mutation {{ systemIdentityAddToGroups(systemIdentityIds: \"{}\", systemIdentityGroupIds: \"{}\") {{ systemIdentityGroups {{ id }} }} }}",
            identity_id, group_id
        )});

        self.perform_graphql_request(auth_credentials, query)?;

        Ok(())
    }

    /// Add identity to NR Control Group, granting organization.create.system_identities capability.
    pub fn add_identity_to_nr_control_group_by_id(
        &self,
        identity_id: &str,
        auth_credentials: &IAMAuthCredential,
    ) -> Result<(), IAMClientError> {
        let group_id =
            self.find_system_identity_group_id_by_name(NR_CONTROL_GROUP_NAME, auth_credentials)?;
        self.add_identity_to_group_by_id(identity_id, &group_id, auth_credentials)
    }

    fn perform_graphql_request(
        &self,
        auth_credentials: &IAMAuthCredential,
        json_body: Value,
    ) -> Result<Value, IAMClientError> {
        let request = self.build_graphql_request(json_body, auth_credentials)?;

        let response = self.http_client.send(request).map_err(|e| {
            IAMClientError::Transport(format!("Failed to send graphql request: {e}"))
        })?;
        let body = response.body();

        if !response.status().is_success() {
            return Err(IAMClientError::Transport(format!(
                "Failed to perform graphql request: {}. Body: {}",
                response.status(),
                String::from_utf8_lossy(body)
            )));
        }

        let json: Value = serde_json::from_slice(body).map_err(|e| {
            IAMClientError::Decoder(format!(
                "Failed to decode JSON response: {e}. Body: {}",
                String::from_utf8_lossy(body)
            ))
        })?;

        if let Some(errors) = json.get("errors") {
            return Err(IAMClientError::Transport(format!(
                "GraphQL errors: {}",
                errors
            )));
        }

        Ok(json)
    }

    fn build_graphql_request(
        &self,
        body: Value,
        auth_credential: &IAMAuthCredential,
    ) -> Result<Request<Vec<u8>>, IAMClientError> {
        let json_body = serde_json::to_vec(&body)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to encode JSON: {e}")))?;

        let mut request_builder = Request::builder()
            .uri(self.metadata.environment.identity_creation_endpoint())
            .method("POST")
            .header(CONTENT_TYPE, "application/json");

        let (header_key, header_value) = Self::get_auth_header(auth_credential)?;
        request_builder = request_builder.header(header_key, header_value);

        request_builder
            .body(json_body)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to build request: {e}")))
    }
}

fn assemble_create_identity_json_value(
    maybe_name: Option<&String>,
    organization_id: &str,
    maybe_pub_key_b64: Option<String>,
) -> Value {
    let optional_name_str = maybe_name
        .map(|n| format!(", name: \"{n}\""))
        .unwrap_or_default();
    let optional_key_str = maybe_pub_key_b64
        .map(|k| format!(", publicKey: \"{k}\""))
        .unwrap_or_default();

    json!({
        "query": format!(
            "mutation {{ systemIdentityCreate(organizationId: \"{organization_id}\"{optional_name_str}{optional_key_str}) {{ clientId, publicKey, id, name, organizationId, clientSecret, credentialExpiration }} }}",
        ),
    })
}

impl<C> L2IdentityCreator for HttpIAMClient<C>
where
    C: HttpClient,
{
    type Error = IAMClientError;
    fn create_l2_system_identity(
        &self,
        auth_credentials: &IAMAuthCredential,
        pub_key: &[u8],
    ) -> Result<SystemIdentity, Self::Error> {
        self.create_system_identity(auth_credentials, Some(pub_key))
    }
}

impl<C> L1IdentityCreator for HttpIAMClient<C>
where
    C: HttpClient,
{
    type Error = IAMClientError;
    fn create_l1_system_identity(
        &self,
        auth_credentials: &IAMAuthCredential,
    ) -> Result<SystemIdentity, Self::Error> {
        self.create_system_identity(auth_credentials, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::tests::MockHttpClient;
    use crate::system_identity::input_data::{
        SystemIdentityCreationMetadata, environment::NewRelicEnvironment,
    };
    use assert_matches::assert_matches;
    use http::{Method, Response, Uri};
    use rstest::rstest;

    #[rstest]
    #[case(None, IAMAuthCredential::BearerToken("test_token".to_string()))]
    #[case(Some("cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==".to_owned()), IAMAuthCredential::BearerToken("test_token".to_string()))]
    #[case(None, IAMAuthCredential::ApiKey("NRAK-XXXXXXXXXX".to_string()))]
    fn build_request(
        #[case] maybe_pub_key_b64: Option<String>,
        #[case] auth_credential: IAMAuthCredential,
    ) {
        let uri: Uri = "https://example.com/graphql".parse().unwrap();
        let name = "test_identity";
        let org_id = "org_123";

        let metadata = SystemIdentityCreationMetadata {
            organization_id: org_id.to_string(),
            name: Some(name.to_string()),
            environment: NewRelicEnvironment::Custom {
                token_renewal_endpoint: Default::default(),
                system_identity_creation_uri: uri.clone(),
            },
        };

        let iam_client = HttpIAMClient::new(MockHttpClient::new(), metadata.clone());

        let json_body = assemble_create_identity_json_value(
            metadata.name.as_ref(),
            metadata.organization_id.as_str(),
            maybe_pub_key_b64.clone(),
        );

        let request = iam_client
            .build_graphql_request(json_body, &auth_credential)
            .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), &uri);
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            &HeaderValue::from_static("application/json")
        );

        match &auth_credential {
            IAMAuthCredential::BearerToken(token) => {
                assert_eq!(
                    request.headers().get(AUTHORIZATION).unwrap(),
                    &HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
                );
                assert!(request.headers().get(AUTHORIZATION).unwrap().is_sensitive());
            }
            IAMAuthCredential::ApiKey(api_key) => {
                assert_eq!(
                    request.headers().get("Api-Key").unwrap(),
                    &HeaderValue::from_str(api_key).unwrap()
                );
                assert!(request.headers().get("Api-Key").unwrap().is_sensitive());
            }
        }

        let body: Value = serde_json::from_slice(request.body()).unwrap();
        assert_eq!(
            body,
            if let Some(pub_key_b64) = maybe_pub_key_b64 {
                json!({
                    "query": format!(
                        "mutation {{ systemIdentityCreate(organizationId: \"{}\", name: \"{}\", publicKey: \"{}\") {{ clientId, publicKey, id, name, organizationId, clientSecret, credentialExpiration }} }}",
                        org_id, name, pub_key_b64
                    ),
                })
            } else {
                json!({
                    "query": format!(
                        "mutation {{ systemIdentityCreate(organizationId: \"{}\", name: \"{}\") {{ clientId, publicKey, id, name, organizationId, clientSecret, credentialExpiration }} }}",
                        org_id, name
                    ),
                })
            }
        );
    }

    #[rstest]
    #[case::found(
        r#"{"data":{"customerAdministration":{"systemIdentityGroups":{"items":[{"id":"group-456"}]}}}}"#,
        Some("group-456")
    )]
    #[case::not_found(
        r#"{"data":{"customerAdministration":{"systemIdentityGroups":{"items":[]}}}}"#,
        None
    )]
    fn test_find_system_identity_group_id_by_name(
        #[case] response_body: &str,
        #[case] expected_group_id: Option<&str>,
    ) {
        let metadata = SystemIdentityCreationMetadata {
            organization_id: "org-123".to_string(),
            name: Some("test-group".to_string()),
            environment: NewRelicEnvironment::Staging,
        };

        let response_body_clone = response_body.to_string();
        let mut mock_http_client = MockHttpClient::default();

        mock_http_client
            .expect_send()
            .once()
            .withf(|req| {
                let body: Value = serde_json::from_slice(req.body()).unwrap();
                let query = body["query"].as_str().unwrap();

                query.contains("organizationId: { eq: \"org-123\" }")
                    && query.contains("name: { eq: \"NR Control Group\" }")
            })
            .returning(move |_| {
                let response = Response::builder()
                    .status(200)
                    .body(response_body_clone.as_bytes().to_vec())
                    .unwrap();
                Ok(response)
            });

        let iam_client = HttpIAMClient::new(mock_http_client, metadata);
        let auth_credential = IAMAuthCredential::BearerToken("test-token".to_string());
        let result = iam_client
            .find_system_identity_group_id_by_name(NR_CONTROL_GROUP_NAME, &auth_credential);

        if let Some(expected_id) = expected_group_id {
            assert_eq!(result.unwrap(), expected_id);
        } else {
            assert!(result.is_err());
        }
    }

    #[rstest]
    #[case::success(200, r#"{"data":{"result":"success"}}"#, None)]
    #[case::http_error(500, "Internal Server Error", Some("500"))]
    #[case::graphql_errors(
        200,
        r#"{"errors":[{"message":"Field not found"}],"data":null}"#,
        Some("GraphQL errors")
    )]
    fn test_perform_graphql_request(
        #[case] status_code: u16,
        #[case] response_body: &str,
        #[case] expected_error_contains: Option<&str>,
    ) {
        let metadata = SystemIdentityCreationMetadata {
            organization_id: "org-123".to_string(),
            name: Some("test".to_string()),
            environment: NewRelicEnvironment::Staging,
        };

        let response_body_clone = response_body.to_string();
        let mut mock_http_client = MockHttpClient::default();
        mock_http_client.expect_send().once().returning(move |_| {
            let response = Response::builder()
                .status(status_code)
                .body(response_body_clone.as_bytes().to_vec())
                .unwrap();
            Ok(response)
        });

        let iam_client = HttpIAMClient::new(mock_http_client, metadata);
        let auth_credential = IAMAuthCredential::BearerToken("test-token".to_string());
        let query = json!({"query": "{ test }"});

        let result = iam_client.perform_graphql_request(&auth_credential, query);

        if let Some(expected_msg) = expected_error_contains {
            assert_matches!(result.unwrap_err(), IAMClientError::Transport(msg) =>{
                assert!(msg.contains(expected_msg))
            })
        } else {
            assert!(result.is_ok());
        }
    }
}
