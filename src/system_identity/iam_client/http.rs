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
    HeaderValue, Request, StatusCode, Uri,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use serde_json::{Value, json};

/// Authentication credential for creating system identities
#[derive(Debug, Clone)]
pub enum IAMAuthCredential {
    /// Bearer token from OAuth authentication
    BearerToken(String),
    /// New Relic User API Key
    ApiKey(String),
}

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

    fn build_request(
        maybe_name: Option<&String>,
        organization_id: &str,
        maybe_pub_key_b64: Option<String>,
        auth_credentials: &IAMAuthCredential,
        system_identity_creation_endpoint: &Uri,
    ) -> Result<Request<Vec<u8>>, IAMClientError> {
        let json_body = serde_json::to_vec(&assemble_json_value(
            maybe_name,
            organization_id,
            maybe_pub_key_b64,
        ))
        .map_err(|e| IAMClientError::Encoder(format!("Failed to encode JSON: {e}")))?;

        let mut request_builder = Request::builder()
            .uri(system_identity_creation_endpoint)
            .method("POST")
            .header(CONTENT_TYPE, "application/json");

        // Add authentication header based on credential type
        match auth_credentials {
            IAMAuthCredential::BearerToken(token) => {
                let mut bearer_token_header = HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|_| {
                    IAMClientError::Transport(
                        "invalid HTTP header value set for Authorization".to_string(),
                    )
                })?;
                bearer_token_header.set_sensitive(true);
                request_builder = request_builder.header(AUTHORIZATION, bearer_token_header);
            }
            IAMAuthCredential::ApiKey(api_key) => {
                let mut api_key_header = HeaderValue::from_str(api_key).map_err(|_| {
                    IAMClientError::Transport(
                        "invalid HTTP header value set for Api-Key".to_string(),
                    )
                })?;
                api_key_header.set_sensitive(true);
                request_builder = request_builder.header("Api-Key", api_key_header);
            }
        }

        request_builder
            .body(json_body)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to build request: {e}")))
    }

    fn create_system_identity(
        &self,
        auth_credentials: &IAMAuthCredential,
        maybe_pub_key: Option<&[u8]>,
    ) -> Result<SystemIdentity, IAMClientError> {
        let pub_key_b64 = maybe_pub_key.map(|k| general_purpose::STANDARD.encode(k));
        let request = Self::build_request(
            self.metadata.name.as_ref(),
            &self.metadata.organization_id,
            pub_key_b64,
            auth_credentials,
            &self.metadata.environment.identity_creation_endpoint(),
        )?;

        let response = self.http_client.send(request).map_err(|e| {
            IAMClientError::Transport(format!(
                "Failed to send HTTP request for system identity creation: {e}"
            ))
        })?;
        let body = response.body();
        match response.status() {
            StatusCode::OK => {
                let system_identity_response: SystemIdentityCreationResponse =
                    serde_json::from_slice(body).map_err(|e| {
                        IAMClientError::Decoder(format!(
                            "Failed to decode JSON response for system identity creation: {e}. Response body: {}",
                            String::from_utf8_lossy(body)
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
            status => Err(IAMClientError::Transport(format!(
                "Unsuccessful HTTP response: {status}. Body: {}",
                String::from_utf8_lossy(body)
            ))),
        }
    }
}

fn assemble_json_value(
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
    use http::Method;
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

        let request = HttpIAMClient::<MockHttpClient>::build_request(
            Some(&name.to_string()),
            org_id,
            maybe_pub_key_b64.clone(),
            &auth_credential,
            &uri,
        )
        .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), &uri);
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            &HeaderValue::from_static("application/json")
        );

        // Check correct authentication header based on credential type
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

        let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
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
}
