use base64::{engine::general_purpose, Engine};
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, StatusCode,
};
use serde_json::json;

use crate::{
    http_client::HttpClient, system_identity::client_input::SystemIdentityCreationMetadata,
    token::AccessToken, TokenRetriever,
};

use super::{error::IAMClientError, response_data::SystemIdentityCreationResponseData, IAMClient};

/// Implementation of the IAMClient trait for a generic HTTP client.
pub struct HttpIAMClient<'a, C, T>
where
    C: HttpClient,
    T: TokenRetriever,
{
    http_client: &'a C,
    token_retriever: T,
    metadata: SystemIdentityCreationMetadata,
}

impl<'a, C, T> HttpIAMClient<'a, C, T>
where
    C: HttpClient,
    T: TokenRetriever,
{
    pub fn new(
        http_client: &'a C,
        token_retriever: T,
        metadata: SystemIdentityCreationMetadata,
    ) -> Self {
        Self {
            http_client,
            token_retriever,
            metadata,
        }
    }

    fn create_system_identity(
        &self,
        token: &AccessToken,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError> {
        let pub_key_b64 = general_purpose::STANDARD.encode(pub_key);
        let json_body_string = json!({
            "query": format!(
                "mutation {{ systemIdentityCreate(name: \"{}\", organizationId: \"{}\", publicKey: \"{}\") {{ clientId, name }} }}",
                self.metadata.name, self.metadata.organization_id, pub_key_b64
            ),
        });
        let json_body = serde_json::to_vec(&json_body_string)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to encode JSON: {e}")))?;

        let mut bearer_token_header =
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                IAMClientError::Transport(
                    "invalid HTTP header value set for Authorization".to_string(),
                )
            })?;
        bearer_token_header.set_sensitive(true);

        let request = http::Request::builder()
            .uri(self.metadata.environment.identity_creation_endpoint())
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, bearer_token_header)
            .body(json_body)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to build request: {e}")))?;

        let response = self
            .http_client
            .send(request)
            .map_err(|e| IAMClientError::Transport(format!("Failed to send HTTP request: {e}")))?;
        let body = response.body();
        match response.status() {
            StatusCode::OK => {
                let system_identity_response: SystemIdentityCreationResponseData =
                    serde_json::from_slice(body).map_err(|e| {
                        IAMClientError::Decoder(format!("Failed to decode JSON: {e}"))
                    })?;
                Ok(system_identity_response)
            }
            status => Err(IAMClientError::Transport(format!(
                "Unsuccessful HTTP response: {status}. Body: {}",
                String::from_utf8_lossy(body)
            ))),
        }
    }
}

impl<C, T> IAMClient for HttpIAMClient<'_, C, T>
where
    C: HttpClient,
    T: TokenRetriever,
{
    type Error = IAMClientError;
    fn create_system_identity(
        &self,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, Self::Error> {
        let token = self
            .token_retriever
            .retrieve()
            .map_err(|e| IAMClientError::IAMClient(e.to_string()))?;
        self.create_system_identity(token.access_token(), pub_key)
    }
}
