use base64::{engine::general_purpose, Engine};
use http::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Request, StatusCode, Uri,
};
use serde_json::json;

use crate::{
    http_client::HttpClient, system_identity::client_input::SystemIdentityCreationMetadata,
    token::Token, TokenRetriever,
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

    fn build_request(
        name: &str,
        organization_id: &str,
        pub_key_b64: &str,
        token: &Token,
        system_identity_creation_endpoint: &Uri,
    ) -> Result<Request<Vec<u8>>, IAMClientError> {
        let json_body_string = json!({
            "query": format!(
                "mutation {{ systemIdentityCreate(name: \"{}\", organizationId: \"{}\", publicKey: \"{}\") {{ clientId, name }} }}",
                name, organization_id, pub_key_b64
            ),
        });
        let json_body = serde_json::to_vec(&json_body_string)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to encode JSON: {e}")))?;

        let mut bearer_token_header =
            HeaderValue::from_str(&format!("Bearer {}", token.access_token())).map_err(|_| {
                IAMClientError::Transport(
                    "invalid HTTP header value set for Authorization".to_string(),
                )
            })?;
        bearer_token_header.set_sensitive(true);

        http::Request::builder()
            .uri(system_identity_creation_endpoint)
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, bearer_token_header)
            .body(json_body)
            .map_err(|e| IAMClientError::Encoder(format!("Failed to build request: {e}")))
    }

    fn create_system_identity(
        &self,
        token: &Token,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, IAMClientError> {
        let pub_key_b64 = general_purpose::STANDARD.encode(pub_key);
        let request = Self::build_request(
            &self.metadata.name,
            &self.metadata.organization_id,
            &pub_key_b64,
            token,
            self.metadata.environment.identity_creation_endpoint(),
        )?;

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
        self.create_system_identity(&token, pub_key)
    }
}

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use http::Method;

    use crate::{
        http_client::tests::MockHttpClient,
        token::{AccessToken, TokenType},
        token_retriever::test::MockTokenRetriever,
    };

    use super::*;

    #[test]
    fn build_request() {
        let uri: Uri = "https://example.com/graphql".parse().unwrap();
        let token = Token::new(
            AccessToken::from("test_token"),
            TokenType::Bearer,
            Utc::now(),
        );
        let name = "test_identity";
        let org_id = "org_123";
        let pub_key_b64 = "cHVibGljS2V5QmFzZTY0RW5jb2RlZFN0cmluZw==";

        let request = HttpIAMClient::<MockHttpClient, MockTokenRetriever>::build_request(
            name,
            org_id,
            pub_key_b64,
            &token,
            &uri,
        )
        .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), &uri);
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            &HeaderValue::from_static("application/json")
        );
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            &HeaderValue::from_str(&format!("Bearer {}", token.access_token())).unwrap()
        );
        assert!(request.headers().get(AUTHORIZATION).unwrap().is_sensitive());
        let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
        assert_eq!(
            body,
            json!({
                "query": format!(
                    "mutation {{ systemIdentityCreate(name: \"{}\", organizationId: \"{}\", publicKey: \"{}\") {{ clientId, name }} }}",
                    name, org_id, pub_key_b64
                ),
            })
        );
    }
}
