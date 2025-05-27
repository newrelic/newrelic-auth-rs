use std::{fmt, time::Duration};

use chrono::{TimeDelta, Utc};
use http::{header::CONTENT_TYPE, StatusCode, Uri};
use serde_json::json;

use crate::{
    authenticator::TokenRetrievalResponse,
    http_client::{HttpClient, HttpClientError},
    system_identity::client_input::ClientSecret,
    token::{Token, TokenType},
    TokenRetriever, TokenRetrieverError,
};

/// HTTP-based token retriever for L1 authentication method (client ID + client secret)
pub struct L1TokenRetriever<C: HttpClient> {
    client_id: String,
    client_secret: ClientSecret,
    http_client: C,
    token_retrieval_uri: Uri,
}

impl<C: HttpClient> fmt::Debug for L1TokenRetriever<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L1TokenRetriever")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<hidden>") // Do not print the secret
            .field("token_retrieval_uri", &self.token_retrieval_uri)
            .field("http_client", &"impl HttpClient") // HttpClient does not implement Debug
            .finish()
    }
}

impl<C: HttpClient> L1TokenRetriever<C> {
    pub(super) fn new(
        client_id: String,
        client_secret: ClientSecret,
        http_client: C,
        token_retrieval_uri: Uri,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            http_client,
            token_retrieval_uri,
        }
    }

    fn build_request(
        client_id: &str,
        client_secret: &ClientSecret,
        uri: &Uri,
    ) -> Result<http::Request<Vec<u8>>, TokenRetrieverError> {
        let json_body_string = json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        });
        let json_body = serde_json::to_vec(&json_body_string).map_err(|e| {
            TokenRetrieverError::TokenRetrieverError(format!("Failed to encode JSON: {e}"))
        })?;

        http::Request::builder()
            .uri(uri)
            .method("POST")
            .header(CONTENT_TYPE, "application/json")
            .body(json_body)
            .map_err(|e| {
                TokenRetrieverError::TokenRetrieverError(format!("Failed to build request: {e}"))
            })
    }
}

impl<C: HttpClient> TokenRetriever for L1TokenRetriever<C> {
    fn retrieve(&self) -> Result<Token, TokenRetrieverError> {
        let request = Self::build_request(
            &self.client_id,
            &self.client_secret,
            &self.token_retrieval_uri,
        )?;

        let response = self.http_client.send(request).map_err(|e| {
            TokenRetrieverError::TokenRetrieverError(format!("Failed to send HTTP request: {e}"))
        })?;
        let body = response.body();

        match response.status() {
            StatusCode::OK => {
                let decoded_body: TokenRetrievalResponse =
                    serde_json::from_slice(body).map_err(|e| {
                        TokenRetrieverError::TokenRetrieverError(format!(
                            "Failed to decode JSON response: {e}"
                        ))
                    })?;
                Token::try_from(decoded_body)
                    .map_err(|e| HttpClientError::InvalidResponse(e.to_string()))
            }
            status => Err(HttpClientError::UnsuccessfulResponse(
                status.as_u16(),
                String::from_utf8_lossy(body).to_string(),
            )),
        }
        .map_err(|e| {
            TokenRetrieverError::TokenRetrieverError(format!("Failed to retrieve token: {e}"))
        })
    }
}

impl TryFrom<TokenRetrievalResponse> for Token {
    type Error = TokenRetrieverError;

    fn try_from(response: TokenRetrievalResponse) -> Result<Self, Self::Error> {
        let access_token = response.access_token;
        let token_type = TokenType::try_from(response.token_type.as_str())
            .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?;

        // Assuming we get seconds from the `expires_in` field of the JSON response
        let time_delta = TimeDelta::from_std(Duration::from_secs(response.expires_in))
            .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?;

        let expires_at = Utc::now().checked_add_signed(time_delta).ok_or_else(|| {
            TokenRetrieverError::TokenRetrieverError(
                "Failed to calculate expiration time".to_string(),
            )
        })?;

        Ok(Token::new(access_token, token_type, expires_at))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::http_client::tests::MockHttpClient;

    use super::*;

    #[test]
    fn build_request() {
        let uri: Uri = "https://example.com/token".parse().unwrap();
        let client_id = "test_client_id".to_string();
        let client_secret = ClientSecret::from("test_client");

        let request =
            L1TokenRetriever::<MockHttpClient>::build_request(&client_id, &client_secret, &uri)
                .unwrap();

        assert!(request.method() == http::Method::POST);
        assert!(request.uri() == &uri);
        assert!(request.headers().get(CONTENT_TYPE).is_some());
        assert_eq!(
            request.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = request.body();
        let expected_body = json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        });
        let body_value: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(body_value, expected_body);
    }
}
