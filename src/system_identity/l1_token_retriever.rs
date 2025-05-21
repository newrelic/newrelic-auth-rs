use std::{fmt, time::Duration};

use chrono::{TimeDelta, Utc};
use http::{header::CONTENT_TYPE, StatusCode, Uri};
use serde::Deserialize;
use serde_json::json;

use crate::{
    http_client::{HttpClient, HttpClientError},
    token::{Token, TokenType},
    TokenRetriever, TokenRetrieverError,
};

pub struct L1TokenRetriever<'a, C: HttpClient> {
    client_id: String,
    client_secret: String,
    http_client: &'a C,
    token_retrieval_uri: &'a Uri,
}

impl<C: HttpClient> fmt::Debug for L1TokenRetriever<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L1TokenRetriever")
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("token_retrieval_uri", &self.token_retrieval_uri)
            .field("http_client", &"impl HttpClient")
            .finish()
    }
}

impl<'a, C: HttpClient> L1TokenRetriever<'a, C> {
    pub fn new(
        client_id: String,
        client_secret: String,
        http_client: &'a C,
        token_retrieval_uri: &'a Uri,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            http_client,
            token_retrieval_uri,
        }
    }
}

impl<C: HttpClient> TokenRetriever for L1TokenRetriever<'_, C> {
    fn retrieve(&self) -> Result<Token, TokenRetrieverError> {
        token_from_client_secret(
            self.http_client,
            &self.client_id,
            &self.client_secret,
            self.token_retrieval_uri,
        )
        .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))
    }
}

/// Basic response coming from the NR token retrieval endpoint
#[derive(Debug, PartialEq, Deserialize)]
struct TokenRetrievalResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
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

fn token_from_client_secret<C: HttpClient>(
    http_client: &C,
    client_id: &str,     // type
    client_secret: &str, // type
    token_retrieval_uri: &Uri,
) -> Result<Token, HttpClientError> {
    let json_body_string = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    });
    let json_body = serde_json::to_vec(&json_body_string)
        .map_err(|e| HttpClientError::EncoderError(format!("Failed to encode JSON: {}", e)))?;

    let request = http::Request::builder()
        .uri(token_retrieval_uri)
        .method("POST")
        .header(CONTENT_TYPE, "application/json")
        .body(json_body)
        .map_err(|e| HttpClientError::EncoderError(format!("Failed to build request: {}", e)))?;

    let response = http_client.send(request)?;
    let body = response.body();
    match response.status() {
        StatusCode::OK => {
            let decoded_body: TokenRetrievalResponse =
                serde_json::from_slice(body).map_err(|e| {
                    HttpClientError::DecoderError(format!("Failed to decode JSON: {}", e))
                })?;
            Token::try_from(decoded_body)
                .map_err(|e| HttpClientError::InvalidResponse(e.to_string()))
        }
        status => Err(HttpClientError::UnsuccessfulResponse(
            status.as_u16(),
            String::from_utf8_lossy(body).to_string(),
        )),
    }
}
