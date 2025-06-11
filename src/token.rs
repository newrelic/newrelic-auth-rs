use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};

use crate::{TokenRetrieverError, authenticator::TokenRetrievalResponse};

pub type AccessToken = String;

#[derive(Clone, Debug, PartialEq)]
pub enum TokenType {
    Bearer,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    expires_at: DateTime<Utc>,
    access_token: AccessToken,
    token_type: TokenType,
}

impl TryFrom<&str> for TokenType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Bearer" | "bearer" => Ok(TokenType::Bearer),
            _ => Err(format!("Invalid token type: {value}")),
        }
    }
}

impl Token {
    pub fn new(
        access_token: AccessToken,
        token_type: TokenType,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Token {
            access_token,
            token_type,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.lt(&Utc::now())
    }

    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    pub fn token_type(&self) -> &TokenType {
        &self.token_type
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
mod test {

    use crate::{
        TokenRetrieverError,
        authenticator::TokenRetrievalResponse,
        token::{AccessToken, Token, TokenType},
    };
    use chrono::{Duration, Utc};

    #[test]
    fn token_is_expired() {
        let past = Utc::now() - Duration::milliseconds(10);
        let token = Token::new(AccessToken::from("some-token"), TokenType::Bearer, past);
        assert!(token.is_expired())
    }

    #[test]
    fn token_is_not_expired() {
        let future = Utc::now() + Duration::milliseconds(10);
        let token = Token::new(AccessToken::from("some-token"), TokenType::Bearer, future);
        assert!(!token.is_expired())
    }

    #[test]
    fn token_retrieval_response_incorrect_time() {
        let response = TokenRetrievalResponse {
            access_token: "some-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: u64::MAX,
        };
        let result = Token::try_from(response);
        assert!(
            result.is_err(),
            "Expected error due to invalid expiration time"
        );

        let err_msg = result.unwrap_err();
        assert!(
            matches!(
                &err_msg,
                TokenRetrieverError::TokenRetrieverError(e) if e == "Source duration value is out of range for the target type"
            ),
            "Expected TokenRetrieverError with specific message: '{}'",
            err_msg
        );
    }
}
