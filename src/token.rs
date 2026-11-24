use std::convert::TryFrom;
use std::fmt;
use std::result::Result;
use std::result::Result::{Err, Ok};
use std::time::Duration;

use crate::{TokenRetrieverError, authenticator::TokenRetrievalResponse};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

pub type AccessToken = String;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum TokenType {
    Bearer,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Token {
    expires_at: Timestamp,
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
    pub fn new(access_token: AccessToken, token_type: TokenType, expires_at: Timestamp) -> Self {
        Token {
            access_token,
            token_type,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Timestamp::now()
    }

    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    pub fn token_type(&self) -> &TokenType {
        &self.token_type
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenType::Bearer => write!(f, "Bearer"),
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.token_type, self.access_token)
    }
}

impl TryFrom<TokenRetrievalResponse> for Token {
    type Error = TokenRetrieverError;

    fn try_from(response: TokenRetrievalResponse) -> Result<Self, Self::Error> {
        let access_token = response.access_token;
        let token_type = TokenType::try_from(response.token_type.as_str())
            .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?;

        // Assuming we get seconds from the `expires_in` field of the JSON response
        let expires_at = Timestamp::now()
            .checked_add(Duration::from_secs(response.expires_in))
            .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?;

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
    use jiff::{SignedDuration, Timestamp};
    use rstest::rstest;
    use std::convert::{From, TryFrom};
    use std::string::ToString;

    #[test]
    fn token_is_expired() {
        let past = Timestamp::now() - SignedDuration::from_millis(10);
        let token = Token::new(AccessToken::from("some-token"), TokenType::Bearer, past);
        assert!(token.is_expired())
    }

    #[test]
    fn token_is_not_expired() {
        let future = Timestamp::now() + SignedDuration::from_millis(10);
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

        let err = result.unwrap_err();
        assert!(
            matches!(&err, TokenRetrieverError::TokenRetrieverError(_)),
            "Expected TokenRetrieverError: '{err}'"
        );
    }

    #[rstest]
    #[case::whole_seconds(0, "2026-11-23T10:00:00Z")]
    #[case::millis(120_000_000, "2026-11-23T10:00:00.12Z")]
    #[case::micros(123_456_000, "2026-11-23T10:00:00.123456Z")]
    #[case::nanos(123_456_789, "2026-11-23T10:00:00.123456789Z")]
    fn token_expires_at_serialization_format(#[case] nanos: i64, #[case] expected: &str) {
        let expires_at = "2026-11-23T10:00:00Z".parse::<Timestamp>().unwrap()
            + SignedDuration::from_nanos(nanos);
        let token = Token::new(
            AccessToken::from("some-token"),
            TokenType::Bearer,
            expires_at,
        );

        let json = serde_json::to_value(&token).unwrap();
        assert_eq!(json["expires_at"], expected);

        let back: Token = serde_json::from_value(json).unwrap();
        assert_eq!(back, token);
    }
}
