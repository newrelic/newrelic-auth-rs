//! # nr-auth library
//!
//! `nr-auth` aims to provide all the functionality needed to authenticate with System Identity Service and retrieve
//! authorization tokens to make authenticated and authorized requests to Fleet Control.
//!
//! It exposes the trait [`TokenRetriever`] which exposes a single method [`retrieve`](TokenRetriever::retrieve) which will retrieve a token with
//! an expiration time:
//!
//! ```rust
//! pub trait TokenRetriever {
//!     fn retrieve(&self) -> Result<Token, TokenRetrieverError>;
//! }
//! ```
//!
//! Token:
//!
//! ```rust
//! pub struct Token {
//!     expires_at: DateTime<Utc>,
//!     access_token: AccessToken,
//!     token_type: TokenType,
//! }
//! ```

pub mod authenticator;
pub mod http_client;
pub mod iam_client;
pub mod jwt;
pub mod key_pair_generator;
pub mod system_identity;
pub mod system_identity_generator;
pub mod token;
pub mod token_retriever;

use crate::token::Token;
use thiserror::Error;

pub type ClientID = String;
pub type OrganizationID = String;

#[derive(Error, Debug)]
pub enum TokenRetrieverError {
    #[error("retrieving token: `{0}`")]
    TokenRetrieverError(String),
    #[error("signing JWT: `{0}`")]
    JwtSignerError(#[from] jwt::error::JwtEncoderError),
    #[error("fetching access token: `{0}`")]
    AuthenticatorError(#[from] authenticator::AuthenticateError),
    #[error("acquiring cache mutex lock")]
    PoisonError,
}

/// The TokenRetriever will be the responsible to retrieve an authorization token
pub trait TokenRetriever {
    fn retrieve(&self) -> Result<Token, TokenRetrieverError>;
}
