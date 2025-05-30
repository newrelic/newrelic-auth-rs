use crate::authenticator::{Authenticator, GrantType, TokenRetrievalRequest};
use crate::jwt::signer::JwtSigner;
use crate::system_identity::input_data::auth_method::ClientSecret;
use crate::token::Token;
use crate::{ClientID, TokenRetriever, TokenRetrieverError};

use ::http::Uri;
use credential::{TokenCredential, DEFAULT_AUDIENCE};
use std::sync::Mutex;
use tracing::debug;

mod credential;

#[derive(Debug)]
pub struct TokenRetrieverWithCache<A, J>
where
    A: Authenticator,
    J: JwtSigner,
{
    client_id: ClientID,
    tokens: Mutex<Option<Token>>,
    credential: TokenCredential<J>,
    authenticator: A,
    retries: u8,
}

impl<A, J> TokenRetriever for TokenRetrieverWithCache<A, J>
where
    A: Authenticator,
    J: JwtSigner,
{
    fn retrieve(&self) -> Result<Token, TokenRetrieverError> {
        let mut cached_token = self
            .tokens
            .lock()
            .map_err(|_| TokenRetrieverError::PoisonError)?;

        if cached_token.is_none() || cached_token.as_ref().is_some_and(|t| t.is_expired()) {
            // Attempt to refresh the token. Retry if failed.
            // This retry will block everyone trying to retrieve the token,
            // so we should enforce low retry numbers and error early.
            let mut attempt = 0;
            loop {
                match self.refresh_token() {
                    Ok(token) => {
                        debug!("authorization token refreshed");
                        *cached_token = Some(token);
                        break;
                    }
                    Err(e) => {
                        debug!("error refreshing token: {e}");

                        attempt += 1;
                        if self.should_retry_refresh(attempt, &e) {
                            debug!("retrying to refresh token");
                            continue;
                        } else {
                            debug!("exhausted retries");
                            return Err(e);
                        }
                    }
                }
            }
        }

        cached_token
            .to_owned()
            .ok_or(TokenRetrieverError::TokenRetrieverError(
                "getting token from cache".into(),
            ))
    }
}

impl<A, J> TokenRetrieverWithCache<A, J>
where
    A: Authenticator,
    J: JwtSigner,
{
    /// Creates a new `TokenRetrieverWithCache` that signs JWTs to operate.
    ///
    /// This is intended to be used when the parent System Identity is L2, as it requires signing
    /// a JWT with the private key to retrieve the token.
    pub fn new_with_jwt_signer(client_id: ClientID, authenticator: A, jwt_signer: J) -> Self {
        let aud = Uri::try_from(DEFAULT_AUDIENCE).expect("constant valid url value");
        Self {
            client_id,
            tokens: Mutex::new(None),
            credential: TokenCredential::JwtSigner { aud, jwt_signer },
            authenticator,
            retries: 0,
        }
    }

    /// Creates a new `TokenRetrieverWithCache` that uses a client secret to operate.
    ///
    /// This is intended to be used when the parent System Identity is L1, as it will
    /// authenticate with a client secret to retrieve the token.
    pub fn new_with_secret(client_id: ClientID, authenticator: A, secret: ClientSecret) -> Self {
        Self {
            client_id,
            tokens: Mutex::new(None),
            credential: TokenCredential::ClientSecret { secret },
            authenticator,
            retries: 0,
        }
    }

    pub fn with_retries(self, retries: u8) -> Self {
        Self { retries, ..self }
    }

    pub fn should_retry_refresh(&self, attempt: u8, _err: &TokenRetrieverError) -> bool {
        attempt < self.retries + 1
        // We could decide to act on the specific error encountered as well.
        //   && matches!(err, TokenRetrieverError::TokenRetrieverError(_))
    }

    fn refresh_token(&self) -> Result<Token, TokenRetrieverError> {
        let credential = self
            .credential
            .build_request_auth_credential(self.client_id.to_owned())?;

        let request = TokenRetrievalRequest {
            client_id: self.client_id.to_owned(),
            grant_type: GrantType::ClientCredentials,
            credential,
        };

        let response = self.authenticator.authenticate(request)?;

        Token::try_from(response)
            .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))
    }
}

#[cfg(test)]
pub mod test {
    use std::{thread, time};

    use chrono::{TimeDelta, Utc};
    use mockall::mock;
    use mockall::{predicate::eq, Sequence};

    use crate::authenticator::test::MockAuthenticatorMock;

    use crate::authenticator::AuthCredential;
    use crate::jwt::signer::tests::MockJwtSigner;
    use crate::token_retriever::credential::DEFAULT_JWT_CLAIM_EXP;
    use crate::{
        authenticator::{
            AuthenticateError, ClientAssertionType, GrantType, TokenRetrievalRequest,
            TokenRetrievalResponse,
        },
        jwt::signed::SignedJwt,
        token::{Token, TokenType},
        TokenRetriever, TokenRetrieverError,
    };

    use super::{TokenRetrieverWithCache, DEFAULT_AUDIENCE};

    mock! {
        pub TokenRetriever {}
        impl TokenRetriever for TokenRetriever {
            fn retrieve(&self) -> Result<Token, TokenRetrieverError>;
        }
    }

    #[test]
    // Test that a new token is retrieved when there is no cache and a cached token is
    // returned in case is not expired.
    fn retrieve_token_miss_hit_cache() {
        let client_id = "client_id";
        let token_expires_in = 1;

        let fake_client_assertion = "client_assertion";
        let fake_token = "fakeToken";

        let mut jwt_signer = MockJwtSigner::new();
        jwt_signer
            .expect_sign()
            .once()
            .withf(move |claims| {
                let exp = Utc::now() + DEFAULT_JWT_CLAIM_EXP;
                claims.iss == client_id
                    && claims.aud == DEFAULT_AUDIENCE
                    && claims.exp == exp.timestamp() as u64
            })
            .returning(move |_| {
                Ok(SignedJwt {
                    value: fake_client_assertion.into(),
                })
            });

        let expected_request = TokenRetrievalRequest {
            client_id: client_id.to_owned(),
            grant_type: GrantType::ClientCredentials,
            credential: AuthCredential::ClientAssertion {
                client_assertion_type: ClientAssertionType::JwtBearer,
                client_assertion: fake_client_assertion.into(),
            },
        };

        let mut authenticator = MockAuthenticatorMock::default();
        authenticator
            .expect_authenticate()
            .once()
            .with(eq(expected_request))
            .returning(move |_| {
                Ok(TokenRetrievalResponse {
                    access_token: fake_token.into(),
                    expires_in: token_expires_in,
                    token_type: "Bearer".into(),
                })
            });

        let token_retriever = TokenRetrieverWithCache::new_with_jwt_signer(
            client_id.into(),
            authenticator,
            jwt_signer,
        );

        let expected_token = Token::new(
            fake_token.into(),
            TokenType::Bearer,
            Utc::now() + TimeDelta::seconds(token_expires_in as i64),
        );

        let cache_miss_token = token_retriever.retrieve().unwrap();

        assert_eq!(
            expected_token.access_token(),
            cache_miss_token.access_token()
        );
        assert!(!cache_miss_token.is_expired());

        let cache_hit_token = token_retriever.retrieve().unwrap();

        assert_eq!(cache_miss_token, cache_hit_token);
    }

    #[test]
    // Test that a new token is retrieved when the cached one expired.
    fn retrieve_token_expired_cache() {
        let client_id = "client_id";
        let token_expires_in = 2;

        let mut jwt_signer = MockJwtSigner::new();
        jwt_signer.expect_sign().times(2).returning(move |_| {
            Ok(SignedJwt {
                value: "client_assertion".into(),
            })
        });

        let mut authenticator = MockAuthenticatorMock::default();
        authenticator
            .expect_authenticate()
            .times(2)
            .returning(move |_| {
                Ok(TokenRetrievalResponse {
                    // generates a different token each time.
                    access_token: Utc::now().to_string(),
                    expires_in: token_expires_in,
                    token_type: "Bearer".into(),
                })
            });

        let token_retriever = TokenRetrieverWithCache::new_with_jwt_signer(
            client_id.into(),
            authenticator,
            jwt_signer,
        );

        let cache_miss_token = token_retriever.retrieve().unwrap();

        // waits until the cached token expired + buffer to avoid flaky failures.
        thread::sleep(time::Duration::from_secs(token_expires_in) + time::Duration::from_secs(1));

        let cache_expired_token = token_retriever.retrieve().unwrap();

        assert_ne!(
            cache_expired_token.access_token(),
            cache_miss_token.access_token()
        )
    }

    #[test]
    fn no_retries_and_fail_calls_retrieve_once() {
        let client_id = "client_id";

        let mut jwt_signer = MockJwtSigner::new();
        // This actually tests TokenRetrieverWithCache's `refresh_token`.
        // Calling `retrieve` makes calls to both first `sign` and then to `authenticate`.
        // We instruct the `authenticate` call to fail every time and check that `sign` is called only the number of times we expect.
        jwt_signer.expect_sign().once().returning(move |_| {
            Ok(SignedJwt {
                value: "client_assertion".into(),
            })
        });

        let mut authenticator = MockAuthenticatorMock::default();
        authenticator
            .expect_authenticate()
            .once()
            .returning(move |_| {
                Err(AuthenticateError::DeserializeError(
                    "some_serde_error".to_owned(),
                ))
            });

        let token_retriever = TokenRetrieverWithCache::new_with_jwt_signer(
            client_id.into(),
            authenticator,
            jwt_signer,
        )
        .with_retries(0);

        // Retries expired, error returned
        let cache_miss_token = token_retriever.retrieve();

        assert!(cache_miss_token.is_err());
    }

    #[test]
    fn retries_success() {
        let client_id = "client_id";
        let fake_token = "fake";
        let token_expires_in = 5;

        let mut jwt_signer = MockJwtSigner::new();
        // This actually tests TokenRetrieverWithCache's `refresh_token`.
        // Calling `retrieve` makes calls to both first `sign` and then to `authenticate`.
        // We instruct the `authenticate` call to fail every time and check that `sign` is called only the number of times we expect.
        jwt_signer.expect_sign().times(2).returning(move |_| {
            Ok(SignedJwt {
                value: "client_assertion".into(),
            })
        });

        let mut auth_sequence = Sequence::new();
        let mut authenticator = MockAuthenticatorMock::default();
        authenticator
            .expect_authenticate()
            .once()
            .in_sequence(&mut auth_sequence)
            .returning(move |_| {
                Err(AuthenticateError::DeserializeError(
                    "some_serde_error".to_owned(),
                ))
            });

        authenticator
            .expect_authenticate()
            .once()
            .returning(move |_| {
                Ok(TokenRetrievalResponse {
                    // generates a different token each time.
                    access_token: fake_token.into(),
                    expires_in: token_expires_in,
                    token_type: "bearer".into(),
                })
            });

        let token_retriever = TokenRetrieverWithCache::new_with_jwt_signer(
            client_id.into(),
            authenticator,
            jwt_signer,
        )
        .with_retries(2);

        let expected_token = Token::new(
            fake_token.into(),
            TokenType::Bearer,
            Utc::now() + TimeDelta::seconds(token_expires_in as i64),
        );

        // Retries expired, error returned
        let cache_miss_token = token_retriever.retrieve().unwrap();

        assert_eq!(
            cache_miss_token.access_token(),
            expected_token.access_token()
        );
    }

    #[test]
    fn retries_fail() {
        let client_id = "client_id";

        let mut jwt_signer = MockJwtSigner::new();
        // This actually tests TokenRetrieverWithCache's `refresh_token`. Calling `retrieve` makes calls to both first `sign` and then to `authenticate`. We instruct the `authenticate` call to fail every time and check that `sign` is called only the number of times we expect.
        jwt_signer.expect_sign().times(3).returning(move |_| {
            Ok(SignedJwt {
                value: "client_assertion".into(),
            })
        });

        let mut authenticator = MockAuthenticatorMock::default();
        authenticator.expect_authenticate().returning(move |_| {
            Err(AuthenticateError::DeserializeError(
                "some_serde_error".to_owned(),
            ))
        });

        let token_retriever = TokenRetrieverWithCache::new_with_jwt_signer(
            client_id.into(),
            authenticator,
            jwt_signer,
        )
        .with_retries(2);

        // Retries expired, error returned
        let cache_miss_token = token_retriever.retrieve();

        assert!(cache_miss_token.is_err());
    }
}
