use chrono::{TimeDelta, Utc};
use http::Uri;

use crate::{
    TokenRetrieverError,
    authenticator::{AuthCredential, ClientAssertionType},
    jwt::{claims::Claims, signer::JwtSigner},
    system_identity::input_data::auth_method::ClientSecret,
};

/// A signed JWT should live enough for the System Identity Service to consume it.
pub(super) const DEFAULT_JWT_CLAIM_EXP: TimeDelta = TimeDelta::seconds(180);
/// The "aud" (audience) claim identifies the recipients that the JWT is intended for.
pub(super) const DEFAULT_AUDIENCE: &str = "https://www.newrelic.com/";

pub trait AuthCredentialBuilder {
    fn build_request_auth_credential(
        &self,
        client_id: String,
    ) -> Result<AuthCredential, TokenRetrieverError>;
}

#[derive(Debug)]
pub struct JwtSignerAuthBuilder<J: JwtSigner> {
    pub(super) aud: Uri,
    pub(super) jwt_signer: J,
}

impl<J: JwtSigner> AuthCredentialBuilder for JwtSignerAuthBuilder<J> {
    fn build_request_auth_credential(
        &self,
        client_id: String,
    ) -> Result<AuthCredential, TokenRetrieverError> {
        let expires_at = Utc::now() + DEFAULT_JWT_CLAIM_EXP;

        let timestamp = expires_at.timestamp().try_into().map_err(|_| {
            TokenRetrieverError::TokenRetrieverError("converting token expiration time".into())
        })?;

        let claims = Claims::new(client_id, self.aud.to_owned(), timestamp);

        let signed_jwt = self.jwt_signer.sign(claims)?;

        Ok(AuthCredential::ClientAssertion {
            client_assertion_type: ClientAssertionType::JwtBearer,
            client_assertion: signed_jwt.value().into(),
        })
    }
}

#[derive(Debug)]
pub struct ClientSecretAuthBuilder {
    pub(super) secret: ClientSecret,
}

impl AuthCredentialBuilder for ClientSecretAuthBuilder {
    fn build_request_auth_credential(
        &self,
        _client_id: String,
    ) -> Result<AuthCredential, TokenRetrieverError> {
        Ok(AuthCredential::ClientSecret {
            client_secret: self.secret.to_owned(),
        })
    }
}
