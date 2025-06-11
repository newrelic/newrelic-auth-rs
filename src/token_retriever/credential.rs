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

#[derive(Debug)]
pub(super) enum TokenCredential<J: JwtSigner> {
    JwtSigner { aud: Uri, jwt_signer: J },
    ClientSecret { secret: ClientSecret },
}

impl<J: JwtSigner> TokenCredential<J> {
    pub(super) fn build_request_auth_credential(
        &self,
        client_id: String,
    ) -> Result<AuthCredential, TokenRetrieverError> {
        let auth_credential = match self {
            TokenCredential::JwtSigner { aud, jwt_signer } => {
                let expires_at = Utc::now() + DEFAULT_JWT_CLAIM_EXP;

                let timestamp = expires_at.timestamp().try_into().map_err(|_| {
                    TokenRetrieverError::TokenRetrieverError(
                        "converting token expiration time".into(),
                    )
                })?;

                let claims = Claims::new(client_id, aud.to_owned(), timestamp);

                let signed_jwt = jwt_signer.sign(claims)?;

                AuthCredential::ClientAssertion {
                    client_assertion_type: ClientAssertionType::JwtBearer,
                    client_assertion: signed_jwt.value().into(),
                }
            }
            TokenCredential::ClientSecret { secret } => AuthCredential::ClientSecret {
                client_secret: secret.to_owned(),
            },
        };

        Ok(auth_credential)
    }
}
