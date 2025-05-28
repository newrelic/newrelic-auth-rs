use std::fmt;

use crate::{
    authenticator::HttpAuthenticator,
    http_client::HttpClient,
    jwt::signer::{local::LocalPrivateKeySigner, JwtSignerImpl},
    system_identity::input_data::{auth_method::AuthMethod, SystemIdentityCreationMetadata},
    token::Token,
    token_retriever::TokenRetrieverWithCache,
    TokenRetriever, TokenRetrieverError,
};

use super::l1_retriever::L1TokenRetriever;

/// HTTP-based token retriever.
///
/// It will work with both L1 and L2 authentication methods, informed by [`AuthMethod`].
pub enum HttpTokenRetriever<C: HttpClient> {
    ClientSecretRetriever(L1TokenRetriever<C>),
    PrivateKeyRetriever(TokenRetrieverWithCache<HttpAuthenticator<C>, JwtSignerImpl>),
}

impl<C: HttpClient> fmt::Debug for HttpTokenRetriever<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpTokenRetriever::ClientSecretRetriever(retriever) => f
                .debug_tuple("ClientSecretRetriever")
                .field(retriever)
                .finish(),
            HttpTokenRetriever::PrivateKeyRetriever(retriever) => f
                .debug_tuple("PrivateKeyRetriever")
                .field(retriever)
                .finish(),
        }
    }
}

impl<C> TokenRetriever for HttpTokenRetriever<C>
where
    C: HttpClient,
{
    fn retrieve(&self) -> Result<Token, TokenRetrieverError> {
        match self {
            HttpTokenRetriever::ClientSecretRetriever(retriever) => retriever.retrieve(),
            HttpTokenRetriever::PrivateKeyRetriever(retriever) => retriever.retrieve(),
        }
    }
}

impl<C> HttpTokenRetriever<C>
where
    C: HttpClient,
{
    /// Creates a new [`HttpTokenRetriever`] based on the provided authentication method.
    pub fn new(
        http_client: C,
        metadata: &SystemIdentityCreationMetadata,
    ) -> Result<Self, TokenRetrieverError> {
        let system_id_input = &metadata.system_identity_input;
        match &system_id_input.auth_method {
            AuthMethod::ClientSecret(client_secret) => Ok(
                HttpTokenRetriever::ClientSecretRetriever(L1TokenRetriever::new(
                    system_id_input.client_id.to_owned(),
                    client_secret.to_owned(),
                    http_client,
                    metadata.environment.token_renewal_endpoint(),
                )),
            ),
            AuthMethod::PrivateKey(private_key_pem) => {
                let signer = LocalPrivateKeySigner::try_from(private_key_pem)
                    .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?;
                let jwt_signer = JwtSignerImpl::Local(signer);
                let authenticator = HttpAuthenticator::new(
                    http_client,
                    metadata.environment.token_renewal_endpoint(),
                );

                Ok(HttpTokenRetriever::PrivateKeyRetriever(
                    TokenRetrieverWithCache::new(
                        system_id_input.client_id.to_owned(),
                        jwt_signer,
                        authenticator,
                    ),
                ))
            }
        }
    }
}
