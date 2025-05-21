use std::fmt;

use http::Uri;

use crate::{
    authenticator::HttpAuthenticator,
    http_client::HttpClient,
    jwt::signer::{local::LocalPrivateKeySigner, JwtSignerImpl},
    token::Token,
    token_retriever::TokenRetrieverWithCache,
    TokenRetriever, TokenRetrieverError,
};

use super::{client_input::AuthMethod, l1_token_retriever::L1TokenRetriever};

pub enum HttpTokenRetrieverImpl<'a, C: HttpClient> {
    ClientSecretRetriever(L1TokenRetriever<'a, C>),
    PrivateKeyRetriever(TokenRetrieverWithCache<HttpAuthenticator<'a, C>, JwtSignerImpl>),
}

impl<C: HttpClient> fmt::Debug for HttpTokenRetrieverImpl<'_, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpTokenRetrieverImpl::ClientSecretRetriever(retriever) => f
                .debug_tuple("ClientSecretRetriever")
                .field(retriever)
                .finish(),
            HttpTokenRetrieverImpl::PrivateKeyRetriever(retriever) => f
                .debug_tuple("PrivateKeyRetriever")
                .field(retriever)
                .finish(),
        }
    }
}

impl<C> TokenRetriever for HttpTokenRetrieverImpl<'_, C>
where
    C: HttpClient,
{
    fn retrieve(&self) -> Result<Token, TokenRetrieverError> {
        match self {
            HttpTokenRetrieverImpl::ClientSecretRetriever(retriever) => retriever.retrieve(),
            HttpTokenRetrieverImpl::PrivateKeyRetriever(retriever) => retriever.retrieve(),
        }
    }
}

impl<'a, C> HttpTokenRetrieverImpl<'a, C>
where
    C: HttpClient,
{
    pub fn from_auth_method(
        http_client: &'a C,
        auth_method: AuthMethod,
        token_retrieval_uri: &'a Uri,
        client_id: String,
    ) -> Result<Self, TokenRetrieverError> {
        match auth_method {
            AuthMethod::ClientSecret(client_secret) => Ok(
                HttpTokenRetrieverImpl::ClientSecretRetriever(L1TokenRetriever::new(
                    client_id,
                    client_secret,
                    http_client,
                    token_retrieval_uri,
                )),
            ),
            AuthMethod::FromLocalPrivateKey(private_key_pem) => {
                let signer = LocalPrivateKeySigner::try_from(private_key_pem.as_slice())
                    .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?;
                let jwt_signer = JwtSignerImpl::Local(signer);
                let authenticator = HttpAuthenticator::new(http_client, token_retrieval_uri);

                Ok(HttpTokenRetrieverImpl::PrivateKeyRetriever(
                    TokenRetrieverWithCache::new(client_id, jwt_signer, authenticator),
                ))
            }
        }
    }
}
