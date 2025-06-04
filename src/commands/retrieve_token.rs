use crate::authenticator::HttpAuthenticator;
use crate::http_client::HttpClient;
use crate::jwt::signer::local::LocalPrivateKeySigner;
use crate::jwt::signer::JwtSignerImpl;
use crate::system_identity::input_data::auth_method::AuthMethod;
use crate::system_identity::input_data::SystemTokenCreationMetadata;
use crate::token::Token;
use crate::token_retriever::TokenRetrieverWithCache;
use crate::{TokenRetriever, TokenRetrieverError};

pub struct RetrieveTokenCommand<C>
where
    C: HttpClient + Clone,
{
    http_client: C,
}

impl<C> RetrieveTokenCommand<C>
where
    C: HttpClient + Clone,
{
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }

    pub fn retrieve_token(
        &self,
        metadata: &SystemTokenCreationMetadata,
    ) -> Result<Token, TokenRetrieverError> {
        let http_authenticator = HttpAuthenticator::new(
            self.http_client.clone(),
            metadata.environment.token_renewal_endpoint(),
        );

        let http_token_retriever = match &metadata.auth_method {
            AuthMethod::ClientSecret(client_secret) => TokenRetrieverWithCache::new_with_secret(
                metadata.client_id.to_owned(),
                http_authenticator,
                client_secret.to_owned(),
            ),
            AuthMethod::PrivateKey(private_key_pem) => {
                let jwt_signer = JwtSignerImpl::Local(
                    LocalPrivateKeySigner::try_from(private_key_pem)
                        .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?,
                );
                TokenRetrieverWithCache::new_with_jwt_signer(
                    metadata.client_id.to_owned(),
                    http_authenticator,
                    jwt_signer,
                )
            }
        };

        Ok(http_token_retriever
            .retrieve()
            .map_err(|e| TokenRetrieverError::TokenRetrieverError(e.to_string()))?)
    }
}
