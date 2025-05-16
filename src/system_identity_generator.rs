use crate::http_client::HttpClient;
use crate::iam_client::{IamClient, SystemIdentityRequest};
use crate::jwt::signer::{JwtSignerBuilder, JwtSignerConfigImpl};
use crate::key_pair_generator::{KeyPairGeneratorBuilder, KeyPairGeneratorConfigImpl};
use crate::system_identity::{AuthMethod, SystemIdentity};
use crate::token_retriever::TokenRetreiverBuilder;
use crate::OrganizationID;

// Do we need a service? perhaps it could just be a
// pub fn generate_system_identity(http_client,config)->Result<SystemIdentity, SystemIdentityGeneratorError>
struct SystemIdentityGenerator<C, T, J, K, I>
where
    C: HttpClient,
    T: TokenRetreiverBuilder,
    J: JwtSignerBuilder,
    K: KeyPairGeneratorBuilder,
    I: IamClient,
{
    http_client: C,
    token_retriever_builder: T,
    jwt_signer_builder: J,
    key_pair_generator_builder: K,
    iam_client: I,
}

impl<C, T, J, K, I> SystemIdentityGenerator<C, T, J, K, I>
where
    C: HttpClient,
    T: TokenRetreiverBuilder,
    J: JwtSignerBuilder,
    K: KeyPairGeneratorBuilder,
    I: IamClient,
{
    pub fn new(
        http_client: C,
        token_retriever_builder: T,
        jwt_signer_builder: J,
        key_pair_generator_builder: K,
        iam_client: I,
    ) -> Self {
        Self {
            http_client,
            token_retriever_builder,
            jwt_signer_builder,
            key_pair_generator_builder,
            iam_client,
        }
    }

    pub fn generate(
        &self,
        parameters: SystemIdentityCreationParameters,
    ) -> Result<SystemIdentity, SystemIdentityGeneratorError> {
        // Pseudo code of the generated function.

        // Obtain requester_auth token
        let parent_token = match parameters.requester_auth {
            RequesterAuthConfig::SistemIdentity(si) => {
                let _token_retreiver: () = match si.auth_method {
                    crate::system_identity::AuthMethod::L1(_client_secret) => {
                        // Build token retreiver for L1 (does not exist yet perhaps we don't implement it yet)
                        // self.token_retriever_builder.build(...)
                        unimplemented!()
                    }
                    crate::system_identity::AuthMethod::L2(jwt_signer_config) => {
                        let _jwt_signer = self.jwt_signer_builder.build(jwt_signer_config);
                        // Build token retreiver for L2
                        // self.token_retriever_builder.build(...)
                        unimplemented!()
                    }
                };

                // build token retriever according to SystemIdentity config (L1 or L2)
                // and retreive the token
                unimplemented!()
            }
            RequesterAuthConfig::SistemIdentityToken(token) => token,
        };

        let (pub_key) = match &parameters.target_identity {
            TargetConfig::KeyPairGeneratorConfig(config) => {
                let key_gen = self.key_pair_generator_builder.build(config);
                // Build key
                unimplemented!()
            }
            TargetConfig::PubKeyPEM(pub_key) => Some(pub_key),

            TargetConfig::NoPubKey => None,
        };

        let response = self.iam_client.systemIdentityCreate(SystemIdentityRequest {
            name: parameters.name,
            org_id: parameters.org_id.clone(),
            pub_key: pub_key.cloned(),
        });

        let auth_method: AuthMethod = match parameters.target_identity {
            TargetConfig::KeyPairGeneratorConfig(_) => {
                // Build L2 auth based on the generated key
                // AuthMethod::L2(JwtSignerConfigImpl)
                unimplemented!()
            }
            TargetConfig::PubKeyPEM(_) => {
                // Build L2 auth based on the generated key
                // AuthMethod::L2(JwtSignerConfigImpl)
                unimplemented!()
            }

            TargetConfig::NoPubKey => AuthMethod::L1(response.client_secret.unwrap()),
        };

        Ok(SystemIdentity {
            client_id: response.client_id,
            org_id: parameters.org_id,
            auth_method: auth_method,
        })
    }
}

struct SystemIdentityCreationParameters {
    org_id: OrganizationID,
    name: String,
    requester_auth: RequesterAuthConfig,
    target_identity: TargetConfig,
}

pub enum RequesterAuthConfig {
    SistemIdentity(SystemIdentity),

    SistemIdentityToken(String),
    // Do we want to support this ?
    // ApiKey(String),
}

pub enum TargetConfig {
    // KeyPair Configs to generate L2
    // Generates a key pair locally or in a external service
    KeyPairGeneratorConfig(KeyPairGeneratorConfigImpl),
    // Use an existing PubKey
    PubKeyPEM(String),

    // Generate L1
    NoPubKey,
}

#[derive(thiserror::Error, Debug)]
pub enum SystemIdentityGeneratorError {
    #[error("TBD: `{0}`")]
    SystemIdentityGenerationError(String),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::http_client::tests::HttpClientUreq;
    use crate::key_pair_generator::KeyPairGeneratorLocalConfig;

    use super::*;

    fn example_generate_l2_from_l1() {
        // User will have org_id, client_id and client_secret

        let http_client = HttpClientUreq::new(Duration::from_millis(1));
        let si_gen = SystemIdentityGenerator::new(
            http_client,
            token_retriever_builder,
            jwt_signer_builder,
            key_pair_generator_builder,
            iam_client,
        );
        let parent_si = SystemIdentity {
            org_id: "my-L1-org-id".to_string(),
            client_id: "my-L1-client-id".to_string(),
            auth_method: AuthMethod::L1("my-client-secret".into()),
        };

        let parameters = SystemIdentityCreationParameters {
            name: "my-generated-ci".to_string(),
            org_id: "my-org-id".to_string(),
            requester_auth: RequesterAuthConfig::SistemIdentity(parent_si),
            target_identity: TargetConfig::KeyPairGeneratorConfig(
                KeyPairGeneratorConfigImpl::Local(KeyPairGeneratorLocalConfig()),
            ),
        };

        let generated_si = si_gen.generate(parameters).unwrap();

        generated_si.to_some_exportable_format();
    }
}
