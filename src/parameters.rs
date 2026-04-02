use crate::http::config::ProxyConfig;
use crate::key::PrivateKeyPem;
use crate::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
use crate::system_identity::input_data::environment::NewRelicEnvironment;
use crate::system_identity::input_data::output_platform::OutputPlatform;
use crate::system_identity::input_data::{
    SystemIdentityCreationMetadata, SystemTokenCreationMetadata,
};
use clap::error::ErrorKind::MissingRequiredArgument;
use clap::{Args, Error, Subcommand, ValueEnum};
use std::clone::Clone;
use std::convert::{From, Into};
use std::fs;
use std::path::PathBuf;
use std::result::Result;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum IdentityCreationCredential {
    /// Bearer token from OAuth authentication flow
    BearerToken(String),
    /// New Relic User API Key
    ApiKey(String),
}

pub const DEFAULT_AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(verbatim_doc_comment)]
    /// Creates a new system identity using either client credentials or a signed JWT.
    ///
    /// Choose the type of identity to create; there are two distinct methods of authentication:
    ///
    /// 1. Client Credentials (L1):
    ///    - Utilizes Client ID and Client Secret.
    ///    - The Client Secret expires.
    /// 2. Signed JWT (L2):
    ///    - Utilizes Client ID and Public/Private Keys.
    ///    - Does not expire.
    ///
    CreateIdentity {
        #[command(subcommand)]
        identity_type: IdentityType,
    },
    #[command(verbatim_doc_comment)]
    /// Creates a bootstrap system identity with NR Control Group membership.
    ///
    /// Bootstrap identities can create other identities. Only API key authentication is supported.
    ///
    CreateBootstrapIdentity {
        #[command(subcommand)]
        identity_type: IdentityTypeBootstrap,
    },
    #[command(verbatim_doc_comment)]
    /// Authenticates with New Relic and returns an authentication token.
    ///
    /// This function allows you to authenticate using either a client secret
    /// or a private key path. Upon successful authentication, it retrieves
    /// an authorization token.
    ///
    /// # Parameters
    /// - `client_secret`: A string containing the client secret for authentication.
    /// - `private_key_path`: A path to the private key file used for authentication.
    ///
    /// # Returns
    /// - An authentication token if the process is successful.
    Authenticate {
        /// Basic information to authenticate in newrelic
        #[command(flatten)]
        auth_args: AuthenticationArgs,

        /// Select format how the Token should be obtained
        #[arg(long)]
        output_token_format: OutputTokenFormat,
    },
}

#[derive(Args, Debug, Clone)]
pub struct ProxyArgs {
    /// Proxy configuration for the NR AUTH HTTP Client.
    ///
    /// The priority for the proxy configuration is as follows:
    /// 1. Arguments provided directly in the application.
    /// 2. Environment variables (`HTTP_PROXY` and `HTTPS_PROXY`).
    ///
    /// If neither arguments nor environment variables are provided, the client operates without a proxy.
    ///
    /// **Proxy URL Format:**
    /// `<protocol>://<user>:<password>@<host>:<port>`
    /// - `protocol`: e.g., `http` or `https`.
    /// - `user` and `password`: Optional credentials for authentication.
    /// - `host`: Required domain or IP address.
    /// - `port`: Optional port number.
    #[arg(long, verbatim_doc_comment)]
    proxy_url: Option<String>,

    /// System path with the CA certificates in PEM format. All `.pem` files in the directory are read.
    #[arg(long)]
    proxy_ca_dir: Option<PathBuf>,

    /// System path with the CA certificate in PEM format.
    #[arg(long)]
    proxy_ca_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct AuthenticationArgs {
    /// ID of the client
    #[arg(long, short)]
    client_id: String,

    /// Environment to target
    #[arg(short, long)]
    environment: Environments,

    /// Options for configuring authentication inputs.
    /// At least one authentication method must be specified.
    #[command(flatten)]
    input_auth_args: AuthInputArgs,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputTokenFormat {
    /// Returns only the access token without type or expiration date
    #[value(name = "PLAIN", alias = "Plain", alias = "plain")]
    PLAIN,
    /// Returns full token information in json format
    #[value(name = "JSON", alias = "Json", alias = "json")]
    JSON,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct AuthInputArgs {
    /// Client secret for authentication during creation
    #[arg(long)]
    client_secret: Option<String>,

    /// Path to the private key file used for authentication
    #[arg(long)]
    private_key_path: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct BasicAuthArgs {
    /// Name for the new resource
    #[arg(long, short)]
    name: Option<String>,

    /// Organization ID for the resource
    #[arg(long, short)]
    organization_id: String,

    /// [DEPRECATED] Optional client ID - no longer used by the API.
    /// The API returns a new client_id after creating the identity.
    /// This parameter is kept for backward compatibility only.
    #[arg(long, short)]
    client_id: Option<String>,

    /// Environment to target
    #[arg(long, short)]
    environment: Environments,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq)]
pub enum Environments {
    #[value(name = "US", alias = "Us", alias = "us")]
    US,
    #[value(name = "EU", alias = "Eu", alias = "eu")]
    EU,
    #[value(name = "STAGING", alias = "Staging", alias = "staging")]
    STAGING,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdentityType {
    #[command(verbatim_doc_comment)]
    /// Creates an identity whose type is 'secret'
    /// This type of identity expires
    ///
    /// EXAMPLE:
    ///
    /// SystemIdentity {
    /// id: "2e483fe9",
    /// name: Some("test1"),
    /// client_id: "8dbf3d32",
    /// organization_id: "b961cf81",
    /// identity_type: L1 {
    /// client_secret: "AfYFAUjf9",
    /// credential_expiration: "2025-06-04T19:25:00Z"
    /// }}
    Secret(SecretArgs),
    #[command(verbatim_doc_comment)]
    /// Creates an identity whose type is 'private key'
    /// This type of identity does not expire.
    ///
    /// EXAMPLE:
    ///
    /// SystemIdentity(
    /// id: e5af42f2,
    /// name: test,
    /// client_id: 8150a0ee,
    /// organization_id: b961cf81,
    /// identity_type: L2(pub_key: LS0tLS1))
    Key(KeyArgs),
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdentityTypeBootstrap {
    #[command(verbatim_doc_comment)]
    /// Creates secret (L1, expires) bootstrap identity.
    Secret(SecretArgsBootstrap),
    #[command(verbatim_doc_comment)]
    /// Creates key (L2, does not expire) bootstrap identity.
    Key(KeyArgsBootstrap),
}

#[derive(Args, Debug, Clone)]
pub struct KeyArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Authentication method for identity creation
    #[command(flatten)]
    auth_credential: AuthCredentialArgs,

    /// Options for configuring the output destination (required for Key identity)
    #[command(flatten)]
    output_options: OutputDestinationArgs,
}

#[derive(Args, Debug, Clone)]
pub struct SecretArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Authentication method for identity creation
    #[command(flatten)]
    auth_credential: AuthCredentialArgs,
}

#[derive(Args, Debug, Clone)]
pub struct KeyArgsBootstrap {
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    #[arg(long)]
    api_key: String,

    #[command(flatten)]
    output_options: OutputDestinationArgs,
}

#[derive(Args, Debug, Clone)]
pub struct SecretArgsBootstrap {
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    #[arg(long)]
    api_key: String,
}

#[derive(Args, Debug, Clone)]
#[group(required = true, multiple = false)]
pub struct AuthCredentialArgs {
    /// Bearer access token obtained from authentication (from authenticate command)
    #[arg(long)]
    bearer_access_token: Option<String>,

    /// New Relic User API Key for identity creation (does not expire, alternative to bearer token)
    #[arg(long)]
    api_key: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputPlatformChoice {
    #[value(name = "local-file")]
    LocalFile,
}

#[derive(Args, Debug, Clone)]
pub struct OutputDestinationArgs {
    /// Platform for the output of the generated key or resource.
    #[arg(long, value_enum)]
    output_platform: OutputPlatformChoice,

    /// Path to the file where the private key output will be saved (required if --output-platform=local-file).
    #[arg(long)]
    output_local_filepath: Option<PathBuf>,
}

pub fn create_metadata_for_token_retrieve(
    auth_args: AuthenticationArgs,
) -> Result<SystemTokenCreationMetadata, Box<dyn std::error::Error>> {
    let auth_method = select_auth_method(
        auth_args.input_auth_args.client_secret.clone(),
        auth_args.input_auth_args.private_key_path.clone(),
    )?;

    Ok(SystemTokenCreationMetadata {
        client_id: auth_args.client_id,
        environment: auth_args.environment.into(),
        auth_method,
    })
}

pub fn create_metadata_for_identity_creation(
    identity_type: &IdentityType,
) -> SystemIdentityCreationMetadata {
    let basic_auth_args = match identity_type {
        IdentityType::Secret(secret_args) => secret_args.basic_auth_args.clone(),
        IdentityType::Key(key_args) => key_args.basic_auth_args.clone(),
    };

    SystemIdentityCreationMetadata {
        organization_id: basic_auth_args.organization_id,
        name: basic_auth_args.name.clone(),
        environment: basic_auth_args.environment.into(),
    }
}

impl From<Environments> for NewRelicEnvironment {
    fn from(value: Environments) -> Self {
        match value {
            Environments::US => NewRelicEnvironment::US,
            Environments::EU => NewRelicEnvironment::EU,
            Environments::STAGING => NewRelicEnvironment::Staging,
        }
    }
}

/// Extracts the authentication credential from the identity creation arguments
pub fn extract_identity_creation_credential(
    identity_type: &IdentityType,
) -> Result<IdentityCreationCredential, Box<dyn std::error::Error>> {
    let auth_credential = match identity_type {
        IdentityType::Secret(secret_args) => &secret_args.auth_credential,
        IdentityType::Key(key_args) => &key_args.auth_credential,
    };

    if let Some(bearer_token) = &auth_credential.bearer_access_token {
        Ok(IdentityCreationCredential::BearerToken(
            bearer_token.clone(),
        ))
    } else if let Some(api_key) = &auth_credential.api_key {
        Ok(IdentityCreationCredential::ApiKey(api_key.clone()))
    } else {
        Err(Error::raw(
            MissingRequiredArgument,
            "Either --bearer-access-token or --api-key must be provided",
        ))?
    }
}

pub fn select_output_platform(key_args: KeyArgs) -> OutputPlatform {
    let output_platform = &key_args.output_options.output_platform;
    let output_filepath = key_args.output_options.output_local_filepath.clone();

    match output_platform {
        OutputPlatformChoice::LocalFile => {
            OutputPlatform::LocalPrivateKeyPath(output_filepath.unwrap_or_default())
        }
    }
}

pub fn select_auth_method(
    input_client_secret: Option<String>,
    input_private_key_path: Option<PathBuf>,
) -> Result<AuthMethod, Error> {
    if input_client_secret.is_some() {
        Ok(AuthMethod::ClientSecret(ClientSecret::from(
            input_client_secret.unwrap_or_default(),
        )))
    } else {
        let private_key = fs::read_to_string(input_private_key_path.unwrap_or_default())?;
        Ok(AuthMethod::PrivateKey(PrivateKeyPem::from(
            private_key.into_bytes(),
        )))
    }
}

pub fn create_metadata_for_bootstrap_identity_creation(
    identity_type: &IdentityTypeBootstrap,
) -> SystemIdentityCreationMetadata {
    let basic_auth_args = match identity_type {
        IdentityTypeBootstrap::Secret(secret_args) => secret_args.basic_auth_args.clone(),
        IdentityTypeBootstrap::Key(key_args) => key_args.basic_auth_args.clone(),
    };

    SystemIdentityCreationMetadata {
        organization_id: basic_auth_args.organization_id,
        name: basic_auth_args.name.clone(),
        environment: basic_auth_args.environment.into(),
    }
}

pub fn extract_api_key_from_bootstrap(identity_type: &IdentityTypeBootstrap) -> String {
    match identity_type {
        IdentityTypeBootstrap::Secret(secret_args) => secret_args.api_key.clone(),
        IdentityTypeBootstrap::Key(key_args) => key_args.api_key.clone(),
    }
}

pub fn select_output_platform_bootstrap(key_args: KeyArgsBootstrap) -> OutputPlatform {
    let output_platform = &key_args.output_options.output_platform;
    let output_filepath = key_args.output_options.output_local_filepath.clone();

    match output_platform {
        OutputPlatformChoice::LocalFile => {
            OutputPlatform::LocalPrivateKeyPath(output_filepath.unwrap_or_default())
        }
    }
}

pub fn build_proxy_args(proxy_args: ProxyArgs) -> Result<ProxyConfig, Error> {
    let config_result = ProxyConfig::new(
        proxy_args.proxy_url.unwrap_or_default(),
        proxy_args.proxy_ca_file.unwrap_or_default(),
        proxy_args.proxy_ca_dir.unwrap_or_default(),
    )?;

    let config = config_result.try_with_url_from_env()?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_build_proxy_with_args() {
        let proxy_args = ProxyArgs {
            proxy_url: Some("http://proxy.example.com:8080".to_string()),
            proxy_ca_file: Some(PathBuf::from("/path/to/certs")),
            proxy_ca_dir: Some(PathBuf::from("/path/to/ca.pem")),
        };

        let result = build_proxy_args(proxy_args);
        assert!(result.is_ok());

        let proxy_config = result.unwrap();
        assert_eq!(
            proxy_config.url_as_string(),
            "http://proxy.example.com:8080/"
        );
        assert_eq!(
            proxy_config.ca_bundle_file(),
            PathBuf::from("/path/to/ca.pem")
        );
        assert_eq!(
            proxy_config.ca_bundle_dir(),
            PathBuf::from("/path/to/certs")
        );
    }

    #[test]
    fn test_build_proxy_without_args() {
        let result = build_proxy_args(ProxyArgs {
            proxy_url: None,
            proxy_ca_dir: None,
            proxy_ca_file: None,
        });
        assert!(result.is_ok());

        let proxy_config = result.unwrap();
        assert_eq!(proxy_config, ProxyConfig::default());
    }

    #[test]
    fn test_build_proxy_invalid_url() {
        let proxy_args = ProxyArgs {
            proxy_url: Some("http://".to_string()),
            proxy_ca_file: None,
            proxy_ca_dir: None,
        };

        let result = build_proxy_args(proxy_args);
        if let Err(e) = result {
            assert!(
                e.to_string().contains("invalid proxy url"),
                "Error message did not contain the expected invalid URL context"
            );
        }
    }
}
