use crate::key::PrivateKeyPem;
use crate::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
use crate::system_identity::input_data::environment::NewRelicEnvironment;
use crate::system_identity::input_data::output_platform::OutputPlatform;
use crate::system_identity::input_data::{
    SystemIdentityCreationMetadata, SystemIdentityInput, SystemTokenCreationMetadata,
};
use crate::token::{AccessToken, Token, TokenType};
use alloc::boxed::Box;
use alloc::string::String;
use chrono::DateTime;
use clap::error::ErrorKind;
use clap::{Args, Error, Subcommand, ValueEnum};
use core::str::FromStr;
use http::Uri;
use std::clone::Clone;
use std::convert::{From, Into};
use std::default::Default;
use std::fs;
use std::option::Option;
use std::path::PathBuf;
use std::result::Result;
use std::result::Result::Ok;
use std::time::Duration;

pub const DEFAULT_AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Subcommand, Debug)]
#[group(id = "input-auth-methods", required = true, multiple = false)]
pub enum Commands {
    /// Creates a new identity with a secret or with a private key, with specified credentials.
    CreateIdentity {
        /// Choose the type of identity to create; there are two distinct identity types.
        ///
        /// 1. Private Key Identity:
        ///    - Known as a parent identity.
        ///    - This identity type does not expire.
        ///
        /// 2. Secret Identity:
        ///    - This identity type expires.
        #[command(subcommand)]
        identity_type: IdentityType,
    },
    /// Retrieve a token providing a client secret or private key path.
    RetrieveToken {
        /// ID of the client
        #[arg(long, short, required = true)]
        client_id: Option<String>,

        /// Environment to target
        #[arg(short, long, required = true)]
        environment: Environments,

        /// Options for configuring the inputs to authenticate one of them at least should be added.
        #[command(flatten)]
        input_auth_args: AuthInputArgs,

        /// Select format how the Token should be obtained
        #[arg(long, required = true)]
        output_token_format: OutPutTokenFormat,

        /// Custom endpoint configuration (only used if --environment=custom).
        #[command(flatten)]
        endpoints: ExternalEndpoints,
    },
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutPutTokenFormat {
    /// Returns only the access token without type or expiration day
    #[value(name = "Plain")]
    Plain,
    /// Returns full token information in json format
    #[value(name = "Json")]
    Json,
}

#[derive(Args, Debug)]
pub struct AuthInputArgs {
    /// Client secret for authentication during creation
    #[arg(long, group = "input-auth-methods")]
    client_secret: Option<String>,

    /// Path to the private key file used for authentication
    #[arg(long, group = "input-auth-methods")]
    private_key_path: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct BasicAuthArgs {
    /// Name for the new resource
    #[arg(long, short, required = false)]
    name: Option<String>,

    /// Organization ID for the resource
    #[arg(long, short, required = true)]
    organization_id: String,

    /// ID of the client
    #[arg(long, short, required = true)]
    client_id: String,

    /// Environment to target
    #[arg(long, short, required = true)]
    environment: Environments,

    /// Custom endpoint configuration (only used if --environment=custom).
    #[command(flatten)]
    endpoints: ExternalEndpoints,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum Environments {
    #[value(name = "US")]
    US,
    #[value(name = "EU")]
    EU,
    #[value(name = "Staging")]
    Staging,
    #[value(name = "Custom")]
    Custom,
}

#[derive(Args, Debug, Clone)]
pub struct ExternalEndpoints {
    /// Custom endpoint for token renewal. Required with '--environment custom'.
    #[arg(long)]
    token_renewal_endpoint: Option<String>,

    /// Custom endpoint for system identity creation. Required with '--environment custom'.
    #[arg(long, short)]
    system_identity_creation_endpoint: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IdentityType {
    /// Creates an identity whose type is 'secret'
    /// This type of identity expires
    ///
    /// EXAMPLE:
    /// SystemIdentity {
    /// id: "2e483fe9",
    /// name: Some("test1"),
    /// client_id: "8dbf3d32",
    /// organization_id: "b961cf81",
    /// identity_type: L1 {
    /// client_secret: "AfYFAUjf9",
    /// credential_expiration: "2025-06-04T19:25:00Z"
    /// }
    /// }
    Secret(SecretArgs),
    /// Creates an identity whose type is 'private key' or known as a parent identity.
    /// This type of identity does not expire.
    ///
    /// EXAMPLE:
    /// SystemIdentity(
    /// id: e5af42f2,
    /// name: test,
    /// client_id: 8150a0ee,
    /// organization_id: b961cf81,
    /// identity_type: L2(pub_key: LS0tLS1)
    /// )
    Key(KeyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct KeyArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Add the access token for identity creation, only bearer token type is accepted
    #[arg(long)]
    bearer_access_token: String,

    /// Options for configuring the output destination (required for Key identity)
    #[command(flatten)]
    output_options: OutputDestinationArgs,
}

#[derive(Args, Debug, Clone)]
pub struct SecretArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Add the access token for identity creation, only bearer token type is accepted
    #[arg(long)]
    bearer_access_token: String,
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

    /// Folder path where the private key output will be saved (required if --output-platform=local-file).
    #[arg(long)]
    output_local_path: Option<PathBuf>,
}

pub fn create_metadata_for_token_retrieve(
    client_id: String,
    environment: Environments,
    auth_args: &AuthInputArgs,
    endpoints: ExternalEndpoints,
) -> Result<SystemTokenCreationMetadata, Box<dyn std::error::Error>> {
    let auth_method = select_auth_method(
        auth_args.client_secret.clone(),
        auth_args.private_key_path.clone(),
    )?;
    let environment = select_environment(
        environment,
        endpoints.token_renewal_endpoint,
        endpoints.system_identity_creation_endpoint,
    )?;

    Ok(SystemTokenCreationMetadata {
        client_id,
        environment,
        auth_method,
    })
}
pub fn create_metadata_for_identity_creation(
    identity_type: &IdentityType,
) -> Result<SystemIdentityCreationMetadata, Box<dyn std::error::Error>> {
    let (basic_auth_args, output_platform) = match identity_type {
        IdentityType::Secret(secret_args) => (
            secret_args.basic_auth_args.clone(),
            OutputPlatform::LocalPrivateKeyPath("./".into()),
        ),
        IdentityType::Key(key_args) => (
            key_args.basic_auth_args.clone(),
            select_output_platform(
                &key_args.output_options.output_platform,
                key_args.output_options.output_local_path.clone(),
            )?,
        ),
    };

    let env = select_environment(
        basic_auth_args.environment.clone(),
        Some(
            basic_auth_args
                .endpoints
                .token_renewal_endpoint
                .unwrap_or_default(),
        ),
        Some(
            basic_auth_args
                .endpoints
                .system_identity_creation_endpoint
                .unwrap_or_default(),
        ),
    )?;

    Ok(SystemIdentityCreationMetadata {
        system_identity_input: SystemIdentityInput {
            client_id: basic_auth_args.client_id,
            organization_id: basic_auth_args.organization_id,
        },
        name: basic_auth_args.name.clone(),
        environment: env,
        output_platform,
    })
}

pub fn select_environment(
    environment: Environments,
    token_url: Option<String>,
    identity_url: Option<String>,
) -> Result<NewRelicEnvironment, Error> {
    match environment {
        Environments::US => Ok(NewRelicEnvironment::US),
        Environments::EU => Ok(NewRelicEnvironment::EU),
        Environments::Staging => Ok(NewRelicEnvironment::Staging),
        Environments::Custom => {
            let token_uri_str = token_url.unwrap_or_default();
            let identity_uri_str = identity_url.unwrap_or_default();

            let token_uri = Uri::from_str(&token_uri_str)
                .map_err(|e| Error::raw(ErrorKind::Format, format!("Invalid token URI: {}", e)))?;
            let identity_uri = Uri::from_str(&identity_uri_str).map_err(|e| {
                Error::raw(ErrorKind::Format, format!("Invalid identity URI: {}", e))
            })?;

            Ok(NewRelicEnvironment::Custom {
                token_renewal_endpoint: token_uri,
                system_identity_creation_uri: identity_uri,
            })
        }
    }
}

pub fn build_token_for_identity_creation(identity_type: &IdentityType) -> Token {
    let token = match identity_type {
        IdentityType::Secret(secret_args) => &secret_args.bearer_access_token,
        IdentityType::Key(key_args) => &key_args.bearer_access_token,
    };
    Token::new(
        AccessToken::from(token),
        TokenType::Bearer,
        DateTime::default(),
    )
}

pub fn select_output_platform(
    output_platform: &OutputPlatformChoice,
    output_path: Option<PathBuf>,
) -> Result<OutputPlatform, Error> {
    match output_platform {
        OutputPlatformChoice::LocalFile => Ok(OutputPlatform::LocalPrivateKeyPath(
            output_path.unwrap_or_default(),
        )),
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
