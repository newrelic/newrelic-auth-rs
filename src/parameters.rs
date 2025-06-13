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
use clap::{Args, Error, Subcommand, ValueEnum};
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
        /// Select what type of identity should be created, identity in a secret or a key
        #[command(subcommand)]
        identity_type: IdentityType,
    },
    /// Retrieve a token providing a client secret or private key path.
    RetrieveToken {
        /// ID of the client
        #[arg(long, required = true)]
        client_id: Option<String>,

        /// Environment to target
        #[arg(long, required = true)]
        environment: Environments,

        /// Options for configuring the inputs to authenticate
        #[command(flatten)]
        input_auth_args: AuthInputArgs,

        /// Select format how the Token should be obtained
        #[arg(long, required = true)]
        output_token_format: OutPutTokenFormat,
    },
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutPutTokenFormat {
    /// Returns only the access token without type or expiration day
    #[value(name = "Clean")]
    Text,
    /// Returns full token information in json format
    #[value(name = "Json")]
    Json,
}

#[derive(Args, Debug)]
pub struct AuthInputArgs {
    /// Client secret for authentication during creation
    #[arg(long, group = "input-auth-methods")]
    input_client_secret: Option<String>,

    /// Path to the private key file
    #[arg(long, group = "input-auth-methods")]
    input_private_key_path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct BasicAuthArgs {
    /// Name for the new resource
    #[arg(long, required = false)]
    name: Option<String>,

    /// Organization ID for the resource
    #[arg(long, required = true)]
    organization_id: Option<String>,

    /// ID of the client
    #[arg(long, required = true)]
    client_id: Option<String>,

    /// Environment to target
    #[arg(long, required = true)]
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

#[derive(Args, Debug)]
pub struct ExternalEndpoints {
    /// Custom endpoint for token renewal. Required with '--environment custom'.
    #[arg(long)]
    token_renewal: Option<String>,

    /// Custom endpoint for system identity creation. Required with '--environment custom'.
    #[arg(long)]
    system_identity_creation: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum IdentityType {
    /// Creates an identity whose type is 'secret'
    /// This type o identity expires
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

#[derive(Args, Debug)]
pub struct KeyArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Add the access token for identity creation, only bearer token type is accepted
    #[arg(long, short)]
    bearer_access_token: String,

    /// Options for configuring the output destination (required for Key identity)
    #[command(flatten)]
    output_options: OutputDestinationArgs,
}

#[derive(Args, Debug)]
pub struct SecretArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Add the access token for identity creation, only bearer token type is accepted
    #[arg(long, short)]
    bearer_access_token: String,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputPlatformChoice {
    #[value(name = "local-file")]
    LocalFile,
}

#[derive(Args, Debug)]
pub struct OutputDestinationArgs {
    /// Platform for the output of the generated key or resource.
    #[arg(long = "output-platform", value_enum)]
    output_platform: OutputPlatformChoice,

    /// File path where the private key output will be saved (required if --output-platform=local-file).
    #[arg(long = "output-local-path")]
    output_local_path: Option<PathBuf>,
}

pub fn create_metadata_for_token_retrieve(
    client_id: String,
    environment: Environments,
    auth_args: &AuthInputArgs,
) -> Result<SystemTokenCreationMetadata, Box<dyn std::error::Error>> {
    let auth_method = select_auth_method(
        auth_args.input_client_secret.clone(),
        auth_args.input_private_key_path.clone(),
    )?;
    let environment = select_environment(environment)?;

    Ok(SystemTokenCreationMetadata {
        client_id,
        environment,
        auth_method,
    })
}
pub fn create_metadata_for_identity_creation(
    identity_type: IdentityType,
) -> Result<SystemIdentityCreationMetadata, Box<dyn std::error::Error>> {
    let (basic_auth_args, _json_token, output_platform, _output_local_path) = match identity_type {
        IdentityType::Secret(secret_args) => (
            secret_args.basic_auth_args,
            secret_args.bearer_access_token.clone(),
            OutputPlatform::LocalPrivateKeyPath("./".into()),
            None,
        ),
        IdentityType::Key(key_args) => (
            key_args.basic_auth_args,
            key_args.bearer_access_token.clone(),
            select_output_platform(
                &key_args.output_options.output_platform,
                key_args.output_options.output_local_path.clone(),
            )?,
            key_args.output_options.output_local_path.clone(),
        ),
    };

    let env = select_environment(basic_auth_args.environment.clone())?;

    Ok(SystemIdentityCreationMetadata {
        system_identity_input: SystemIdentityInput {
            client_id: basic_auth_args.client_id.unwrap_or_default(),
            organization_id: basic_auth_args.organization_id.unwrap_or_default(),
        },
        name: basic_auth_args.name.clone(),
        environment: env,
        output_platform,
    })
}

pub fn select_environment(environment: Environments) -> Result<NewRelicEnvironment, Error> {
    match environment {
        Environments::US => Ok(NewRelicEnvironment::US),
        Environments::EU => Ok(NewRelicEnvironment::EU),
        Environments::Staging => Ok(NewRelicEnvironment::Staging),
        Environments::Custom => Ok(NewRelicEnvironment::Custom {
            token_renewal_endpoint: Default::default(),
            system_identity_creation_uri: Default::default(),
        }),
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
