use crate::key::PrivateKeyPem;
use crate::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
use crate::system_identity::input_data::environment::NewRelicEnvironment;
use crate::system_identity::input_data::output_platform::OutputPlatform;
use crate::system_identity::input_data::{
    SystemIdentityCreationMetadata, SystemIdentityInput, SystemTokenCreationMetadata,
};
use crate::token::{Token, TokenType};
use chrono::DateTime;
use clap::error::ErrorKind;
use clap::{Args, Error, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
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

        /// Options for configuring the output destination.
        #[command(flatten)]
        output_options: OutputDestinationArgs,
    },
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
    #[arg(long, required = true)]
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
    /// Creates an identity, returning a secret
    Secret(IdentityArgs),
    /// Creates an identity, returning a key
    Key(IdentityArgs),
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum TokenTypeList {
    #[value(name = "Bearer")]
    Bearer,
}

#[derive(Args, Debug)]
pub struct InputToken {
    /// The access token string.
    #[arg(long)]
    access_token: Option<String>,

    /// The token type (e.g., Bearer).
    #[arg(long)]
    token_type: TokenTypeList,

    /// Expiration date or timestamp for the token.
    #[arg(long)]
    expires_at: Option<String>,
}

#[derive(Args, Debug)]
pub struct IdentityArgs {
    /// Basic information need for auth name, client_id, etc.
    #[command(flatten)]
    basic_auth_args: BasicAuthArgs,

    /// Token needed to create identities
    #[command(flatten)]
    token: InputToken,

    /// Options for configuring the output destination only works with a key identities.
    #[command(flatten)]
    output_options: OutputDestinationArgs,
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

    /// File path where the output will be saved (required if --output-platform=local-file).
    #[arg(long = "output-local-path")]
    output_local_path: Option<PathBuf>,
}

pub fn create_metadata_for_token_retrieve(
    client_id: String,
    environment: Environments,
    auth_args: &AuthInputArgs,
    output_options: &OutputDestinationArgs,
) -> Result<SystemTokenCreationMetadata, Box<dyn std::error::Error>> {
    let auth_method = select_auth_method(
        auth_args.input_client_secret.clone(),
        auth_args.input_private_key_path.clone(),
    )?;
    let environment = select_environment(environment)?;
    let output_platform_type = select_output_platform(
        output_options.output_platform.clone(),
        output_options.output_local_path.clone(),
    )?;

    Ok(SystemTokenCreationMetadata {
        client_id,
        environment,
        auth_method,
        output_platform: output_platform_type,
    })
}
pub fn create_metadata_for_identity_creation(
    args: &IdentityArgs,
) -> Result<SystemIdentityCreationMetadata, Box<dyn std::error::Error>> {
    let auth_method = AuthMethod::ClientSecret(ClientSecret::from("")); // TO DELETE
    let mut output_platform_type = OutputPlatform::LocalPrivateKeyPath("./".into());
    let env = select_environment(args.basic_auth_args.environment.clone())?;

    Ok(SystemIdentityCreationMetadata {
        system_identity_input: SystemIdentityInput {
            client_id: args.basic_auth_args.client_id.clone().unwrap_or_default(),
            organization_id: args
                .basic_auth_args
                .organization_id
                .clone()
                .unwrap_or_default(),
        },
        name: args.basic_auth_args.name.clone(),
        environment: env,
        output_platform: output_platform_type,
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
        _ => Err(Error::new(ErrorKind::InvalidValue)),
    }
}

pub fn select_token_type(token: TokenTypeList) -> Result<TokenType, Error> {
    match token {
        TokenTypeList::Bearer => Ok(TokenType::Bearer),
        _ => Err(Error::new(ErrorKind::InvalidValue)),
    }
}

pub fn build_token_for_identity_creation(args: IdentityArgs) -> Result<Token, Error> {
    let token_type = select_token_type(args.token.token_type)?;
    let expiration = DateTime::parse_from_rfc3339(args.token.expires_at.unwrap().as_str());
    Ok(Token::new(
        args.token.access_token.unwrap(),
        token_type,
        expiration.unwrap().to_utc(),
    ))
}

pub fn select_output_platform(
    output_platform: OutputPlatformChoice,
    output_path: Option<PathBuf>,
) -> Result<OutputPlatform, Error> {
    match output_platform {
        OutputPlatformChoice::LocalFile => Ok(OutputPlatform::LocalPrivateKeyPath(
            output_path.unwrap_or_default(),
        )),
        _ => Err(Error::new(ErrorKind::InvalidValue)),
    }
}

pub fn select_auth_method(
    input_client_secret: Option<String>,
    input_private_key_path: Option<PathBuf>,
) -> Result<AuthMethod, Error> {
    if !input_client_secret.is_none() {
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
