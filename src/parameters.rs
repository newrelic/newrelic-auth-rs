use crate::key::PrivateKeyPem;
use crate::system_identity::input_data::auth_method::{AuthMethod, ClientSecret};
use crate::system_identity::input_data::environment::NewRelicEnvironment;
use crate::system_identity::input_data::output_platform::OutputPlatform;
use crate::system_identity::input_data::{SystemIdentityCreationMetadata, SystemIdentityInput};
use clap::error::ErrorKind;
use clap::{Args, Error, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Subcommand, Debug)]
#[group(id = "input-auth-methods", required = true, multiple = false)]
#[group(id = "output-auth-methods", required = true, multiple = false)]
pub enum Commands {
    /// Creates a new identity (L1 or L2) with specified credentials.
    Create {
        /// Basic information need for auth name, client_id, etc.
        #[command(flatten)]
        basic_auth_args: BasicAuthArgs,

        /// Select what type of identity should be created
        #[command(subcommand)]
        identity_type: IdentityType,
    },
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
    environment: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum IdentityType {
    /// Creates an L1 type identity
    L1(L1Args),
    /// Creates an L2 type identity
    L2(L2Args),
}

#[derive(Args, Debug)]
pub struct L1Args {
    /// Options for configuring the inputs to authenticate.
    #[command(flatten)]
    input_auth_args: AuthInputArgs,
}

#[derive(Args, Debug)]
pub struct L2Args {
    /// Options for configuring the inputs to authenticate.
    #[command(flatten)]
    input_auth_args: AuthInputArgs,

    /// Options for configuring the output destination.
    #[command(flatten)]
    output_options: OutputDestinationArgs,
}

#[derive(Args, Debug)]
pub struct AuthInputArgs {
    /// Client secret for authentication during creation
    #[arg(long, group = "input-auth-methods")]
    input_client_secret: Option<String>,

    /// Path to the private key file
    #[arg(long, group = "input-auth-methods")]
    input_private_key_path: Option<std::path::PathBuf>,
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

pub fn create_metadata_for_identity_creation(
    basic_auth_args: &BasicAuthArgs,
    identity_type: &IdentityType,
) -> Result<SystemIdentityCreationMetadata, Box<dyn std::error::Error>> {
    let auth_method: AuthMethod;
    let mut output_platform_type = OutputPlatform::LocalPrivateKeyPath("./".into());
    match identity_type {
        IdentityType::L1(L1Args { input_auth_args }) => {
            auth_method = select_auth_method(
                input_auth_args.input_client_secret.clone(),
                input_auth_args.input_private_key_path.clone(),
            )?;
        }
        IdentityType::L2(L2Args {
            input_auth_args,
            output_options,
        }) => {
            auth_method = select_auth_method(input_auth_args.input_client_secret.clone(), input_auth_args.input_private_key_path.clone())?;
            output_platform_type =
                select_output_platform(output_options.output_platform.clone(), output_options.output_local_path.clone())?;
        }
    }
    let env = select_environment(basic_auth_args.environment.clone().unwrap_or_default().to_lowercase())?;

    Ok(SystemIdentityCreationMetadata {
        system_identity_input: SystemIdentityInput {
            auth_method,
            client_id: basic_auth_args.client_id.clone().unwrap_or_default(),
            organization_id: basic_auth_args.organization_id.clone().unwrap_or_default(),
        },
        name: basic_auth_args.name.clone(),
        environment: env,
        output_platform: output_platform_type,
    })
}

pub fn select_environment(environment: String) -> Result<NewRelicEnvironment, Error> {
    match environment.as_str() {
        "us" => Ok(NewRelicEnvironment::US),
        "eu" => Ok(NewRelicEnvironment::EU),
        "staging" => Ok(NewRelicEnvironment::Staging),
        "custom" => Ok(NewRelicEnvironment::Custom {
            token_renewal_endpoint: Default::default(),
            system_identity_creation_uri: Default::default(),
        }),
        _ => Err(Error::new(ErrorKind::InvalidValue)),
    }
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
