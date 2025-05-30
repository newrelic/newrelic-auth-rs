use crate::system_identity::client_input::{
    AuthMethod, ClientSecret, PrivateKeyPem, SystemIdentityCreationMetadata,
};
use crate::system_identity::environment::SystemIdentityCreationEnvironment;
use crate::system_identity::output_platform::AuthOutputPlatform;
use clap::error::ErrorKind;
use clap::{Args, Error, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_AUTHENTICATOR_TIMEOUT: Duration = Duration::from_secs(5);
#[derive(Subcommand, Debug)]
pub enum Commands {
    Create {
        /// Name for the new resource
        #[arg(long, required = true)]
        name: String,

        /// Organization ID for the resource
        #[arg(long, required = true)]
        organization_id: String,

        /// ID of the client
        #[arg(long, required = true)]
        client_id: String,

        /// Client secret for authentication during creation
        #[arg(long)]
        client_secret: Option<String>,

        /// Path to the private key file
        #[arg(long)]
        private_key_path: Option<std::path::PathBuf>,

        /// Environment to target
        #[arg(long, required = true)]
        environment: String,

        /// Authentication method to use
        #[arg(long)]
        output_platform: Option<String>,
    },
    Add {
        /// ID of the client
        #[arg(long, required = true)]
        client_id: Option<String>,

        /// Client secret for authentication during creation
        #[arg(long, required = true)]
        client_secret: Option<String>,

        /// identity id for the new resource
        #[arg(long, required = true)]
        identity_id: Option<String>,

        /// group id for the new resource
        #[arg(long, required = true)]
        group_id: Option<String>,

        /// group id for the new resource
        #[arg(long, required = true)]
        api_key: Option<String>,

        /// Path to the private key file
        #[arg(long, required = true)]
        private_key_path: Option<std::path::PathBuf>,
    },
    Retrieve {
        /// ID of the client
        #[arg(long, required = true)]
        client_id: Option<String>,

        /// Client secret for authentication during creation
        #[arg(long)]
        client_secret: Option<String>,

        /// Path to the private key file
        #[arg(long)]
        private_key_path: Option<std::path::PathBuf>,
    },
}

pub fn create_metadata_for_identity_creation(
    name: String,
    organization_id: String,
    client_id: String,
    client_secret: String,
    private_key_path: PathBuf,
    environment: String,
    output_platform: PathBuf,
) -> Result<SystemIdentityCreationMetadata,Box<dyn std::error::Error>> {
    let auth: AuthMethod;
    if !client_secret.is_empty() {
        auth = AuthMethod::ClientSecret(ClientSecret::from(client_secret.as_str()));
    } else {
        let private_key = fs::read_to_string(private_key_path)?;
        auth = AuthMethod::PrivateKey(PrivateKeyPem::from(private_key.into_bytes()));
    }

    let env = select_environment(environment.to_lowercase())?;

    Ok(SystemIdentityCreationMetadata {
        name,
        organization_id,
        client_id,
        auth_method: auth,
        environment: env,
        output_platform: AuthOutputPlatform::LocalPrivateKeyPath(output_platform),
    })
}

pub fn select_environment(environment: String) -> Result<SystemIdentityCreationEnvironment, Error> {
    match environment.as_str() {
        "us" => Ok(SystemIdentityCreationEnvironment::US),
        "eu" => Ok(SystemIdentityCreationEnvironment::EU),
        "staging" => Ok(SystemIdentityCreationEnvironment::Staging),
        "custom" => Ok(SystemIdentityCreationEnvironment::Custom {
            token_renewal_endpoint: Default::default(),
            system_identity_creation_uri: Default::default(),
        }),
        _ => Err(Error::new(ErrorKind::InvalidValue)),
    }
}
