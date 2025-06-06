use clap::{Args, Parser, Subcommand};
use nr_auth::commands::create::CreateCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::parameters::{create_metadata_for_identity_creation, Commands, IdentityType};
use std::error::Error;
use std::fmt::Debug;
use tracing::info;
use nr_auth::commands::retrieve_token::RetrieveTokenCommand;

#[derive(Parser, Debug)]
#[command(name = "newrelic-auth-cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
fn main() -> Result<(), Box<dyn Error>> {
    let cli_command = Cli::parse();

    let http_client = HttpClient::new()?;
    let retrieve_token_command = RetrieveTokenCommand::new(http_client.clone());
    let create_command = CreateCommand::new(http_client.clone());
    

    match cli_command.command {
        Commands::Create {
            basic_auth_args,
            identity_type,
        } => {
            let meta = create_metadata_for_identity_creation(
                &basic_auth_args,
                &identity_type,
            )?;
            let token = retrieve_token_command.retrieve_token(&meta)?;
            match identity_type {
                IdentityType::L1(..) => {
                    let system_identity = create_command.create_l1_system_identity(&meta,token)?;
                    info!("system identity created: {:?}", system_identity);
                    Ok(())
                }
                IdentityType::L2(..) => {
                    let system_identity = create_command.create_l2_system_identity(&meta,token)?;
                    info!("system identity created: {:?}", system_identity);
                    Ok(())
                }
            }
        }
    }
}
