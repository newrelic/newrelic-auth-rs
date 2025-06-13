extern crate alloc;

use alloc::sync::Arc;
use clap::Parser;
use nr_auth::commands::create::CreateCommand;
use nr_auth::commands::retrieve_token::RetrieveTokenCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::parameters::{
    Commands, IdentityType, OutPutTokenFormat, build_token_for_identity_creation,
    create_metadata_for_identity_creation, create_metadata_for_token_retrieve,
};
use std::boxed::Box;
use std::error::Error;
use std::fmt::Debug;
use std::result::Result;
use std::result::Result::Ok;

#[derive(Parser, Debug)]
#[command(name = "newrelic-auth-cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
fn main() -> Result<(), Box<dyn Error>> {
    let cli_command = Cli::parse();

    let http_client = Arc::new(HttpClient::new()?);
    let retrieve_token_command = RetrieveTokenCommand::new(http_client.clone());
    let create_command = CreateCommand::new(http_client.clone());

    match cli_command.command {
        Commands::CreateIdentity { identity_type } => match identity_type {
            IdentityType::Secret(..) => {
                let token = build_token_for_identity_creation(&identity_type);
                let meta = create_metadata_for_identity_creation(identity_type)?;
                let system_identity = create_command.create_l1_system_identity(&meta, token)?;
                println!("{}", system_identity);
                Ok(())
            }
            IdentityType::Key(..) => {
                let token = build_token_for_identity_creation(&identity_type);
                let meta = create_metadata_for_identity_creation(identity_type)?;
                let system_identity = create_command.create_l2_system_identity(&meta, token)?;
                println!("{}", system_identity);
                Ok(())
            }
        },
        Commands::RetrieveToken {
            client_id,
            environment,
            input_auth_args,
            output_token_format,
        } => {
            let meta = create_metadata_for_token_retrieve(
                client_id.unwrap_or_default(),
                environment,
                &input_auth_args,
            )?;
            let token = retrieve_token_command.retrieve_token(&meta)?;
            match output_token_format {
                OutPutTokenFormat::Text => {
                    println!("{}", token);
                }
                OutPutTokenFormat::Json => {
                    let output = serde_json::to_string_pretty(&token)?;
                    println!("{}", output);
                }
            }
            Ok(())
        }
    }
}
