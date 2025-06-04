use clap::{Args, Parser, Subcommand};
use nr_auth::commands::create::CreateCommand;
use nr_auth::commands::retrieve_token::RetrieveTokenCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::parameters::{build_token_for_identity_creation, create_metadata_for_identity_creation, create_metadata_for_token_retrieve, select_token_type, Commands, IdentityType};
use std::error::Error;
use std::fmt::Debug;

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
        Commands::CreateIdentity {
            identity_type,
        } => {
            match identity_type {
                IdentityType::Secret(args) => {
                    let meta = create_metadata_for_identity_creation(&args)?;
                    let token = build_token_for_identity_creation(args)?;
                    let system_identity = create_command.create_l1_system_identity(&meta, token)?;
                    println!("{:?}", system_identity);
                    Ok(())
                }
                IdentityType::Key(args) => {
                    let meta = create_metadata_for_identity_creation(&args)?;
                    let token = build_token_for_identity_creation(args)?;
                    let system_identity = create_command.create_l2_system_identity(&meta, token)?;
                    println!("{:?}", system_identity);
                    Ok(())
                }
            }
        }
        Commands::RetrieveToken {
            client_id,
            environment,
            input_auth_args,
            output_options,
        } => {
            let meta = create_metadata_for_token_retrieve(
                client_id.unwrap_or_default(),
                environment,
                &input_auth_args,
                &output_options,
            )?;
            let token = retrieve_token_command.retrieve_token(&meta)?;
            println!("{:?}", token);
            Ok(())
        }
    }
}
