extern crate alloc;

use clap::Parser;
use nr_auth::authenticator::HttpAuthenticator;
use nr_auth::commands::create::CreateCommand;
use nr_auth::commands::retrieve_token::RetrieveTokenCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::parameters::{
    Commands, IdentityType, OutPutTokenFormat, build_token_for_identity_creation,
    create_metadata_for_identity_creation, create_metadata_for_token_retrieve,
};
use nr_auth::system_identity::iam_client::http::HttpIAMClient;
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

    let http_client =
        HttpClient::new().map_err(|e| format!("error creating http client: {}", e))?;

    match cli_command.command {
        Commands::CreateIdentity { identity_type } => match identity_type {
            IdentityType::Secret(..) => {
                let meta = create_metadata_for_identity_creation(&identity_type)?;
                let token = build_token_for_identity_creation(&identity_type);
                let iam_client = HttpIAMClient::new(http_client, meta);
                let system_identity =
                    CreateCommand::new(iam_client).create_l1_system_identity(token)?;
                println!("{}", system_identity);
                Ok(())
            }
            IdentityType::Key(..) => {
                let meta = create_metadata_for_identity_creation(&identity_type)?;
                let token = build_token_for_identity_creation(&identity_type);
                let iam_client = HttpIAMClient::new(http_client, meta.clone());
                let system_identity =
                    CreateCommand::new(iam_client).create_l2_system_identity(&meta, token)?;
                println!("{}", system_identity);
                Ok(())
            }
        },
        Commands::RetrieveToken {
            client_id,
            environment,
            input_auth_args,
            output_token_format,
            endpoints,
        } => {
            let meta = create_metadata_for_token_retrieve(
                client_id.unwrap_or_default(),
                environment,
                &input_auth_args,
                endpoints,
            )?;
            let http_authenticator =
                HttpAuthenticator::new(http_client, meta.environment.token_renewal_endpoint());
            let retrieve_token_command = RetrieveTokenCommand::new(http_authenticator);
            let token = retrieve_token_command.retrieve_token(&meta)?;
            match output_token_format {
                OutPutTokenFormat::Plain => {
                    println!("{}", token.access_token());
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
