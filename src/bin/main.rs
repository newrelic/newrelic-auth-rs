use clap::{Args, Parser, Subcommand};
use nr_auth::commands::create::CreateCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::parameters::{create_metadata_for_identity_creation, Commands};
use std::error::Error;
use std::fmt::Debug;
use nr_auth::commands::add::AddCommand;
use nr_auth::commands::retrieve::RetrieveCommand;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
fn main() -> Result<(), Box<dyn Error>> {
    let cli_command = Cli::parse();

    let http_client = HttpClient::new();
    let create_command = CreateCommand::new(http_client);
    let add_command = AddCommand::new(http_client);
    let retrieve_command = RetrieveCommand::new(http_client);

    match cli_command.command {
        Commands::Create(
            name,
            organization_id,
            client_id,
            client_secret,
            private_key_path,
            environment,
            output_platform,
        ) => {
            let meta = create_metadata_for_identity_creation(
                name,
                organization_id,
                client_id,
                client_secret,
                private_key_path,
                environment,
                output_platform,
            )?;
            Ok(create_command.create(&meta)?)
        }
        Commands::Add(..) => Ok(()),
        Commands::Retrieve(..) => Ok(()),
        _ => Ok(()),
    }
}
