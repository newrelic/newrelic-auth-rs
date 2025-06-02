use clap::{Args, Parser, Subcommand};
use nr_auth::commands::add::AddCommand;
use nr_auth::commands::create::CreateCommand;
use nr_auth::commands::retrieve::RetrieveCommand;
use nr_auth::http::client::HttpClient;
use nr_auth::parameters::{create_metadata_for_identity_creation, Commands};
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
fn main() -> Result<(), Box<dyn Error>> {
    let cli_command = Cli::parse();

    let http_client = HttpClient::new();
    let create_command = CreateCommand::new(http_client.clone());
    let add_command = AddCommand::new(http_client.clone());
    let retrieve_command = RetrieveCommand::new(http_client);

    match cli_command.command {
        Commands::Create {
            name,
            organization_id,
            client_id,
            client_secret,
            private_key_path,
            environment,
            output_platform,
        } => {
            let output_platform = PathBuf::from(output_platform.unwrap_or_default());
            let meta = create_metadata_for_identity_creation(
                name,
                organization_id,
                client_id,
                client_secret.unwrap_or_default(),
                private_key_path.unwrap_or_default(),
                environment,
                output_platform,
            )?;
            let system_identity = create_command.create(&meta)?;
            info!("system identity created: {}", system_identity.name);
            Ok(())
        }
        Commands::Add(..) => Ok(()),
        Commands::Retrieve(..) => Ok(()),
        _ => Ok(()),
    }
}
