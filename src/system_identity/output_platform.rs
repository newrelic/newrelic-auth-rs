use std::path::PathBuf;

/// This type represents the output platform for the authentication credentials created with
/// the System Identity.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthOutputPlatform {
    LocalPrivateKeyPath(PathBuf),
    // Vault(VaultConfig), // TODO: Vault
}
