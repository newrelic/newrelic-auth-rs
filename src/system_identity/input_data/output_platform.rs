use std::path::PathBuf;

/// This type represents the output platform for the authentication credentials created with
/// the System Identity.
///
/// This would be declared as an input to the system identity creation process, so after the
/// system identity is created, the result can be persisted, stored or moved into this platform.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputPlatform {
    LocalPrivateKeyPath(PathBuf),
    // Vault(VaultConfig), // TODO: Vault
}
