use std::path::PathBuf;

// TODO: Currently this is the only supported output for the application, so we are
// not actually using this enum yet.
pub enum AuthOutputPlatform {
    LocalPrivateKeyPath(PathBuf),
    // Vault(VaultConfig), // TODO: Vault
}
