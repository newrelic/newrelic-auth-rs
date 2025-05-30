//! The types contained inside this module are the required inputs for the System Identity creation
//! supported methods.

pub mod auth_method;
pub mod environment;
pub mod output_platform;

use auth_method::AuthMethod;
use environment::NewRelicEnvironment;
use output_platform::OutputPlatform;

/// Represents the input data required to create a System Identity.
///
/// The rationaly behind this struct is to group all the necessary information, so any consumer of
/// the System Identity creation functionality should make sure it can create this object,
/// for example from CLI arguments or by library usage, before reaching for any actual creation service.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationMetadata {
    pub system_identity_input: SystemIdentityInput,
    pub name: Option<String>,
    pub environment: NewRelicEnvironment,
    pub output_platform: OutputPlatform,
}

/// The existing System Identity data that is required as input to create a new System Identity.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityInput {
    pub organization_id: String,
    pub client_id: String,
    pub auth_method: AuthMethod,
}
