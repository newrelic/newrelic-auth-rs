//! The types contained inside this module are the required inputs for the System Identity creation
//! supported methods.

pub mod auth_method;
pub mod environment;
pub mod output_platform;

use auth_method::AuthMethod;
use environment::NewRelicEnvironment;

/// Represents the input data required to create a System Identity.
///
/// The rationaly behind this struct is to group all the necessary information, so any consumer of
/// the System Identity creation functionality should make sure it can create this object,
/// for example from CLI arguments or by library usage, before reaching for any actual creation service.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationMetadata {
    pub organization_id: String,
    pub name: Option<String>,
    pub environment: NewRelicEnvironment,
}

/// Represents the input data required to create an Identity Token.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemTokenCreationMetadata {
    pub client_id: String,
    pub environment: NewRelicEnvironment,
    pub auth_method: AuthMethod,
}
