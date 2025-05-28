//! The types contained inside this module are the required inputs for the System Identity creation
//! supported methods.

pub mod auth_method;
pub mod environment;
pub mod output_platform;

use auth_method::AuthMethod;
use environment::SystemIdentityCreationEnvironment;
use output_platform::AuthOutputPlatform;

/// Represents the input data required to create a System Identity.
///
/// The rationaly behind this struct is to group all the necessary information, so any consumer of
/// the System Identity creation functionality should make sure it can create this object,
/// for example from CLI arguments or by library usage, before reaching for any actual creation service.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemIdentityCreationMetadata {
    pub name: String,
    pub organization_id: String,
    pub client_id: String,
    pub auth_method: AuthMethod,
    pub environment: SystemIdentityCreationEnvironment,
    pub output_platform: AuthOutputPlatform,
}
