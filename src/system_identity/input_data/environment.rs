use http::Uri;

// Known endpoints. Should these be configurable instead? Otherwise,
// if they change we will need to create a new release.
// Staging endpoints
const STAGING_TOKEN_RENEWAL_ENDPOINT_STR: &str =
    "https://system-identity-oauth.staging-service.newrelic.com/oauth2/token";
const STAGING_IDENTITY_CREATION_ENDPOINT_STR: &str = "https://staging-api.newrelic.com/graphql";

// EU endpoints
const EU_TOKEN_RENEWAL_ENDPOINT_STR: &str =
    "https://system-identity-oauth.service.newrelic.com/oauth2/token";
const EU_IDENTITY_CREATION_ENDPOINT_STR: &str = "https://api.eu.newrelic.com/graphql";

// US endpoints
const US_TOKEN_RENEWAL_ENDPOINT_STR: &str =
    "https://system-identity-oauth.service.newrelic.com/oauth2/token";
const US_IDENTITY_CREATION_ENDPOINT_STR: &str = "https://api.newrelic.com/graphql";

/// Represents the environment in which a System Identity is created (US, EU, Staging).
#[derive(Debug, Clone, PartialEq)]
pub enum SystemIdentityCreationEnvironment {
    US,
    EU,
    Staging,
    Custom {
        token_renewal_endpoint: Uri,
        system_identity_creation_uri: Uri,
    },
}

impl SystemIdentityCreationEnvironment {
    /// Get a reference to the URI for the System Identity creation endpoint
    /// for the current environment.
    pub fn identity_creation_endpoint(&self) -> Uri {
        match self {
            SystemIdentityCreationEnvironment::US => {
                Uri::try_from(US_IDENTITY_CREATION_ENDPOINT_STR)
                    .expect("Failed to parse known URL: US_IDENTITY_CREATION_ENDPOINT")
            }
            SystemIdentityCreationEnvironment::EU => {
                Uri::try_from(EU_IDENTITY_CREATION_ENDPOINT_STR)
                    .expect("Failed to parse known URL: EU_IDENTITY_CREATION_ENDPOINT")
            }
            SystemIdentityCreationEnvironment::Staging => {
                Uri::try_from(STAGING_IDENTITY_CREATION_ENDPOINT_STR)
                    .expect("Failed to parse known URL: STAGING_IDENTITY_CREATION_ENDPOINT")
            }
            SystemIdentityCreationEnvironment::Custom {
                system_identity_creation_uri,
                ..
            } => system_identity_creation_uri.to_owned(),
        }
    }

    /// Get a reference to the URI for the token renewal endpoint for the current environment.
    pub fn token_renewal_endpoint(&self) -> Uri {
        match self {
            SystemIdentityCreationEnvironment::US => Uri::try_from(US_TOKEN_RENEWAL_ENDPOINT_STR)
                .expect("Failed to parse known URL: US_TOKEN_RENEWAL_ENDPOINT"),
            SystemIdentityCreationEnvironment::EU => Uri::try_from(EU_TOKEN_RENEWAL_ENDPOINT_STR)
                .expect("Failed to parse known URL: EU_TOKEN_RENEWAL_ENDPOINT"),
            SystemIdentityCreationEnvironment::Staging => {
                Uri::try_from(STAGING_TOKEN_RENEWAL_ENDPOINT_STR)
                    .expect("Failed to parse known URL: STAGING_TOKEN_RENEWAL_ENDPOINT")
            }
            SystemIdentityCreationEnvironment::Custom {
                token_renewal_endpoint,
                ..
            } => token_renewal_endpoint.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_endpoints() {
        let env = SystemIdentityCreationEnvironment::US;
        assert_eq!(
            env.identity_creation_endpoint().to_string(),
            US_IDENTITY_CREATION_ENDPOINT_STR
        );
        assert_eq!(
            env.token_renewal_endpoint().to_string(),
            US_TOKEN_RENEWAL_ENDPOINT_STR
        );
    }

    #[test]
    fn eu_endpoints() {
        let env = SystemIdentityCreationEnvironment::EU;
        assert_eq!(
            env.identity_creation_endpoint().to_string(),
            EU_IDENTITY_CREATION_ENDPOINT_STR
        );
        assert_eq!(
            env.token_renewal_endpoint().to_string(),
            EU_TOKEN_RENEWAL_ENDPOINT_STR
        );
    }

    #[test]
    fn staging_endpoints() {
        let env = SystemIdentityCreationEnvironment::Staging;
        assert_eq!(
            env.identity_creation_endpoint().to_string(),
            STAGING_IDENTITY_CREATION_ENDPOINT_STR
        );
        assert_eq!(
            env.token_renewal_endpoint().to_string(),
            STAGING_TOKEN_RENEWAL_ENDPOINT_STR
        );
    }
}
