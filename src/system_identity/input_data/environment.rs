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
pub enum NewRelicEnvironment {
    US,
    EU,
    Staging,
    Custom {
        token_renewal_endpoint: Uri,
        system_identity_creation_uri: Uri,
    },
}

impl TryFrom<&str> for NewRelicEnvironment {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "us" => Ok(Self::US),
            "eu" => Ok(Self::EU),
            "staging" => Ok(Self::Staging),
            _ => Err(format!("Invalid environment: {}", value)),
        }
    }
}

impl NewRelicEnvironment {
    /// Get a reference to the URI for the System Identity creation endpoint
    /// for the current environment.
    pub fn identity_creation_endpoint(&self) -> Uri {
        match self {
            Self::US => Uri::try_from(US_IDENTITY_CREATION_ENDPOINT_STR)
                .expect("Failed to parse known URL: US_IDENTITY_CREATION_ENDPOINT"),
            Self::EU => Uri::try_from(EU_IDENTITY_CREATION_ENDPOINT_STR)
                .expect("Failed to parse known URL: EU_IDENTITY_CREATION_ENDPOINT"),
            Self::Staging => Uri::try_from(STAGING_IDENTITY_CREATION_ENDPOINT_STR)
                .expect("Failed to parse known URL: STAGING_IDENTITY_CREATION_ENDPOINT"),
            Self::Custom {
                system_identity_creation_uri,
                ..
            } => system_identity_creation_uri.to_owned(),
        }
    }

    /// Get a reference to the URI for the token renewal endpoint for the current environment.
    pub fn token_renewal_endpoint(&self) -> Uri {
        match self {
            Self::US => Uri::try_from(US_TOKEN_RENEWAL_ENDPOINT_STR)
                .expect("Failed to parse known URL: US_TOKEN_RENEWAL_ENDPOINT"),
            Self::EU => Uri::try_from(EU_TOKEN_RENEWAL_ENDPOINT_STR)
                .expect("Failed to parse known URL: EU_TOKEN_RENEWAL_ENDPOINT"),
            Self::Staging => Uri::try_from(STAGING_TOKEN_RENEWAL_ENDPOINT_STR)
                .expect("Failed to parse known URL: STAGING_TOKEN_RENEWAL_ENDPOINT"),
            Self::Custom {
                token_renewal_endpoint,
                ..
            } => token_renewal_endpoint.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(
        NewRelicEnvironment::US,
        US_IDENTITY_CREATION_ENDPOINT_STR,
        US_TOKEN_RENEWAL_ENDPOINT_STR
    )]
    #[case(
        NewRelicEnvironment::EU,
        EU_IDENTITY_CREATION_ENDPOINT_STR,
        EU_TOKEN_RENEWAL_ENDPOINT_STR
    )]
    #[case(
        NewRelicEnvironment::Staging,
        STAGING_IDENTITY_CREATION_ENDPOINT_STR,
        STAGING_TOKEN_RENEWAL_ENDPOINT_STR
    )]
    #[case(NewRelicEnvironment::Custom {
        token_renewal_endpoint: Uri::try_from("https://custom-token-renewal.com").unwrap(),
        system_identity_creation_uri: Uri::try_from("https://custom-creation.com").unwrap(),
    }, "https://custom-creation.com/", "https://custom-token-renewal.com/")]
    fn endpoints(
        #[case] env: NewRelicEnvironment,
        #[case] expected_identity_creation_url: &str,
        #[case] expected_token_renewal_url: &str,
    ) {
        assert_eq!(
            env.identity_creation_endpoint().to_string(),
            expected_identity_creation_url
        );
        assert_eq!(
            env.token_renewal_endpoint().to_string(),
            expected_token_renewal_url
        );
    }
}
