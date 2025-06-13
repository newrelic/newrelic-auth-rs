//! Module defining the response structure for System Identity creation from the New Relic GraphQL API.

/*
This is the complete definition for the involved query and its full response.

```graphql
mutation SystemIdentityCreateQuery($name: String, $organizationId: String!, publicKey: String) {
    systemIdentityCreate(
        name: $name
        organizationId: $organizationId
        publicKey: $publicKey
    ) {
        clientId
        publicKey
        id
        name
        organizationId
        clientSecret
        credentialExpiration
    }
}
```

If the `publicKey` is provided, it means we are creating an L2 System Identity.
The response will have `clientSecret` and `credentialExpiration` set to `null`.

If the `publicKey` is not provided, it means we are creating an L1 System Identity.
The response will have `publicKey` set to `null`, and `clientSecret` and `credentialExpiration`
will be present.

Any other combination of fields is considered malformed, as we cannot decide between L1 and L2.

We thus handle these cases using the definitions below.
*/
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{SystemIdentity, SystemIdentityType};

/// Represents the response from the System Identity creation endpoint.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
pub struct SystemIdentityCreationResponse {
    data: InnerData,
}

impl SystemIdentityCreationResponse {
    /// Extracts the System Identity data from the response.
    pub fn data(&self) -> &SystemIdentityData {
        &self.data.system_identity_create
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
pub struct InnerData {
    #[serde(rename = "systemIdentityCreate")]
    system_identity_create: SystemIdentityData,
}

/// The actual information returned from the System Identity creation response.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemIdentityData {
    pub client_id: String,
    pub public_key: Option<String>,
    pub id: String,
    pub name: Option<String>,
    pub organization_id: String,
    pub client_secret: Option<String>,
    pub credential_expiration: Option<String>,
}

/// Error for when the incoming System Identity data is malformed and we cannot decide if
/// the data represents an L1 or an L2 system identity.
#[derive(Debug, Clone, Error)]
#[error(
    "Malformed System Identity data.
    Expected either a `public_key` with no `client_secret` and no `credential_expiration` (L2),
    or a `client_secret` with a `credential_expiration` and no `public_key` (L1)."
)]
pub struct MalformedSystemIdentityData;

impl TryFrom<SystemIdentityData> for SystemIdentity {
    type Error = MalformedSystemIdentityData;

    fn try_from(
        SystemIdentityData {
            client_id,
            public_key,
            id,
            name,
            organization_id,
            client_secret,
            credential_expiration,
        }: SystemIdentityData,
    ) -> Result<Self, Self::Error> {
        // An L1 system identity has no public key but has a client secret and a credential expiration.
        // An L2 system identity has a public key but no client secret and no credential expiration.
        match (public_key, client_secret, credential_expiration) {
            (Some(pub_key), None, None) => Ok(SystemIdentity {
                id,
                name,
                client_id,
                organization_id,
                identity_type: SystemIdentityType::L2 { pub_key },
            }),
            (None, Some(client_secret), Some(credential_expiration)) => Ok(SystemIdentity {
                id,
                name,
                client_id,
                organization_id,
                identity_type: SystemIdentityType::L1 {
                    client_secret: client_secret.into(),
                    credential_expiration,
                },
            }),
            _ => Err(MalformedSystemIdentityData), // I assume we just can't decide
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        SystemIdentityData {
            client_id: "client-id".to_string(),
            public_key: Some("public-key".to_string()),
            id: "id".to_string(),
            name: Some("public key only (L2)".to_string()),
            organization_id: "org-id".to_string(),
            client_secret: None,
            credential_expiration: None,
        },
        |r: &Result<SystemIdentity, _>| r.as_ref().is_ok_and(|i| matches!(i.identity_type, SystemIdentityType::L2 { .. })))]
    #[case(
        SystemIdentityData {
            client_id: "client-id".to_string(),
            public_key: None,
            id: "id".to_string(),
            name: Some("client secret and date (L1)".to_string()),
            organization_id: "org-id".to_string(),
            client_secret: Some("some-secret".to_string()),
            credential_expiration: Some("some-date-not-caring-format".to_string()),
        },
       |r: &Result<SystemIdentity, _>| r
            .as_ref()
            .is_ok_and(|i| matches!(i.identity_type, SystemIdentityType::L1 { .. }))
    )]
    #[case(
        SystemIdentityData {
            client_id: "client-id".to_string(),
            public_key: None,
            id: "id".to_string(),
            name: Some("no public key, no client secret, no date should fail".to_string()),
            organization_id: "org-id".to_string(),
            client_secret: None,
            credential_expiration: None,
        },
        |r: &Result<SystemIdentity, _>| r.is_err())]
    #[case(
        SystemIdentityData {
            client_id: "client-id".to_string(),
            public_key: Some("public-key".to_string()),
            id: "id".to_string(),
            name: Some("public key, client secret and date should fail".to_string()),
            organization_id: "org-id".to_string(),
            client_secret: Some("some-secret".to_string()),
            credential_expiration: Some("some-date-not-caring-format".to_string()),
        },
        |r: &Result<SystemIdentity, _>| r.is_err()
    )]
    #[case(
        SystemIdentityData {
            client_id: "client-id".to_string(),
            public_key: Some("public-key".to_string()),
            id: "id".to_string(),
            name: Some("public key and date and no client secret should fail".to_string()),
            organization_id: "org-id".to_string(),
            client_secret: None,
            credential_expiration: Some("some-date-not-caring-format".to_string()),
        },
        |r: &Result<SystemIdentity, _>| r.is_err()
    )]
    #[case(
        SystemIdentityData {
            client_id: "client-id".to_string(),
            public_key: None,
            id: "id".to_string(),
            name: Some("no public key, no client secret and a date should fail".to_string()),
            organization_id: "org-id".to_string(),
            client_secret: None,
            credential_expiration: Some("some-date-not-caring-format".to_string()),
        },
        |r: &Result<SystemIdentity, _>| r.is_err())]
    fn test_system_identity_data_conversion(
        #[case] system_identity_data: SystemIdentityData,
        #[case] check: impl FnOnce(&Result<SystemIdentity, MalformedSystemIdentityData>) -> bool,
    ) {
        let case_name = system_identity_data
            .name
            .to_owned()
            .unwrap_or_else(|| "Unnamed Case".to_string());

        let result = system_identity_data.try_into();
        assert!(
            check(&result),
            "Case {} failed. Result {:?}",
            case_name,
            result
        );
    }
}
