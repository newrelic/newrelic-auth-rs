use serde::{Deserialize, Deserializer};

use crate::system_identity::{SystemIdentity, SystemIdentityType};

use super::common_nerdgraph_response;

/// Represents the response data from the System Identity service
#[derive(Debug, Clone, PartialEq)]
pub struct L2SystemIdentityCreationResponseData {
    client_id: String,
    name: String,
}

impl From<(L2SystemIdentityCreationResponseData, Vec<u8>)> for SystemIdentity {
    fn from((response, pub_key): (L2SystemIdentityCreationResponseData, Vec<u8>)) -> Self {
        Self {
            name: response.name,
            client_id: response.client_id,
            identity_type: SystemIdentityType::L2 { pub_key },
        }
    }
}

impl TryFrom<SystemIdentity> for L2SystemIdentityCreationResponseData {
    type Error = &'static str;

    fn try_from(value: SystemIdentity) -> Result<Self, Self::Error> {
        if let SystemIdentityType::L2 { .. } = value.identity_type {
            Ok(Self {
                client_id: value.client_id,
                name: value.name,
            })
        } else {
            Err("Cannot convert non-L2 SystemIdentity to L2SystemIdentityCreationResponseData")
        }
    }
}

impl<'de> Deserialize<'de> for L2SystemIdentityCreationResponseData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            client_id: String,
            name: String,
        }

        let response = common_nerdgraph_response::<_, Response>(deserializer)?;

        Ok(Self {
            client_id: response.client_id,
            name: response.name,
        })
    }
}
