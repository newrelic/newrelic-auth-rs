use super::types::{L1AccessTokenResponse, SystemIdentityCreationResponseData};

pub trait L1IdentityGetter {
    fn get_l1_identity(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Result<L1AccessTokenResponse, impl Into<String>>;
}

pub trait L2IdentityCreator {
    fn create_l2_identity(
        &self,
        access_token: &str,
        name: &str,
        organization_id: &str,
        b64_public_key: &str,
    ) -> Result<SystemIdentityCreationResponseData, impl Into<String>>;
}

struct IAMClient;
