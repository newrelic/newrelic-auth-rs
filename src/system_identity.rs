use crate::jwt::signer::JwtSignerConfigImpl;
use crate::{ClientID, OrganizationID};

pub type ClientSecret = String;

pub enum AuthMethod {
    L1(ClientSecret),
    L2(JwtSignerConfigImpl),
}
pub struct SystemIdentity {
    // TODO encapsulate all this
    pub(crate) org_id: OrganizationID,
    pub(crate) client_id: ClientID,
    pub(crate) auth_method: AuthMethod,
}
