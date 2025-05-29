use super::SystemIdentity;

/// Interface describing being able to create L2 System Identities.
pub trait L1IdentityCreator {
    // TODO type Output;
    type Error: std::error::Error;
    fn create_l1_system_identity(&self) -> Result<SystemIdentity, Self::Error>;
}

/// Interface describing being able to create L2 System Identities.
pub trait L2IdentityCreator {
    // TODO type Output;
    type Error: std::error::Error;
    fn create_l2_system_identity(&self, pub_key: &[u8]) -> Result<SystemIdentity, Self::Error>;
}

#[cfg(test)]
pub mod tests {
    use mockall::mock;
    use thiserror::Error;

    use super::*;

    #[derive(Debug, Error)]
    #[error("mock IAM client error")]
    pub struct MockIAMClientError;

    mock! {
        pub L1IAMClient {}
        impl L1IdentityCreator for L1IAMClient {
            type Error = MockIAMClientError;
            fn create_l1_system_identity(&self)
              -> Result<SystemIdentity, MockIAMClientError>;
        }
    }

    mock! {
        pub L2IAMClient {}
        impl L2IdentityCreator for L2IAMClient {
            type Error = MockIAMClientError;
            fn create_l2_system_identity(
                &self,
                pub_key: &[u8]
            ) -> Result<SystemIdentity, MockIAMClientError>;
        }
    }
}
