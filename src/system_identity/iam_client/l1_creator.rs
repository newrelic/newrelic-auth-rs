use super::response_data::SystemIdentityCreationResponseData;

/// Interface describing being able to create L2 System Identities.
pub trait L1IdentityCreator {
    // TODO type Output;
    type Error: std::error::Error;
    fn create_l1_system_identity(&self) -> Result<SystemIdentityCreationResponseData, Self::Error>;
}

// Accept closures as L1IdentityCreator implementations
impl<F, E> L1IdentityCreator for F
where
    F: Fn() -> Result<SystemIdentityCreationResponseData, E>,
    E: std::error::Error,
{
    type Error = E;

    fn create_l1_system_identity(&self) -> Result<SystemIdentityCreationResponseData, Self::Error> {
        self()
    }
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
              -> Result<SystemIdentityCreationResponseData, MockIAMClientError>;
        }
    }
}
