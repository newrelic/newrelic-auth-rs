use response_data::SystemIdentityCreationResponseData;

mod error;
pub mod http_iam_client;
pub mod http_token_retriever;
mod l1_token_retriever;
pub mod response_data;

pub trait IAMClient {
    // TODO type Output;
    type Error: std::error::Error;
    fn create_system_identity(
        &self,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, Self::Error>;
}

// Accept closures as IAMClient implementations
impl<F, E> IAMClient for F
where
    F: Fn(&[u8]) -> Result<SystemIdentityCreationResponseData, E>,
    E: std::error::Error,
{
    type Error = E;

    fn create_system_identity(
        &self,
        pub_key: &[u8],
    ) -> Result<SystemIdentityCreationResponseData, Self::Error> {
        self(pub_key)
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
        pub IAMClient {}
        impl IAMClient for IAMClient {
            type Error = MockIAMClientError;
            fn create_system_identity(
                &self,
                pub_key: &[u8]
            ) -> Result<SystemIdentityCreationResponseData, MockIAMClientError>;
        }
    }
}
