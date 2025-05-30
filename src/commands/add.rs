use crate::http_client::HttpClient;
use http::Error;
use reqwest::blocking::Client;

pub struct AddCommand<C>
where
    C: HttpClient,
{
    http_client: C,
}

impl<C> AddCommand<C>
where
    C: HttpClient,
{
    pub fn new(http_client: C) -> Self {
        Self { http_client }
    }

    pub fn add(metadata: String) -> Result<(), Error> {
        Ok(())
    }
}
