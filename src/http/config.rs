use clap::{error::Error as ClapError, error::ErrorKind};
use http::Uri;
use std::env;
use std::env::VarError;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Default, Clone)]
pub struct HttpConfig {
    pub(crate) timeout: Duration,
    pub(crate) conn_timeout: Duration,
    pub(crate) proxy: ProxyConfig,
}

impl HttpConfig {
    pub fn new(timeout: Duration, conn_timeout: Duration, proxy: ProxyConfig) -> Self {
        Self {
            timeout,
            conn_timeout,
            proxy,
        }
    }
}
const HTTP_PROXY_ENV_NAME: &str = "HTTP_PROXY";
const HTTPS_PROXY_ENV_NAME: &str = "HTTPS_PROXY";

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("invalid proxy url `{0}`: `{1}`")]
    InvalidUrl(String, String),
}

/// Type to represent a Url which can be used in proxy implementations.
/// It allows representing empty urls and perform basic uri validations.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ProxyUrl(Option<Uri>);

impl TryFrom<&str> for ProxyUrl {
    type Error = ProxyError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Ok(Self(None));
        }
        let uri = s
            .parse::<Uri>()
            .map_err(|err| ProxyError::InvalidUrl(s.to_string(), err.to_string()))?;
        Ok(Self(Some(uri)))
    }
}

impl Display for ProxyUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(url) => write!(f, "{url}"),
            None => write!(f, ""),
        }
    }
}

impl ProxyUrl {
    fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

/// Proxy for Auth Cli HTTP Clients.
#[derive(Debug, PartialEq, Clone, Default)]
pub struct ProxyConfig {
    /// Proxy URL proxy:
    /// <protocol>://<user>:<password>@<host>:<port>
    /// (All parts except host are optional)
    url: ProxyUrl,
    /// System path with the CA certificates in PEM format. All `.pem` files in the directory are read.
    ca_bundle_dir: PathBuf,
    /// System path with the CA certificate in PEM format.
    ca_bundle_file: PathBuf,
}

impl ProxyConfig {
    pub fn new(
        proxy_url: String,
        ca_bundle_dir: PathBuf,
        ca_bundle_file: PathBuf,
    ) -> Result<Self, ProxyError> {
        let url = ProxyUrl::try_from(proxy_url.as_str())?;
        Ok(Self {
            url,
            ca_bundle_dir,
            ca_bundle_file,
        })
    }
    pub fn ca_bundle_dir(&self) -> &Path {
        self.ca_bundle_dir.as_path()
    }

    pub fn ca_bundle_file(&self) -> &Path {
        self.ca_bundle_file.as_path()
    }

    /// Returns a string representation of the proxy url.
    pub fn url_as_string(&self) -> String {
        self.url.to_string()
    }
    /// Returns a new instance whose url is taken from the standard environment variables if needed.
    pub fn try_with_url_from_env(self) -> Result<Self, ProxyError> {
        self.with_env_aware_url(env::var)
    }

    /// Returns a new instance setting up the using the provided `env_var` function to get it from the
    /// environment if required. It fails if the url from the environment is not valid.
    fn with_env_aware_url<F>(self, env_var: F) -> Result<Self, ProxyError>
    where
        F: Fn(&'static str) -> Result<String, VarError>,
    {
        if !self.url.is_empty() {
            return Ok(self);
        }
        let url = env_var(HTTPS_PROXY_ENV_NAME)
            .or_else(|_| env_var(HTTP_PROXY_ENV_NAME))
            .unwrap_or_default()
            .as_str()
            .try_into()?;
        Ok(ProxyConfig { url, ..self })
    }
}

impl From<ProxyError> for ClapError {
    fn from(err: ProxyError) -> ClapError {
        ClapError::raw(ErrorKind::InvalidValue, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::ProxyError;
    use assert_matches::assert_matches;

    use super::{ProxyConfig, ProxyUrl};
    use std::{collections::HashMap, env::VarError};

    impl ProxyConfig {
        /// Convenient builder function for testing
        pub(crate) fn from_url(url: String) -> ProxyConfig {
            ProxyConfig {
                url: url.as_str().try_into().unwrap(),
                ..Default::default()
            }
        }
    }

    #[test]
    fn test_system_proxy_values() {
        struct TestCase {
            name: &'static str,
            env_values: HashMap<&'static str, &'static str>,
            config: ProxyConfig,
            expected: ProxyUrl,
        }

        impl TestCase {
            fn run(&self) {
                let config = self.config.clone().with_env_aware_url(|k| {
                    self.env_values
                        .get(k)
                        .map(|v| v.to_string())
                        .ok_or(VarError::NotPresent)
                });
                assert_eq!(
                    config.unwrap().url,
                    self.expected,
                    "Test name {}",
                    self.name
                )
            }
        }
        let test_cases = [
            TestCase {
                name: "No system proxy configured and no proxy in config",
                env_values: HashMap::from([("SOME_OTHER", "env-variable")]),
                config: ProxyConfig::default(),
                expected: ProxyUrl::default(),
            },
            TestCase {
                name: "No system proxy configured and proxy url",
                env_values: HashMap::from([("SOME_OTHER", "env-variable")]),
                config: ProxyConfig::from_url("http://localhost:8888".to_string()),
                expected: "http://localhost:8888".try_into().unwrap(),
            },
            TestCase {
                name: "Config url proxy has priority over system proxy",
                env_values: HashMap::from([("HTTPS_PROXY", "http://other.proxy:9999")]),
                config: ProxyConfig::from_url("http://localhost:8888".to_string()),
                expected: "http://localhost:8888".try_into().unwrap(),
            },
            TestCase {
                name: "HTTPS_PROXY env variable value is used",
                env_values: HashMap::from([("HTTPS_PROXY", "http://other.proxy:9999")]),
                config: ProxyConfig::default(),
                expected: "http://other.proxy:9999".try_into().unwrap(),
            },
            TestCase {
                name: "HTTP_PROXY env variable value is used",
                env_values: HashMap::from([("HTTP_PROXY", "http://other.proxy:9999")]),
                config: ProxyConfig::default(),
                expected: "http://other.proxy:9999".try_into().unwrap(),
            },
            TestCase {
                name: "HTTPS_PROXY has more priority",
                env_values: HashMap::from([
                    ("HTTPS_PROXY", "http://one.proxy:9999"),
                    ("HTTP_PROXY", "http://other.proxy:9999"),
                ]),
                config: ProxyConfig::default(),
                expected: "http://one.proxy:9999".try_into().unwrap(),
            },
        ];

        for test_case in test_cases {
            test_case.run();
        }
    }

    #[test]
    fn invalid_system_proxy() {
        let config = ProxyConfig::default();
        let result = config.with_env_aware_url(|_| Ok("http://".to_string()));
        assert_matches!(result.unwrap_err(), ProxyError::InvalidUrl(s, _) => {
            assert_eq!(s, "http://".to_string())
        });
    }
}
