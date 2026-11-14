//! Settings and credentials of the reg.ru client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now). They are a compatibility surface: applications persist them.

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::redact::Detail;

/// Default API endpoint.
// Source: the reg.ru API 2 documentation, section 2.2.2 ("Передача входных параметров"),
// <https://www.reg.ru/reseller/api2doc>: requests go to `https://api.reg.ru/api/regru2/<function>`;
// lego providers/dns/regru/internal/client.go:16 (`defaultBaseURL`, with a trailing slash).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.reg.ru/api/regru2";

/// Default minimum time between two requests, in milliseconds.
// Source: the documentation, section 1.2, states a limit of 1200 requests per hour for a client
// and for an IP address, at once: one request per three seconds on average. The interval below
// (1000 ms, design section 5.7, `RateGate`) is not derived from the documentation: it spaces
// the few requests of one operation, while staying within the hourly limit is the
// application's concern; it is a setting, so an application can widen it.
pub(super) const DEFAULT_INTERVAL_MS: u64 = 1000;

/// Largest interval the setting accepts, in milliseconds.
pub(super) const MAX_INTERVAL_MS: u64 = 60_000;

/// Settings of the reg.ru client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RegruConfig {
    /// The user name (login) of the account.
    pub username: String,
    /// Minimum time between two requests, in milliseconds: 0 to 60000, default 1000.
    #[serde(default = "default_interval")]
    pub min_request_interval_ms: u64,
    /// API endpoint; default `https://api.reg.ru/api/regru2`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_MS
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_owned()
}

impl RegruConfig {
    /// Settings with the one required key; every other field starts at its default.
    #[must_use]
    pub fn new(username: String) -> RegruConfig {
        RegruConfig {
            username,
            min_request_interval_ms: DEFAULT_INTERVAL_MS,
            base_url: default_base_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if self.username.is_empty() || self.username.chars().any(char::is_control) {
            return Err(config(
                "username must be a non-empty name without control characters",
            ));
        }
        if self.min_request_interval_ms > MAX_INTERVAL_MS {
            return Err(config(
                "min_request_interval_ms must be between 0 and 60000",
            ));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            interval: Duration::from_millis(self.min_request_interval_ms),
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// Minimum time between two requests.
    pub(super) interval: Duration,
}

/// Credentials of the reg.ru client: the secret part of its configuration.
///
/// The password is the account's API password, which the account's API settings can set apart
/// from the sign-in password. When the account has an API client certificate loaded, every
/// request must present it: `tls_cert_pem` and `tls_key_pem` are given together or not at all.
///
/// Unknown keys are ignored. Nothing prints or serializes a secret.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct RegruCredentials {
    /// The API password.
    pub password: SecretString,
    /// The client certificate chain, PEM, leaf first.
    #[serde(default)]
    pub tls_cert_pem: Option<SecretString>,
    /// The private key of the client certificate, PEM (PKCS#8, PKCS#1 or SEC1).
    #[serde(default)]
    pub tls_key_pem: Option<SecretString>,
}

impl RegruCredentials {
    /// Credentials with the API password and no client certificate.
    #[must_use]
    pub fn new(password: SecretString) -> RegruCredentials {
        RegruCredentials {
            password,
            tls_cert_pem: None,
            tls_key_pem: None,
        }
    }

    /// Credentials with the API password and a client certificate with its key.
    #[must_use]
    pub fn with_client_certificate(
        password: SecretString,
        cert_pem: SecretString,
        key_pem: SecretString,
    ) -> RegruCredentials {
        RegruCredentials {
            password,
            tls_cert_pem: Some(cert_pem),
            tls_key_pem: Some(key_pem),
        }
    }

    /// The certificate and key as text, both or neither; one without the other is
    /// `Error::Config`.
    pub(super) fn identity(&self) -> Result<Option<(&str, &str)>, Error> {
        match (&self.tls_cert_pem, &self.tls_key_pem) {
            (Some(cert), Some(key)) => Ok(Some((cert.expose_secret(), key.expose_secret()))),
            (None, None) => Ok(None),
            _ => Err(config(
                "tls_cert_pem and tls_key_pem must be given together",
            )),
        }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<RegruConfig, Error> {
    serde_json::from_str(text).map_err(|e| {
        if e.to_string().starts_with("missing field `username`") {
            config("the settings lack the required key username")
        } else {
            Error::settings_syntax(e.line(), e.column())
        }
    })
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<RegruCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the string key password and, \
             optionally, the string keys tls_cert_pem and tls_key_pem",
        )
    })
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
