//! Settings and credentials of the Beget client (design sections 2.8 and 11.3).
//!
//! The keys are a compatibility surface: applications persist them, so none is renamed or
//! reused.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::redact::Detail;

/// Default API endpoint.
// Source: https://beget.com/ru/kb/api/obshhij-princzip-raboty-s-api ("Способ взаимодействия":
// "https://api.beget.com/api/раздел/метод?параметры") and lego providers/dns/beget/internal/
// client.go:15 (`defaultBaseURL`, with a trailing slash).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.beget.com/api";

/// TTL of a new TXT value when the caller gives none.
// Source: lego providers/dns/beget/beget.go:47 (`BEGET_TTL`, default 300).
pub(super) const DEFAULT_TTL: u32 = 300;

/// TTL range the client accepts, in seconds.
// Assumption (not documented): neither the function descriptions nor the principles page state
// a TTL at all; lego sends a `ttl` field with every TXT record it writes
// (providers/dns/beget/internal/types.go:94) and its default is 300. The bounds are the
// client's own. Being wrong only refuses a TTL the API would accept; a value the API refuses
// comes back as `Error::Rejected` and writes nothing.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// Default spacing of requests, in milliseconds.
// Source: https://beget.com/ru/kb/api/obshhij-princzip-raboty-s-api ("Используемые коды ошибок",
// `LIMIT_ERROR`: "не более 60 запросов в минуту для пользователя"), which one request per
// second keeps.
pub(super) const DEFAULT_INTERVAL_MS: u64 = 1000;

/// Largest spacing the client accepts, in milliseconds: a bound of the client's own.
pub(super) const INTERVAL_MAX_MS: u64 = 60_000;

/// Longest login the client accepts: a bound of the client's own, not of the API.
const LOGIN_MAX: usize = 255;

/// Settings of the Beget client: the non-secret part of its configuration.
///
/// The login is not secret, but the client treats it like the password in everything it prints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct BegetConfig {
    /// The login of the Beget account.
    pub login: String,
    /// TTL of a new TXT value, in seconds: 60 to 86400, default 300. A value that joins an
    /// existing TXT set takes the TTL of that set.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Minimum time between two requests, in milliseconds: 0 to 60000, default 1000. The API
    /// allows 60 requests a minute per user.
    #[serde(default = "default_interval")]
    pub min_request_interval_ms: u64,
    /// API endpoint; default `https://api.beget.com/api`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_MS
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_owned()
}

impl BegetConfig {
    /// Settings with the required login; every other field starts at its default.
    #[must_use]
    pub fn new(login: String) -> BegetConfig {
        BegetConfig {
            login,
            ttl: DEFAULT_TTL,
            min_request_interval_ms: DEFAULT_INTERVAL_MS,
            base_url: default_base_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if self.login.is_empty()
            || self.login.chars().count() > LOGIN_MAX
            || self.login.chars().any(char::is_control)
        {
            return Err(config(
                "login must be 1 to 255 characters long, without control characters",
            ));
        }
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 60 and 86400"));
        }
        if self.min_request_interval_ms > INTERVAL_MAX_MS {
            return Err(config(
                "min_request_interval_ms must be between 0 and 60000",
            ));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            ttl: self.ttl,
            interval_ms: self.min_request_interval_ms,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// TTL of a new TXT value.
    pub(super) ttl: u32,
    /// Spacing of requests, in milliseconds.
    pub(super) interval_ms: u64,
}

/// Credentials of the Beget client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the password.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct BegetCredentials {
    /// The API password, set in the API section of the control panel; not the password for
    /// signing in.
    pub password: SecretString,
}

impl BegetCredentials {
    /// Credentials with the API password.
    #[must_use]
    pub fn new(password: SecretString) -> BegetCredentials {
        BegetCredentials { password }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing login, its name.
pub(super) fn parse_settings(text: &str) -> Result<BegetConfig, Error> {
    serde_json::from_str(text).map_err(|e| {
        if e.to_string().starts_with("missing field `login`") {
            config("the settings lack the required key login")
        } else {
            Error::settings_syntax(e.line(), e.column())
        }
    })
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<BegetCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key password"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
