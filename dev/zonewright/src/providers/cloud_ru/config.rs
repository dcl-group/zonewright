//! Settings and credentials of the Cloud.ru client (design sections 2.8 and 11.3).
//!
//! The keys follow design section 11.3 and are a compatibility surface: applications persist
//! them. A propagation timeout is not a setting of the crate (`ProviderMeta`). The
//! access key ID is a setting, the access key secret the only credential; the client registers
//! both with its scrubber, because the token service receives them together.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::redact::Detail;

/// Default DNS API endpoint.
// Source: the Evolution DNS OpenAPI specification,
// https://cloud.ru/docs/api/specs/evolution-dns/ug/_specs/openapi.yaml (`servers`:
// `https://dns.api.cloud.ru`).
pub(super) const DEFAULT_DNS_URL: &str = "https://dns.api.cloud.ru";

/// Default token endpoint for an access key.
// Source: https://cloud.ru/docs/evolution-dns/ug/topics/api-ref__authentication and
// https://cloud.ru/docs/console_api/ug/topics/guides__auth_api (`POST
// https://iam.api.cloud.ru/api/v1/auth/token`).
pub(super) const DEFAULT_IAM_URL: &str = "https://iam.api.cloud.ru/api/v1/auth/token";

/// TTL of a new record when the caller gives none: the documented minimum.
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the service accepts, in seconds.
// Source: https://cloud.ru/docs/evolution-dns/ug/topics/overview__limitations ("Минимальное
// значение TTL 60 сек.", "Максимальное значение TTL 86 400 сек.").
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// Default interval between two polls of an operation (design section 3.7).
pub(super) const DEFAULT_POLL_MS: u64 = 1000;
const POLL_MS_MIN: u64 = 250;
const POLL_MS_MAX: u64 = 60_000;

/// Longest project ID and access key ID the client accepts: a bound of the client's own, not of
/// the API.
const ID_MAX: usize = 128;

/// Settings of the Cloud.ru client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CloudRuConfig {
    /// The Evolution project that holds the public zones.
    pub project_id: String,
    /// The ID ("login") of the access key. It is sent to the token service with the secret and
    /// is kept out of error texts like a secret.
    pub key_id: String,
    /// TTL of a new record, in seconds: 60 to 86400, default 60.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Interval between two polls of an operation, in milliseconds: 250 to 60000, default 1000.
    #[serde(default = "default_poll_ms")]
    pub operation_poll_ms: u64,
    /// DNS API endpoint; default `https://dns.api.cloud.ru`.
    #[serde(default = "default_dns_url")]
    pub dns_url: String,
    /// Token endpoint; default `https://iam.api.cloud.ru/api/v1/auth/token`.
    #[serde(default = "default_iam_url")]
    pub iam_url: String,
}

fn default_ttl() -> u32 {
    DEFAULT_TTL
}

fn default_poll_ms() -> u64 {
    DEFAULT_POLL_MS
}

fn default_dns_url() -> String {
    DEFAULT_DNS_URL.to_owned()
}

fn default_iam_url() -> String {
    DEFAULT_IAM_URL.to_owned()
}

impl CloudRuConfig {
    /// Settings with the two required keys; every other field starts at its default.
    #[must_use]
    pub fn new(project_id: String, key_id: String) -> CloudRuConfig {
        CloudRuConfig {
            project_id,
            key_id,
            ttl: DEFAULT_TTL,
            operation_poll_ms: DEFAULT_POLL_MS,
            dns_url: default_dns_url(),
            iam_url: default_iam_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if !usable_id(&self.project_id) {
            return Err(config(
                "project_id must be 1 to 128 characters without control characters",
            ));
        }
        if !usable_id(&self.key_id) {
            return Err(config(
                "key_id must be 1 to 128 characters without control characters",
            ));
        }
        if !(TTL_MIN..=TTL_MAX).contains(&self.ttl) {
            return Err(config("ttl must be between 60 and 86400"));
        }
        if !(POLL_MS_MIN..=POLL_MS_MAX).contains(&self.operation_poll_ms) {
            return Err(config("operation_poll_ms must be between 250 and 60000"));
        }
        Ok(Settings {
            dns: Endpoint::parse("dns_url", &self.dns_url, ctx)?,
            iam: Endpoint::parse("iam_url", &self.iam_url, ctx)?,
        })
    }
}

/// A project ID or key ID the client can send: not empty, bounded, no control characters.
fn usable_id(id: &str) -> bool {
    !id.is_empty() && id.chars().count() <= ID_MAX && !id.chars().any(char::is_control)
}

/// The endpoints after validation.
#[derive(Debug)]
pub(super) struct Settings {
    /// The DNS API.
    pub(super) dns: Endpoint,
    /// The token endpoint.
    pub(super) iam: Endpoint,
}

/// Credentials of the Cloud.ru client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the secret.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct CloudRuCredentials {
    /// The secret ("password") of the access key.
    pub secret: SecretString,
}

impl CloudRuCredentials {
    /// Credentials with the access key's secret.
    #[must_use]
    pub fn new(secret: SecretString) -> CloudRuCredentials {
        CloudRuCredentials { secret }
    }

    /// True when the secret is empty.
    pub(super) fn is_empty(&self) -> bool {
        self.secret.expose_secret().is_empty()
    }
}

/// The settings keys that a settings object must contain.
const REQUIRED_KEYS: [(&str, &str); 2] = [
    (
        "project_id",
        "the settings lack the required key project_id",
    ),
    ("key_id", "the settings lack the required key key_id"),
];

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<CloudRuConfig, Error> {
    serde_json::from_str(text).map_err(|e| {
        let message = e.to_string();
        let missing = REQUIRED_KEYS
            .iter()
            .find(|(key, _)| message.starts_with(&format!("missing field `{key}`")));
        match missing {
            Some((_, text)) => config(text),
            None => Error::settings_syntax(e.line(), e.column()),
        }
    })
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<CloudRuCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key secret"))
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
