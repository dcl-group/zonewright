//! Settings and credentials of the nic.ru client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout
//! (an application setting now). They are a compatibility surface: applications persist them.

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default DNS hosting API endpoint.
// Source: "API of DNS hosting" (API_DNS-hosting-en.pdf, linked from
// https://www.nic.ru/help/api-of-dns-hosting_1579.html; Internet Archive copy of 2024-09-13),
// sections 3 and 4 ("https://api.nic.ru/dns-master/..."); lego
// providers/dns/nicru/internal/client.go:16 (`apiBaseURL`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.nic.ru/dns-master";

/// Default OAuth token endpoint.
// Source: "API of DNS hosting", section 2.2 ("POST https://api.nic.ru/oauth/token"); lego
// providers/dns/nicru/internal/identity.go:9 (`authBaseURL`).
pub(super) const DEFAULT_TOKEN_URL: &str = "https://api.nic.ru/oauth/token";

/// Default OAuth scope: full access to every DNS hosting service of the contract.
// Source: "API of DNS hosting", section 2.1 ("scope=.+:/dns-master/.+ full access to all DNS
// hosting services under the agreement"); lego providers/dns/nicru/internal/identity.go:23.
pub(super) const DEFAULT_SCOPE: &str = ".+:/dns-master/.+";

/// TTL of a new record when the caller gives none: lego's default
/// (providers/dns/nicru/nicru.go:49, `NICRU_TTL` default 30).
pub(super) const DEFAULT_TTL: u32 = 30;

/// Range of the `ttl` setting, in seconds. The documentation states no limit (section 4.6:
/// "ttl setting - optional setting"); the bounds are the client's own, with lego's default as
/// the minimum, and match the capabilities.
pub(super) const TTL_MIN: u32 = 30;
pub(super) const TTL_MAX: u32 = 86_400;

/// Default spacing of requests. The documentation states no rate limit; the spacing is the
/// client's own precaution (design section 5.7).
pub(super) const DEFAULT_MIN_REQUEST_INTERVAL_MS: u64 = 500;

/// Largest `min_request_interval_ms`.
const MIN_REQUEST_INTERVAL_MAX: u64 = 60_000;

/// Longest user name and scope the client accepts: bounds of the client's own.
const TEXT_MAX: usize = 1024;

/// Settings of the nic.ru client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NicruConfig {
    /// The contract number used as the user name, for example `123/NIC-REG`.
    pub username: String,
    /// TTL of a new record: 30 to 86400 seconds, or `"provider_default"` for the zone's default
    /// TTL (the record is staged without `<ttl>`). Default 30.
    #[serde(default = "default_ttl")]
    pub ttl: RrsetTtl,
    /// The OAuth scope requested for the token; default `.+:/dns-master/.+` (full access to
    /// every DNS hosting service of the contract). It can be narrowed to the zones to manage.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Minimum time between two requests, in milliseconds: 0 to 60000, default 500.
    #[serde(default = "default_min_request_interval_ms")]
    pub min_request_interval_ms: u64,
    /// DNS hosting API endpoint; default `https://api.nic.ru/dns-master`.
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// OAuth token endpoint; default `https://api.nic.ru/oauth/token`.
    #[serde(default = "default_token_url")]
    pub token_url: String,
}

fn default_ttl() -> RrsetTtl {
    RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL))
}

fn default_scope() -> String {
    DEFAULT_SCOPE.to_owned()
}

fn default_min_request_interval_ms() -> u64 {
    DEFAULT_MIN_REQUEST_INTERVAL_MS
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_owned()
}

fn default_token_url() -> String {
    DEFAULT_TOKEN_URL.to_owned()
}

impl NicruConfig {
    /// Settings with the one required key; every other field starts at its default.
    #[must_use]
    pub fn new(username: String) -> NicruConfig {
        NicruConfig {
            username,
            ttl: default_ttl(),
            scope: default_scope(),
            min_request_interval_ms: DEFAULT_MIN_REQUEST_INTERVAL_MS,
            base_url: default_base_url(),
            token_url: default_token_url(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if self.username.is_empty() || self.username.len() > TEXT_MAX {
            return Err(config("username must be 1 to 1024 bytes long"));
        }
        if self.scope.is_empty()
            || self.scope.len() > TEXT_MAX
            || self.scope.chars().any(char::is_control)
        {
            return Err(config(
                "scope must be 1 to 1024 bytes long, without control characters",
            ));
        }
        if let RrsetTtl::Explicit(ttl) = self.ttl
            && !(TTL_MIN..=TTL_MAX).contains(&ttl.as_secs())
        {
            return Err(config(
                "ttl must be between 30 and 86400, or provider_default",
            ));
        }
        if self.min_request_interval_ms > MIN_REQUEST_INTERVAL_MAX {
            return Err(config(
                "min_request_interval_ms must be between 0 and 60000",
            ));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            token: Endpoint::parse("token_url", &self.token_url, ctx)?,
            ttl: self.ttl,
            interval: Duration::from_millis(self.min_request_interval_ms),
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The DNS hosting API.
    pub(super) api: Endpoint,
    /// The token endpoint.
    pub(super) token: Endpoint,
    /// TTL of a new record: a number, or the zone's default.
    pub(super) ttl: RrsetTtl,
    /// Spacing of requests; zero for none.
    pub(super) interval: Duration,
}

/// Credentials of the nic.ru client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes them. The application ID is not a
/// secret in the OAuth sense but arrives in the credentials object, and is held like the
/// secrets.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct NicruCredentials {
    /// The password of the account (administrative or technical).
    pub password: SecretString,
    /// The ID of the OAuth application registered for the contract.
    pub client_id: SecretString,
    /// The secret of the OAuth application.
    pub client_secret: SecretString,
}

impl NicruCredentials {
    /// Credentials from the account's password and the OAuth application's ID and secret.
    #[must_use]
    pub fn new(
        password: SecretString,
        client_id: SecretString,
        client_secret: SecretString,
    ) -> NicruCredentials {
        NicruCredentials {
            password,
            client_id,
            client_secret,
        }
    }

    /// Checks that no field is empty.
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.password.expose_secret().is_empty() {
            return Err(config("password must not be empty"));
        }
        if self.client_id.expose_secret().is_empty() {
            return Err(config("client_id must not be empty"));
        }
        if self.client_secret.expose_secret().is_empty() {
            return Err(config("client_secret must not be empty"));
        }
        Ok(())
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for the missing required key, its
/// name.
pub(super) fn parse_settings(text: &str) -> Result<NicruConfig, Error> {
    serde_json::from_str(text).map_err(|e| {
        if e.to_string().starts_with("missing field `username`") {
            config("the settings lack the required key username")
        } else {
            Error::settings_syntax(e.line(), e.column())
        }
    })
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<NicruCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the string keys password, client_id and \
             client_secret",
        )
    })
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
