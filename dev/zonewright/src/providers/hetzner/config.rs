//! Settings and credentials of the Hetzner client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now). They are a compatibility surface: applications persist them.

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::{Endpoint, poll_interval};
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default API endpoint.
// Source: the `servers` entry of the published OpenAPI description of the Hetzner Cloud API,
// https://docs.hetzner.cloud/cloud.spec.json; lego
// providers/dns/hetzner/internal/hetznerv1/internal/client.go:18 (`defaultBaseURL`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.hetzner.cloud/v1";

/// TTL of a new rrset when the caller gives none.
// Source for the default: the smallest TTL the API accepts, 60 seconds (Zone RRSets, the `ttl`
// field: "Must be in between 60s and 2147483647s"). lego sends its own default, 120
// (`dns01.DefaultTTL`, hetznerv1.go:46); the value is a choice, not an API requirement.
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the client accepts, in seconds.
// Source: Zone RRSets, "Add Records to an RRSet", `ttl`: minimum 60, maximum 2147483647
// (https://docs.hetzner.cloud/reference/cloud, checked against the published OpenAPI description
// https://docs.hetzner.cloud/cloud.spec.json).
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 2_147_483_647;

/// Default interval between two looks at a running action, in milliseconds.
// Source: design section 3.7. The Actions section of the reference says to avoid polling "too
// frequently" and gives no figure; lego polls at its own configured interval
// (hetznerv1.go:187 to 209).
pub(super) const DEFAULT_POLL_MS: u64 = 1000;

/// Range of the polling interval, in milliseconds. The floor is the transport's.
pub(super) const POLL_MS_MIN: u64 = 250;
pub(super) const POLL_MS_MAX: u64 = 60_000;

/// Most looks at a running action.
// Design section 3.7; at the default interval this waits for two minutes.
pub(super) const ACTION_POLLS: u32 = 120;

/// Settings of the Hetzner client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct HetznerConfig {
    /// API endpoint; default `https://api.hetzner.cloud/v1`.
    pub base_url: String,
    /// TTL of a new rrset: 60 to 2147483647 seconds, or `"provider_default"` for the zone's
    /// default TTL. Default 60. An existing rrset keeps its own TTL.
    pub ttl: RrsetTtl,
    /// Interval between two polls of a running action, in milliseconds: 250 to 60000, default
    /// 1000.
    pub action_poll_ms: u64,
}

impl Default for HetznerConfig {
    fn default() -> HetznerConfig {
        HetznerConfig {
            base_url: DEFAULT_BASE_URL.to_owned(),
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
            action_poll_ms: DEFAULT_POLL_MS,
        }
    }
}

impl HetznerConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        if let RrsetTtl::Explicit(ttl) = self.ttl
            && !(TTL_MIN..=TTL_MAX).contains(&ttl.as_secs())
        {
            return Err(config(
                "ttl must be between 60 and 2147483647, or provider_default",
            ));
        }
        if !(POLL_MS_MIN..=POLL_MS_MAX).contains(&self.action_poll_ms) {
            return Err(config("action_poll_ms must be between 250 and 60000"));
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            ttl: self.ttl,
            poll: poll_interval(Some(self.action_poll_ms), DEFAULT_POLL_MS),
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// TTL of a new rrset.
    pub(super) ttl: RrsetTtl,
    /// Interval between two looks at a running action.
    pub(super) poll: Duration,
}

/// Credentials of the Hetzner client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct HetznerCredentials {
    /// An API token of the Hetzner Console project that holds the zones, with read and write
    /// permission.
    pub api_token: SecretString,
}

impl HetznerCredentials {
    /// Credentials with the project API token.
    #[must_use]
    pub fn new(api_token: SecretString) -> HetznerCredentials {
        HetznerCredentials { api_token }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<HetznerConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<HetznerCredentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key api_token"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
