//! Settings and credentials of the OVHcloud client (design sections 2.8 and 11.3).
//!
//! The keys are a compatibility surface: applications persist them.

use std::time::Duration;

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// The endpoint used when the settings name none.
// Source: lego providers/dns/ovh/ovh.go (`OVH_ENDPOINT`, default `ovh-eu`) and ovh.toml.
pub(super) const DEFAULT_ENDPOINT: &str = "ovh-eu";

/// The API endpoints by name.
// Source: go-ovh ovh/ovh.go (`OvhEU`, `OvhCA`, `OvhUS` and the `Endpoints` map: `ovh-eu`,
// `ovh-ca`, `ovh-us`), the provider's own client. The EU host is also the one of the provider's
// guide "First steps with the OVHcloud APIs"
// (https://docs.ovhcloud.com/en/guides/manage-and-operate/api/first-steps: the console at
// `https://api.eu.ovhcloud.com/console/` and `https://api.eu.ovhcloud.com/createToken/`). The
// API schema https://eu.api.ovh.com/1.0/domain.json states the older host `eu.api.ovh.com` as its
// `basePath`, and dns-update uses the older `eu.api.ovh.com` and `ca.api.ovh.com`; the provider's
// client is followed. go-ovh's `kimsufi-*` and `soyoustart-*` endpoints belong to other product
// lines and are not offered.
pub(super) const ENDPOINTS: &[(&str, &str)] = &[
    ("ovh-eu", "https://api.eu.ovhcloud.com/1.0"),
    ("ovh-ca", "https://api.ca.ovhcloud.com/1.0"),
    ("ovh-us", "https://api.us.ovhcloud.com/1.0"),
];

/// TTL of a new record when the caller gives none.
// Source: lego providers/dns/ovh/ovh.go (`OVH_TTL`, default `dns01.DefaultTTL`, 120 seconds;
// challenge/dns01/dns_challenge.go).
pub(super) const DEFAULT_TTL: u32 = 120;

/// TTL range the client accepts, in seconds.
// Source for the lower bound: the provider's Terraform provider,
// ovh/resource_domain_zone_record.go, which refuses a `ttl` below 60 other than 0 ("must be
// either equal to 0 or, greater than or equal to 60"). The API schema
// (https://eu.api.ovh.com/1.0/domain.json, `domain.zone.RecordCreate.ttl`) states only a `long`.
// Assumption (not documented, not observed against the live API): an upper bound of 86400.
// Being wrong only refuses a TTL the API would accept; a TTL the API refuses comes back as
// `Error::Rejected` and writes nothing.
pub(super) const TTL_MIN: u32 = 60;
pub(super) const TTL_MAX: u32 = 86_400;

/// The first pause before a listed record that answered `404` is read again, in milliseconds.
// The client's own choice: Terraform retries such a read for up to one minute without stating
// a spacing (see `api.rs`, `READ_ATTEMPTS`). The lower bound lets tests run without waiting.
pub(super) const DEFAULT_READ_RETRY_MS: u64 = 1000;
pub(super) const READ_RETRY_MS_MIN: u64 = 1;
pub(super) const READ_RETRY_MS_MAX: u64 = 60_000;

/// Settings of the OVHcloud client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OvhConfig {
    /// The application key (AK) of the API application. An identifier, sent in a header with
    /// every request; the application secret and the consumer key are the credentials.
    pub application_key: String,
    /// The API endpoint by name: `ovh-eu` (default), `ovh-ca` or `ovh-us`.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// An API endpoint given as a URL, used instead of `endpoint`; for a test server.
    #[serde(default)]
    pub base_url: Option<String>,
    /// TTL of a new record, in seconds: 60 to 86400, default 120.
    #[serde(default = "default_ttl")]
    pub ttl: RrsetTtl,
    /// The first pause, in milliseconds, before a record the listing holds but whose read
    /// answered `404` is read again; it doubles for each of the following reads: 1 to 60000,
    /// default 1000.
    #[serde(default = "default_read_retry_ms")]
    pub read_retry_ms: u64,
}

fn default_read_retry_ms() -> u64 {
    DEFAULT_READ_RETRY_MS
}

fn default_endpoint() -> String {
    DEFAULT_ENDPOINT.to_owned()
}

fn default_ttl() -> RrsetTtl {
    RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL))
}

impl OvhConfig {
    /// Settings with the application key and every other key at its default.
    #[must_use]
    pub fn new(application_key: String) -> OvhConfig {
        OvhConfig {
            application_key,
            endpoint: default_endpoint(),
            base_url: None,
            ttl: default_ttl(),
            read_retry_ms: DEFAULT_READ_RETRY_MS,
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 60 and 86400")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the client writes an explicit TTL on every \
                     record",
                ));
            }
        };
        if !(READ_RETRY_MS_MIN..=READ_RETRY_MS_MAX).contains(&self.read_retry_ms) {
            return Err(config("read_retry_ms must be between 1 and 60000"));
        }
        let key = self.application_key.trim();
        // The key is sent as a header value and is a part of every signature.
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(config(
                "application_key must be a non-empty string of visible ASCII characters",
            ));
        }
        let api = match &self.base_url {
            Some(url) => Endpoint::parse("base_url", url, ctx)?,
            None => {
                let url = ENDPOINTS
                    .iter()
                    .find(|(name, _)| *name == self.endpoint)
                    .map(|(_, url)| *url)
                    .ok_or_else(|| config("endpoint must be one of ovh-eu, ovh-ca, ovh-us"))?;
                Endpoint::parse("endpoint", url, ctx)?
            }
        };
        Ok(Settings {
            api,
            application_key: key.to_owned(),
            ttl,
            read_pause: Duration::from_millis(self.read_retry_ms),
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API, ending in `/1.0`.
    pub(super) api: Endpoint,
    /// The application key, trimmed.
    pub(super) application_key: String,
    /// TTL of a new record.
    pub(super) ttl: u32,
    /// The first pause before a listed record is read again.
    pub(super) read_pause: Duration,
}

/// Credentials of the OVHcloud client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the secrets.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct OvhCredentials {
    /// The application secret (AS). Never sent: it is a part of the string every request
    /// signature is computed over.
    pub application_secret: SecretString,
    /// The consumer key (CK), sent in the `X-Ovh-Consumer` header and a part of every
    /// signature.
    pub consumer_key: SecretString,
}

impl OvhCredentials {
    /// Credentials with the application secret and the consumer key.
    #[must_use]
    pub fn new(application_secret: SecretString, consumer_key: SecretString) -> OvhCredentials {
        OvhCredentials {
            application_secret,
            consumer_key,
        }
    }

    /// Both values are non-empty visible ASCII without whitespace. The consumer key is sent in
    /// a header, where surrounding whitespace is removed in transit while the signature covers
    /// it, and both are parts of the signed text: a value with whitespace would make every
    /// request fail.
    pub(super) fn validate(&self) -> Result<(), Error> {
        let visible = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_graphic());
        if !visible(self.application_secret.expose_secret()) {
            return Err(config(
                "application_secret must be a non-empty string of visible ASCII characters \
                 without whitespace",
            ));
        }
        if !visible(self.consumer_key.expose_secret()) {
            return Err(config(
                "consumer_key must be a non-empty string of visible ASCII characters without \
                 whitespace",
            ));
        }
        Ok(())
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<OvhConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected keys.
pub(super) fn parse_credentials(text: &SecretString) -> Result<OvhCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config(
            "the credentials must be a JSON object with the string keys application_secret and \
             consumer_key",
        )
    })
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use super::OvhConfig;
    use crate::context::{Context, ContextOptions};

    /// The named endpoints map to the hosts of go-ovh; `base_url` takes precedence.
    #[test]
    fn endpoints_map_to_the_hosts_of_the_providers_client() {
        let ctx = Context::new(ContextOptions::default()).unwrap();
        for (name, url) in [
            ("ovh-eu", "https://api.eu.ovhcloud.com/1.0"),
            ("ovh-ca", "https://api.ca.ovhcloud.com/1.0"),
            ("ovh-us", "https://api.us.ovhcloud.com/1.0"),
        ] {
            let mut config = OvhConfig::new("k".to_owned());
            config.endpoint = name.to_owned();
            let settings = config.validate(&ctx).unwrap();
            assert_eq!(settings.api.as_url().as_str(), url);
        }
        let mut config = OvhConfig::new("k".to_owned());
        config.endpoint = "kimsufi-eu".to_owned();
        assert!(config.validate(&ctx).is_err());
        config.base_url = Some("https://example.net/api/1.0".to_owned());
        let settings = config.validate(&ctx).unwrap();
        assert_eq!(
            settings.api.as_url().as_str(),
            "https://example.net/api/1.0"
        );
        assert_eq!(settings.application_key, "k");
    }
}
