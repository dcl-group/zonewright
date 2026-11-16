//! Settings and credentials of the Gandi client (design section 2.8).
//!
//! The keys are a compatibility surface: applications persist them.
//!
//! The credential is a personal access token, sent as `Authorization: Bearer <token>`. The API
//! also accepts the deprecated API key (`Authorization: Apikey <key>`); the client does not offer
//! it: the documentation calls it deprecated and "be replaced by personal access token" (LiveDNS
//! API reference, header `Authorization`), and says that an account without an API key cannot
//! create one any more ("You cannot create an API key if you don't have one, you can only
//! regenerate an existing one", <https://api.gandi.net/docs/authentication/>). A second
//! credential kind would be a persisted setting kept for a mechanism that is being retired.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default API endpoint.
// Source: the LiveDNS API reference <https://api.gandi.net/docs/livedns/> (paths
// `https://api.gandi.net/v5/livedns/domains…`); lego providers/dns/gandiv5/internal/client.go:18
// (`defaultBaseURL = "https://api.gandi.net/v5/livedns"`).
pub(super) const DEFAULT_BASE_URL: &str = "https://api.gandi.net/v5/livedns";

/// TTL of a new rrset when the caller gives none.
// Source: lego providers/dns/gandiv5/gandiv5.go:34 and :58 (`minTTL = 300`, the default of
// `GANDIV5_TTL`), which is also the documented minimum of `rrset_ttl`.
pub(super) const DEFAULT_TTL: u32 = 300;

/// TTL range of `rrset_ttl`: "Minimum: 300", "Maximum: 2592000" (LiveDNS API reference).
pub(super) const TTL_MIN: u32 = 300;
pub(super) const TTL_MAX: u32 = 2_592_000;

/// Longest `sharing_id` the client accepts. The documentation gives no format beyond
/// "Organization ID"; the identifiers of its examples are UUIDs.
const SHARING_ID_MAX: usize = 128;

/// Settings of the Gandi client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct GandiConfig {
    /// TTL of a new rrset: 300 to 2592000 seconds, default 300. An existing rrset keeps its own
    /// TTL.
    pub ttl: RrsetTtl,
    /// The organization whose domains `list_zones` shows. Without it, the API lists only the
    /// domains of the personal organization of the token's owner. 1 to 128 ASCII letters,
    /// digits, `-` and `_`.
    pub sharing_id: Option<String>,
    /// API endpoint; default `https://api.gandi.net/v5/livedns`.
    pub base_url: String,
}

impl Default for GandiConfig {
    fn default() -> GandiConfig {
        GandiConfig {
            ttl: RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL)),
            sharing_id: None,
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }
}

impl GandiConfig {
    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 300 and 2592000")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the client always sends a TTL of its own",
                ));
            }
        };
        if let Some(id) = &self.sharing_id {
            let usable = (1..=SHARING_ID_MAX).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !usable {
                return Err(config(
                    "sharing_id must be 1 to 128 ASCII letters, digits, '-' and '_'",
                ));
            }
        }
        Ok(Settings {
            api: Endpoint::parse("base_url", &self.base_url, ctx)?,
            ttl,
            sharing_id: self.sharing_id.clone(),
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// The API.
    pub(super) api: Endpoint,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
    /// The organization of the zone listing.
    pub(super) sharing_id: Option<String>,
}

/// Credentials of the Gandi client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the token.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct GandiCredentials {
    /// A personal access token, scoped to the organization whose domains the client manages,
    /// with the permission to manage their records.
    pub personal_access_token: SecretString,
}

impl GandiCredentials {
    /// Credentials with the personal access token.
    #[must_use]
    pub fn new(personal_access_token: SecretString) -> GandiCredentials {
        GandiCredentials {
            personal_access_token,
        }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<GandiConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<GandiCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config("the credentials must be a JSON object with the string key personal_access_token")
    })
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
