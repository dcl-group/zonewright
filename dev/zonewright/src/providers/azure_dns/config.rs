//! Settings and credentials of the Azure DNS client (design section 2.8).
//!
//! The keys are a compatibility surface: applications persist them.
//!
//! Authentication is a service principal with a client secret only: the OAuth 2.0 client
//! credentials grant at the Microsoft identity platform. The tenant, the application (client)
//! ID, the subscription and the resource group are settings; the client secret is the one
//! credential. The two hosts and the scope have the public cloud's documented values as
//! defaults, so that a national cloud is a matter of configuration.

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

/// Default Azure Resource Manager endpoint of the public cloud.
// Source: https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01
// (`PUT https://management.azure.com/subscriptions/…`); the Go SDK's public cloud configuration,
// https://raw.githubusercontent.com/Azure/azure-sdk-for-go/main/sdk/azcore/arm/runtime/runtime.go
// (`Endpoint: "https://management.azure.com"`).
pub(super) const DEFAULT_MANAGEMENT_URL: &str = "https://management.azure.com";

/// Default Microsoft identity platform host of the public cloud.
// Source: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
// (`POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`).
pub(super) const DEFAULT_LOGIN_URL: &str = "https://login.microsoftonline.com";

/// Default scope of the token request: Azure Resource Manager with `.default`.
// Source: https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc, "Trailing slash
// and `.default`": "when you request a token for `https://management.azure.com/` and use
// `.default`, you must request `https://management.azure.com//.default` (notice the double
// slash!)"; "Client credentials requests in your client service *must* include
// `scope={resource}/.default`" (same page). The scope is a setting of its own rather than derived
// from `management_url`: the documentation states the resource identifier for the public cloud's
// Resource Manager only.
pub(super) const DEFAULT_SCOPE: &str = "https://management.azure.com//.default";

/// TTL of a new rrset when the caller gives none.
// Source: lego providers/dns/azuredns/azuredns.go, `NewDefaultConfig` (`TTL:
// env.GetOrDefaultInt(EnvTTL, 60)`).
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the API accepts, in seconds.
// Source: https://learn.microsoft.com/en-us/azure/dns/dns-zones-records ("Azure DNS supports any
// TTL value between 1 and 2,147,483,647 seconds").
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 2_147_483_647;

/// Longest identifier setting the client accepts: a bound of the client's own, not of the API,
/// that keeps each identifier one short path segment or form value.
const IDENTIFIER_MAX: usize = 256;

/// Settings of the Azure DNS client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AzureDnsConfig {
    /// The Microsoft Entra tenant of the service principal: its ID (a GUID) or a domain name of
    /// the tenant.
    pub tenant_id: String,
    /// The application (client) ID of the service principal.
    pub client_id: String,
    /// The Azure subscription that holds the zones.
    pub subscription_id: String,
    /// The resource group that holds the zones. Only zones in this group are seen.
    pub resource_group: String,
    /// TTL of a new rrset: 1 to 2147483647 seconds, default 60. An existing rrset keeps its
    /// own TTL.
    #[serde(default = "default_ttl")]
    pub ttl: RrsetTtl,
    /// Azure Resource Manager endpoint; default `https://management.azure.com` (the public
    /// cloud).
    #[serde(default = "default_management_url")]
    pub management_url: String,
    /// Microsoft identity platform host; default `https://login.microsoftonline.com` (the
    /// public cloud).
    #[serde(default = "default_login_url")]
    pub login_url: String,
    /// The scope of the token request; default `https://management.azure.com//.default` (the
    /// public cloud's Resource Manager). A national cloud needs its own Resource Manager
    /// resource identifier here.
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_ttl() -> RrsetTtl {
    RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL))
}

fn default_management_url() -> String {
    DEFAULT_MANAGEMENT_URL.to_owned()
}

fn default_login_url() -> String {
    DEFAULT_LOGIN_URL.to_owned()
}

fn default_scope() -> String {
    DEFAULT_SCOPE.to_owned()
}

impl AzureDnsConfig {
    /// Settings with the four required keys; every other field starts at its default (the
    /// public cloud).
    #[must_use]
    pub fn new(
        tenant_id: String,
        client_id: String,
        subscription_id: String,
        resource_group: String,
    ) -> AzureDnsConfig {
        AzureDnsConfig {
            tenant_id,
            client_id,
            subscription_id,
            resource_group,
            ttl: default_ttl(),
            management_url: default_management_url(),
            login_url: default_login_url(),
            scope: default_scope(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Settings, Error> {
        // A tenant is a GUID or a domain name ("`tenant`: … the tenant's GUID or domain name",
        // v2-oauth2-client-creds-grant-flow, "First case").
        if !identifier(&self.tenant_id, |b| {
            b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
        }) {
            return Err(config(
                "tenant_id must be the tenant's ID or domain name (letters, digits, '-' and '.')",
            ));
        }
        if !identifier(&self.client_id, |b| b.is_ascii_graphic()) {
            return Err(config(
                "client_id must be the application (client) ID, printable ASCII without spaces",
            ));
        }
        if !identifier(&self.subscription_id, |b| {
            b.is_ascii_alphanumeric() || b == b'-'
        }) {
            return Err(config(
                "subscription_id must be the subscription ID (letters, digits and '-')",
            ));
        }
        // A resource group name goes into one path segment, percent-encoded; a `/`, a control
        // character or a trailing `.` cannot be part of it.
        let group = &self.resource_group;
        if group.is_empty()
            || group.chars().count() > IDENTIFIER_MAX
            || group.chars().any(|c| c.is_control() || c == '/')
            || group.ends_with('.')
        {
            return Err(config(
                "resource_group must be the name of a resource group: no '/', no control \
                 character, not ending in '.'",
            ));
        }
        if !identifier(&self.scope, |b| b.is_ascii_graphic()) {
            return Err(config(
                "scope must be printable ASCII without spaces, such as \
                 https://management.azure.com//.default",
            ));
        }
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 1 and 2147483647")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the client always sends a TTL",
                ));
            }
        };
        Ok(Settings {
            management: Endpoint::parse("management_url", &self.management_url, ctx)?,
            login: Endpoint::parse("login_url", &self.login_url, ctx)?,
            ttl,
        })
    }
}

/// `value` is 1 to [`IDENTIFIER_MAX`] bytes, each accepted by `allowed`.
fn identifier(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= IDENTIFIER_MAX && value.bytes().all(allowed)
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    /// Azure Resource Manager.
    pub(super) management: Endpoint,
    /// The identity platform host.
    pub(super) login: Endpoint,
    /// TTL of a new rrset.
    pub(super) ttl: u32,
}

/// Credentials of the Azure DNS client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the secret.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct AzureDnsCredentials {
    /// A client secret of the service principal's application registration.
    pub client_secret: SecretString,
}

impl AzureDnsCredentials {
    /// Credentials with the client secret.
    #[must_use]
    pub fn new(client_secret: SecretString) -> AzureDnsCredentials {
        AzureDnsCredentials { client_secret }
    }
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is built from the position of the problem only.
pub(super) fn parse_settings(text: &str) -> Result<AzureDnsConfig, Error> {
    serde_json::from_str(text).map_err(|e| Error::settings_syntax(e.line(), e.column()))
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<AzureDnsCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config("the credentials must be a JSON object with the string key client_secret")
    })
}

pub(super) fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
