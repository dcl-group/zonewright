//! Settings and credentials of the acme-dns client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now). They are a compatibility surface: applications persist them.
//!
//! The credentials are the answers of the server's register call, one per registration. The
//! answer's shape is documented in the project's README, section "Register endpoint":
//! <https://github.com/joohoi/acme-dns/blob/master/README.md> (an object with `username`,
//! `password`, `fulldomain`, `subdomain` and `allowfrom`, the last of which the client does not
//! use).

use std::fmt;

use reqwest::header::HeaderValue;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::error::Error;
use crate::http::Endpoint;
use crate::name::DomainName;
use crate::redact::Detail;

/// Longest subdomain label the server accepts.
// Source: acme-dns `pkg/api/util.go`, `validSubdomain`: the regular expression
// `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$` (1 to 63 characters).
const SUBDOMAIN_MAX: usize = 63;

/// Settings of the acme-dns client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AcmeDnsConfig {
    /// Base URL of the acme-dns HTTP API, for example `https://auth.example.org`. There is no
    /// default: the public server named in the project's README is an example, not a service to
    /// send credentials to.
    pub server_url: String,
}

impl AcmeDnsConfig {
    /// Settings with the required key.
    #[must_use]
    pub fn new(server_url: String) -> AcmeDnsConfig {
        AcmeDnsConfig { server_url }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(&self, ctx: &Context) -> Result<Endpoint, Error> {
        Endpoint::parse("server_url", &self.server_url, ctx)
    }
}

/// Credentials of the acme-dns client: the secret part of its configuration.
///
/// `registrations` is the JSON text of the server's register answer: one object, or an array of
/// objects for several registrations. Unknown keys of the credentials object are ignored.
/// Nothing prints or serializes the registrations.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct AcmeDnsCredentials {
    /// The register answer or answers, as JSON text.
    pub registrations: SecretString,
}

impl AcmeDnsCredentials {
    /// Credentials with the registrations as JSON text.
    #[must_use]
    pub fn new(registrations: SecretString) -> AcmeDnsCredentials {
        AcmeDnsCredentials { registrations }
    }

    /// Parses and validates the registrations. Every error text is fixed and quotes nothing.
    pub(super) fn parse_registrations(&self) -> Result<Vec<Registration>, Error> {
        let text = self.registrations.expose_secret().trim();
        let raw: Vec<RawRegistration> = if text.starts_with('[') {
            serde_json::from_str(text).map_err(|_| shape())?
        } else {
            vec![serde_json::from_str(text).map_err(|_| shape())?]
        };
        if raw.is_empty() {
            return Err(shape());
        }
        let mut out: Vec<Registration> = Vec::with_capacity(raw.len());
        for r in raw {
            let fulldomain = DomainName::parse(&r.fulldomain)
                .map_err(|_| config("registrations: fulldomain is not a valid domain name"))?;
            if !valid_subdomain(&r.subdomain) {
                return Err(config(
                    "registrations: subdomain must be 1 to 63 letters, digits and hyphens, \
                     starting and ending with a letter or digit",
                ));
            }
            // The server answers with `<subdomain>.<its own domain>`; a registration whose
            // fulldomain is anything else cannot be the one this subdomain belongs to.
            let own_label = fulldomain.labels().next();
            let has_domain = fulldomain.parent().is_some_and(|rest| !rest.is_root());
            if !own_label.is_some_and(|label| label.eq_ignore_ascii_case(&r.subdomain))
                || !has_domain
            {
                return Err(config(
                    "registrations: fulldomain must be <subdomain>.<acme-dns domain>",
                ));
            }
            for secret in [&r.username, &r.password] {
                let text = secret.expose_secret();
                if text.is_empty() {
                    return Err(config("registrations: username and password are required"));
                }
                if HeaderValue::from_str(text).is_err() {
                    return Err(config(
                        "registrations: username and password must be usable in an HTTP header",
                    ));
                }
            }
            if out.iter().any(|o| o.fulldomain == fulldomain) {
                return Err(config("registrations: duplicate fulldomain"));
            }
            out.push(Registration {
                username: r.username,
                password: r.password,
                subdomain: r.subdomain,
                fulldomain,
            });
        }
        Ok(out)
    }
}

/// One registration as the register answer states it. Other fields (`allowfrom`) are ignored.
#[derive(Deserialize)]
struct RawRegistration {
    /// The user name (`X-Api-User`).
    username: SecretString,
    /// The key (`X-Api-Key`).
    password: SecretString,
    /// The label the server serves the registration under.
    subdomain: String,
    /// The domain the `_acme-challenge` CNAME points to.
    fulldomain: String,
}

/// A validated registration.
pub(super) struct Registration {
    /// The user name; sent in `X-Api-User`.
    pub(super) username: SecretString,
    /// The key; sent in `X-Api-Key`.
    pub(super) password: SecretString,
    /// The subdomain, as the update's body names it.
    pub(super) subdomain: String,
    /// The name of the registration's TXT rrset.
    pub(super) fulldomain: DomainName,
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The credentials are not shown; the names are public DNS names.
        f.debug_struct("Registration")
            .field("fulldomain", &self.fulldomain.as_str())
            .finish_non_exhaustive()
    }
}

/// The server's rule for a subdomain.
fn valid_subdomain(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |b: &u8| b.is_ascii_alphanumeric();
    !bytes.is_empty()
        && bytes.len() <= SUBDOMAIN_MAX
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<AcmeDnsConfig, Error> {
    serde_json::from_str(text).map_err(|e| {
        if e.to_string().starts_with("missing field `server_url`") {
            config("the settings lack the required key server_url")
        } else {
            Error::settings_syntax(e.line(), e.column())
        }
    })
}

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<AcmeDnsCredentials, Error> {
    serde_json::from_str(text.expose_secret()).map_err(|_| {
        config("the credentials must be a JSON object with the string key registrations")
    })
}

fn shape() -> Error {
    config(
        "registrations: a JSON object or array from the acme-dns register call expected \
         (username, password, subdomain, fulldomain)",
    )
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}
