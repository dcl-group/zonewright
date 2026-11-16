//! Settings and credentials of the RFC 2136 client (design sections 2.8 and 11.3).
//!
//! The keys are those of the earlier TXT-only implementation, minus its propagation timeout (an
//! application setting now). They are a compatibility surface: applications persist them. The
//! optional keys accept `null` as "the default", as the earlier implementation did; the default
//! is declared on the field (design section 2.8), so a deserialized config holds it.

use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use secrecy::{ExposeSecret as _, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::context::Context;
use crate::error::Error;
use crate::name::DomainName;
use crate::record::{RrsetTtl, Ttl};
use crate::redact::Detail;

use super::tsig::{Algorithm, Key};

/// TTL of a new record when the caller gives none.
// The earlier implementation's default; lego's default TTL comes from `dns01.DefaultTTL`
// (providers/dns/rfc2136/rfc2136.go, `NewDefaultConfig`).
pub(super) const DEFAULT_TTL: u32 = 60;

/// TTL range the client accepts for its setting, in seconds. A bound of the client, not of the
/// protocol (RFC 2181 section 8 allows up to 2^31 - 1).
pub(super) const TTL_MIN: u32 = 1;
pub(super) const TTL_MAX: u32 = 86_400;

/// The DNS port (RFC 1035 section 4.2.2; lego appends 53 when the configured nameserver has no
/// port, providers/dns/rfc2136/rfc2136.go, `NewDNSProviderConfig`).
pub(super) const DEFAULT_PORT: u16 = 53;

/// Shortest secret accepted, in octets: half the output of SHA-256. RFC 8945 section 8: "The
/// secret SHOULD be at least as long as the keyed hash output"; design section 11.3 sets the
/// floor at 16.
pub(super) const MIN_SECRET_LEN: usize = 16;

/// Settings of the RFC 2136 client: the non-secret part of its configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Rfc2136Config {
    /// The primary server of the zone, reached over TCP: `host`, `host:port`, `IPv4`,
    /// `IPv4:port`, `IPv6` or `[IPv6]:port`; port 53 by default.
    pub server: String,
    /// The name of the TSIG key, as configured on the server.
    pub key_name: String,
    /// `hmac-sha256` (the default), `hmac-sha384` or `hmac-sha512`. An absent key, `null` and an
    /// empty text mean the default.
    #[serde(
        default = "default_algorithm",
        deserialize_with = "algorithm_or_default"
    )]
    pub algorithm: String,
    /// TTL of new records, in seconds: 1 to 86400; default 60. An absent key and `null` mean
    /// the default (60), as they always have; `"provider_default"` is refused, since every RR
    /// carries a TTL on the wire.
    #[serde(default = "default_ttl", deserialize_with = "ttl_or_default")]
    pub ttl: RrsetTtl,
}

/// The default of `algorithm`.
fn default_algorithm() -> String {
    Algorithm::HmacSha256.as_str().to_owned()
}

/// The default of `ttl`.
fn default_ttl() -> RrsetTtl {
    RrsetTtl::Explicit(Ttl::clamped(DEFAULT_TTL))
}

/// `algorithm`, with `null` read as the default.
fn algorithm_or_default<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_else(default_algorithm))
}

/// `ttl`, with `null` read as the default.
fn ttl_or_default<'de, D: serde::Deserializer<'de>>(d: D) -> Result<RrsetTtl, D::Error> {
    Ok(Option::<RrsetTtl>::deserialize(d)?.unwrap_or_else(default_ttl))
}

impl Rfc2136Config {
    /// Settings with the two required keys; the others start at their defaults.
    #[must_use]
    pub fn new(server: String, key_name: String) -> Rfc2136Config {
        Rfc2136Config {
            server,
            key_name,
            algorithm: default_algorithm(),
            ttl: default_ttl(),
        }
    }

    /// Checks everything that can be checked without the network. Error texts name the key,
    /// never its value.
    pub(super) fn validate(
        &self,
        credentials: &Rfc2136Credentials,
        ctx: &Context,
    ) -> Result<Settings, Error> {
        let server = parse_server(&self.server)?;
        if ctx.options().loopback_only {
            let loopback = matches!(&server, Server::Addr(addr) if addr.ip().is_loopback());
            if !loopback {
                return Err(config(
                    "server must be a loopback IP address: the context allows loopback \
                     connections only",
                ));
            }
        }
        let key_name = DomainName::parse(self.key_name.trim())
            .ok()
            .filter(|name| !name.is_root())
            .ok_or_else(|| config("key_name must be a domain-style key name"))?;
        let algorithm = match self.algorithm.trim() {
            "" => Algorithm::HmacSha256,
            text => Algorithm::parse(text).ok_or_else(|| {
                config("algorithm must be hmac-sha256, hmac-sha384 or hmac-sha512")
            })?,
        };
        let ttl = match self.ttl {
            RrsetTtl::Explicit(ttl) if (TTL_MIN..=TTL_MAX).contains(&ttl.as_secs()) => {
                ttl.as_secs()
            }
            RrsetTtl::Explicit(_) => return Err(config("ttl must be between 1 and 86400")),
            RrsetTtl::ProviderDefault => {
                return Err(config(
                    "ttl cannot be provider_default: the provider has no default TTL of its own",
                ));
            }
        };
        let secret = decode_secret(&credentials.secret)?;
        Ok(Settings {
            server,
            key: Key::new(key_name, algorithm, secret),
            ttl,
        })
    }
}

/// The settings after validation, in the form the client uses.
#[derive(Debug)]
pub(super) struct Settings {
    pub(super) server: Server,
    pub(super) key: Key,
    pub(super) ttl: u32,
}

/// Where the server is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Server {
    /// An IP literal with its port.
    Addr(SocketAddr),
    /// A host name, resolved on every connection, with its port.
    Host {
        /// Lowercase, without the trailing dot.
        host: String,
        port: u16,
    },
}

/// `host`, `host:port`, `IPv4`, `IPv4:port`, `IPv6`, `[IPv6]:port`.
fn parse_server(text: &str) -> Result<Server, Error> {
    let bad = || config("server must be host, host:port, an IP address or [IPv6]:port");
    let text = text.trim();
    if text.is_empty() {
        return Err(bad());
    }
    let nonzero = |port: u16| if port == 0 { Err(bad()) } else { Ok(port) };
    if let Ok(addr) = text.parse::<SocketAddr>() {
        nonzero(addr.port())?;
        return Ok(Server::Addr(addr));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(Server::Addr(SocketAddr::new(ip, DEFAULT_PORT)));
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, nonzero(port.parse::<u16>().map_err(|_| bad())?)?),
        None => (text, DEFAULT_PORT),
    };
    let host = DomainName::parse(host)
        .ok()
        .filter(|name| !name.is_root() && !name.is_wildcard())
        .ok_or_else(bad)?;
    Ok(Server::Host {
        host: host.without_dot().to_owned(),
        port,
    })
}

/// Decodes the base64 secret into memory that is wiped when the key drops.
fn decode_secret(secret: &SecretString) -> Result<SecretSlice<u8>, Error> {
    let compact: Zeroizing<String> = Zeroizing::new(
        secret
            .expose_secret()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect(),
    );
    let mut decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| config("secret must be base64"))?,
    );
    if decoded.len() < MIN_SECRET_LEN {
        return Err(config("secret must decode to at least 16 octets"));
    }
    Ok(SecretSlice::from(std::mem::take(&mut *decoded)))
}

/// Credentials of the RFC 2136 client: the secret part of its configuration.
///
/// Unknown keys are ignored. Nothing prints or serializes the secret.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Rfc2136Credentials {
    /// The TSIG secret in base64, as `tsig-keygen` or `keymgr` print it; at least 16 octets
    /// once decoded.
    pub secret: SecretString,
}

impl Rfc2136Credentials {
    /// Credentials with the base64 TSIG secret.
    #[must_use]
    pub fn new(secret: SecretString) -> Rfc2136Credentials {
        Rfc2136Credentials { secret }
    }
}

/// The settings keys that a settings object must contain.
const REQUIRED_KEYS: [(&str, &str); 2] = [
    ("server", "the settings lack the required key server"),
    ("key_name", "the settings lack the required key key_name"),
];

/// Parses the settings object. The deserializer's message can quote the input, so the error
/// text is fixed apart from the position of the problem and, for a missing key, its name.
pub(super) fn parse_settings(text: &str) -> Result<Rfc2136Config, Error> {
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

/// Parses the credentials object. Any failure is one fixed text naming the expected key.
pub(super) fn parse_credentials(text: &SecretString) -> Result<Rfc2136Credentials, Error> {
    serde_json::from_str(text.expose_secret())
        .map_err(|_| config("the credentials must be a JSON object with the string key secret"))
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(h: &str, port: u16) -> Server {
        Server::Host {
            host: h.to_owned(),
            port,
        }
    }

    #[test]
    fn server_forms() {
        assert_eq!(
            parse_server("ns1.example.org").unwrap(),
            host("ns1.example.org", 53)
        );
        assert_eq!(
            parse_server("NS1.example.org:5353").unwrap(),
            host("ns1.example.org", 5353)
        );
        assert_eq!(
            parse_server("192.0.2.1").unwrap(),
            Server::Addr("192.0.2.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_server("192.0.2.1:54").unwrap(),
            Server::Addr("192.0.2.1:54".parse().unwrap())
        );
        assert_eq!(
            parse_server("[2001:db8::1]:53").unwrap(),
            Server::Addr("[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_server("2001:db8::1").unwrap(),
            Server::Addr("[2001:db8::1]:53".parse().unwrap())
        );
        for bad in [
            "",
            "host:",
            "host:0",
            "host:99999",
            "a b:53",
            "[::1]",
            "192.0.2.1:0",
            ".",
            "*.example.org",
            "http://ns1.example.org",
        ] {
            assert!(parse_server(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn secret_rules() {
        let ok = SecretString::from("MDEyMzQ1Njc4OWFiY2RlZg==".to_owned());
        assert!(decode_secret(&ok).is_ok());
        let spaced = SecretString::from("MDEyMzQ1 Njc4OWFi\nY2RlZg==".to_owned());
        assert!(decode_secret(&spaced).is_ok());
        let short = SecretString::from("c2hvcnQ=".to_owned());
        assert!(decode_secret(&short).is_err());
        let garbage = SecretString::from("not base64!".to_owned());
        assert!(decode_secret(&garbage).is_err());
    }
}
