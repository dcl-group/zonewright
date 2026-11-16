//! The explicit proxy of a context (design section 5.1).
//!
//! `ContextOptions::proxy` is checked here and turned into one `reqwest::Proxy` for every client
//! of the context. Facts from the `reqwest` 0.13.5 and `hyper-util` 0.1.21 sources this module
//! relies on:
//!
//! - `ClientBuilder::proxy` sets `auto_sys_proxy = false` and turns the `Proxy` into its matcher
//!   at once (`reqwest` `async_impl/client.rs`), so with the setting the environment is not read
//!   either.
//! - The proxy is a `Proxy::custom` (`reqwest` `proxy.rs`): for every connection and every
//!   forwarded request `reqwest` calls the closure with `scheme://host:port` of the target, and
//!   [`Exclusions::matches`] decides there whether the target goes directly. `Custom::call`
//!   ignores a `NoProxy` list, and none is set: the crate's own matcher is the only one, and the
//!   same matcher tells the transport whether a request went through the proxy. `NoProxy` was
//!   not used because any host-name entry in it also matches every name below that name
//!   (`hyper-util` `client/proxy/matcher.rs`, `DomainMatcher::contains`), so it cannot express
//!   an exact host, and the entry `*` matches everything.
//! - The URL the closure returns is parsed by `IntoProxy` and then by `hyper-util`'s
//!   `parse_env_uri` (`matcher.rs`); when either fails, `Custom::call` returns no proxy and the
//!   request goes directly. [`ProxySetting::parse`] therefore admits only URLs built from a fixed
//!   scheme, a host name of letters, digits, `.`, `-` and `_` or an IP literal, a port, and user
//!   info made of unreserved characters and percent escapes, all of which both parsers accept.
//! - Proxy URL schemes: `http` and `https`; `socks5` and `socks5h` with `reqwest`'s `socks`
//!   feature, which pulls in no crate (`reqwest` `Cargo.toml`, `socks = []`; the SOCKS client is
//!   `hyper-util`'s `SocksV5`, part of its `client-proxy` feature that `reqwest` always enables).
//!   The crate enables it only through its own feature `socks`, so that an application without
//!   SOCKS5 proxies does not get it in every `reqwest` client of its build (Cargo unifies
//!   features). Without that feature a `socks5` or `socks5h` URL is still parsed and checked like
//!   any other, credentials included, and then refused with a text that names the feature; the
//!   SOCKS code here stays compiled, as part of that check. `socks4` and `socks4a` are refused in
//!   every build.
//! - An `https://` target behind an HTTP proxy goes through a `CONNECT` tunnel (`hyper-util`
//!   `client/legacy/connect/proxy/tunnel.rs`), and the TLS session with the target runs inside it
//!   with the crate's `ClientConfig`. The TLS connection to an `https://` proxy uses a clone of
//!   the same `ClientConfig` with ALPN cleared (`reqwest` `connect.rs`,
//!   `ConnectorBuilder::new_rustls_tls`): the same provider and verifier, so the proxy's
//!   certificate is checked against the context's trust anchors. An `http://` target is
//!   forwarded in absolute form, with the `Proxy-Authorization` header added to the request
//!   (`async_impl/client.rs`, `proxy_auth`).
//! - Credentials for an HTTP proxy are set with `Proxy::custom_http_auth` and used for both
//!   (`Intercepted::basic_auth` prefers them). `Proxy::basic_auth` is not used: it writes the
//!   password into the proxy URL, which `reqwest` keeps as an ordinary string and prints in its
//!   `Debug`.
//! - Through a SOCKS5 proxy, every target, `http://` and `https://`, is reached through a
//!   SOCKS5 `CONNECT` (`connect.rs`, `connect_socks` and `mod socks`); the TLS session with an
//!   `https://` target runs inside it with the crate's `ClientConfig`, and a plain-HTTP request
//!   is sent in origin form without any proxy header. With `socks5` `reqwest` resolves the target
//!   name itself and sends the proxy an IP address; with `socks5h` it sends the name and the proxy
//!   resolves it (`connect_socks`, `DnsResolve`).
//! - SOCKS5 credentials (RFC 1929) reach `hyper-util` only through the user info of the proxy
//!   URL: `parse_env_uri` percent-decodes it into `Auth::Raw`, `reqwest` passes it to
//!   `SocksV5::with_auth` (`connect.rs`, `raw_auth`). There is no other route. The URL with the
//!   user info lives in this module in a wiped buffer and is handed to `reqwest` as a fresh copy
//!   for every call of the closure; `Intercept`'s `Debug` omits the credentials and its URI has
//!   none (`matcher.rs`); `reqwest` formats no `SocksV5` value (whose derived `Debug` would show
//!   them).
//! - `hyper-util`'s SOCKS5 client writes the whole handshake (method negotiation, the RFC 1929
//!   request and the `CONNECT` request) into one 262-byte buffer and fails when it does not fit
//!   (`socks/v5/mod.rs`, `send_buf`; `socks/v5/messages.rs`, `write_to_buf`). The crate limits
//!   username and password together to [`SOCKS_CREDENTIALS_MAX`] bytes, which leaves room for a
//!   target host name of up to 121 bytes.
//! - A `407` answer to `CONNECT` is `TunnelError::ProxyAuthRequired`; the type sits in a private
//!   module of `hyper-util` and cannot be named, so [`refused_credentials`] compares the error's
//!   text with the library's constant. The `407` body is never read by `hyper-util`. A refusal by
//!   a SOCKS5 proxy is `SocksV5Error::Auth`, also in a private module: `AuthError::Failed` when
//!   the proxy answered the RFC 1929 request with a non-zero status, `AuthError::Unsupported`
//!   when it accepted none of the offered methods (`socks/v5/mod.rs`, `errors.rs`, and
//!   `SocksError`'s `Display` in `socks/mod.rs`). Their texts are constants of the library; the
//!   proxy chooses only a status byte.

use std::net::IpAddr;
use std::sync::Arc;

use base64::Engine as _;
use reqwest::Url;
use reqwest::header::HeaderValue;
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::context::HttpProxy;
use crate::error::Error;
use crate::redact::Detail;

use super::request::sensitive_value;
use super::url::is_loopback_literal;

/// The text of `hyper-util`'s `TunnelError::ProxyAuthRequired` (0.1.21,
/// `client/legacy/connect/proxy/tunnel.rs`, `impl Display for TunnelError`).
const TUNNEL_PROXY_AUTH_REQUIRED: &str = "tunnel error: proxy authorization required";

/// The texts of `hyper-util`'s `SocksError::V5(SocksV5Error::Auth(_))` for a refused password and
/// for a proxy that accepted none of the offered methods (0.1.21,
/// `client/legacy/connect/proxy/socks/mod.rs`, `impl Display for SocksError`, and
/// `socks/v5/errors.rs`, `impl Display for AuthError`).
const SOCKS_AUTH_REFUSED: [&str; 2] = [
    "SOCKS error: credentials not accepted",
    "SOCKS error: server does not support user/pass authentication",
];

/// Most bytes of the SOCKS5 username and password together (see the module documentation).
pub(crate) const SOCKS_CREDENTIALS_MAX: usize = 128;

/// The kind of proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProxyKind {
    /// An HTTP proxy reached over `http://` or `https://`.
    Http,
    /// A SOCKS5 proxy, `socks5://` or `socks5h://`.
    Socks,
}

/// A checked proxy setting.
pub(crate) struct ProxySetting {
    kind: ProxyKind,
    /// True when the host is a loopback IP literal.
    loopback: bool,
    /// True for an `https://` proxy.
    tls: bool,
    /// `Basic <base64(user:password)>` for an HTTP proxy, marked sensitive and built in a wiped
    /// buffer.
    auth: Option<HeaderValue>,
    /// The URL handed to `reqwest`: `scheme://host:port`, with the percent-encoded SOCKS5
    /// credentials as user info when there are any.
    route: Arc<Zeroizing<String>>,
    /// Hosts reached directly.
    exclusions: Arc<Exclusions>,
    /// What every client's scrubber registers: the password and its encoded forms.
    secrets: Vec<Zeroizing<String>>,
}

impl ProxySetting {
    /// Checks `proxy` (design section 5.1). Every refusal is `Error::Config` with a text that
    /// repeats neither the URL, nor a credential, nor an exclusion.
    pub(crate) fn parse(proxy: &HttpProxy, loopback_only: bool) -> Result<ProxySetting, Error> {
        let (url, explicit_port, scheme, kind) = parse_url(&proxy.url)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(config(
                "proxy.url must not contain user info; pass the credentials in proxy.username and proxy.password",
            ));
        }
        let host = match url.host_str().map(host_ref) {
            Some(HostRef::Name(name)) if is_plain_host(name) => name.to_owned(),
            Some(HostRef::Ip(IpAddr::V4(ip))) => ip.to_string(),
            Some(HostRef::Ip(IpAddr::V6(ip))) => format!("[{ip}]"),
            _ => return Err(config("proxy.url is not a valid absolute URL with a host")),
        };
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(config(
                "proxy.url must not contain a path, a query or a fragment",
            ));
        }
        let loopback = is_loopback_literal(&url);
        if loopback_only && !loopback {
            return Err(config(
                "proxy.url is not a loopback IP literal, and the context allows loopback addresses only",
            ));
        }
        let port = match (explicit_port, kind) {
            (Some(port), _) => port,
            (None, ProxyKind::Http) => url
                .port_or_known_default()
                .ok_or_else(|| config("proxy.url is not a valid absolute URL with a host"))?,
            // RFC 1928 section 3; also `reqwest`'s default (`proxy.rs`, `into_proxy`).
            (None, ProxyKind::Socks) => 1080,
        };
        let canonical = format!("{scheme}://{host}:{port}");
        let exclusions = Arc::new(Exclusions::parse(&proxy.exclusions)?);

        let credentials = match (&proxy.username, &proxy.password) {
            (None, None) => None,
            (None, Some(_)) => return Err(config("proxy.password requires proxy.username")),
            (Some(username), password) => {
                if username.is_empty()
                    || username.contains(':')
                    || username.chars().any(char::is_control)
                {
                    return Err(config(
                        "proxy.username must not be empty and must contain no colon and no control characters",
                    ));
                }
                let password = password.as_ref().map(|p| p.expose_secret());
                if password.is_some_and(|p| p.chars().any(char::is_control)) {
                    return Err(config("proxy.password must contain no control characters"));
                }
                Some((username.as_str(), password))
            }
        };
        let (auth, route, secrets) = match (kind, credentials) {
            (_, None) => (None, Zeroizing::new(canonical), Vec::new()),
            (ProxyKind::Http, Some((username, password))) => {
                let (auth, secrets) = basic_credentials(username, password.unwrap_or(""))?;
                (Some(auth), Zeroizing::new(canonical), secrets)
            }
            (ProxyKind::Socks, Some((username, password))) => {
                let (route, secrets) = socks_credentials(scheme, &host, port, username, password)?;
                (None, route, secrets)
            }
        };
        // Last, so that every other problem of a SOCKS5 setting is reported as in a build with
        // the feature.
        if kind == ProxyKind::Socks && !cfg!(feature = "socks") {
            return Err(config(
                "proxy.url uses SOCKS5, which needs the `socks` feature of this crate",
            ));
        }
        Ok(ProxySetting {
            kind,
            loopback,
            tls: scheme == "https",
            auth,
            route: Arc::new(route),
            exclusions,
            secrets,
        })
    }

    /// The `reqwest` proxy for every request of the context.
    pub(crate) fn reqwest(&self) -> reqwest::Proxy {
        let route = self.route.clone();
        let exclusions = self.exclusions.clone();
        let proxy = reqwest::Proxy::custom(move |target: &Url| {
            if exclusions.matches(target) {
                None
            } else {
                Some(route.as_str().to_owned())
            }
        });
        match &self.auth {
            Some(auth) => proxy.custom_http_auth(auth.clone()),
            None => proxy,
        }
    }

    /// The kind of proxy that `url` is reached through, or `None` when it is excluded and
    /// reached directly. The same decision `reqwest` makes through [`ProxySetting::reqwest`].
    pub(crate) fn route_for(&self, url: &Url) -> Option<ProxyKind> {
        (!self.exclusions.matches(url)).then_some(self.kind)
    }

    /// True when the proxy's host is a loopback IP literal.
    pub(crate) fn is_loopback(&self) -> bool {
        self.loopback
    }

    /// True for an `https://` proxy.
    pub(crate) fn is_tls(&self) -> bool {
        self.tls
    }

    /// The secrets every client's scrubber registers.
    pub(crate) fn secrets(&self) -> impl Iterator<Item = &str> {
        self.secrets.iter().map(|s| s.as_str())
    }
}

/// Parses `raw` as a proxy URL: the URL whose host is checked, the port written in `raw` (none
/// when it is absent or the scheme's default), the scheme in lowercase and the kind of proxy.
///
/// The URL parser treats `socks5` as a scheme without special rules: it would keep the host as
/// an opaque string, neither lowercased nor checked as an IP literal. The host of a SOCKS URL is
/// therefore read from the same URL with its scheme replaced by `http`, which gives it the
/// canonical form of an HTTP proxy's host; the port is taken from the original, so that an
/// explicit `:80` is not lost as the `http` default.
fn parse_url(raw: &str) -> Result<(Url, Option<u16>, &'static str, ProxyKind), Error> {
    let invalid = || config("proxy.url is not a valid absolute URL with a host");
    let url = Url::parse(raw).map_err(|_| invalid())?;
    let (scheme, kind) = match url.scheme() {
        "http" => ("http", ProxyKind::Http),
        "https" => ("https", ProxyKind::Http),
        "socks5" => ("socks5", ProxyKind::Socks),
        "socks5h" => ("socks5h", ProxyKind::Socks),
        _ => {
            return Err(config(
                "proxy.url must use http, https, socks5 or socks5h; socks4, socks4a and other schemes are not supported",
            ));
        }
    };
    if kind == ProxyKind::Http {
        let port = url.port();
        return Ok((url, port, scheme, kind));
    }
    // `socks5:///name` has an empty host, which `http:///name` would not show.
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid());
    }
    let trimmed = raw.trim_start();
    let rest = trimmed
        .get(..scheme.len())
        .filter(|written| written.eq_ignore_ascii_case(scheme))
        .and_then(|_| trimmed.get(scheme.len()..))
        .and_then(|rest| rest.strip_prefix("://"))
        .filter(|rest| rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '['))
        .ok_or_else(invalid)?;
    let host_url = Url::parse(&format!("http://{rest}")).map_err(|_| invalid())?;
    Ok((host_url, url.port(), scheme, kind))
}

/// A URL host as written by the URL parser: an IP literal (brackets removed) or a name. In a
/// URL with a special scheme an IPv4 address is always parsed as one, so a name never reads as
/// an address.
fn host_ref(host: &str) -> HostRef<'_> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.parse::<IpAddr>() {
        Ok(ip) => HostRef::Ip(ip),
        Err(_) => HostRef::Name(host),
    }
}

/// True for a host name the proxy URL may carry: ASCII letters (already lowercase in a parsed
/// URL), digits, `.`, `-` and `_`.
fn is_plain_host(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}

/// The `Proxy-Authorization` value for `username` and `password` and the secrets to register.
fn basic_credentials(
    username: &str,
    password: &str,
) -> Result<(HeaderValue, Vec<Zeroizing<String>>), Error> {
    let mut joined = Zeroizing::new(String::with_capacity(username.len() + 1 + password.len()));
    joined.push_str(username);
    joined.push(':');
    joined.push_str(password);
    let mut token = Zeroizing::new(String::new());
    base64::engine::general_purpose::STANDARD.encode_string(joined.as_bytes(), &mut token);
    let header = sensitive_value("Basic ", token.as_bytes())
        .ok_or_else(|| config("the proxy credentials cannot be sent in an HTTP header"))?;
    let mut secrets = vec![token];
    if !password.is_empty() {
        secrets.push(Zeroizing::new(password.to_owned()));
    }
    Ok((header, secrets))
}

/// The proxy URL with the SOCKS5 credentials as user info, and the secrets to register: the
/// password and its percent-encoded form.
fn socks_credentials(
    scheme: &str,
    host: &str,
    port: u16,
    username: &str,
    password: Option<&str>,
) -> Result<(Zeroizing<String>, Vec<Zeroizing<String>>), Error> {
    // RFC 1929 section 2: both fields are 1 to 255 bytes.
    let Some(password) = password.filter(|p| !p.is_empty()) else {
        return Err(config(
            "a SOCKS5 proxy needs both proxy.username and proxy.password, neither empty",
        ));
    };
    if username.len() + password.len() > SOCKS_CREDENTIALS_MAX {
        return Err(config(
            "for a SOCKS5 proxy, proxy.username and proxy.password together must be at most 128 bytes",
        ));
    }
    let user = percent_encode(username);
    let encoded = percent_encode(password);
    let mut route = Zeroizing::new(String::with_capacity(
        scheme.len() + 3 + user.len() + 1 + encoded.len() + 1 + host.len() + 6,
    ));
    route.push_str(scheme);
    route.push_str("://");
    route.push_str(&user);
    route.push(':');
    route.push_str(&encoded);
    route.push('@');
    route.push_str(host);
    route.push(':');
    route.push_str(&port.to_string());
    let mut secrets = vec![Zeroizing::new(password.to_owned())];
    if encoded.as_str() != password {
        secrets.push(encoded);
    }
    Ok((route, secrets))
}

/// `text` with every byte outside the unreserved characters of RFC 3986 (section 2.3)
/// percent-encoded, in a wiped buffer. `hyper-util` decodes it back (`parse_env_uri`).
fn percent_encode(text: &str) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mut out = Zeroizing::new(String::with_capacity(text.len() * 3));
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// One entry of [`HttpProxy::exclusions`].
#[derive(Debug, PartialEq, Eq)]
enum Exclusion {
    /// Exactly this host name, lowercase.
    Host(String),
    /// Every name below this one (`*.example.com`), not the name itself.
    Below(String),
    /// Exactly this IP address.
    Ip(IpAddr),
    /// Every IP address in the block; the host bits of `network` are zero.
    Net { network: IpAddr, prefix: u8 },
}

/// The hosts a context's clients reach directly, bypassing the proxy.
#[derive(Debug, Default)]
pub(crate) struct Exclusions(Vec<Exclusion>);

impl Exclusions {
    /// Checks every entry. A refusal names the entry's position, never its text.
    fn parse(entries: &[String]) -> Result<Exclusions, Error> {
        entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                parse_exclusion(entry).ok_or_else(|| Error::Config {
                    detail: Detail::new(&format!(
                        "proxy.exclusions[{i}] is not a host name, a *. suffix, an IP address or a CIDR block"
                    )),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Exclusions)
    }

    /// True when the host of `url` matches an entry. A host name is compared with the URL's
    /// host as the URL parser wrote it (lowercase, IDNA in A-label form); an IP literal of the
    /// URL with an address or a block. A name is never resolved to compare it with an address.
    pub(crate) fn matches(&self, url: &Url) -> bool {
        let Some(host) = url.host_str().map(host_ref) else {
            return false;
        };
        self.0.iter().any(|entry| match (entry, host) {
            (Exclusion::Host(name), HostRef::Name(host)) => host == name,
            (Exclusion::Below(suffix), HostRef::Name(host)) => host
                .strip_suffix(suffix.as_str())
                .and_then(|label| label.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty()),
            (Exclusion::Ip(ip), HostRef::Ip(host)) => *ip == host,
            (Exclusion::Net { network, prefix }, HostRef::Ip(host)) => {
                mask(host, *prefix) == Some(*network)
            }
            _ => false,
        })
    }
}

#[derive(Clone, Copy)]
enum HostRef<'a> {
    Name(&'a str),
    Ip(IpAddr),
}

/// Parses one exclusion entry under the grammar of [`HttpProxy::exclusions`].
fn parse_exclusion(entry: &str) -> Option<Exclusion> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(Exclusion::Ip(ip));
    }
    if let Some((address, prefix)) = entry.split_once('/') {
        let network = address.parse::<IpAddr>().ok()?;
        let bits = if network.is_ipv4() { 32 } else { 128 };
        // Digits only, no sign and no leading zero; `/0` would match every address.
        if prefix.is_empty()
            || !prefix.bytes().all(|b| b.is_ascii_digit())
            || prefix.starts_with('0')
        {
            return None;
        }
        let prefix = prefix.parse::<u8>().ok().filter(|p| *p <= bits)?;
        // The host bits must be zero, so that the entry reads as the block it matches.
        return (mask(network, prefix) == Some(network))
            .then_some(Exclusion::Net { network, prefix });
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host_name(suffix).map(Exclusion::Below);
    }
    host_name(entry).map(Exclusion::Host)
}

/// `name` in lowercase when it is a host name: labels of 1 to 63 ASCII letters, digits and `-`,
/// not starting or ending with `-`, separated by single dots, at most 253 characters, no
/// leading or trailing dot, and a last label that starts with a letter (so that the URL parser
/// would never read the name as an IPv4 address).
fn host_name(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let valid_label = |label: &&str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let last_is_alpha = labels
        .last()
        .and_then(|l| l.bytes().next())
        .is_some_and(|b| b.is_ascii_alphabetic());
    (labels.iter().all(valid_label) && last_is_alpha).then(|| name.to_ascii_lowercase())
}

/// `ip` with all but the first `prefix` bits cleared; `None` for a prefix longer than the
/// address.
fn mask(ip: IpAddr, prefix: u8) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(v4) => {
            let free = 32u32.checked_sub(u32::from(prefix))?;
            let keep = u32::MAX.checked_shl(free).unwrap_or(0);
            Some(IpAddr::V4((u32::from(v4) & keep).into()))
        }
        IpAddr::V6(v6) => {
            let free = 128u32.checked_sub(u32::from(prefix))?;
            let keep = u128::MAX.checked_shl(free).unwrap_or(0);
            Some(IpAddr::V6((u128::from(v6) & keep).into()))
        }
    }
}

/// True when the source chain of `e` holds the refusal of the proxy credentials by a proxy of
/// `kind`: an HTTP proxy answered `CONNECT` with `407`, or a SOCKS5 proxy refused the username
/// and password or every offered method. Only the library's constant texts are compared; the
/// proxy cannot choose them, since it sends only a status code or a status byte, which the
/// library parses and does not keep as text.
pub(crate) fn refused_credentials(e: &reqwest::Error, kind: ProxyKind) -> bool {
    let refused = |text: &str| match kind {
        ProxyKind::Http => text == TUNNEL_PROXY_AUTH_REQUIRED,
        ProxyKind::Socks => SOCKS_AUTH_REFUSED.contains(&text),
    };
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(e);
    let mut depth = 0;
    while let Some(current) = next {
        depth += 1;
        if depth > 32 {
            return false;
        }
        if refused(&current.to_string()) {
            return true;
        }
        next = match current.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => current.source(),
        };
    }
    false
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::error::ErrorKind;

    fn proxy(url: &str) -> HttpProxy {
        HttpProxy::new(url.to_owned())
    }

    #[test]
    fn accepted_urls_are_canonical() {
        for (raw, canonical, loopback, tls, kind) in [
            (
                "http://127.0.0.1:3128",
                "http://127.0.0.1:3128",
                true,
                false,
                ProxyKind::Http,
            ),
            (
                "http://127.0.0.1:3128/",
                "http://127.0.0.1:3128",
                true,
                false,
                ProxyKind::Http,
            ),
            (
                "https://[::1]:8443",
                "https://[::1]:8443",
                true,
                true,
                ProxyKind::Http,
            ),
            (
                "http://proxy.example.test",
                "http://proxy.example.test:80",
                false,
                false,
                ProxyKind::Http,
            ),
            (
                "HTTPS://Proxy.Example.Test",
                "https://proxy.example.test:443",
                false,
                true,
                ProxyKind::Http,
            ),
            #[cfg(feature = "socks")]
            (
                "socks5://127.0.0.1:1080",
                "socks5://127.0.0.1:1080",
                true,
                false,
                ProxyKind::Socks,
            ),
            #[cfg(feature = "socks")]
            (
                "SOCKS5H://127.1",
                "socks5h://127.0.0.1:1080",
                true,
                false,
                ProxyKind::Socks,
            ),
            #[cfg(feature = "socks")]
            (
                "socks5h://[::1]:9050/",
                "socks5h://[::1]:9050",
                true,
                false,
                ProxyKind::Socks,
            ),
            #[cfg(feature = "socks")]
            (
                "socks5://127.0.0.1:80",
                "socks5://127.0.0.1:80",
                true,
                false,
                ProxyKind::Socks,
            ),
            #[cfg(feature = "socks")]
            (
                "socks5://Socks.Example.Test",
                "socks5://socks.example.test:1080",
                false,
                false,
                ProxyKind::Socks,
            ),
        ] {
            let setting = ProxySetting::parse(&proxy(raw), false).unwrap();
            assert_eq!(setting.route.as_str(), canonical, "{raw}");
            assert_eq!(setting.is_loopback(), loopback, "{raw}");
            assert_eq!(setting.is_tls(), tls, "{raw}");
            assert_eq!(setting.kind, kind, "{raw}");
            assert!(setting.auth.is_none() && setting.secrets().next().is_none());
            // The route parses back to the same proxy, as `reqwest` reads it.
            let reparsed = Url::parse(setting.route.as_str()).unwrap();
            assert_eq!(reparsed.scheme(), canonical.split(':').next().unwrap());
        }
    }

    #[test]
    fn refused_settings_quote_nothing() {
        let canary = "pr0xy-canary";
        for (raw, loopback_only) in [
            ("http://user:pr0xy-canary@127.0.0.1:3128", false),
            ("http://pr0xy-canary@127.0.0.1:3128", false),
            ("http://:pr0xy-canary@127.0.0.1:3128", false),
            ("socks5://user:pr0xy-canary@127.0.0.1:1080", false),
            ("socks5h://pr0xy-canary@127.0.0.1:1080", false),
            ("socks4://pr0xy-canary:1080", false),
            ("socks4a://127.0.0.1:1080", false),
            ("socks://127.0.0.1:1080", false),
            ("socks5:127.0.0.1:1080", false),
            ("socks5:///pr0xy-canary", false),
            ("socks5://127.0.0.1:1080/pr0xy-canary", false),
            ("socks5://pr0xy-canary.example.test:1080", true),
            ("socks5://pr0xy!canary.example.test:1080", false),
            ("ftp://127.0.0.1:21", false),
            ("http://127.0.0.1:3128/pr0xy-canary", false),
            ("http://127.0.0.1:3128?pr0xy-canary", false),
            ("http://127.0.0.1:3128#pr0xy-canary", false),
            ("http://pr0xy$canary.example.test:3128", false),
            ("pr0xy-canary", false),
            ("", false),
            ("http://pr0xy-canary.example.test:3128", true),
            ("http://localhost:3128", true),
        ] {
            let e = ProxySetting::parse(&proxy(raw), loopback_only)
                .err()
                .unwrap_or_else(|| panic!("{raw} was accepted"));
            assert_eq!(e.kind(), ErrorKind::Config, "{raw}");
            let text = format!("{e} {e:?}");
            assert!(text.contains("proxy.url"), "{raw}: {text}");
            assert!(
                !text.contains(canary) && !text.contains("example"),
                "{text}"
            );
        }
    }

    #[test]
    fn credentials_are_checked_and_registered() {
        let password = SecretString::from("pa55: w@rd/+é".to_owned());
        let base = proxy("http://127.0.0.1:3128");
        let setting =
            ProxySetting::parse(&base.clone().with_credentials("u".into(), password), false)
                .unwrap();
        let auth = setting.auth.as_ref().unwrap();
        assert!(auth.is_sensitive());
        let expected = base64::engine::general_purpose::STANDARD.encode("u:pa55: w@rd/+é");
        assert_eq!(auth.to_str().unwrap(), format!("Basic {expected}"));
        let secrets: Vec<&str> = setting.secrets().collect();
        assert_eq!(secrets, [expected.as_str(), "pa55: w@rd/+é"]);
        // The credentials of an HTTP proxy never enter the URL handed to `reqwest`.
        assert_eq!(setting.route.as_str(), "http://127.0.0.1:3128");
        // A user name alone is sent with an empty password; nothing but the token is a secret.
        let mut only_user = base.clone();
        only_user.username = Some("u".into());
        let setting = ProxySetting::parse(&only_user, false).unwrap();
        assert_eq!(setting.secrets().count(), 1);
        for (username, password, key) in [
            (None, Some("cr3d-canary"), "proxy.password requires"),
            (Some(""), Some("cr3d-canary"), "proxy.username"),
            (Some("a:b"), Some("cr3d-canary"), "proxy.username"),
            (Some("a\nb"), Some("cr3d-canary"), "proxy.username"),
            (Some("u"), Some("cr3d-canary\r\n"), "proxy.password"),
            (Some("u"), Some("cr3d-canary\u{7f}"), "proxy.password"),
        ] {
            for url in ["http://127.0.0.1:3128", "socks5://127.0.0.1:1080"] {
                let mut p = proxy(url);
                p.username = username.map(str::to_owned);
                p.password = password.map(|s| SecretString::from(s.to_owned()));
                let e = ProxySetting::parse(&p, false).err().unwrap();
                assert_eq!(e.kind(), ErrorKind::Config);
                let text = format!("{e} {e:?}");
                assert!(text.contains(key), "{text}");
                assert!(!text.contains("canary"), "{text}");
            }
        }
    }

    #[cfg(feature = "socks")]
    #[test]
    fn socks_credentials_go_into_the_route_only() {
        let password = "pa55: w@rd/+é%";
        let setting = ProxySetting::parse(
            &proxy("socks5h://127.0.0.1:1080")
                .with_credentials("us.er~1".into(), SecretString::from(password.to_owned())),
            true,
        )
        .unwrap();
        assert!(setting.auth.is_none());
        let encoded = "pa55%3A%20w%40rd%2F%2B%C3%A9%25";
        assert_eq!(
            setting.route.as_str(),
            format!("socks5h://us.er~1:{encoded}@127.0.0.1:1080")
        );
        let secrets: Vec<&str> = setting.secrets().collect();
        assert_eq!(secrets, [password, encoded]);
        // The route parses as a URL whose user info decodes back to the credentials.
        let reparsed = Url::parse(setting.route.as_str()).unwrap();
        assert_eq!(reparsed.username(), "us.er~1");
        assert_eq!(reparsed.password(), Some(encoded));
        // An unreserved password is its own encoding and registered once.
        let setting = ProxySetting::parse(
            &proxy("socks5://127.0.0.1:1080")
                .with_credentials("u".into(), SecretString::from("plain-Pass_1".to_owned())),
            true,
        )
        .unwrap();
        assert_eq!(setting.secrets().collect::<Vec<_>>(), ["plain-Pass_1"]);
        // RFC 1929 needs a password; the buffer of `hyper-util` bounds the two together.
        let mut only_user = proxy("socks5://127.0.0.1:1080");
        only_user.username = Some("u".into());
        let long = "p".repeat(SOCKS_CREDENTIALS_MAX);
        let fits = "p".repeat(SOCKS_CREDENTIALS_MAX - 1);
        for (p, key) in [
            (only_user.clone(), "both proxy.username and proxy.password"),
            (
                only_user
                    .clone()
                    .with_credentials("u".into(), SecretString::from(String::new())),
                "both proxy.username and proxy.password",
            ),
            (
                only_user
                    .clone()
                    .with_credentials("u".into(), SecretString::from(long)),
                "at most 128 bytes",
            ),
        ] {
            let e = ProxySetting::parse(&p, false).err().unwrap();
            assert_eq!(e.kind(), ErrorKind::Config);
            assert!(e.to_string().contains(key), "{e}");
        }
        assert!(
            ProxySetting::parse(
                &only_user.with_credentials("u".into(), SecretString::from(fits)),
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn exclusion_grammar() {
        let ok = [
            ("api.example.com", Exclusion::Host("api.example.com".into())),
            ("API.Example.COM", Exclusion::Host("api.example.com".into())),
            ("localhost", Exclusion::Host("localhost".into())),
            (
                "xn--bcher-kva.example",
                Exclusion::Host("xn--bcher-kva.example".into()),
            ),
            ("a-1.b2", Exclusion::Host("a-1.b2".into())),
            ("*.example.com", Exclusion::Below("example.com".into())),
            ("*.internal", Exclusion::Below("internal".into())),
            ("127.0.0.1", Exclusion::Ip("127.0.0.1".parse().unwrap())),
            ("::1", Exclusion::Ip("::1".parse().unwrap())),
            ("2001:db8::7", Exclusion::Ip("2001:db8::7".parse().unwrap())),
            (
                "10.0.0.0/8",
                Exclusion::Net {
                    network: "10.0.0.0".parse().unwrap(),
                    prefix: 8,
                },
            ),
            (
                "192.0.2.1/32",
                Exclusion::Net {
                    network: "192.0.2.1".parse().unwrap(),
                    prefix: 32,
                },
            ),
            (
                "fd00::/8",
                Exclusion::Net {
                    network: "fd00::".parse().unwrap(),
                    prefix: 8,
                },
            ),
        ];
        for (entry, expected) in ok {
            assert_eq!(parse_exclusion(entry), Some(expected), "{entry}");
        }
        let long_label = format!("{}.example", "a".repeat(64));
        let long_name = format!("{}example", "abcdefghi.".repeat(25));
        for entry in [
            "",
            " ",
            "*",
            ".",
            "*.",
            ".example.com",
            "example.com.",
            "*example.com",
            "*.*.example.com",
            "a.*.example.com",
            "**.example.com",
            "example..com",
            "-example.com",
            "example-.com",
            "exa_mple.com",
            "exa mple.com",
            " example.com",
            "example.com ",
            "example.com,other.com",
            "example.com:443",
            "https://example.com",
            "bücher.example",
            "1.2.3",
            "127.1",
            "999.0.0.1",
            "example.123",
            "0x7f.1",
            "[::1]",
            "[::1]:443",
            "10.0.0.0/",
            "10.0.0.0/08",
            "10.0.0.0/+8",
            "10.0.0.0/0",
            "::/0",
            "10.0.0.1/8",
            "10.0.0.0/33",
            "fd00::1/8",
            "fd00::/129",
            "example.com/8",
            "10.0.0.0/8/8",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert_eq!(parse_exclusion(entry), None, "{entry:?}");
        }
    }

    #[test]
    fn exclusions_match_hosts_exactly() {
        let list = |entries: &[&str]| {
            Exclusions::parse(&entries.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>()).unwrap()
        };
        let matches = |e: &Exclusions, raw: &str| e.matches(&Url::parse(raw).unwrap());
        let host = list(&["api.example.com"]);
        assert!(matches(&host, "https://api.example.com/x"));
        assert!(matches(&host, "https://API.example.com:8443/x"));
        assert!(!matches(&host, "https://v4.api.example.com/x"));
        assert!(!matches(&host, "https://example.com/x"));
        assert!(!matches(&host, "https://xapi.example.com/x"));
        let below = list(&["*.example.com"]);
        assert!(matches(&below, "https://api.example.com/x"));
        assert!(matches(&below, "https://a.b.example.com/x"));
        assert!(!matches(&below, "https://example.com/x"));
        assert!(!matches(&below, "https://notexample.com/x"));
        assert!(!matches(&below, "https://example.com.evil.test/x"));
        let ips = list(&["127.0.0.1", "::1", "10.0.0.0/8", "fd00::/16"]);
        assert!(matches(&ips, "http://127.0.0.1:8080/x"));
        assert!(matches(&ips, "http://[::1]:8080/x"));
        assert!(matches(&ips, "https://10.200.3.4/x"));
        assert!(matches(&ips, "https://[fd00:1::5]/x"));
        assert!(!matches(&ips, "http://127.0.0.2/x"));
        assert!(!matches(&ips, "https://11.0.0.1/x"));
        assert!(!matches(&ips, "https://[fd01::5]/x"));
        assert!(!matches(&ips, "https://[::ffff:127.0.0.1]/x"));
        // A name is never resolved, and an address entry never matches a name.
        assert!(!matches(&ips, "https://localhost/x"));
        assert!(!matches(&list(&["localhost"]), "http://127.0.0.1/x"));
        // The empty list matches nothing.
        assert!(!matches(
            &Exclusions::default(),
            "https://api.example.com/x"
        ));
        // A refusal names the position only.
        let e = Exclusions::parse(&[
            "ok.example".to_owned(),
            "*.exc-canary".to_owned(),
            "*".to_owned(),
        ])
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Config);
        let text = format!("{e} {e:?}");
        assert!(text.contains("proxy.exclusions[2]"), "{text}");
        assert!(
            !text.contains("canary") && !text.contains("ok.example"),
            "{text}"
        );
    }

    #[test]
    fn routes_follow_the_exclusions() {
        let cases = [
            ("http://127.0.0.1:3128", ProxyKind::Http),
            #[cfg(feature = "socks")]
            ("socks5://127.0.0.1:1080", ProxyKind::Socks),
        ];
        for (raw, kind) in cases {
            let setting = ProxySetting::parse(
                &proxy(raw)
                    .with_exclusions(vec!["127.0.0.1".to_owned(), "*.example.org".to_owned()]),
                false,
            )
            .unwrap();
            let route = |raw: &str| setting.route_for(&Url::parse(raw).unwrap());
            assert_eq!(route("http://127.0.0.1:1/x"), None);
            assert_eq!(route("https://api.example.org/x"), None);
            assert_eq!(route("https://example.org/x"), Some(kind));
            assert_eq!(route("http://[::1]:1/x"), Some(kind));
        }
        let e = ProxySetting::parse(
            &proxy("http://127.0.0.1:3128").with_exclusions(vec!["*".to_owned()]),
            false,
        )
        .err()
        .unwrap();
        assert!(e.to_string().contains("proxy.exclusions[0]"), "{e}");
    }

    /// Without the `socks` feature a SOCKS5 URL is refused with a text naming the feature, after
    /// every other check: a setting that is wrong for another reason gets that reason.
    #[cfg(not(feature = "socks"))]
    #[test]
    fn socks5_needs_the_feature() {
        for raw in [
            "socks5://127.0.0.1:1080",
            "socks5h://[::1]:9050",
            "SOCKS5H://127.1",
        ] {
            for p in [
                proxy(raw),
                proxy(raw)
                    .with_credentials("u".into(), SecretString::from("cr3d-canary".to_owned())),
            ] {
                let e = ProxySetting::parse(&p, true).err().unwrap();
                assert_eq!(e.kind(), ErrorKind::Config, "{raw}");
                let text = format!("{e} {e:?}");
                assert!(text.contains("the `socks` feature"), "{raw}: {text}");
                assert!(!text.contains("canary"), "{text}");
            }
        }
        for (p, key) in [
            (proxy("socks5://u:pw@127.0.0.1:1080"), "user info"),
            (proxy("socks5://127.0.0.1:1080/x"), "a path"),
            (proxy("socks5://192.0.2.1:1080"), "loopback"),
            (
                proxy("socks5://127.0.0.1:1080")
                    .with_credentials("u".into(), SecretString::from(String::new())),
                "both proxy.username and proxy.password",
            ),
        ] {
            let e = ProxySetting::parse(&p, true).err().unwrap();
            assert_eq!(e.kind(), ErrorKind::Config);
            assert!(e.to_string().contains(key), "{e}");
        }
    }

    #[test]
    fn mask_clears_host_bits() {
        assert_eq!(
            mask("10.1.2.3".parse().unwrap(), 8),
            Some("10.0.0.0".parse().unwrap())
        );
        assert_eq!(
            mask("10.1.2.3".parse().unwrap(), 32),
            Some("10.1.2.3".parse().unwrap())
        );
        assert_eq!(
            mask("fd00:1::5".parse().unwrap(), 16),
            Some("fd00::".parse().unwrap())
        );
        assert_eq!(mask("10.1.2.3".parse().unwrap(), 33), None);
        assert_eq!(mask("::1".parse().unwrap(), 129), None);
    }
}
