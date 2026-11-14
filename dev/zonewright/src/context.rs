//! The state shared by all clients of one process (design section 2.8).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;

use crate::error::Error;
use crate::locks::NameLocks;
use crate::redact::Detail;

/// Most characters of [`ContextOptions::user_agent_suffix`].
const USER_AGENT_SUFFIX_MAX: usize = 128;

/// State shared by all clients of one process: the HTTP client, the per-name locks and the
/// process-local memory of the providers that need one. Cheap to clone; clones share the state.
///
/// The application creates one `Context` per process and builds every client from it.
/// Per-name serialization of mutating operations holds between clients that share a `Context`,
/// and not between clients built from different ones.
#[derive(Clone)]
pub struct Context {
    inner: Arc<Inner>,
}

/// The shared state behind a [`Context`].
struct Inner {
    options: ContextOptions,
    /// Per-name locks of all mutating operations (design section 3.3).
    locks: NameLocks,
    /// The HTTP client of every HTTP provider client (design section 5.1).
    #[cfg(feature = "__http")]
    http: crate::http::Transport,
    /// Process-local memory of the acme-dns client (design section 11.3).
    #[cfg(feature = "acme_dns")]
    acme_dns: crate::providers::acme_dns::State,
    /// Zone locks and staged-change marks of the nic.ru client (design section 11.3).
    #[cfg(feature = "nicru")]
    nicru: crate::providers::nicru::State,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("options", &self.inner.options)
            .field("locks", &self.inner.locks)
            .finish_non_exhaustive()
    }
}

impl Context {
    /// Builds the shared state. Fails with [`Error::Config`] when an option is invalid,
    /// including an entry of [`ContextOptions::extra_root_certificates`] that is not a
    /// DER-encoded certificate (checked in builds with an HTTP provider, the only ones that use
    /// it).
    ///
    /// Builds no connection and needs no `tokio` runtime. No process-wide TLS crypto provider is
    /// installed or consulted.
    pub fn new(options: ContextOptions) -> Result<Context, Error> {
        options.validate()?;
        #[cfg(feature = "__http")]
        let http = crate::http::Transport::new(&options)?;
        Ok(Context {
            inner: Arc::new(Inner {
                options,
                locks: NameLocks::new(),
                #[cfg(feature = "__http")]
                http,
                #[cfg(feature = "acme_dns")]
                acme_dns: crate::providers::acme_dns::State::default(),
                #[cfg(feature = "nicru")]
                nicru: crate::providers::nicru::State::default(),
            }),
        })
    }

    /// The options the context was built with. Read by the HTTP transport's URL policy and the
    /// RFC 2136 client.
    #[cfg(any(feature = "__http", feature = "rfc2136"))]
    pub(crate) fn options(&self) -> &ContextOptions {
        &self.inner.options
    }

    /// The HTTP client, shared by every HTTP provider client of this context.
    #[cfg(feature = "__http")]
    pub(crate) fn http(&self) -> &crate::http::Transport {
        &self.inner.http
    }

    /// The per-name locks. A client passes them to the TXT value layer, or takes a lock itself
    /// for a record-level write.
    #[cfg(any(
        feature = "acme_dns",
        feature = "beget",
        feature = "cloud_ru",
        feature = "cloudflare",
        feature = "digitalocean",
        feature = "hetzner",
        feature = "nicru",
        feature = "regru",
        feature = "rfc2136",
        feature = "route53",
        feature = "selectel_v2",
        feature = "timeweb_cloud",
        feature = "vk_cloud",
        feature = "yandex_360",
        feature = "yandex_cloud"
    ))]
    pub(crate) fn locks(&self) -> &NameLocks {
        &self.inner.locks
    }

    /// The acme-dns client's memory.
    #[cfg(feature = "acme_dns")]
    pub(crate) fn acme_dns(&self) -> &crate::providers::acme_dns::State {
        &self.inner.acme_dns
    }

    /// The nic.ru client's zone locks and staged-change marks.
    #[cfg(feature = "nicru")]
    pub(crate) fn nicru(&self) -> &crate::providers::nicru::State {
        &self.inner.nicru
    }
}

/// Options of a [`Context`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContextOptions {
    /// Appended to the user agent: `zonewright/<version> <suffix>`. At most 128 characters,
    /// printable ASCII.
    pub user_agent_suffix: Option<String>,
    /// TCP and TLS connect timeout. Default 10 s.
    pub connect_timeout: Duration,
    /// Limit for one HTTP request from start to the end of the body. Default 30 s.
    pub request_timeout: Duration,
    /// DER-encoded certificates trusted in addition to the platform's roots.
    pub extra_root_certificates: Vec<Vec<u8>>,
    /// Refuse to connect to anything but loopback addresses. For tests. Default false.
    ///
    /// With a [`proxy`](ContextOptions::proxy), the proxy must be a loopback IP literal as well;
    /// the policy for request URLs is unchanged.
    pub loopback_only: bool,
    /// The proxy, HTTP or SOCKS5, every HTTP provider request of the context goes through,
    /// except requests to its [exclusions](HttpProxy::exclusions). Default `None`: requests go
    /// directly to the provider.
    ///
    /// Only this setting configures a proxy. The environment (`HTTP_PROXY`, `HTTPS_PROXY`,
    /// `ALL_PROXY`, `NO_PROXY` and their lowercase forms) and the system proxy configuration are
    /// ignored, with and without it. See [`HttpProxy`] for what is supported and what the proxy
    /// can see.
    ///
    /// The RFC 2136 client (DNS over TCP) and the inspector (DNS over UDP and TCP) do not use it;
    /// they connect to their name servers directly.
    ///
    /// Checked by [`Context::new`] in builds with an HTTP provider, the only ones that use it.
    pub proxy: Option<HttpProxy>,
}

impl Default for ContextOptions {
    fn default() -> ContextOptions {
        ContextOptions {
            user_agent_suffix: None,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            extra_root_certificates: Vec::new(),
            loopback_only: false,
            proxy: None,
        }
    }
}

/// A proxy for the provider requests of a [`Context`] ([`ContextOptions::proxy`]): an HTTP proxy
/// or a SOCKS5 proxy.
///
/// Supported schemes of [`url`](HttpProxy::url): `http`, `https`, `socks5` and `socks5h`.
///
/// Through an HTTP proxy (`http://` or `https://`), a request to an `https://` provider endpoint
/// goes through a `CONNECT` tunnel (RFC 9110 section 9.3.6): the proxy sees the host and port of
/// the endpoint and nothing else; the TLS session with the provider runs inside the tunnel, and
/// the provider's certificate is verified exactly as without a proxy. A request to a plain-HTTP
/// loopback endpoint (tests) is forwarded in absolute form. With `https://`, the connection to
/// the proxy is verified with the context's trust anchors (the platform's and
/// [`ContextOptions::extra_root_certificates`]). With `http://`, the proxy credentials travel to
/// the proxy unencrypted; the provider traffic is still protected by TLS.
///
/// Through a SOCKS5 proxy (RFC 1928), every request, `https://` or plain HTTP, goes through a
/// SOCKS5 `CONNECT`; the TLS session with an `https://` provider runs inside it, verified as
/// without a proxy. With `socks5://` the client resolves the endpoint's host name itself and
/// sends the proxy only the IP address; with `socks5h://` it sends the host name and the proxy
/// resolves it. The connection to a SOCKS5 proxy is not encrypted: the proxy credentials travel
/// in clear text, as RFC 1929 defines them. Without a port, a SOCKS5 proxy is on 1080.
///
/// A request to a plain-HTTP loopback endpoint through a proxy that is not itself on a loopback
/// IP literal is refused, so that plain HTTP never leaves the host.
///
/// Through any proxy, an `https://` endpoint written as an IPv6 literal (`https://[2001:db8::1]`)
/// cannot be reached, and through a `socks5://` proxy neither can a plain-HTTP one: the HTTP
/// stack passes the bracketed address on as a name. Such a request fails with
/// [`Error::Transient`](crate::Error::Transient). Endpoints named by host names and IPv4
/// literals are not affected.
///
/// Every HTTP request of the context goes through the proxy, except requests to the hosts in
/// [`exclusions`](HttpProxy::exclusions), which go directly.
///
/// Refused with [`Error::Config`] by [`Context::new`]: a URL with user info (the credentials go in
/// [`username`](HttpProxy::username) and [`password`](HttpProxy::password)), another scheme
/// (`socks4` and `socks4a` included), a host that is neither an IP literal nor a name of
/// letters, digits, `.`, `-` and `_`, a path, query or fragment, an invalid exclusion, and, with
/// [`ContextOptions::loopback_only`], a host that is not a loopback IP literal. No error text
/// repeats the URL, a credential or an exclusion.
///
/// Credentials, when [`username`](HttpProxy::username) is set, are sent to an HTTP proxy as
/// `Proxy-Authorization: Basic` (RFC 7617), and to a SOCKS5 proxy with the username/password
/// method (RFC 1929), which needs both a username and a password, each not empty, together at
/// most 128 bytes. A proxy that refuses them, or demands credentials that are not configured
/// (`407` from an HTTP proxy; a refused username and password or authentication method from a
/// SOCKS5 proxy), makes the request fail with [`Error::ProxyAuth`](crate::Error::ProxyAuth),
/// which is not retryable. A proxy that refuses to open a tunnel, or cannot be reached, gives
/// [`Error::Transient`](crate::Error::Transient). The password is removed from every error text
/// like a provider credential, and `Debug` shows neither credential.
#[derive(Clone)]
#[non_exhaustive]
pub struct HttpProxy {
    /// `http://host:port`, `https://host:port`, `socks5://host:port` or `socks5h://host:port`;
    /// without a port, 80, 443 or 1080.
    pub url: String,
    /// User name for proxy authentication: not empty, without `:` and control characters.
    pub username: Option<String>,
    /// Password for proxy authentication, without control characters. Requires
    /// [`username`](HttpProxy::username); required with it for a SOCKS5 proxy.
    pub password: Option<SecretString>,
    /// Hosts reached directly, bypassing the proxy. Default empty: every request goes through
    /// the proxy.
    ///
    /// Each entry is one of:
    ///
    /// - a host name, `api.example.com`: exactly that host, not the names below it. Labels of
    ///   ASCII letters, digits and `-`, the last one starting with a letter; no trailing dot;
    ///   letter case does not matter. An internationalized name is written in its A-label form
    ///   (`xn--…`).
    /// - `*.` and a host name, `*.example.com`: every name below `example.com`, not
    ///   `example.com` itself (list it as well if it should go directly too).
    /// - an IP address, `192.0.2.10` or `2001:db8::10` (IPv6 without brackets): exactly that
    ///   address.
    /// - a CIDR block, `10.0.0.0/8` or `fd00::/8`: every address in it. The host bits must be
    ///   zero and the prefix at least 1.
    ///
    /// Nothing else is accepted: no `*` alone, no leading dot, no port, no scheme, no spaces, no
    /// list in one string. An entry is compared with the host of the request URL as it is
    /// written there, for every port; a host name is never resolved to compare it with an
    /// address entry, so `127.0.0.0/8` does not cover `localhost`.
    pub exclusions: Vec<String>,
}

impl HttpProxy {
    /// A proxy without credentials and without exclusions.
    pub fn new(url: String) -> HttpProxy {
        HttpProxy {
            url,
            username: None,
            password: None,
            exclusions: Vec::new(),
        }
    }

    /// The same proxy with credentials.
    #[must_use]
    pub fn with_credentials(mut self, username: String, password: SecretString) -> HttpProxy {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    /// The same proxy with [`exclusions`](HttpProxy::exclusions), replacing any set before.
    #[must_use]
    pub fn with_exclusions(mut self, exclusions: Vec<String>) -> HttpProxy {
        self.exclusions = exclusions;
        self
    }
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A URL with user info is refused by `Context::new`, but `Debug` may run before that:
        // a URL that could carry user info is not shown.
        let url = if self.url.contains('@') {
            "[withheld: the URL contains user info]"
        } else {
            self.url.as_str()
        };
        f.debug_struct("HttpProxy")
            .field("url", &url)
            .field("username", &self.username.as_ref().map(|_| "[set]"))
            .field("password", &self.password.as_ref().map(|_| "[set]"))
            .field("exclusions", &self.exclusions)
            .finish()
    }
}

impl ContextOptions {
    /// Checks what can be checked without the HTTP stack. The texts name the option, never its
    /// value.
    fn validate(&self) -> Result<(), Error> {
        if let Some(suffix) = &self.user_agent_suffix {
            let printable = suffix.bytes().all(|b| (0x20..=0x7e).contains(&b));
            if suffix.is_empty() || suffix.len() > USER_AGENT_SUFFIX_MAX || !printable {
                return Err(config(
                    "user_agent_suffix must be 1 to 128 printable ASCII characters",
                ));
            }
        }
        if self.connect_timeout.is_zero() {
            return Err(config("connect_timeout must be greater than zero"));
        }
        if self.request_timeout.is_zero() {
            return Err(config("request_timeout must be greater than zero"));
        }
        Ok(())
    }
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Context, ContextOptions};
    use crate::error::ErrorKind;

    #[test]
    fn defaults() {
        let options = ContextOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.request_timeout, Duration::from_secs(30));
        assert!(!options.loopback_only);
        let ctx = Context::new(options).unwrap();
        assert_eq!(ctx.inner.locks.len(), 0);
        let _clone = ctx.clone();
    }

    #[test]
    fn invalid_options_are_config_errors_without_the_value() {
        for suffix in ["", "tab\there", "ü", &"a".repeat(129)] {
            let options = ContextOptions {
                user_agent_suffix: Some(suffix.to_owned()),
                ..ContextOptions::default()
            };
            let err = Context::new(options).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config);
            if !suffix.is_empty() {
                assert!(!err.to_string().contains(suffix));
            }
        }
        let ok = ContextOptions {
            user_agent_suffix: Some("app/1.0 (+https://example.org)".to_owned()),
            ..ContextOptions::default()
        };
        assert!(Context::new(ok).is_ok());
        let zero = ContextOptions {
            request_timeout: Duration::ZERO,
            ..ContextOptions::default()
        };
        assert_eq!(Context::new(zero).unwrap_err().kind(), ErrorKind::Config);
    }

    #[test]
    fn context_is_send_sync() {
        fn assert_traits<T: Send + Sync + Clone + 'static>() {}
        assert_traits::<Context>();
    }
}
