//! The explicit HTTP proxy of a context (design section 5.1).
//!
//! `ContextOptions::proxy` is checked here and turned into one `reqwest::Proxy` for every client
//! of the context. Facts from the `reqwest` 0.13.5 source this module relies on:
//!
//! - `ClientBuilder::proxy` sets `auto_sys_proxy = false` (`async_impl/client.rs`), so with the
//!   setting the environment is not read either; `Proxy::all` builds its matcher from the given
//!   URL alone (`proxy.rs`, `into_matcher`), with an empty exclusion list.
//! - Proxy URL schemes: `http` and `https`; `socks4`, `socks4a`, `socks5` and `socks5h` only with
//!   the `socks` feature, which the crate does not enable (`proxy.rs`, the commented-out
//!   `ProxyScheme::parse`, and `connect.rs`, `connect_via_proxy`). Anything else is ignored by
//!   `hyper-util`'s matcher (0.1.21, `client/proxy/matcher.rs`, `parse_env_uri`), which would
//!   send the request directly, so the scheme is checked here.
//! - An `https://` target goes through a `CONNECT` tunnel (`hyper-util`
//!   `client/legacy/connect/proxy/tunnel.rs`), and the TLS session with the target runs inside it
//!   with the crate's `ClientConfig`. The TLS connection to an `https://` proxy uses a clone of the
//!   same `ClientConfig` with ALPN cleared (`connect.rs`, `ConnectorBuilder::new_rustls_tls`):
//!   the same provider and verifier, so the proxy's certificate is checked against the context's
//!   trust anchors. An `http://` target is forwarded in absolute form, with the
//!   `Proxy-Authorization` header added to the request (`async_impl/client.rs`, `proxy_auth`).
//! - Credentials set with `Proxy::custom_http_auth` are used for both (`Intercepted::basic_auth`
//!   prefers them). `Proxy::basic_auth` is not used: it writes the password into the proxy URL,
//!   which `reqwest` keeps as an ordinary string and prints in its `Debug`.
//! - A `407` answer to `CONNECT` is `TunnelError::ProxyAuthRequired`; the type sits in a private
//!   module of `hyper-util` and cannot be named, so [`refused_credentials`] compares the error's
//!   text with the library's constant. The `407` body is never read by `hyper-util`.

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

/// Text of the `Error::Config` of a request whose proxy refused the proxy credentials.
pub(crate) const CREDENTIALS_REFUSED: &str =
    "the proxy refused the proxy credentials (HTTP 407); check proxy.username and proxy.password";

/// The text of `hyper-util`'s `TunnelError::ProxyAuthRequired` (0.1.21,
/// `client/legacy/connect/proxy/tunnel.rs`, `impl Display for TunnelError`).
const TUNNEL_PROXY_AUTH_REQUIRED: &str = "tunnel error: proxy authorization required";

/// A checked proxy setting.
pub(crate) struct ProxySetting {
    /// `scheme://host:port`, nothing else.
    url: String,
    /// True when the host is a loopback IP literal.
    loopback: bool,
    /// True for an `https://` proxy.
    tls: bool,
    /// `Basic <base64(user:password)>`, marked sensitive and built in a wiped buffer.
    auth: Option<HeaderValue>,
    /// What every client's scrubber registers: the password and the base64 credentials.
    secrets: Vec<Zeroizing<String>>,
}

impl ProxySetting {
    /// Checks `proxy` (design section 5.1). Every refusal is `Error::Config` with a fixed text
    /// that repeats neither the URL nor a credential.
    pub(crate) fn parse(proxy: &HttpProxy, loopback_only: bool) -> Result<ProxySetting, Error> {
        let url = Url::parse(&proxy.url)
            .map_err(|_| config("proxy.url is not a valid absolute URL with a host"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(config(
                "proxy.url must not contain user info; pass the credentials in proxy.username and proxy.password",
            ));
        }
        let tls = match url.scheme() {
            "http" => false,
            "https" => true,
            _ => {
                return Err(config(
                    "proxy.url must use http or https; SOCKS and other proxy schemes are not supported",
                ));
            }
        };
        let Some(host) = url.host_str().filter(|h| !h.is_empty()) else {
            return Err(config("proxy.url is not a valid absolute URL with a host"));
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
        let Some(port) = url.port_or_known_default() else {
            return Err(config("proxy.url is not a valid absolute URL with a host"));
        };
        let canonical = format!("{}://{host}:{port}", url.scheme());

        let (auth, secrets) = match (&proxy.username, &proxy.password) {
            (None, None) => (None, Vec::new()),
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
                let password = password.as_ref().map_or("", |p| p.expose_secret());
                if password.chars().any(char::is_control) {
                    return Err(config("proxy.password must contain no control characters"));
                }
                credentials(username, password)?
            }
        };
        Ok(ProxySetting {
            url: canonical,
            loopback,
            tls,
            auth,
            secrets,
        })
    }

    /// The `reqwest` proxy for every request of the context.
    pub(crate) fn reqwest(&self) -> Result<reqwest::Proxy, Error> {
        let proxy = reqwest::Proxy::all(self.url.as_str())
            .map_err(|_| config("the proxy could not be configured"))?;
        Ok(match &self.auth {
            Some(auth) => proxy.custom_http_auth(auth.clone()),
            None => proxy,
        })
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

/// The `Proxy-Authorization` value for `username` and `password` and the secrets to register.
fn credentials(
    username: &str,
    password: &str,
) -> Result<(Option<HeaderValue>, Vec<Zeroizing<String>>), Error> {
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
    Ok((Some(header), secrets))
}

/// True when the source chain of `e` holds `hyper-util`'s refusal of the proxy credentials: the
/// proxy answered `CONNECT` with `407`. Only that library's constant text is compared; the proxy
/// cannot choose it, since the status is parsed and the answer's text is never kept.
pub(crate) fn refused_credentials(e: &reqwest::Error) -> bool {
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(e);
    let mut depth = 0;
    while let Some(current) = next {
        depth += 1;
        if depth > 32 {
            return false;
        }
        if current.to_string() == TUNNEL_PROXY_AUTH_REQUIRED {
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
        for (raw, canonical, loopback, tls) in [
            (
                "http://127.0.0.1:3128",
                "http://127.0.0.1:3128",
                true,
                false,
            ),
            (
                "http://127.0.0.1:3128/",
                "http://127.0.0.1:3128",
                true,
                false,
            ),
            ("https://[::1]:8443", "https://[::1]:8443", true, true),
            (
                "http://proxy.example.test",
                "http://proxy.example.test:80",
                false,
                false,
            ),
            (
                "HTTPS://Proxy.Example.Test",
                "https://proxy.example.test:443",
                false,
                true,
            ),
        ] {
            let setting = ProxySetting::parse(&proxy(raw), false).unwrap();
            assert_eq!(setting.url, canonical, "{raw}");
            assert_eq!(setting.is_loopback(), loopback, "{raw}");
            assert_eq!(setting.is_tls(), tls, "{raw}");
            assert!(setting.auth.is_none() && setting.secrets().next().is_none());
            assert!(setting.reqwest().is_ok());
        }
    }

    #[test]
    fn refused_settings_quote_nothing() {
        let canary = "pr0xy-canary";
        for (raw, loopback_only) in [
            ("http://user:pr0xy-canary@127.0.0.1:3128", false),
            ("http://pr0xy-canary@127.0.0.1:3128", false),
            ("http://:pr0xy-canary@127.0.0.1:3128", false),
            ("socks5://pr0xy-canary:1080", false),
            ("socks5h://127.0.0.1:1080", false),
            ("ftp://127.0.0.1:21", false),
            ("http://127.0.0.1:3128/pr0xy-canary", false),
            ("http://127.0.0.1:3128?pr0xy-canary", false),
            ("http://127.0.0.1:3128#pr0xy-canary", false),
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
            let mut p = base.clone();
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
