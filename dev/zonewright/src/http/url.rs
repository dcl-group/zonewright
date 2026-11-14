//! URL policy and URL building (design sections 5.1 and 5.2).
//!
//! Every configurable endpoint (`*_url` settings) passes [`Endpoint::parse`] in the client's
//! constructor. Request URLs are built from an endpoint with [`UrlBuilder`], which percent-encodes
//! path segments and query values and checks identifiers taken from provider answers. A URL
//! returned by a provider is never requested.
//!
//! A secret is never part of a URL, neither path nor query: the transport writes the path to
//! `tracing`, and a URL is easily logged by whoever handles it.

use std::net::IpAddr;

use reqwest::Url;

use crate::context::Context;
use crate::error::Error;
use crate::redact::Detail;

use super::encode::percent;

/// Longest identifier accepted in a URL path.
const ID_MAX: usize = 128;

/// True when `url`'s host is a loopback IP literal: `127.0.0.0/8` or `[::1]`. Host names,
/// `localhost` included, are not, and neither are IPv4-mapped IPv6 addresses.
pub(crate) fn is_loopback_literal(url: &Url) -> bool {
    // The URL parser has already put an IP literal into its canonical form ("127.1" becomes
    // "127.0.0.1"); an IPv6 literal keeps its brackets.
    url.host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|ip| match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        })
}

/// A provider endpoint that passed the URL policy: the base of the request URLs of one API.
///
/// The policy: `https` is always accepted; `http` only when the host is a loopback IP literal
/// (`127.0.0.0/8`, `[::1]`); host names, `localhost` included, and private addresses require
/// `https`. A URL with user info, a query or a fragment is refused. With
/// `ContextOptions::loopback_only`, a URL whose host is not a loopback literal is refused
/// whatever its scheme. A trailing `/` is removed from the path.
///
/// Error texts name the setting, never its value: a URL refused for its user info would
/// otherwise repeat the password in it.
#[derive(Clone)]
pub(crate) struct Endpoint {
    base: Url,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A validated endpoint has no user info and no query; it is safe to show.
        f.debug_tuple("Endpoint")
            .field(&self.base.as_str())
            .finish()
    }
}

impl Endpoint {
    /// Applies the URL policy to the value of the setting `key`, with the context's
    /// `loopback_only` option.
    pub(crate) fn parse(key: &'static str, raw: &str, ctx: &Context) -> Result<Endpoint, Error> {
        Endpoint::parse_with(key, raw, ctx.options().loopback_only)
    }

    /// [`Endpoint::parse`] with the `loopback_only` option given directly.
    pub(crate) fn parse_with(
        key: &'static str,
        raw: &str,
        loopback_only: bool,
    ) -> Result<Endpoint, Error> {
        let refuse = |why: PolicyError| Error::Config {
            detail: Detail::new(&format!("{key} {}", why.text())),
        };
        let mut url = Url::parse(raw).map_err(|_| refuse(PolicyError::Invalid))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(refuse(PolicyError::UserInfo));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(refuse(PolicyError::QueryOrFragment));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(refuse(PolicyError::Invalid));
        }
        let loopback = is_loopback_literal(&url);
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err(refuse(PolicyError::Scheme)),
        }
        if loopback_only && !loopback {
            return Err(refuse(PolicyError::NotLoopback));
        }
        let path = url.path().trim_end_matches('/').to_owned();
        url.set_path(&path);
        Ok(Endpoint { base: url })
    }

    /// A builder for a request URL below this endpoint.
    pub(crate) fn url(&self) -> UrlBuilder {
        UrlBuilder {
            base: self.base.clone(),
            path: self.base.path().trim_end_matches('/').to_owned(),
            query: String::new(),
            error: None,
        }
    }

    /// The endpoint itself as a URL, for a setting that names one resource (a token URL).
    pub(crate) fn as_url(&self) -> &Url {
        &self.base
    }
}

/// Why [`Endpoint::parse`] refused a URL. The texts follow the setting's key.
#[derive(Clone, Copy)]
enum PolicyError {
    Invalid,
    UserInfo,
    QueryOrFragment,
    Scheme,
    NotLoopback,
}

impl PolicyError {
    fn text(self) -> &'static str {
        match self {
            PolicyError::Invalid => "is not a valid absolute URL with a host",
            PolicyError::UserInfo => "must not contain user info",
            PolicyError::QueryOrFragment => "must not contain a query or a fragment",
            PolicyError::Scheme => {
                "must use https; http is accepted only for a loopback IP literal (127.0.0.0/8, [::1])"
            }
            PolicyError::NotLoopback => {
                "is not a loopback IP literal, and the context allows loopback addresses only"
            }
        }
    }
}

/// Checks an identifier taken from a provider's answer before it goes into a URL path: it must
/// match `[A-Za-z0-9_-]{1,128}`. Anything else is `Error::Protocol`, so that an identifier cannot
/// change the path (`..`, `/`) or add a query.
pub(crate) fn path_id(id: &str) -> Result<&str, Error> {
    let ok = !id.is_empty()
        && id.len() <= ID_MAX
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(id)
    } else {
        Err(Error::Protocol {
            detail: Detail::constant("the provider returned an identifier of an unexpected form"),
        })
    }
}

/// Builds one request URL below an [`Endpoint`].
///
/// Path pieces are appended in order. The first piece that cannot be used makes [`build`] fail;
/// the methods themselves never fail, so a URL is written as one chain.
///
/// [`build`]: UrlBuilder::build
#[must_use]
pub(crate) struct UrlBuilder {
    base: Url,
    path: String,
    query: String,
    error: Option<Error>,
}

impl UrlBuilder {
    /// Appends a fixed path written in the client's source, such as `/zones`, `/v2/zones/` or
    /// `:upsertRecordSets`. It is appended as it is: it must start with `/` or `:` and contain
    /// only characters a path may carry unencoded (RFC 3986 `pchar` without `%`, and `/`).
    pub(crate) fn path(mut self, literal: &'static str) -> UrlBuilder {
        let usable = (literal.starts_with('/') || literal.starts_with(':'))
            && literal
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&b));
        if usable {
            self.path.push_str(literal);
        } else {
            self.fail(Error::InvalidInput {
                detail: Detail::constant(
                    "a fixed URL path contains a character that needs encoding",
                ),
            });
        }
        self
    }

    /// Appends `/` and `segment`, percent-encoded. An empty segment and the dot segments `.`
    /// and `..` are refused (`Error::InvalidInput`).
    pub(crate) fn segment(mut self, segment: &str) -> UrlBuilder {
        if segment.is_empty() || segment == "." || segment == ".." {
            self.fail(Error::InvalidInput {
                detail: Detail::constant("a URL path segment is empty or a dot segment"),
            });
        } else {
            self.path.push('/');
            self.path.push_str(&percent(segment));
        }
        self
    }

    /// Appends `/` and an identifier taken from a provider's answer, checked by [`path_id`].
    pub(crate) fn id(mut self, id: &str) -> UrlBuilder {
        match path_id(id) {
            Ok(id) => {
                self.path.push('/');
                self.path.push_str(id);
            }
            Err(e) => self.fail(e),
        }
        self
    }

    /// Appends the query parameter `key=value`, with `value` percent-encoded. Never a secret.
    pub(crate) fn query(mut self, key: &'static str, value: &str) -> UrlBuilder {
        if !self.query.is_empty() {
            self.query.push('&');
        }
        self.query.push_str(&percent(key));
        self.query.push('=');
        self.query.push_str(&percent(value));
        self
    }

    /// The URL, or the error of the first piece that could not be used.
    pub(crate) fn build(self) -> Result<Url, Error> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let mut url = self.base;
        // Every piece is already encoded with unreserved characters, `%XX` and `/` only, which
        // the URL parser keeps as they are; it cannot introduce a dot segment either.
        url.set_path(&self.path);
        url.set_query((!self.query.is_empty()).then_some(self.query.as_str()));
        Ok(url)
    }

    fn fail(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn parse(raw: &str) -> Result<Endpoint, Error> {
        Endpoint::parse_with("base_url", raw, false)
    }

    #[test]
    fn https_always_http_only_on_loopback_literals() {
        for ok in [
            "https://api.example.org",
            "https://api.example.org/v4/",
            "https://10.0.0.1",
            "https://localhost:8443/x",
            "http://127.0.0.1:8080/x",
            "http://127.1.2.3",
            "http://[::1]:9",
        ] {
            assert!(parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://10.0.0.1",
            "http://192.168.1.10:8080",
            "http://172.16.0.1",
            "http://[fd00::1]",
            "http://[::ffff:127.0.0.1]",
            "http://localhost",
            "http://auth.example.org",
            "ftp://127.0.0.1",
            "file:///etc/passwd",
            "not a url",
            "",
        ] {
            let e = parse(bad).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config, "{bad}");
            assert!(e.to_string().contains("base_url"), "{bad}: {e}");
        }
    }

    #[test]
    fn user_info_query_and_fragment_are_refused_without_the_value() {
        for (bad, secret) in [
            (
                "https://user:hunter2-canary@api.example.org/v1",
                "hunter2-canary",
            ),
            ("https://token-canary@api.example.org", "token-canary"),
            (
                "https://api.example.org/v1?key=query-canary",
                "query-canary",
            ),
            ("https://api.example.org/v1#frag-canary", "frag-canary"),
            ("https://api.example.org/v1?", "?"),
        ] {
            let e = parse(bad).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config, "{bad}");
            for text in [e.to_string(), format!("{e:?}")] {
                assert!(!text.contains(secret), "{text}");
                assert!(!text.contains("api.example.org"), "{text}");
            }
        }
    }

    #[test]
    fn loopback_only_refuses_everything_else() {
        for ok in ["http://127.0.0.1:1/x", "https://[::1]:443"] {
            assert!(Endpoint::parse_with("base_url", ok, true).is_ok(), "{ok}");
        }
        for bad in [
            "https://api.example.org",
            "https://localhost",
            "https://10.0.0.1",
        ] {
            let e = Endpoint::parse_with("base_url", bad, true).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config);
            assert!(e.to_string().contains("loopback"), "{e}");
            assert!(!e.to_string().contains("example"), "{e}");
        }
    }

    #[test]
    fn urls_are_built_with_encoded_pieces() {
        let ep = parse("https://api.example.org/client/v4/").unwrap();
        let url = ep
            .url()
            .path("/zones")
            .id("023e105f4ecef8ad9ca31a8372d0c353")
            .path("/dns_records")
            .segment("_acme-challenge.пример.рф")
            .query("name", "a b&c=d/e")
            .query("page", "2")
            .build()
            .unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.example.org/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353\
             /dns_records/_acme-challenge.%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.%D1%80%D1%84\
             ?name=a%20b%26c%3Dd%2Fe&page=2"
        );
        assert_eq!(url.path_segments().unwrap().count(), 6);
        let root = parse("https://api.example.org/").unwrap();
        assert_eq!(
            root.url().path("/x").build().unwrap().as_str(),
            "https://api.example.org/x"
        );
        assert_eq!(
            root.url().build().unwrap().as_str(),
            "https://api.example.org/"
        );
        assert_eq!(root.as_url().as_str(), "https://api.example.org/");
    }

    #[test]
    fn unusable_pieces_fail_the_build() {
        let ep = parse("https://api.example.org/v1").unwrap();
        for builder in [
            ep.url().segment(""),
            ep.url().segment("."),
            ep.url().segment(".."),
            ep.url().path("zones"),
            ep.url().path("/zones%2F"),
            ep.url().path("/zones#x"),
            ep.url().path("/zones?x=1"),
            ep.url().path("/a b"),
        ] {
            assert_eq!(builder.build().unwrap_err().kind(), ErrorKind::InvalidInput);
        }
        let action = ep
            .url()
            .path("/zones")
            .id("abc")
            .path(":upsertRecordSets")
            .build();
        assert_eq!(action.unwrap().path(), "/v1/zones/abc:upsertRecordSets");
        let traversal = ep.url().path("/zones").id("../admin").build().unwrap_err();
        assert_eq!(traversal.kind(), ErrorKind::Protocol);
        // A segment that merely contains dots or slashes is encoded, not refused.
        let url = ep.url().segment("../x").segment("a.b").build().unwrap();
        assert_eq!(url.path(), "/v1/..%2Fx/a.b");
    }

    #[test]
    fn path_id_accepts_only_the_safe_form() {
        assert!(path_id("023e105f4ecef8ad9ca31a8372d0c353").is_ok());
        assert!(path_id("a_b-C9").is_ok());
        assert!(path_id(&"a".repeat(128)).is_ok());
        for bad in ["", "../zones", "a?b", "a/b", "a b", "ключ", "a.b", "a%2F"] {
            assert_eq!(
                path_id(bad).unwrap_err().kind(),
                ErrorKind::Protocol,
                "{bad}"
            );
        }
        assert!(path_id(&"a".repeat(129)).is_err());
    }

    #[test]
    fn loopback_literals() {
        for (raw, loopback) in [
            ("http://127.0.0.1/", true),
            ("http://127.255.0.9/", true),
            ("http://[::1]/", true),
            ("http://localhost/", false),
            ("http://[::ffff:127.0.0.1]/", false),
            ("http://10.0.0.1/", false),
        ] {
            assert_eq!(
                is_loopback_literal(&Url::parse(raw).unwrap()),
                loopback,
                "{raw}"
            );
        }
    }
}
