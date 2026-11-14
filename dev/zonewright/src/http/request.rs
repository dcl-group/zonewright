//! Requests, responses and secret header values (design sections 5.2 and 5.4).

use std::borrow::Cow;
use std::fmt;

use bytes::Bytes;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::redact::Detail;

use super::encode;

/// Largest response body the transport reads, error bodies included.
pub(crate) const BODY_LIMIT: usize = 4 * 1024 * 1024;

/// The text of the error for a body over [`BODY_LIMIT`].
pub(crate) const BODY_TOO_LARGE: &str = "the response body exceeds the limit of 4 MiB";

/// A header value that carries a secret: built in a zeroizing buffer that the value refers to
/// without a copy, and marked sensitive, so that `Debug` of the value and of any request that
/// carries it prints no secret.
///
/// `RequestBuilder::bearer_auth` and `basic_auth` are not used: they build the value with an
/// ordinary `format!`, which leaves a copy of the secret in memory that is never wiped.
pub(crate) fn sensitive_value(prefix: &str, secret: &[u8]) -> Option<HeaderValue> {
    let mut buf = Zeroizing::new(Vec::with_capacity(prefix.len() + secret.len()));
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(secret);
    let mut value = HeaderValue::from_maybe_shared(encode::wiped(buf)).ok()?;
    value.set_sensitive(true);
    Some(value)
}

/// `Basic` credentials for an `Authorization` header: `base64(user ":" password)`, in a
/// zeroizing buffer of exactly its length.
pub(crate) fn basic_credentials(user: &str, password: &str) -> Zeroizing<String> {
    use base64::Engine as _;
    let mut plain = Zeroizing::new(Vec::with_capacity(user.len() + 1 + password.len()));
    plain.extend_from_slice(user.as_bytes());
    plain.push(b':');
    plain.extend_from_slice(password.as_bytes());
    let len = base64::encoded_len(plain.len(), true).unwrap_or(0);
    let mut out = Zeroizing::new(vec![0u8; len]);
    let written = base64::engine::general_purpose::STANDARD
        .encode_slice(&*plain, &mut out)
        .unwrap_or(0);
    out.truncate(written);
    // Base64 output is ASCII.
    let text = String::from_utf8(std::mem::take(&mut *out)).unwrap_or_default();
    Zeroizing::new(text)
}

/// How a token from a [`TokenSource`](super::token::TokenSource) is sent: the header and the
/// text before the token.
#[derive(Clone, Debug)]
pub(crate) struct TokenAuth {
    name: HeaderName,
    prefix: &'static str,
}

impl TokenAuth {
    /// `Authorization: Bearer <token>`.
    pub(crate) const BEARER: TokenAuth = TokenAuth {
        name: AUTHORIZATION,
        prefix: "Bearer ",
    };

    /// The token in header `name` after `prefix`. Use a `const` header name
    /// (`HeaderName::from_static` in a `const` is checked at compile time).
    pub(crate) const fn new(name: HeaderName, prefix: &'static str) -> TokenAuth {
        TokenAuth { name, prefix }
    }

    /// The header for `token`, or `Error::Protocol` when the provider issued a token that is not
    /// a valid header value.
    pub(crate) fn header(&self, token: &str) -> Result<(HeaderName, HeaderValue), Error> {
        let value = sensitive_value(self.prefix, token.as_bytes()).ok_or(Error::Protocol {
            detail: Detail::constant(
                "the provider issued a token that is not a valid header value",
            ),
        })?;
        Ok((self.name.clone(), value))
    }
}

/// Which credential a request carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthMode {
    /// The client's static credential header, if the client has one.
    Client,
    /// None: for token endpoints and APIs that authenticate in the body.
    Anonymous,
}

/// One HTTP request as a client describes it. The transport builds a fresh `reqwest` request
/// from it for every attempt; the body is shared, not copied.
///
/// `Debug` shows the method and the URL path only.
pub(crate) struct Request {
    pub(super) method: Method,
    pub(super) url: Url,
    pub(super) idempotent: bool,
    pub(super) accept: &'static str,
    pub(super) headers: Vec<(HeaderName, HeaderValue)>,
    pub(super) body: Option<(&'static str, Bytes)>,
    pub(super) auth: AuthMode,
    pub(super) keep: Vec<u16>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.url.path())
            .field("idempotent", &self.idempotent)
            .finish_non_exhaustive()
    }
}

impl Request {
    /// A request that is sent once: whatever goes wrong becomes the operation's error. Mark it
    /// [`idempotent`](Request::idempotent) when executing it twice leaves the same state as
    /// executing it once and an automatic repeat is wanted (design section 5.3).
    pub(crate) fn new(method: Method, url: Url) -> Request {
        Request {
            method,
            url,
            idempotent: false,
            accept: encode::JSON,
            headers: Vec::new(),
            body: None,
            auth: AuthMode::Client,
            keep: Vec::new(),
        }
    }

    /// A `GET` request, idempotent.
    pub(crate) fn get(url: Url) -> Request {
        Request::new(Method::GET, url).idempotent()
    }

    /// Marks the request idempotent: it is retried after a connection error, a timeout, a 5xx
    /// answer and a 429 answer, at most three attempts in all.
    pub(crate) fn idempotent(mut self) -> Request {
        self.idempotent = true;
        self
    }

    /// The `Accept` header; `application/json` by default.
    pub(crate) fn accept(mut self, media_type: &'static str) -> Request {
        self.accept = media_type;
        self
    }

    /// Adds a header that carries no secret.
    pub(crate) fn header(mut self, name: HeaderName, value: HeaderValue) -> Request {
        self.headers.push((name, value));
        self
    }

    /// Adds a header that carries no secret, from text. A value that is not a valid header value
    /// is `Error::InvalidInput`.
    pub(crate) fn header_text(self, name: HeaderName, value: &str) -> Result<Request, Error> {
        let value = HeaderValue::from_str(value).map_err(|_| Error::InvalidInput {
            detail: Detail::constant("a request header value contains a character it cannot carry"),
        })?;
        Ok(self.header(name, value))
    }

    /// Adds a header that carries a secret computed per request (a signature, a session
    /// token): built in a zeroizing buffer and marked sensitive. `prefix` comes before the
    /// secret. The caller registers the secret with the client's scrubber if it can be echoed.
    pub(crate) fn secret_header(
        self,
        name: HeaderName,
        prefix: &str,
        secret: &str,
    ) -> Result<Request, Error> {
        let value = sensitive_value(prefix, secret.as_bytes()).ok_or(Error::InvalidInput {
            detail: Detail::constant("a secret header value contains a character it cannot carry"),
        })?;
        Ok(self.header(name, value))
    }

    /// Sends no credential header, for token endpoints and APIs that authenticate in the body.
    pub(crate) fn anonymous(mut self) -> Request {
        self.auth = AuthMode::Anonymous;
        self
    }

    /// A body of `content_type`. A body that carries a secret comes from
    /// [`encode::wiped`] or [`encode::wiped_text`].
    pub(crate) fn body(mut self, content_type: &'static str, body: Bytes) -> Request {
        self.body = Some((content_type, body));
        self
    }

    /// A JSON body, encoded into a zeroizing buffer ([`encode::json`]).
    pub(crate) fn json<T: Serialize + ?Sized>(self, value: &T) -> Result<Request, Error> {
        Ok(self.body(encode::JSON, encode::json(value)?))
    }

    /// A form body, encoded into a zeroizing buffer ([`encode::form`]).
    pub(crate) fn form(self, pairs: &[(&str, &str)]) -> Request {
        self.body(encode::FORM, encode::wiped_text(encode::form(pairs)))
    }

    /// Returns an answer with `status` to the caller as it is, instead of the shared mapping
    /// (401 `Auth`, 403 `Forbidden`, 429 rate limit, 3xx refused redirect, 5xx `Transient` with
    /// retries). For a client that documents an exception to that mapping.
    pub(crate) fn keep_status(mut self, status: u16) -> Request {
        self.keep.push(status);
        self
    }

    /// The URL path, for `tracing`: never the query string.
    pub(crate) fn path(&self) -> &str {
        self.url.path()
    }
}

/// An HTTP answer that the transport did not turn into an error: any status the shared mapping
/// leaves to the client (2xx, 4xx other than 401, 403 and 429, and those kept with
/// [`Request::keep_status`]), with its whole body (at most [`BODY_LIMIT`]).
///
/// `Debug` shows the status only.
pub(crate) struct Response {
    pub(super) status: u16,
    pub(super) headers: HeaderMap,
    pub(super) body: Bytes,
    pub(super) attempt: u32,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Response {
    /// The HTTP status.
    pub(crate) fn status(&self) -> u16 {
        self.status
    }

    /// The attempt that produced this answer, from 1. Above 1, earlier attempts of the same
    /// request got no usable answer and may have been executed: a repeated delete by identifier
    /// answered "not found" is a success (design section 5.3).
    pub(crate) fn attempt(&self) -> u32 {
        self.attempt
    }

    /// True for 2xx.
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The value of header `name` as text, if present and visible ASCII.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The body.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body as text, with invalid UTF-8 replaced. Text that leaves the crate goes through
    /// the client's scrubber first.
    pub(crate) fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// The body parsed as JSON into `T`. A body that does not parse is `Error::Protocol` with
    /// the constant text `what` (for example "the zone listing is not in the expected form");
    /// the parser's message is not used, because it can quote the body.
    pub(crate) fn json<T: DeserializeOwned>(&self, what: &'static str) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(|_| Error::Protocol {
            detail: Detail::constant(what),
        })
    }
}

/// Extracts the provider's error message from a response body. A client with a known error
/// shape passes its own to `HttpBuilder::message`.
pub(crate) type MessageFn = fn(&str) -> Option<String>;

/// The default message extractor: the first string found in a JSON body under one of the field
/// names APIs commonly use (`message`, `error_description`, `error`, `detail`, `description`,
/// `error_text`, `errors[0].message`, `error.message`). `None` when the body is not JSON or has
/// none of them; the start of the body is used then.
pub(crate) fn default_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let direct = [
        "message",
        "error_description",
        "error",
        "detail",
        "description",
        "error_text",
    ];
    direct
        .iter()
        .find_map(|key| value.get(key).and_then(|v| v.as_str()))
        .or_else(|| {
            value
                .get("errors")
                .and_then(|e| e.get(0))
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
        })
        .or_else(|| {
            value
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_values_are_hidden_and_wiped_buffers() {
        let value = sensitive_value("Bearer ", b"tok-canary").unwrap();
        assert!(value.is_sensitive());
        assert_eq!(value.to_str().unwrap(), "Bearer tok-canary");
        assert!(!format!("{value:?}").contains("tok-canary"));
        assert!(sensitive_value("", b"bad\nvalue").is_none());
        let (name, value) = TokenAuth::BEARER.header("t-1").unwrap();
        assert_eq!(name, AUTHORIZATION);
        assert!(value.is_sensitive());
        assert!(TokenAuth::BEARER.header("bad\r\nx").is_err());
    }

    #[test]
    fn basic_credentials_are_base64() {
        // RFC 7617 section 2's example.
        assert_eq!(
            basic_credentials("Aladdin", "open sesame").as_str(),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(basic_credentials("", "").as_str(), "Og==");
    }

    #[test]
    fn request_debug_shows_no_secret() {
        let url = Url::parse("http://127.0.0.1:1/zones?key=query-canary").unwrap();
        let req = Request::new(Method::POST, url)
            .secret_header(AUTHORIZATION, "Bearer ", "header-canary")
            .unwrap()
            .form(&[("password", "body-canary")]);
        let debug = format!("{req:?}");
        for canary in ["query-canary", "header-canary", "body-canary"] {
            assert!(!debug.contains(canary), "{debug}");
        }
        assert!(debug.contains("/zones"));
        assert!(!req.idempotent);
        assert!(Request::get(Url::parse("http://127.0.0.1/").unwrap()).idempotent);
    }

    #[test]
    fn default_message_reads_common_fields() {
        for (body, expected) in [
            (r#"{"message":"m"}"#, Some("m")),
            (r#"{"error":"e","error_description":"d"}"#, Some("d")),
            (
                r#"{"errors":[{"code":7,"message":"first"}]}"#,
                Some("first"),
            ),
            (r#"{"error":{"code":1,"message":"nested"}}"#, Some("nested")),
            (r#"{"other":"x"}"#, None),
            ("<Error><Message>x</Message></Error>", None),
            ("plain", None),
        ] {
            assert_eq!(default_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn response_json_failure_is_a_constant_protocol_error() {
        let response = Response {
            status: 200,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{\"secret\": \"body-canary\""),
            attempt: 1,
        };
        let e = response
            .json::<serde_json::Value>("the answer is not in the expected form")
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "unexpected provider response: the answer is not in the expected form"
        );
        assert!(!format!("{response:?}").contains("canary"));
    }
}
