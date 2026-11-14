//! The echo server of the secret tests.
//!
//! It behaves like a provider API that quotes the request back in its error messages: every
//! request is answered with a chosen status and a body that repeats the request — method, path,
//! query, every header (credentials included) and the body — inside the fields a client reads
//! error text from. A client under test must keep all of it out of its errors, `Debug` output and
//! logs.
//!
//! Requests under the token path (by default [`DEFAULT_TOKEN_PATH`]) are instead answered `201`
//! with a canary token in the shapes token endpoints use, so that clients which exchange
//! credentials for a token get past authentication and reach the API, where the echo then repeats
//! the issued token as well.
//!
//! What is echoed, and how, is chosen per server:
//!
//! - the renderer ([`Render`]) decides the body format: a flat JSON object ([`json()`]), JSON with
//!   `\/` and `\uXXXX` escapes ([`json_ascii`]), XML from a template ([`xml`]) or plain text
//!   ([`text`]); a provider test can pass its own closure for the provider's exact error envelope,
//!   and choose a different renderer per path prefix;
//! - the spelling ([`Spelling`]) transforms the echoed text first: verbatim, or form-urlencoded
//!   with `+` or with `%20` for a space.
//!
//! Together these produce every spelling the client's redaction must recognize. The server is an
//! ordinary [`MockServer`], so its request log shows that the endpoints were reached and its fault
//! queue works as usual.

use std::fmt;
use std::fmt::Write as _;
use std::ops::Deref;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::MockServer;

/// Default path prefix of the token endpoint.
pub const DEFAULT_TOKEN_PATH: &str = "/echo-token";

/// Default token handed out by the token endpoint. It contains a space, `/`, `+` and `@`, so that
/// every encoding changes it.
pub const DEFAULT_ISSUED_TOKEN: &str = "echo-issued token/canary+1@mock";

/// Expiry stated in the default token response, far in the future.
const TOKEN_EXPIRES_AT: &str = "2099-01-01T00:00:00Z";

/// One request as the renderer sees it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Echoed {
    /// Status the echo answers with.
    pub status: StatusCode,
    /// Request method.
    pub method: Method,
    /// URL path.
    pub path: String,
    /// Raw query string, if any.
    pub query: Option<String>,
    /// Every request header as `(name, value)`, values decoded lossily as UTF-8.
    pub headers: Vec<(String, String)>,
    /// The request body, decoded lossily as UTF-8.
    pub body: String,
    /// All of the above in one text, after the server's [`Spelling`] was applied. This is what the
    /// built-in renderers echo.
    pub text: String,
}

/// Turns an [`Echoed`] request into the echo's answer.
pub type Render = Arc<dyn Fn(&Echoed) -> Response + Send + Sync>;

/// Builds the answer of the token endpoint from the issued token.
pub type TokenRender = Arc<dyn Fn(&str) -> Response + Send + Sync>;

/// How the echoed text is spelled before it is rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Spelling {
    /// As received.
    #[default]
    Verbatim,
    /// WHATWG `application/x-www-form-urlencoded`, space as `+`.
    FormPlus,
    /// Form-urlencoded with space as `%20`.
    FormPercent,
}

/// Configuration of an echo server; [`Echo::start`] runs it.
#[must_use]
pub struct Echo {
    status: StatusCode,
    spelling: Spelling,
    token_path: String,
    issued_token: String,
    default_render: Render,
    prefixed: Vec<(String, Render)>,
    token_render: TokenRender,
}

impl fmt::Debug for Echo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Echo")
            .field("status", &self.status)
            .field("spelling", &self.spelling)
            .field("token_path", &self.token_path)
            .field(
                "prefixes",
                &self.prefixed.iter().map(|(p, _)| p).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Echo {
    /// An echo that answers every API request with `status`, renders with [`json()`], spells
    /// verbatim, and issues [`DEFAULT_ISSUED_TOKEN`] under [`DEFAULT_TOKEN_PATH`].
    ///
    /// # Panics
    ///
    /// If `status` is not a valid status code.
    pub fn new(status: u16) -> Self {
        Self {
            status: StatusCode::from_u16(status)
                .unwrap_or_else(|_| panic!("invalid status code {status}")),
            spelling: Spelling::Verbatim,
            token_path: DEFAULT_TOKEN_PATH.to_owned(),
            issued_token: DEFAULT_ISSUED_TOKEN.to_owned(),
            default_render: json(),
            prefixed: Vec::new(),
            token_render: Arc::new(token_response),
        }
    }

    /// Spells the echoed text with `spelling`.
    pub fn spelling(mut self, spelling: Spelling) -> Self {
        self.spelling = spelling;
        self
    }

    /// Serves the token endpoint under `path` (a prefix: any path below it is a token request).
    pub fn token_path(mut self, path: &str) -> Self {
        self.token_path = path.to_owned();
        self
    }

    /// Hands out `token` instead of [`DEFAULT_ISSUED_TOKEN`].
    pub fn issued_token(mut self, token: &str) -> Self {
        self.issued_token = token.to_owned();
        self
    }

    /// Renders API answers with `render` unless a prefix renderer applies.
    pub fn render(mut self, render: Render) -> Self {
        self.default_render = render;
        self
    }

    /// Renders answers to paths starting with `prefix` with `render`. The first matching prefix,
    /// in the order added, wins.
    pub fn render_under(mut self, prefix: &str, render: Render) -> Self {
        self.prefixed.push((prefix.to_owned(), render));
        self
    }

    /// Builds token answers with `render` instead of [`token_response`].
    pub fn token_render(
        mut self,
        render: impl Fn(&str) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.token_render = Arc::new(render);
        self
    }

    /// Starts the server.
    pub async fn start(self) -> EchoServer {
        let token_path = self.token_path.clone();
        let issued_token = self.issued_token.clone();
        let router = Router::new().fallback(echo).with_state(Arc::new(self));
        EchoServer {
            server: MockServer::start(router).await,
            token_path,
            issued_token,
        }
    }
}

/// A running echo server. Dereferences to its [`MockServer`] for the log and the fault queue.
#[derive(Debug)]
pub struct EchoServer {
    server: MockServer,
    token_path: String,
    issued_token: String,
}

impl EchoServer {
    /// Starts an echo with the defaults of [`Echo::new`].
    pub async fn start(status: u16) -> Self {
        Echo::new(status).start().await
    }

    /// The URL of the token endpoint: the base URL followed by the token path.
    pub fn token_url(&self) -> String {
        self.server.url(&self.token_path)
    }

    /// The token the token endpoint hands out.
    pub fn issued_token(&self) -> &str {
        &self.issued_token
    }

    /// Number of requests to the token endpoint.
    pub fn token_requests(&self) -> usize {
        self.server
            .log()
            .entries()
            .iter()
            .filter(|r| r.path.starts_with(&self.token_path))
            .count()
    }

    /// Number of requests outside the token endpoint.
    pub fn api_requests(&self) -> usize {
        self.server.log().len() - self.token_requests()
    }
}

impl Deref for EchoServer {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

async fn echo(
    State(cfg): State<Arc<Echo>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    if path.starts_with(&cfg.token_path) {
        return (cfg.token_render)(&cfg.issued_token);
    }
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = String::from_utf8_lossy(&body).into_owned();
    let query = uri.query().map(str::to_owned);

    let mut text = format!("request {method} {path}");
    if let Some(q) = &query {
        let _ = write!(text, "?{q}");
    }
    for (name, value) in &headers {
        let _ = write!(text, "\n{name}: {value}");
    }
    let _ = write!(text, "\nbody: {body}");
    let text = match cfg.spelling {
        Spelling::Verbatim => text,
        Spelling::FormPlus => form_encode(&text, "+"),
        Spelling::FormPercent => form_encode(&text, "%20"),
    };

    let echoed = Echoed {
        status: cfg.status,
        method,
        path,
        query,
        headers,
        body,
        text,
    };
    let render = cfg
        .prefixed
        .iter()
        .find(|(prefix, _)| echoed.path.starts_with(prefix.as_str()))
        .map_or(&cfg.default_render, |(_, r)| r);
    render(&echoed)
}

/// The default token answer: `201`, the token in an `X-Subject-Token` header, and a JSON body
/// with the token and its expiry under the field names common token endpoints use
/// (`access_token`/`token_type`/`expires_in`, `iamToken`/`expiresAt`, `token.expires_at`).
pub fn token_response(token: &str) -> Response {
    let mut response = (
        StatusCode::CREATED,
        axum::Json(json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "iamToken": token,
            "expiresAt": TOKEN_EXPIRES_AT,
            "token": { "expires_at": TOKEN_EXPIRES_AT },
        })),
    )
        .into_response();
    if let Ok(value) = token.parse() {
        response.headers_mut().insert("x-subject-token", value);
    }
    response
}

/// The text in a flat JSON object under the field names clients commonly read error text from
/// (`error`, `message`, `description`, `detail`, `error_text`, `error_description`) and in an
/// `errors` array of `{code, message}`. Escaped by `serde_json`.
pub fn json() -> Render {
    Arc::new(|e: &Echoed| {
        let t = &e.text;
        let body = json!({
            "error": t,
            "message": t,
            "description": t,
            "detail": t,
            "error_text": t,
            "error_description": t,
            "errors": [{ "code": 1000, "message": t }],
        });
        (e.status, axum::Json(body)).into_response()
    })
}

/// Like [`json()`], but every string escapes `/` as `\/` and every non-ASCII character as a
/// lowercase `\uXXXX` sequence (surrogate pairs above the BMP), as some JSON encoders do.
pub fn json_ascii() -> Render {
    Arc::new(|e: &Echoed| {
        let t = json_ascii_string(&e.text);
        let body = format!(
            "{{\"error\":{t},\"message\":{t},\"description\":{t},\"detail\":{t},\
             \"error_text\":{t},\"error_description\":{t},\
             \"errors\":[{{\"code\":1000,\"message\":{t}}}]}}"
        );
        (e.status, [("content-type", "application/json")], body).into_response()
    })
}

/// The text XML-escaped and put into `template` in place of every `{text}`, sent as
/// `application/xml`. The template is the provider's error document, for example
/// `<Error><Message>{text}</Message></Error>`.
pub fn xml(template: &str) -> Render {
    let template = template.to_owned();
    Arc::new(move |e: &Echoed| {
        let body = template.replace("{text}", &xml_escape(&e.text));
        (e.status, [("content-type", "application/xml")], body).into_response()
    })
}

/// The text as the whole body, sent as `text/plain`.
pub fn text() -> Render {
    Arc::new(|e: &Echoed| {
        (
            e.status,
            [("content-type", "text/plain; charset=utf-8")],
            e.text.clone(),
        )
            .into_response()
    })
}

/// XML-escapes `&`, `<`, `>`, `"` and `'`.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// WHATWG form-urlencoding of `s`, with `space` as the spelling of a space.
pub fn form_encode(s: &str, space: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(b));
            }
            b' ' => out.push_str(space),
            b => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// A JSON string literal (with quotes) escaping `/` and all non-ASCII characters.
fn json_ascii_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii_control() || !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding() {
        assert_eq!(form_encode("a b+c/d@e", "+"), "a+b%2Bc%2Fd%40e");
        assert_eq!(form_encode("a b", "%20"), "a%20b");
        assert_eq!(form_encode("\u{e9}", "+"), "%C3%A9");
    }

    #[test]
    fn json_ascii_escapes() {
        assert_eq!(
            json_ascii_string("a/b\"\u{e9}\u{1d11e}"),
            r#""a\/b\"\u00e9\ud834\udd1e""#
        );
        let parsed: String =
            serde_json::from_str(&json_ascii_string("x/\u{e9}\u{1d11e}\n")).unwrap();
        assert_eq!(parsed, "x/\u{e9}\u{1d11e}\n");
    }

    #[test]
    fn xml_escaping() {
        assert_eq!(
            xml_escape("<a & 'b'>\""),
            "&lt;a &amp; &apos;b&apos;&gt;&quot;"
        );
    }
}
