//! Fault injection shared by every mock server.
//!
//! A test pushes [`Fault`]s onto the server's [`Faults`] queue. The harness middleware offers each
//! incoming request to the queue before the provider mock's router sees it; a fault that takes the
//! request decides what happens to it. Provider mocks therefore get fault injection without any
//! code of their own.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};

use crate::log::LoggedRequest;

type Predicate = Arc<dyn Fn(&LoggedRequest) -> bool + Send + Sync>;
type Hook = Arc<dyn Fn() + Send + Sync>;

/// One injected behavior: which requests it takes, how many, and what it does to them.
///
/// # Matching
///
/// A fault matches a request by method (or any method) and by a pattern over the URL path, without
/// the query string. In the pattern, `*` matches any run of characters within one path segment and
/// `**` matches any run of characters including `/`; every other character matches itself. An
/// optional predicate ([`Fault::when`]) narrows the match further, for example by body content.
///
/// # Counting
///
/// Requests are offered to the queued faults in the order the faults were pushed. The first
/// matching fault that is still active takes the request. While it still has requests to skip
/// ([`Fault::skip`]) it lets the request through unchanged and counts it; after that it acts on the
/// next [`Fault::times`] requests (one by default) and is then removed from the queue.
///
/// # Actions
///
/// The default action passes the request on to the mock unchanged, which is useful together with
/// [`Fault::delay`] or [`Fault::run`]. The other actions replace it: answer with a given response,
/// or write raw bytes to the connection (see [`Fault::raw`]). Delay and hook run first, in that
/// order, whatever the action.
#[derive(Clone)]
#[must_use = "a fault does nothing until it is pushed onto a server's `Faults`"]
pub struct Fault {
    method: Option<Method>,
    path: String,
    predicate: Option<Predicate>,
    skip: u32,
    times: Option<u32>,
    delay: Option<Duration>,
    hook: Option<Hook>,
    headers: Vec<(HeaderName, HeaderValue)>,
    action: Action,
}

#[derive(Clone, Debug)]
pub(crate) enum Action {
    PassThrough,
    Respond { status: StatusCode, body: Bytes },
    Raw(Vec<(Duration, Bytes)>),
}

/// What the middleware does with a request a fault took.
pub(crate) struct Plan {
    pub(crate) delay: Option<Duration>,
    pub(crate) hook: Option<Hook>,
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) action: Action,
}

impl fmt::Debug for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fault")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("predicate", &self.predicate.is_some())
            .field("skip", &self.skip)
            .field("times", &self.times)
            .field("delay", &self.delay)
            .field("hook", &self.hook.is_some())
            .field("headers", &self.headers)
            .field("action", &self.action)
            .finish()
    }
}

impl Fault {
    /// A fault for requests with method `method` (case-insensitive) whose path matches `path`.
    ///
    /// # Panics
    ///
    /// If `method` is not a valid HTTP method.
    pub fn on(method: &str, path: &str) -> Self {
        let method = Method::from_bytes(method.to_ascii_uppercase().as_bytes())
            .unwrap_or_else(|_| panic!("invalid HTTP method {method:?}"));
        Self::new(Some(method), path)
    }

    /// A fault for requests with any method whose path matches `path`.
    pub fn path(path: &str) -> Self {
        Self::new(None, path)
    }

    /// A fault for any request.
    pub fn any() -> Self {
        Self::new(None, "**")
    }

    fn new(method: Option<Method>, path: &str) -> Self {
        Self {
            method,
            path: path.to_owned(),
            predicate: None,
            skip: 0,
            times: Some(1),
            delay: None,
            hook: None,
            headers: Vec::new(),
            action: Action::PassThrough,
        }
    }

    // --- matching and counting ---

    /// Takes only requests for which `predicate` also holds.
    pub fn when(
        mut self,
        predicate: impl Fn(&LoggedRequest) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.predicate = Some(Arc::new(predicate));
        self
    }

    /// Lets the first `n` matching requests through unchanged before acting.
    pub fn skip(mut self, n: u32) -> Self {
        self.skip = n;
        self
    }

    /// Acts on `n` matching requests, then is removed. The default is 1. `0` removes the fault on
    /// the first request it would act on, without acting.
    pub fn times(mut self, n: u32) -> Self {
        self.times = Some(n);
        self
    }

    /// Acts on every matching request until [`Faults::clear`].
    pub fn always(mut self) -> Self {
        self.times = None;
        self
    }

    // --- modifiers that combine with any action ---

    /// Waits `delay` before acting. With the default action this delays the mock's answer.
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    /// Runs `hook` before acting (after the delay, if any). A provider mock uses this to change its
    /// state between a client's read and its write, for example to insert a foreign value.
    pub fn run(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.hook = Some(Arc::new(hook));
        self
    }

    /// Adds a response header to the HTTP answer, whether the fault answers itself or passes the
    /// request through to the mock. Ignored by raw actions.
    ///
    /// # Panics
    ///
    /// If `name` or `value` is not a valid header name or value.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes())
            .unwrap_or_else(|_| panic!("invalid header name {name:?}"));
        let value = HeaderValue::from_str(value)
            .unwrap_or_else(|_| panic!("invalid header value {value:?}"));
        self.headers.push((name, value));
        self
    }

    // --- actions ---

    /// Passes the request on to the mock unchanged (the default action).
    pub fn pass(mut self) -> Self {
        self.action = Action::PassThrough;
        self
    }

    /// Answers with `status` and `body` instead of the mock.
    ///
    /// # Panics
    ///
    /// If `status` is not a valid status code.
    pub fn respond(mut self, status: u16, body: impl Into<Bytes>) -> Self {
        self.action = Action::Respond {
            status: status_code(status),
            body: body.into(),
        };
        self
    }

    /// Answers with `status` and an empty body.
    pub fn status(self, status: u16) -> Self {
        self.respond(status, Bytes::new())
    }

    /// Answers `429 Too Many Requests` with `Retry-After: <retry_after>`. The value is sent as
    /// given, so it may be delta-seconds (`"2"`) or an HTTP date.
    pub fn rate_limited(self, retry_after: &str) -> Self {
        self.respond(429, Bytes::new())
            .header("retry-after", retry_after)
    }

    /// Answers with a redirect: `status` (301, 302, 303, 307 or 308) and `Location: <location>`.
    pub fn redirect(self, status: u16, location: &str) -> Self {
        self.respond(status, Bytes::new())
            .header("location", location)
    }

    /// Answers with `status` and a body of exactly `len` bytes sent with `Content-Length`.
    pub fn oversized_body(self, status: u16, len: usize) -> Self {
        self.respond(status, vec![b'x'; len])
    }

    /// Answers with `status` and a body of `len` bytes in chunked transfer encoding, so the
    /// client cannot learn the size from a `Content-Length`. Written raw; the connection closes
    /// after the last chunk.
    pub fn oversized_chunked_body(self, status: u16, len: usize) -> Self {
        let head = format!(
            "HTTP/1.1 {}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
            status_line(status)
        );
        let mut chunks = vec![(Duration::ZERO, Bytes::from(head))];
        const CHUNK: usize = 64 * 1024;
        let mut left = len;
        while left > 0 {
            let n = left.min(CHUNK);
            let mut chunk = format!("{n:x}\r\n").into_bytes();
            chunk.extend(std::iter::repeat_n(b'x', n));
            chunk.extend_from_slice(b"\r\n");
            chunks.push((Duration::ZERO, Bytes::from(chunk)));
            left -= n;
        }
        chunks.push((Duration::ZERO, Bytes::from_static(b"0\r\n\r\n")));
        self.raw(chunks)
    }

    /// Closes the connection without sending a single byte.
    pub fn drop_connection(self) -> Self {
        self.raw(Vec::new())
    }

    /// Sends a head announcing `Content-Length: <declared_len>`, then `body` (which should be
    /// shorter), then closes the connection.
    pub fn truncated_body(self, status: u16, declared_len: usize, body: impl Into<Bytes>) -> Self {
        let head = format!(
            "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {declared_len}\r\nconnection: close\r\n\r\n",
            status_line(status)
        );
        self.raw(vec![
            (Duration::ZERO, Bytes::from(head)),
            (Duration::ZERO, body.into()),
        ])
    }

    /// Sends the status line, waits `pause`, then sends the rest of the head and `body` and closes
    /// the connection. Exercises a timeout that must cover reading the response head.
    pub fn slow_headers(self, status: u16, pause: Duration, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        let rest = format!(
            "content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        self.raw(vec![
            (
                Duration::ZERO,
                Bytes::from(format!("HTTP/1.1 {}\r\n", status_line(status))),
            ),
            (pause, Bytes::from(rest)),
            (Duration::ZERO, body),
        ])
    }

    /// Takes the connection away from the HTTP server and writes `chunks` to it, each after its
    /// pause, then closes it. Nothing else is sent: the chunks are the whole answer, head
    /// included. An empty list closes the connection without an answer.
    pub fn raw(mut self, chunks: Vec<(Duration, Bytes)>) -> Self {
        self.action = Action::Raw(chunks);
        self
    }

    fn matches(&self, request: &LoggedRequest) -> bool {
        self.method.as_ref().is_none_or(|m| *m == request.method)
            && glob(self.path.as_bytes(), request.path.as_bytes())
            && self.predicate.as_ref().is_none_or(|p| p(request))
    }
}

/// The fault queue of one server.
///
/// Cloning gives another handle to the same queue. See [`Fault`] for how requests are matched.
#[derive(Clone, Default)]
pub struct Faults(Arc<Mutex<Vec<Fault>>>);

impl fmt::Debug for Faults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Faults").field(&*self.lock()).finish()
    }
}

impl Faults {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Fault>> {
        self.0.lock().expect("fault queue poisoned")
    }

    /// Appends `fault` to the queue.
    pub fn push(&self, fault: Fault) {
        self.lock().push(fault);
    }

    /// Number of faults still queued.
    pub fn pending(&self) -> usize {
        self.lock().len()
    }

    /// Removes every queued fault.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Offers `request` to the queue. `Some` if a fault takes it and acts; a fault that is still
    /// skipping counts the request and returns `None`.
    pub(crate) fn take(&self, request: &LoggedRequest) -> Option<Plan> {
        let mut queue = self.lock();
        let index = queue.iter().position(|f| f.matches(request))?;
        let fault = queue.get_mut(index)?;
        if fault.skip > 0 {
            fault.skip -= 1;
            return None;
        }
        let plan = match fault.times {
            Some(0) => None,
            _ => Some(Plan {
                delay: fault.delay,
                hook: fault.hook.clone(),
                headers: fault.headers.clone(),
                action: fault.action.clone(),
            }),
        };
        match &mut fault.times {
            Some(n) if *n <= 1 => {
                let _removed = queue.remove(index);
            }
            Some(n) => *n -= 1,
            None => {}
        }
        plan
    }
}

/// Matches `path` against `pattern`: `*` within one segment, `**` across segments.
pub(crate) fn glob(pattern: &[u8], path: &[u8]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((b'*', rest)) => {
            if let Some((b'*', rest)) = rest.split_first() {
                (0..=path.len()).any(|i| path.get(i..).is_some_and(|p| glob(rest, p)))
            } else {
                for i in 0..=path.len() {
                    if path.get(i..).is_some_and(|p| glob(rest, p)) {
                        return true;
                    }
                    if path.get(i) == Some(&b'/') {
                        return false;
                    }
                }
                false
            }
        }
        Some((c, rest)) => path.first() == Some(c) && glob(rest, path.get(1..).unwrap_or_default()),
    }
}

fn status_code(status: u16) -> StatusCode {
    StatusCode::from_u16(status).unwrap_or_else(|_| panic!("invalid status code {status}"))
}

fn status_line(status: u16) -> String {
    let code = status_code(status);
    format!(
        "{} {}",
        code.as_u16(),
        code.canonical_reason().unwrap_or("Unknown")
    )
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn glob_patterns() {
        let m = |p: &str, s: &str| glob(p.as_bytes(), s.as_bytes());
        assert!(m("/zones", "/zones"));
        assert!(!m("/zones", "/zones/"));
        assert!(m("/zones/*", "/zones/abc"));
        assert!(!m("/zones/*", "/zones/abc/rrset"));
        assert!(m("/zones/*/rrset", "/zones/abc/rrset"));
        assert!(m("/zones/*/rrset/*", "/zones/abc/rrset/x"));
        assert!(m("/zones/**", "/zones/abc/rrset/x"));
        assert!(m("**", "/anything/at/all"));
        assert!(m("/v*/zones", "/v2/zones"));
        assert!(!m("/v*/zones", "/v2/x/zones"));
        assert!(m("/a/**/z", "/a/b/c/z"));
        assert!(!m("/a/**/z", "/a/b/c/y"));
    }
}
