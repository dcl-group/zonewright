//! The request log every mock server keeps.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method};

use crate::fault::glob;

/// One request as the mock server received it.
///
/// All request headers are kept, credentials included: the secret tests search the log for them,
/// and the invariant tests assert that some requests were never sent.
#[derive(Clone, Debug)]
pub struct LoggedRequest {
    /// Position in the log, starting at 0.
    pub seq: usize,
    /// Request method.
    pub method: Method,
    /// URL path, without the query string.
    pub path: String,
    /// Raw query string without the leading `?`, if the URL had one.
    pub query: Option<String>,
    /// All request headers.
    pub headers: HeaderMap,
    /// The complete request body.
    pub body: Bytes,
    /// Status of the answer the server sent, once it is known. `None` while the request is in
    /// progress and for faults that write raw bytes or drop the connection.
    pub status: Option<u16>,
    /// Whether an injected fault took this request.
    pub faulted: bool,
    /// When the harness received the request (its body read, before any fault or the router ran),
    /// on the real clock. A test measures the spacing of retries from these instants rather than
    /// from the total time of a call, which also counts the client's own work.
    pub received: Instant,
    /// Identity that survives [`RequestLog::clear`], for updating the status.
    uid: u64,
}

impl LoggedRequest {
    pub(crate) fn new(
        method: Method,
        path: String,
        query: Option<String>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Self {
        Self {
            seq: 0,
            method,
            path,
            query,
            headers,
            body,
            status: None,
            faulted: false,
            received: Instant::now(),
            uid: 0,
        }
    }

    /// The value of header `name` (case-insensitive) as text, if present and valid UTF-8.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The body as text, with invalid UTF-8 replaced.
    pub fn body_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// The body parsed as JSON, or `None` if it is not JSON.
    pub fn body_json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// Whether the request matches `method` (`None` for any) and the path pattern (see
    /// [`Fault`](crate::Fault) for the pattern syntax).
    pub fn matches(&self, method: Option<&str>, path: &str) -> bool {
        method.is_none_or(|m| self.method.as_str().eq_ignore_ascii_case(m))
            && glob(path.as_bytes(), self.path.as_bytes())
    }

    /// Whether `needle` occurs anywhere in the request: method, path, query, any header name or
    /// value, or the body. Matching is on raw bytes, so it finds a value in whatever encoding it
    /// was sent.
    pub fn contains(&self, needle: impl AsRef<[u8]>) -> bool {
        let needle = needle.as_ref();
        if needle.is_empty() {
            return true;
        }
        let hit = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        hit(self.method.as_str().as_bytes())
            || hit(self.path.as_bytes())
            || self.query.as_deref().is_some_and(|q| hit(q.as_bytes()))
            || self
                .headers
                .iter()
                .any(|(n, v)| hit(n.as_str().as_bytes()) || hit(v.as_bytes()))
            || hit(&self.body)
    }
}

/// The shared, append-only log of the requests one server received, in arrival order.
///
/// Cloning gives another handle to the same log.
#[derive(Clone, Debug, Default)]
pub struct RequestLog(Arc<Mutex<Inner>>);

#[derive(Debug, Default)]
struct Inner {
    entries: Vec<LoggedRequest>,
    next_uid: u64,
}

impl std::ops::Deref for Inner {
    type Target = Vec<LoggedRequest>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl RequestLog {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().expect("request log poisoned")
    }

    /// A copy of every entry.
    pub fn entries(&self) -> Vec<LoggedRequest> {
        self.lock().clone()
    }

    /// Number of requests received.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no request was received.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The entries that match `method` (`None` for any) and the path pattern.
    pub fn matching(&self, method: Option<&str>, path: &str) -> Vec<LoggedRequest> {
        self.lock()
            .iter()
            .filter(|r| r.matches(method, path))
            .cloned()
            .collect()
    }

    /// Number of entries that match `method` (`None` for any) and the path pattern.
    pub fn count(&self, method: Option<&str>, path: &str) -> usize {
        self.lock()
            .iter()
            .filter(|r| r.matches(method, path))
            .count()
    }

    /// The most recent entry.
    pub fn last(&self) -> Option<LoggedRequest> {
        self.lock().last().cloned()
    }

    /// Whether any entry contains `needle` (see [`LoggedRequest::contains`]).
    pub fn contains(&self, needle: impl AsRef<[u8]>) -> bool {
        let needle = needle.as_ref();
        self.lock().iter().any(|r| r.contains(needle))
    }

    /// Removes every entry. Sequence numbers start again at 0.
    pub fn clear(&self) {
        self.lock().entries.clear();
    }

    /// Appends `entry`, assigning its sequence number, and returns the handle for
    /// [`RequestLog::set_status`].
    pub(crate) fn push(&self, mut entry: LoggedRequest) -> u64 {
        let mut log = self.lock();
        entry.uid = log.next_uid;
        log.next_uid += 1;
        entry.seq = log.entries.len();
        let uid = entry.uid;
        log.entries.push(entry);
        uid
    }

    pub(crate) fn set_status(&self, uid: u64, status: u16) {
        let mut log = self.lock();
        if let Some(entry) = log.entries.iter_mut().rev().find(|e| e.uid == uid) {
            entry.status = Some(status);
        }
    }
}
