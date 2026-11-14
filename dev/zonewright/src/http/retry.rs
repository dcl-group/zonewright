//! Sending a request: attempts, retries, rate limits, the status mapping, the size cap and the
//! `tracing` event of every attempt (design sections 5.3, 5.4 and 5.6).
//!
//! - At most [`MAX_ATTEMPTS`] attempts per request, counting the first.
//! - An idempotent request is retried after a connection or timeout error and after a 5xx
//!   answer. Back-off before attempt `n + 1` is `500 ms × n` plus a random 0–25 %.
//! - A request that is not idempotent is sent once; whatever goes wrong becomes the error.
//! - 429, and any answer the client's rate-limit classifier marks (`HttpBuilder::rate_limit`):
//!   the wait comes from `Retry-After` (seconds or an HTTP date) or `RateLimit-Reset`. An
//!   idempotent request with attempts left sleeps for a wait of at most [`MAX_INLINE_WAIT`] and
//!   retries, or uses the back-off when no wait is given; otherwise `Error::RateLimited`.
//! - 401 to a request made with a token from a [`TokenSource`]: the token's generation is
//!   invalidated. An idempotent request with attempts left gets a new token and is repeated once;
//!   the repeat counts toward the attempts, and a 401 for a token fetched during the call is
//!   `Error::Auth`. Otherwise `Error::Transient`: the caller's repeat of the operation obtains a
//!   new token.
//! - 401 otherwise `Auth`, 403 `Forbidden`, 3xx `Rejected` (redirects are not followed), 5xx
//!   `Transient`; every other status goes back to the client.
//! - Refusals by the URL policy at send time (`loopback_only`, no CA certificates) are never
//!   retried and contact nothing.
//! - A request with a finisher (`Request::finish_with`) is completed for every attempt, right
//!   before it is sent, from exactly what that attempt sends.
//! - [`Http::try_send`] reports with the error whether the request certainly never reached the
//!   provider ([`SendError::certainly_unsent`]).
//!
//! One `DEBUG` event per attempt, target `zonewright::http`, with the fields `provider`,
//! `method`, `path` (no query string), `status` (absent when there was no answer), `attempt`
//! and `elapsed_ms`. Nothing else: no header, no body, no query, no detail text.

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use secrecy::ExposeSecret;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::redact::Detail;

use super::Http;
use super::request::{
    AuthMode, BODY_LIMIT, BODY_TOO_LARGE, Outgoing, Request, Response, TokenAuth,
};
use super::tls::NO_CA_CERTIFICATES;
use super::token::{Lease, Token, TokenSource};
use super::url::is_loopback_literal;

/// Most attempts per request, counting the first.
pub(crate) const MAX_ATTEMPTS: u32 = 3;

/// Longest rate-limit wait the transport sleeps through itself; a longer one is returned as
/// `Error::RateLimited`.
pub(crate) const MAX_INLINE_WAIT: Duration = Duration::from_secs(30);

/// Longest wait reported in `Error::RateLimited`: a provider's header could state any number,
/// and a caller adding it to an `Instant` must not overflow.
pub(crate) const MAX_REPORTED_WAIT: Duration = Duration::from_secs(24 * 60 * 60);

/// `Target` of the transport's `tracing` events.
const TARGET: &str = "zonewright::http";

/// A cached-token credential for one call.
struct TokenUse<'a, F> {
    source: &'a TokenSource,
    auth: &'a TokenAuth,
    fetch: &'a F,
}

/// The fetch type of a call without a token; never called.
type NoFetch = fn() -> std::future::Ready<Result<Token, Error>>;

/// The error of [`Http::try_send`]: the operation's error, and whether the request certainly
/// never reached the provider.
#[derive(Debug)]
pub(crate) struct SendError {
    error: Error,
    unsent: bool,
}

impl SendError {
    /// An error a client met before it handed the request to the transport (building the URL
    /// or the body): nothing was sent.
    pub(crate) fn before_send(error: Error) -> SendError {
        SendError {
            error,
            unsent: true,
        }
    }

    /// An error a client made of an answer the transport passed on: the request was sent.
    pub(crate) fn answered(error: Error) -> SendError {
        SendError {
            error,
            unsent: false,
        }
    }

    /// The operation's error, the same [`Http::send`] returns.
    pub(crate) fn error(&self) -> &Error {
        &self.error
    }

    /// The operation's error.
    pub(crate) fn into_error(self) -> Error {
        self.error
    }

    /// True only when it is certain that no byte of the request reached the provider in any
    /// attempt: the request was refused by a check before any connection (the URL policy, a
    /// header value it cannot carry, a token that could not be obtained, a finisher that
    /// failed), or every attempt failed while its connection was being established (TCP
    /// connect or TLS handshake, before the request is written). False whenever that is not
    /// certain: a timeout or a broken connection after the connection was established, any
    /// answer, a refused certificate (in TLS 1.3 the server can refuse the client certificate
    /// after the client has started to send).
    pub(crate) fn certainly_unsent(&self) -> bool {
        self.unsent
    }
}

impl From<SendError> for Error {
    fn from(e: SendError) -> Error {
        e.error
    }
}

/// Why an attempt produced no usable answer.
enum Failure {
    /// No answer, or an answer cut off: connection refused or broken, timeout. Retryable for
    /// an idempotent request. The text is a constant; the status is that of an answer whose
    /// body was cut off. `unsent` is true only for a failure to establish the connection.
    Network {
        text: &'static str,
        status: Option<u16>,
        unsent: bool,
    },
    /// The answer's body is over [`BODY_LIMIT`].
    TooLarge { status: u16 },
    /// The request could not be built (a header value the client set is unusable).
    Build,
    /// The request's finisher failed; nothing was sent.
    Finish(Error),
    /// TLS certificate verification failed, on either side. Repeating it gives the same answer.
    Certificate,
}

impl Failure {
    fn from_reqwest(e: &reqwest::Error, status: Option<u16>) -> Failure {
        // Only the classification of a `reqwest` error is used, never its text: it can contain
        // the URL with its query string.
        //
        // `is_connect` is true only for an error of the connector (TCP connect, TLS handshake,
        // a connect timeout), which runs before the request is written; a request on a reused
        // connection does not go through the connector. A certificate failure is classified
        // first and never counts as unsent.
        let unsent = status.is_none() && e.is_connect();
        let network = |text: &'static str| Failure::Network {
            text,
            status,
            unsent,
        };
        if e.is_builder() {
            Failure::Build
        } else if certificate_failure(e) {
            Failure::Certificate
        } else if e.is_timeout() {
            network("the request to the provider timed out")
        } else if e.is_connect() {
            network("could not connect to the provider")
        } else if e.is_body() || e.is_decode() {
            network("the connection broke while the provider's answer was read")
        } else {
            network("the request to the provider failed")
        }
    }

    /// True when the attempt certainly wrote nothing of the request.
    fn unsent(&self) -> bool {
        match self {
            Failure::Network { unsent, .. } => *unsent,
            Failure::Build | Failure::Finish(_) => true,
            Failure::TooLarge { .. } | Failure::Certificate => false,
        }
    }
}

/// True when the source chain of `e` holds a `rustls` certificate failure: the server's
/// certificate was refused, or the server refused the client certificate. Only the types are
/// inspected, never a message.
fn certificate_failure(e: &reqwest::Error) -> bool {
    use rustls::AlertDescription as Alert;
    let is_certificate = |tls: &rustls::Error| match tls {
        rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => true,
        rustls::Error::General(text) => text == super::tls::NO_CA_CERTIFICATES,
        rustls::Error::AlertReceived(alert) => matches!(
            alert,
            Alert::BadCertificate
                | Alert::UnsupportedCertificate
                | Alert::CertificateRevoked
                | Alert::CertificateExpired
                | Alert::CertificateUnknown
                | Alert::UnknownCA
                | Alert::CertificateRequired
                | Alert::AccessDenied
        ),
        _ => false,
    };
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(e);
    let mut depth = 0;
    while let Some(current) = next {
        depth += 1;
        if depth > 32 {
            return false;
        }
        if let Some(tls) = current.downcast_ref::<rustls::Error>() {
            return is_certificate(tls);
        }
        // An I/O error hides the error it wraps from `source()`; follow it with `get_ref`.
        // `tokio-rustls` wraps the `rustls` error in an I/O error, and the connector wraps
        // that in another.
        next = match current.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => current.source(),
        };
    }
    false
}

impl Http {
    /// Sends `request` with the client's static credential (if any) under the rules of the
    /// module documentation.
    pub(crate) async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.try_send(request).await.map_err(SendError::into_error)
    }

    /// [`Http::send`], with the error saying whether the request certainly never reached the
    /// provider. For a client that must tell a write that was refused from one whose outcome is
    /// unknown.
    pub(crate) async fn try_send(&self, request: &Request) -> Result<Response, SendError> {
        let mut sent = false;
        self.run::<NoFetch, _>(request, None, &mut sent)
            .await
            .map_err(|error| SendError {
                error,
                unsent: !sent,
            })
    }

    /// Sends `request` with a token from `tokens`, sent as `auth` says. `fetch` obtains a new
    /// token when there is none or it is due; it runs inside this call's future (see
    /// [`TokenSource`]). Every token used is registered with the scrubber.
    pub(crate) async fn send_with_token<F, Fut>(
        &self,
        request: &Request,
        tokens: &TokenSource,
        auth: &TokenAuth,
        fetch: F,
    ) -> Result<Response, Error>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Token, Error>>,
    {
        let token = TokenUse {
            source: tokens,
            auth,
            fetch: &fetch,
        };
        let mut sent = false;
        self.run(request, Some(token), &mut sent).await
    }

    /// The attempts of one request. `sent` becomes true as soon as an attempt may have written
    /// any of the request.
    async fn run<F, Fut>(
        &self,
        request: &Request,
        token: Option<TokenUse<'_, F>>,
        sent: &mut bool,
    ) -> Result<Response, Error>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Token, Error>>,
    {
        self.preflight(request, token.is_some())?;
        let mut lease: Option<Lease> = None;
        let mut refreshed = false;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let token_header = match &token {
                Some(token) => {
                    let current = match lease.take() {
                        Some(current) => current,
                        None => token.source.get(|| (token.fetch)()).await?,
                    };
                    // A comparison when the token is already the slot's current one.
                    self.scrubber
                        .remember(token.source.secret_slot(), current.token.expose_secret());
                    let header = token.auth.header(current.token.expose_secret())?;
                    lease = Some(current);
                    Some(header)
                }
                None => None,
            };

            if let Some(gate) = &self.gate {
                gate.wait().await;
            }
            let started = Instant::now();
            let mut result = self.attempt(request, token_header).await;
            if !matches!(&result, Err(failure) if failure.unsent()) {
                *sent = true;
            }
            if let Ok(response) = &mut result {
                response.token_generation = lease.as_ref().map(|used| used.generation);
            }
            let status = match &result {
                Ok(response) => Some(response.status),
                Err(Failure::TooLarge { status }) => Some(*status),
                Err(Failure::Network { status, .. }) => *status,
                Err(Failure::Certificate | Failure::Build | Failure::Finish(_)) => None,
            };
            self.trace(request, status, attempt, started.elapsed());
            let retry_left = request.idempotent && attempt < MAX_ATTEMPTS;

            let response = match result {
                Ok(response) => response,
                Err(Failure::TooLarge { status }) => {
                    // A rejected token is discarded even when the answer cannot be read.
                    if status == 401
                        && let (Some(token), Some(used)) = (&token, lease.take())
                    {
                        token.source.invalidate(used.generation).await;
                    }
                    return Err(protocol(BODY_TOO_LARGE));
                }
                Err(Failure::Certificate) => {
                    return Err(Error::Config {
                        detail: Detail::constant(
                            "the provider's TLS certificate, or the client certificate, was not accepted",
                        ),
                    });
                }
                Err(Failure::Build) => {
                    return Err(Error::InvalidInput {
                        detail: Detail::constant("the HTTP request could not be built"),
                    });
                }
                Err(Failure::Finish(error)) => return Err(error),
                Err(Failure::Network { text, .. }) => {
                    if retry_left {
                        tokio::time::sleep(backoff(attempt)).await;
                        continue;
                    }
                    return Err(Error::Transient {
                        detail: Detail::constant(text),
                    });
                }
            };

            let status = response.status;
            if request.keep.contains(&status) {
                return Ok(response);
            }
            let rate_limited =
                status == 429 || self.rate_limit.is_some_and(|classify| classify(&response));
            if rate_limited {
                let wait = rate_wait(&response.headers, jiff::Timestamp::now())
                    .map(|wait| wait.min(MAX_REPORTED_WAIT));
                match wait {
                    // A zero or past wait still backs off, so that a provider answering
                    // `Retry-After: 0` does not get three requests in a few milliseconds.
                    Some(wait) if retry_left && wait <= MAX_INLINE_WAIT => {
                        tokio::time::sleep(wait.max(backoff(attempt))).await;
                    }
                    None if retry_left => tokio::time::sleep(backoff(attempt)).await,
                    _ => return Err(Error::RateLimited { retry_after: wait }),
                }
                continue;
            }
            match status {
                300..=399 => {
                    return Err(Error::Rejected {
                        status: Some(status),
                        detail: Detail::constant(
                            "the provider answered with a redirect, which is not followed",
                        ),
                    });
                }
                401 => {
                    let (Some(token), Some(used)) = (&token, lease.take()) else {
                        return Err(Error::Auth {
                            detail: self.body_detail(&response),
                        });
                    };
                    token.source.invalidate(used.generation).await;
                    if used.fresh || refreshed {
                        return Err(Error::Auth {
                            detail: self.body_detail(&response),
                        });
                    }
                    if !retry_left {
                        return Err(Error::Transient {
                            detail: Detail::constant(
                                "the provider rejected the cached token; repeating the operation obtains a new one",
                            ),
                        });
                    }
                    refreshed = true;
                }
                403 => {
                    return Err(Error::Forbidden {
                        detail: self.body_detail(&response),
                    });
                }
                500..=599 => {
                    if retry_left {
                        tokio::time::sleep(backoff(attempt)).await;
                        continue;
                    }
                    let message = self.body_detail(&response);
                    return Err(Error::Transient {
                        detail: self.scrubber.detail(&format!("status {status}: {message}")),
                    });
                }
                _ => return Ok(response),
            }
        }
    }

    /// Checks made before any connection: the URL policy (https, or http on a loopback literal),
    /// `loopback_only`, and the absence of CA certificates for an https URL. None is retried.
    fn preflight(&self, request: &Request, with_token: bool) -> Result<(), Error> {
        let url = &request.url;
        let loopback = is_loopback_literal(url);
        let allowed = match url.scheme() {
            "https" => true,
            "http" => loopback,
            _ => false,
        };
        if !allowed {
            return Err(config(
                "the request URL must use https; http is accepted only for a loopback IP literal",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(config(
                "the request URL must not contain user info or a fragment",
            ));
        }
        if self.transport.shared.loopback_only && !loopback {
            return Err(config(
                "the request URL is not a loopback IP literal, and the context allows loopback addresses only",
            ));
        }
        // Credentials go only to the client's own endpoints: its static header, a cached token,
        // its client certificate, and anything else once the client has declared endpoints.
        let credentialed = with_token
            || self.identity
            || (request.auth == AuthMode::Client && self.auth.is_some());
        if (credentialed || !self.origins.is_empty())
            && !self.origins.iter().any(|origin| origin.matches(url))
        {
            return Err(config(
                "the request URL is not on one of the endpoints the client was configured with",
            ));
        }
        if url.scheme() == "https" && self.transport.shared.trust.no_ca_certificates() {
            return Err(config(NO_CA_CERTIFICATES));
        }
        Ok(())
    }

    /// One HTTP exchange: build the request, send it, read the answer under the size cap.
    async fn attempt(
        &self,
        request: &Request,
        token: Option<(HeaderName, HeaderValue)>,
    ) -> Result<Response, Failure> {
        let mut outgoing = reqwest::Request::new(request.method.clone(), request.url.clone());
        let headers = outgoing.headers_mut();
        let accept = HeaderValue::from_str(request.accept).map_err(|_| Failure::Build)?;
        headers.insert(ACCEPT, accept);
        if request.auth == AuthMode::Client
            && let Some((name, value)) = &self.auth
        {
            headers.insert(name.clone(), value.clone());
        }
        if let Some((name, value)) = token {
            headers.insert(name, value);
        }
        for (name, value) in &request.headers {
            headers.append(name.clone(), value.clone());
        }
        if let Some((content_type, body)) = &request.body {
            let content_type = HeaderValue::from_str(content_type).map_err(|_| Failure::Build)?;
            headers.insert(CONTENT_TYPE, content_type);
            *outgoing.body_mut() = Some(reqwest::Body::from(body.clone()));
        }
        // Last, so that what it computes covers exactly the method, URL and body of this
        // attempt. The headers it returns replace any of the same name.
        if let Some(finisher) = &request.finisher {
            let attempt = Outgoing {
                method: &request.method,
                url: &request.url,
                body: request.body.as_ref().map_or(&[], |(_, body)| body.as_ref()),
            };
            let added = finisher.finish(&attempt).map_err(Failure::Finish)?;
            let headers = outgoing.headers_mut();
            for (name, value) in added {
                headers.insert(name, value);
            }
        }
        let answer = self
            .transport
            .client
            .execute(outgoing)
            .await
            .map_err(|e| Failure::from_reqwest(&e, None))?;
        let status = answer.status().as_u16();
        let headers = answer.headers().clone();
        let body = read_body(answer, status).await?;
        Ok(Response {
            status,
            headers,
            body,
            token_generation: None,
        })
    }

    /// The `tracing` event of one attempt.
    fn trace(&self, request: &Request, status: Option<u16>, attempt: u32, elapsed: Duration) {
        let provider = self.provider.as_str();
        let method = request.method.as_str();
        let path = request.path();
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        match status {
            Some(status) => tracing::debug!(
                target: TARGET,
                provider,
                method,
                path,
                status,
                attempt,
                elapsed_ms,
                "provider request"
            ),
            None => tracing::debug!(
                target: TARGET,
                provider,
                method,
                path,
                attempt,
                elapsed_ms,
                "provider request"
            ),
        }
    }
}

/// Reads the body of `answer`, at most [`BODY_LIMIT`] bytes. A `Content-Length` over the limit
/// fails before anything is read; a body without one is read chunk by chunk and fails as soon
/// as the limit is passed.
async fn read_body(mut answer: reqwest::Response, status: u16) -> Result<Bytes, Failure> {
    let limit = u64::try_from(BODY_LIMIT).unwrap_or(u64::MAX);
    let declared = answer.content_length();
    if declared.is_some_and(|len| len > limit) {
        return Err(Failure::TooLarge { status });
    }
    let capacity = declared.map_or(0, |len| usize::try_from(len).unwrap_or(0));
    // Answers can carry issued tokens. The buffer is wiped when the last reference drops; it is
    // allocated once when the length is declared, while a body without a declared length may
    // leave unwiped copies behind when the buffer grows.
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    while let Some(chunk) = answer
        .chunk()
        .await
        .map_err(|e| Failure::from_reqwest(&e, Some(status)))?
    {
        if body.len().saturating_add(chunk.len()) > BODY_LIMIT {
            return Err(Failure::TooLarge { status });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(super::encode::wiped(body))
}

/// The back-off before attempt `attempt + 1`: `500 ms × attempt` plus a random 0–25 %.
pub(crate) fn backoff(attempt: u32) -> Duration {
    let base = 500u64.saturating_mul(u64::from(attempt));
    Duration::from_millis(base.saturating_add(fastrand::u64(0..=base / 4)))
}

/// Values of `RateLimit-Reset` above this are Unix times (Hetzner), below it delta-seconds
/// (the IETF RateLimit header draft).
const UNIX_TIME_THRESHOLD: u64 = 1_000_000_000;

/// The wait a rate-limit answer asks for, counted from `now`: `Retry-After` as delta-seconds or
/// an HTTP date, else `RateLimit-Reset` as delta-seconds or a Unix time. A time in the past is a
/// wait of zero. `None` when no usable header is present.
pub(crate) fn rate_wait(headers: &HeaderMap, now: jiff::Timestamp) -> Option<Duration> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    let until =
        |at: jiff::Timestamp| Duration::try_from(at.duration_since(now)).unwrap_or_default();
    if let Some(value) = header(RETRY_AFTER.as_str()) {
        if value.bytes().all(|b| b.is_ascii_digit())
            && let Ok(seconds) = value.parse::<u64>()
        {
            return Some(Duration::from_secs(seconds));
        }
        // RFC 9110 section 10.2.3: delay-seconds or an HTTP-date; the IMF-fixdate form of an
        // HTTP-date is an RFC 2822 date with "GMT".
        if let Ok(at) = jiff::fmt::rfc2822::DateTimeParser::new().parse_timestamp(value) {
            return Some(until(at));
        }
    }
    let reset = header("ratelimit-reset")?.parse::<u64>().ok()?;
    if reset > UNIX_TIME_THRESHOLD {
        let at = jiff::Timestamp::from_second(i64::try_from(reset).ok()?).ok()?;
        Some(until(at))
    } else {
        Some(Duration::from_secs(reset))
    }
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn rate_wait_reads_seconds_dates_and_resets() {
        let now: jiff::Timestamp = "2026-11-06T08:49:00Z".parse().unwrap();
        assert_eq!(rate_wait(&headers(&[]), now), None);
        assert_eq!(
            rate_wait(&headers(&[("retry-after", " 7 ")]), now),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            rate_wait(
                &headers(&[("retry-after", "Fri, 06 Nov 2026 08:49:37 GMT")]),
                now
            ),
            Some(Duration::from_secs(37))
        );
        // A date in the past is no wait.
        assert_eq!(
            rate_wait(
                &headers(&[("retry-after", "Fri, 06 Nov 2026 08:48:00 GMT")]),
                now
            ),
            Some(Duration::ZERO)
        );
        // Unusable Retry-After: fall back to RateLimit-Reset.
        assert_eq!(
            rate_wait(
                &headers(&[("retry-after", "soon"), ("ratelimit-reset", "12")]),
                now
            ),
            Some(Duration::from_secs(12))
        );
        let reset = (now.as_second() + 100).to_string();
        assert_eq!(
            rate_wait(&headers(&[("ratelimit-reset", &reset)]), now),
            Some(Duration::from_secs(100))
        );
        assert_eq!(rate_wait(&headers(&[("retry-after", "-1")]), now), None);
        // The obsolete RFC 850 date form is not read; without a reset header there is no wait.
        assert_eq!(
            rate_wait(
                &headers(&[("retry-after", "Friday, 06-Nov-26 08:49:37 GMT")]),
                now
            ),
            None
        );
    }

    #[test]
    fn backoff_grows_with_jitter_of_a_quarter() {
        for attempt in 1..=2u32 {
            let base = Duration::from_millis(500 * u64::from(attempt));
            for _ in 0..200 {
                let wait = backoff(attempt);
                assert!(wait >= base && wait <= base + base / 4, "{wait:?}");
            }
        }
    }
}
