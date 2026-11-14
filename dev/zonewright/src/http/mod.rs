//! The HTTP transport shared by every HTTP provider client (design section 5).
//!
//! A client describes a request and how to read the answer; connection handling, timeouts,
//! retries, rate-limit handling, the size cap, redaction and logging live here.
//!
//! - [`Transport`] is the `reqwest` client of a [`Context`]: own `rustls` configuration with the
//!   `aws-lc-rs` provider passed explicitly, HTTP/1.1 only, no redirects, no proxy, no cookies,
//!   no decompression, connect and whole-request timeouts.
//! - [`Http`] is one provider client's handle on it: the provider ID for `tracing`, the client's
//!   [`Scrubber`], its static credential header, its request pacing and its error-message
//!   extractor. [`Http::send`] and [`Http::send_with_token`] run the retry rules of section 5.3
//!   and the status mapping of section 5.4.
//! - Helpers for provider families: [`TokenSource`], [`Keystone`], [`RateGate`], [`Poller`],
//!   [`pager`], [`ZoneCache`], the encoders in [`encode`] and the URL policy in [`url`].
//!
//! A typical bearer-token JSON call:
//!
//! ```text
//! let http = Http::builder(ctx, ProviderId::Cloudflare)
//!     .bearer("api_token", credentials.api_token.expose_secret())
//!     .build()?;
//! let api = Endpoint::parse("base_url", &config.base_url, ctx)?;
//! let url = api.url().path("/zones").query("name", zone.as_str()).build()?;
//! let response = http.send(&Request::get(url)).await?;
//! if !response.is_success() {
//!     return Err(http.reject(&response));
//! }
//! let zones: ZoneList = response.json("the zone listing is not in the expected form")?;
//! ```

// TEMPORARY (core phase): no client uses the transport yet.
#![allow(dead_code)]
// TEMPORARY (core phase): the re-exports have no user until the clients land; `dead_code` does
// not cover unused imports.
#![allow(unused_imports)]

pub(crate) mod encode;
pub(crate) mod gate;
pub(crate) mod keystone;
pub(crate) mod pager;
pub(crate) mod poll;
pub(crate) mod request;
mod retry;
pub(crate) mod tls;
pub(crate) mod token;
pub(crate) mod url;
pub(crate) mod zone_cache;

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;

pub(crate) use gate::RateGate;
pub(crate) use keystone::Keystone;
pub(crate) use poll::{PollStep, Poller, poll_interval};
pub(crate) use request::{Request, Response, TokenAuth};
pub(crate) use token::{Token, TokenSource, lifetime_until};
pub(crate) use url::{Endpoint, path_id};
pub(crate) use zone_cache::{Attempt, ZoneCache, ZoneId};

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use rustls::crypto::CryptoProvider;
use zeroize::Zeroizing;

use crate::context::{Context, ContextOptions};
use crate::error::Error;
use crate::id::ProviderId;
use crate::redact::{Detail, Scrubber};

use request::MessageFn;
use tls::{ClientIdentity, Trust};

/// The user agent without the application's suffix.
const USER_AGENT: &str = concat!("zonewright/", env!("CARGO_PKG_VERSION"));

/// The HTTP client of a [`Context`]. Cheap to clone; clones share connections.
#[derive(Clone)]
pub(crate) struct Transport {
    client: reqwest::Client,
    shared: Arc<Shared>,
}

/// What every HTTP client of one context is built from.
struct Shared {
    provider: Arc<CryptoProvider>,
    trust: Trust,
    user_agent: HeaderValue,
    connect_timeout: Duration,
    request_timeout: Duration,
    loopback_only: bool,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("loopback_only", &self.shared.loopback_only)
            .field(
                "no_ca_certificates",
                &self.shared.trust.no_ca_certificates(),
            )
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Builds the HTTP client of a context from its options (design section 5.1). An invalid
    /// extra root certificate is `Error::Config`.
    pub(crate) fn new(options: &ContextOptions) -> Result<Transport, Error> {
        let provider = tls::crypto_provider();
        let extra = tls::extra_roots(&options.extra_root_certificates)?;
        let trust = Trust::platform(extra, &provider)?;
        Transport::with_trust(options, provider, trust)
    }

    /// [`Transport::new`] with the verifier given.
    pub(crate) fn with_trust(
        options: &ContextOptions,
        provider: Arc<CryptoProvider>,
        trust: Trust,
    ) -> Result<Transport, Error> {
        let mut agent = String::from(USER_AGENT);
        if let Some(suffix) = &options.user_agent_suffix {
            agent.push(' ');
            agent.push_str(suffix);
        }
        let user_agent = HeaderValue::from_str(&agent).map_err(|_| Error::Config {
            detail: Detail::constant(
                "user_agent_suffix must be 1 to 128 printable ASCII characters",
            ),
        })?;
        let shared = Arc::new(Shared {
            provider,
            trust,
            user_agent,
            connect_timeout: options.connect_timeout,
            request_timeout: options.request_timeout,
            loopback_only: options.loopback_only,
        });
        let client = build_client(&shared, None)?;
        Ok(Transport { client, shared })
    }

    /// A second client with otherwise identical options that presents `identity` as its TLS
    /// client certificate. `reqwest` does not apply a client identity to a preconfigured TLS
    /// configuration, so this is a separate configuration and a separate client.
    pub(crate) fn with_identity(&self, identity: ClientIdentity) -> Result<Transport, Error> {
        Ok(Transport {
            client: build_client(&self.shared, Some(identity))?,
            shared: self.shared.clone(),
        })
    }

    /// True when the context refuses everything but loopback addresses.
    pub(crate) fn loopback_only(&self) -> bool {
        self.shared.loopback_only
    }
}

/// One `reqwest` client with the options of section 5.1.
fn build_client(
    shared: &Shared,
    identity: Option<ClientIdentity>,
) -> Result<reqwest::Client, Error> {
    let tls = tls::client_config(&shared.provider, &shared.trust, identity)?;
    reqwest::Client::builder()
        // The preconfigured path: `reqwest` uses this configuration as it is and does not look
        // for a process-wide crypto provider.
        .tls_backend_preconfigured(tls)
        .http1_only()
        // Credentials travel in headers and bodies; a 307 or 308 would replay them elsewhere.
        .redirect(reqwest::redirect::Policy::none())
        // Retries are the transport's (section 5.3), never `reqwest`'s.
        .retry(reqwest::retry::never())
        // `reqwest` reads HTTP_PROXY, HTTPS_PROXY and ALL_PROXY even without its
        // `system-proxy` feature; a variable set for another purpose must not route provider
        // credentials through a proxy.
        .no_proxy()
        .referer(false)
        .connect_timeout(shared.connect_timeout)
        .timeout(shared.request_timeout)
        .user_agent(shared.user_agent.clone())
        .build()
        .map_err(|_| Error::Config {
            detail: Detail::constant("the HTTP client could not be built"),
        })
}

/// One provider client's handle on the transport.
///
/// Built with [`Http::builder`] in the client's constructor, from every secret the client holds.
pub(crate) struct Http {
    transport: Transport,
    provider: ProviderId,
    scrubber: Scrubber,
    auth: Option<(HeaderName, HeaderValue)>,
    gate: Option<RateGate>,
    message: MessageFn,
}

impl fmt::Debug for Http {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http")
            .field("provider", &self.provider)
            .field("paced", &self.gate.is_some())
            .finish_non_exhaustive()
    }
}

impl Http {
    /// A builder for the handle of a client of `provider` on `ctx`'s transport.
    pub(crate) fn builder(ctx: &Context, provider: ProviderId) -> HttpBuilder {
        HttpBuilder::new(ctx.http().clone(), provider)
    }

    /// The provider this handle belongs to.
    pub(crate) fn provider(&self) -> ProviderId {
        self.provider
    }

    /// The client's scrubber.
    pub(crate) fn scrubber(&self) -> &Scrubber {
        &self.scrubber
    }

    /// Registers a secret obtained at run time (a token, a signed assertion) with the scrubber.
    pub(crate) fn remember(&self, secret: &str) {
        self.scrubber.remember(secret);
    }

    /// A [`Detail`] from text taken from a provider's answer, with every secret of the client
    /// removed.
    pub(crate) fn detail(&self, text: &str) -> Detail {
        self.scrubber.detail(text)
    }

    /// A [`Detail`] from a response body: the provider's error message where the body has a
    /// known shape, otherwise the start of the body; scrubbed; `status N` when empty.
    pub(crate) fn body_detail(&self, response: &Response) -> Detail {
        let text = response.text();
        let message = (self.message)(&text).unwrap_or_else(|| text.into_owned());
        if message.trim().is_empty() {
            self.scrubber
                .detail(&format!("status {}", response.status()))
        } else {
            self.scrubber.detail(&message)
        }
    }

    /// The default classification of an answer the client does not expect:
    /// `Error::Rejected` with the status and [`Http::body_detail`].
    pub(crate) fn reject(&self, response: &Response) -> Error {
        Error::Rejected {
            status: Some(response.status()),
            detail: self.body_detail(response),
        }
    }
}

/// Builds an [`Http`]. Problems are reported by [`HttpBuilder::build`], so that a constructor
/// is written as one chain.
#[must_use]
pub(crate) struct HttpBuilder {
    transport: Transport,
    provider: ProviderId,
    secrets: Vec<Zeroizing<String>>,
    auth: Option<(HeaderName, HeaderValue)>,
    gate: Option<Duration>,
    identity: Option<ClientIdentity>,
    message: MessageFn,
    error: Option<Error>,
}

impl HttpBuilder {
    fn new(transport: Transport, provider: ProviderId) -> HttpBuilder {
        HttpBuilder {
            transport,
            provider,
            secrets: Vec::new(),
            auth: None,
            gate: None,
            identity: None,
            message: request::default_message,
            error: None,
        }
    }

    /// Registers a secret with the client's scrubber: every field of the credentials, whether
    /// or not it is sent in a header. Besides the secret itself, its form-encoded spellings are
    /// registered as secrets of their own, so that an API that echoes an already form-encoded
    /// value (a form body, a query) encoded once more is recognized too.
    pub(crate) fn secret(mut self, secret: &str) -> HttpBuilder {
        if !secret.is_empty() {
            self.secrets.push(Zeroizing::new(secret.to_owned()));
            self.secrets.push(encode::form_component(secret, "+"));
            self.secrets.push(encode::form_component(secret, "%20"));
        }
        self
    }

    /// Sends `Authorization: Bearer <token>` with every request and registers the token.
    /// `field` names the credential in an error.
    pub(crate) fn bearer(self, field: &'static str, token: &str) -> HttpBuilder {
        self.auth_header(field, AUTHORIZATION, "Bearer ", token)
    }

    /// Sends header `name` with `prefix` and `secret` with every request and registers the
    /// secret. `field` names the credential in an error.
    pub(crate) fn auth_header(
        mut self,
        field: &'static str,
        name: HeaderName,
        prefix: &'static str,
        secret: &str,
    ) -> HttpBuilder {
        match request::sensitive_value(prefix, secret.as_bytes()) {
            Some(value) => self.auth = Some((name, value)),
            None => self.fail(Error::Config {
                detail: Detail::new(&format!(
                    "{field} contains a character that cannot be sent in an HTTP header"
                )),
            }),
        }
        self.secret(secret)
    }

    /// Sends `Authorization: Basic base64(user:password)` with every request and registers the
    /// password and the encoded value. The user is registered too: credentials objects carry it
    /// as a secret field.
    pub(crate) fn basic(mut self, user: &str, password: &str) -> HttpBuilder {
        let encoded = request::basic_credentials(user, password);
        match request::sensitive_value("Basic ", encoded.as_bytes()) {
            Some(value) => self.auth = Some((AUTHORIZATION, value)),
            None => self.fail(Error::Config {
                detail: Detail::constant("the basic credentials cannot be sent in an HTTP header"),
            }),
        }
        self.secret(user).secret(password).secret(&encoded)
    }

    /// Spaces requests by `interval` ([`RateGate`]).
    pub(crate) fn pacing(mut self, interval: Duration) -> HttpBuilder {
        self.gate = Some(interval);
        self
    }

    /// Presents a TLS client certificate: the client gets its own `reqwest` client with
    /// otherwise identical options. The key is registered as a secret.
    pub(crate) fn client_identity(mut self, cert_pem: &str, key_pem: &str) -> HttpBuilder {
        match ClientIdentity::from_pem(cert_pem, key_pem) {
            Ok(identity) => self.identity = Some(identity),
            Err(e) => self.fail(e),
        }
        self.secret(key_pem)
    }

    /// Extracts error messages with `message` instead of the default extractor.
    pub(crate) fn message(mut self, message: MessageFn) -> HttpBuilder {
        self.message = message;
        self
    }

    /// The handle, or the first problem met while building it.
    pub(crate) fn build(self) -> Result<Http, Error> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let transport = match self.identity {
            Some(identity) => self.transport.with_identity(identity)?,
            None => self.transport,
        };
        Ok(Http {
            transport,
            provider: self.provider,
            scrubber: Scrubber::new(self.secrets.iter().map(|s| s.as_str())),
            auth: self.auth,
            gate: self.gate.map(RateGate::new),
            message: self.message,
        })
    }

    fn fail(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}
