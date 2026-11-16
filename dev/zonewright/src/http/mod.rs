//! The HTTP transport shared by every HTTP provider client (design section 5).
//!
//! A client describes a request and how to read the answer; connection handling, timeouts,
//! retries, rate-limit handling, the size cap, redaction and logging live here.
//!
//! - [`Transport`] is the `reqwest` client of a [`Context`]: own `rustls` configuration with the
//!   `aws-lc-rs` provider passed explicitly, HTTP/1.1 only, no redirects, no proxy from the
//!   environment (only the explicit `ContextOptions::proxy`, see [`proxy`]), no cookies, no
//!   decompression, connect and whole-request timeouts.
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
//! let api = Endpoint::parse("base_url", &config.base_url, ctx)?;
//! let http = Http::builder(ctx, ProviderId::Cloudflare)
//!     .endpoint(&api)
//!     .bearer("api_token", credentials.api_token.expose_secret())
//!     .build()?;
//! let url = api.url().path("/zones").query("name", zone.as_str()).build()?;
//! let response = http.send(&Request::get(url)).await?;
//! if !response.is_success() {
//!     return Err(http.reject(&response));
//! }
//! let zones: ZoneList = response.json("the zone listing is not in the expected form")?;
//! ```

// Design section 9.2: not every provider uses every shared helper, so builds without
// `all-providers` allow unused code here; the build with all providers does not, so that a
// helper no provider uses is found.
#![cfg_attr(not(feature = "all-providers"), allow(dead_code))]

pub(crate) mod encode;
pub(crate) mod gate;
pub(crate) mod keystone;
pub(crate) mod pager;
pub(crate) mod poll;
pub(crate) mod proxy;
pub(crate) mod request;
mod retry;
pub(crate) mod roots;
pub(crate) mod tls;
pub(crate) mod token;
pub(crate) mod url;
pub(crate) mod zone_cache;

#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;

// Each re-export is compiled with the clients that import it, so that a build with only some
// providers has no unused import (the items themselves are covered by the `dead_code` allowance
// above).
pub(crate) use gate::RateGate;
#[cfg(any(feature = "selectel_v2", feature = "vk_cloud"))]
pub(crate) use keystone::Keystone;
#[cfg(any(feature = "cloud_ru", feature = "hetzner", feature = "yandex_cloud"))]
pub(crate) use poll::poll_interval;
#[cfg(any(
    feature = "cloud_ru",
    feature = "hetzner",
    feature = "route53",
    feature = "yandex_cloud"
))]
pub(crate) use poll::{PollStep, Poller};
#[cfg(any(
    feature = "acme_dns",
    feature = "beget",
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "digitalocean",
    feature = "hetzner",
    feature = "nicru",
    feature = "regru",
    feature = "route53",
    feature = "selectel_v2",
    feature = "timeweb_cloud",
    feature = "vk_cloud",
    feature = "yandex_360",
    feature = "yandex_cloud"
))]
pub(crate) use request::Request;
pub(crate) use request::Response;
#[cfg(any(feature = "cloud_ru", feature = "nicru", feature = "yandex_cloud"))]
pub(crate) use request::TokenAuth;
#[cfg(feature = "route53")]
pub(crate) use request::{Finish, Outgoing};
#[cfg(feature = "acme_dns")]
pub(crate) use retry::SendError;
#[cfg(any(
    feature = "cloud_ru",
    feature = "nicru",
    feature = "selectel_v2",
    feature = "yandex_cloud"
))]
pub(crate) use token::Token;
#[cfg(any(
    feature = "cloud_ru",
    feature = "nicru",
    feature = "selectel_v2",
    feature = "vk_cloud",
    feature = "yandex_cloud"
))]
pub(crate) use token::TokenSource;
#[cfg(feature = "yandex_cloud")]
pub(crate) use token::lifetime_until;
#[cfg(any(
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "route53",
    feature = "selectel_v2",
    feature = "vk_cloud",
    feature = "yandex_cloud"
))]
pub(crate) use url::path_id;
pub(crate) use url::{Endpoint, Origin};
#[cfg(any(
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "hetzner",
    feature = "selectel_v2",
    feature = "vk_cloud",
    feature = "yandex_cloud"
))]
pub(crate) use zone_cache::ZoneId;
#[cfg(any(
    feature = "cloud_ru",
    feature = "cloudflare",
    feature = "hetzner",
    feature = "route53",
    feature = "selectel_v2",
    feature = "vk_cloud",
    feature = "yandex_cloud"
))]
pub(crate) use zone_cache::{Attempt, ZoneCache};

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use rustls::crypto::CryptoProvider;
use zeroize::Zeroizing;

use crate::context::{Context, ContextOptions};
use crate::error::Error;
use crate::id::ProviderId;
use crate::redact::{Detail, Scrubber, SecretSlot};

use proxy::ProxySetting;
use request::MessageFn;

/// A client's classifier of further rate-limit answers ([`HttpBuilder::rate_limit`]).
pub(crate) type RateLimitFn = fn(&Response) -> bool;
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
    /// The explicit proxy of the context, if any.
    proxy: Option<ProxySetting>,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("loopback_only", &self.shared.loopback_only)
            .field("proxied", &self.shared.proxy.is_some())
            .field(
                "no_ca_certificates",
                &self.shared.trust.no_ca_certificates(),
            )
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// Builds the HTTP client of a context from its options (design section 5.1). An invalid
    /// trust setting (an extra root certificate, a set of roots this build cannot provide, no
    /// root at all) or proxy setting is `Error::Config`.
    pub(crate) fn new(options: &ContextOptions) -> Result<Transport, Error> {
        let provider = tls::crypto_provider();
        let trust = Trust::from_options(options, &provider)?;
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
        let proxy = options
            .proxy
            .as_ref()
            .map(|proxy| ProxySetting::parse(proxy, options.loopback_only))
            .transpose()?;
        let shared = Arc::new(Shared {
            provider,
            trust,
            user_agent,
            connect_timeout: options.connect_timeout,
            request_timeout: options.request_timeout,
            loopback_only: options.loopback_only,
            proxy,
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
}

/// One `reqwest` client with the options of section 5.1.
fn build_client(
    shared: &Shared,
    identity: Option<ClientIdentity>,
) -> Result<reqwest::Client, Error> {
    let tls = tls::client_config(&shared.provider, &shared.trust, identity)?;
    let mut builder = reqwest::Client::builder()
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
        // Covers the whole connector: the TCP connection (to the proxy, if any), the `CONNECT`
        // exchange and the TLS handshake with the provider.
        .connect_timeout(shared.connect_timeout)
        .timeout(shared.request_timeout)
        .user_agent(shared.user_agent.clone());
    // After `no_proxy`, which clears the list: the explicit proxy is the only one, and adding it
    // keeps the environment unread (`auto_sys_proxy = false` in `ClientBuilder::proxy`).
    if let Some(proxy) = &shared.proxy {
        builder = builder.proxy(proxy.reqwest());
    }
    builder.build().map_err(|_| Error::Config {
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
    /// Marks further answers as rate-limit answers, treated like a 429.
    rate_limit: Option<RateLimitFn>,
    /// The origins of the client's endpoints: the only hosts its requests may go to.
    origins: Vec<Origin>,
    /// True when the transport presents a client certificate.
    identity: bool,
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

    /// The client's scrubber.
    pub(crate) fn scrubber(&self) -> &Scrubber {
        &self.scrubber
    }

    /// Registers a secret obtained at run time as the current secret of `slot` (see
    /// [`SecretSlot`]). Tokens used through [`Http::send_with_token`] are registered by the
    /// transport under their [`TokenSource`]'s slot; a client that signs assertions (a JWT)
    /// registers each one under a slot of its own.
    pub(crate) fn remember(&self, slot: &SecretSlot, secret: &str) {
        self.scrubber.remember(slot, secret);
    }

    /// A [`Detail`] from text taken from a provider's answer, with every secret of the client
    /// removed.
    pub(crate) fn detail(&self, text: &str) -> Detail {
        self.scrubber.detail(text)
    }

    /// A [`Detail`] from a response body, scrubbed: the provider's error message where the
    /// body has a known shape; for any other JSON body, its string values
    /// decoded (never the raw JSON text, whose escapes the scrubber may not know); otherwise the
    /// start of the body. `status N` when empty.
    pub(crate) fn body_detail(&self, response: &Response) -> Detail {
        let text = response.text();
        let message = (self.message)(&text)
            .or_else(|| request::json_strings(response.body()))
            .unwrap_or_else(|| text.into_owned());
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
    rate_limit: Option<RateLimitFn>,
    origins: Vec<Origin>,
    error: Option<Error>,
}

impl HttpBuilder {
    fn new(transport: Transport, provider: ProviderId) -> HttpBuilder {
        let shared = transport.shared.clone();
        let builder = HttpBuilder {
            transport,
            provider,
            secrets: Vec::new(),
            auth: None,
            gate: None,
            identity: None,
            message: request::default_message,
            rate_limit: None,
            origins: Vec::new(),
            error: None,
        };
        // The context's proxy credentials are secrets of every client: a forwarding proxy's
        // error answer can echo them, and that answer goes through the client's scrubber.
        let proxy_secrets = shared.proxy.iter().flat_map(ProxySetting::secrets);
        proxy_secrets.fold(builder, HttpBuilder::secret)
    }

    /// Registers a secret with the client's scrubber: every field of the credentials, whether
    /// or not it is sent in a header. Besides the secret itself, its form-encoded and
    /// percent-encoded spellings are registered as secrets of their own, so that an API that
    /// echoes an already encoded value (a form body, a query) encoded once more is replaced in
    /// place too.
    pub(crate) fn secret(mut self, secret: &str) -> HttpBuilder {
        if !secret.is_empty() {
            self.secrets.push(Zeroizing::new(secret.to_owned()));
            self.secrets.push(encode::form_component(secret, "+"));
            self.secrets.push(encode::form_component(secret, "%20"));
            self.secrets.push(Zeroizing::new(encode::percent(secret)));
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

    /// Declares an endpoint of the client: the API, the identity or token service. Requests
    /// may go only to the origins (scheme, host, port) of declared endpoints; a request to any
    /// other origin is refused before it is sent, so that no credential reaches a host the
    /// client was not configured with. A client with a static credential or a client
    /// certificate must declare at least one endpoint; a request with a cached token is refused
    /// when none is declared.
    pub(crate) fn endpoint(mut self, endpoint: &Endpoint) -> HttpBuilder {
        let origin = endpoint.origin();
        if !self.origins.contains(&origin) {
            self.origins.push(origin);
        }
        self
    }

    /// Spaces requests by `interval` ([`RateGate`]).
    pub(crate) fn pacing(mut self, interval: Duration) -> HttpBuilder {
        self.gate = Some(interval);
        self
    }

    /// Presents a TLS client certificate: the client gets its own `reqwest` client with
    /// otherwise identical options.
    ///
    /// The key is not registered with the scrubber: private key material (PEM or DER) is
    /// never sent to a provider — TLS uses it to sign only — so no API can echo it, and a
    /// multi-line PEM document makes needles that match nothing an API returns. The same holds
    /// for a key a client uses to sign assertions; the signed assertions are registered instead.
    pub(crate) fn client_identity(mut self, cert_pem: &str, key_pem: &str) -> HttpBuilder {
        match ClientIdentity::from_pem(cert_pem, key_pem) {
            Ok(identity) => self.identity = Some(identity),
            Err(e) => self.fail(e),
        }
        self
    }

    /// Extracts error messages with `message` instead of the default extractor.
    pub(crate) fn message(mut self, message: MessageFn) -> HttpBuilder {
        self.message = message;
        self
    }

    /// Declares further rate-limit answers: an answer for which `classify` is true is treated
    /// exactly like a 429 (design section 5.3), for a provider that signals a refused request
    /// rate with another status. It sees every answer that is not kept with
    /// [`Request::keep_status`].
    pub(crate) fn rate_limit(mut self, classify: RateLimitFn) -> HttpBuilder {
        self.rate_limit = Some(classify);
        self
    }

    /// The handle, or the first problem met while building it.
    pub(crate) fn build(self) -> Result<Http, Error> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let identity = self.identity.is_some();
        if (identity || self.auth.is_some()) && self.origins.is_empty() {
            return Err(Error::Config {
                detail: Detail::constant(
                    "a client with credentials must declare the endpoints they may be sent to",
                ),
            });
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
            rate_limit: self.rate_limit,
            origins: self.origins,
            identity,
        })
    }

    fn fail(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}
