//! The acme-dns client: construction, `Debug` and the [`Provider`] implementation.
//!
//! This client does not use the generic TXT value layer (`values.rs`). Its three shapes all read
//! the rrset before writing, and acme-dns has no read: the only operation is an update that stores
//! a value in one of two rotating slots (see `api.rs`). `add_txt_value` therefore implements the
//! two-step contract of design sections 3.1 and 11.3 directly: the checks before any request, the
//! per-name lock of the context, then the decision about whether to send, made from the
//! context's memory of recent sends (`state.rs`).
//!
//! `check` sends nothing. The only request the API authenticates is the update, a write: there is
//! no request that tests credentials without storing a value (see `AcmeDns::check`).

use std::fmt;

use secrecy::{ExposeSecret as _, SecretString};
use tokio::time::Instant;

use crate::context::Context;
use crate::error::{Error, ErrorKind};
use crate::http::{Http, SendError};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::operation::Call;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;

use super::api::{self, Api};
use super::config::{self, AcmeDnsConfig, AcmeDnsCredentials, Registration};
use super::state::{Outcome, State};

/// Characters of a value the server accepts.
// Source: server `util.go`, `validTXT`: exactly 43 characters, all matching `[A-Za-z0-9_-]`
// (`SanitizeString` in `pkg/acmedns/util.go` removes everything else).
const VALUE_LEN: usize = 43;

/// The detail of every zone of a `check` report: what `check` cannot do.
const UNTESTED: &str = "the credentials were not tested: the only authenticated acme-dns request \
                        stores a value";

/// The acme-dns client.
///
/// Authenticates every request with the `X-Api-User` and `X-Api-Key` headers of one registration.
/// The API has a single operation, an update that stores a value in one of the registration's two
/// rotating slots, so this client offers `check` and `add_txt_value` only:
///
/// - `check` sends nothing and reports `credentials_verified: false`: the update is the only
///   request the server authenticates, and it is a write.
/// - `add_txt_value` accepts the name of a configured registration (its `fulldomain`) and a value
///   of exactly 43 characters of the base64url alphabet, the only thing the server accepts. It
///   always reports `AddOutcome::Accepted`: the state before and after cannot be observed, and
///   another writer may have displaced the value since. A value this process sent recently is not
///   sent again, because a repeat would be written into the other slot and displace a live neighbor
///   (design section 11.3, `docs/design/11-providers.md` in the repository). Such a suppressed
///   repeat is `Accepted` although nothing was sent, so a value that another writer (another
///   process, or a client with another `Context`) displaced since is not restored by it. Sends to
///   one name are at least 1.1 s apart, so that the server, which stamps its writes with whole
///   seconds, overwrites the oldest value.
/// - `remove_txt_value` is not offered: the server keeps the two most recent values and has no
///   delete. It returns `Error::Unsupported`; it does not pretend that the value is gone.
/// - `list_zones` and every record-level operation are not offered: the API has no read.
///
/// The update request is sent once, whatever happens.
pub struct AcmeDns {
    config: AcmeDnsConfig,
    api: Api,
    registrations: Vec<Registration>,
    /// The per-name locks of the context.
    locks: NameLocks,
    /// The context's memory of recent sends.
    state: State,
}

impl fmt::Debug for AcmeDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings and the registrations' public names; no credential.
        f.debug_struct("AcmeDns")
            .field("config", &self.config)
            .field("registrations", &self.registrations)
            .finish_non_exhaustive()
    }
}

impl AcmeDns {
    /// Builds the client. Validates the settings and the registrations; makes no request.
    pub fn new(
        config: AcmeDnsConfig,
        credentials: AcmeDnsCredentials,
        ctx: &Context,
    ) -> Result<AcmeDns, Error> {
        let endpoint = config.validate(ctx)?;
        let registrations = credentials.parse_registrations()?;
        let mut http = Http::builder(ctx, ProviderId::AcmeDns)
            .endpoint(&endpoint)
            .code(api::error_code);
        for registration in &registrations {
            http = http
                .secret(registration.username.expose_secret())
                .secret(registration.password.expose_secret());
        }
        Ok(AcmeDns {
            api: Api::new(http.build()?, endpoint),
            config,
            registrations,
            locks: ctx.locks().clone(),
            state: ctx.acme_dns().clone(),
        })
    }

    /// The registration whose `fulldomain` is `name`.
    fn registration(&self, name: &DomainName) -> Option<&Registration> {
        self.registrations.iter().find(|r| &r.fulldomain == name)
    }

    /// The report of `check` for `zones` (the `check` of the `Provider` implementation below).
    fn check_zones(&self, zones: &[DomainName]) -> CheckReport {
        let checks = zones
            .iter()
            .map(|zone| {
                let found = self
                    .registrations
                    .iter()
                    .any(|r| r.fulldomain.is_within(zone));
                let detail = if found {
                    Detail::constant(UNTESTED)
                } else {
                    Detail::constant(
                        "no acme-dns registration is configured in this zone; the credentials \
                         were not tested",
                    )
                };
                ZoneCheck::new(zone.clone(), found, Some(detail))
            })
            .collect();
        CheckReport::new(false, checks)
    }

    /// The work of `add_txt_value` (the `add_txt_value` of the `Provider` implementation below).
    async fn add(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        if zone.is_root() || zone.is_wildcard() {
            return Err(invalid("the zone must not be the root or a wildcard name"));
        }
        if !name.is_within(zone) {
            return Err(Error::name_outside_zone(name.clone(), zone.clone()));
        }
        if matches!(ttl, Some(RrsetTtl::Explicit(_))) {
            return Err(invalid(
                "the provider chooses the TTL; a requested TTL cannot be honored",
            ));
        }
        let Some(text) = acceptable(value) else {
            return Err(invalid(
                "acme-dns accepts only a value of exactly 43 characters of the base64url \
                 alphabet (A-Z, a-z, 0-9, - and _)",
            ));
        };
        let Some(registration) = self.registration(name) else {
            return Err(invalid(
                "no configured acme-dns registration has this name as its fulldomain; the \
                 challenge name must be a CNAME to the fulldomain of a registration",
            ));
        };

        let _guard = self.locks.lock(name).await;
        let server = self.api.server();
        // Wait out the pace before anything is recorded: a future dropped while it waits leaves
        // no trace in the memory.
        if let Some(at) = self.state.pace(server, name) {
            tokio::time::sleep_until(at).await;
        }
        let begin = self.state.begin(server, name, text, Instant::now());
        if !begin.send {
            // This process sent the value recently (or an unconfirmed send is still pending next
            // to a live neighbor): a repeat would be written into the other slot.
            return Ok(AddOutcome::Accepted);
        }
        if begin.displaced.is_some() {
            tracing::warn!(
                provider = "acme_dns",
                "acme-dns keeps two values per registration: this send displaces the oldest \
                 value this process sent for the name"
            );
        }
        let result = self.api.store(registration, text).await;
        let outcome = match &result {
            Ok(()) => Outcome::Confirmed,
            Err(e) if refused(e) => Outcome::Refused,
            Err(_) => Outcome::Unknown,
        };
        self.state
            .finish(server, name, text, outcome, begin.displaced, Instant::now());
        result
            .map(|()| AddOutcome::Accepted)
            .map_err(SendError::into_error)
    }
}

/// The value as text, if it is one the server accepts.
fn acceptable(value: &Txt) -> Option<&str> {
    let bytes = value.as_bytes();
    let alphabet = |b: &u8| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_';
    if bytes.len() == VALUE_LEN && bytes.iter().all(alphabet) {
        value.as_str()
    } else {
        None
    }
}

/// True when the error says the request did not change anything at the server: the transport
/// knows it never reached the server (refused before it was sent, or no connection could be
/// established: `SendError::certainly_unsent`), or the server answered with a refusal (a 4xx
/// status, mapped to `Auth`, `Forbidden`, `RateLimited` or `Rejected`). Anything else leaves the
/// outcome unknown: a timeout, a connection lost after it was established, a 5xx, an answer that
/// cannot be read, and an error the transport raises itself without being certain that nothing
/// was sent, such as a refused certificate (`Config`; in TLS 1.3 the server can refuse the client
/// certificate after the client has started to send). The error kind alone never decides that a
/// request was not sent.
///
/// A failed connection must count as a refusal: as an unknown outcome it would stay in the memory
/// as an unconfirmed send, and next to a live neighbor every repeat within the memory's lifetime
/// would be suppressed and reported `Accepted`, although the value never reached the server.
fn refused(error: &SendError) -> bool {
    error.certainly_unsent()
        || matches!(
            error.error().kind(),
            ErrorKind::Auth | ErrorKind::Forbidden | ErrorKind::RateLimited | ErrorKind::Rejected
        )
}

fn invalid(text: &'static str) -> Error {
    Error::InvalidInput {
        detail: Detail::constant(text),
        code: None,
    }
}

impl Provider for AcmeDns {
    fn id(&self) -> ProviderId {
        ProviderId::AcmeDns
    }

    /// Sends nothing and reports `credentials_verified: false`: the provider has no request that
    /// tests credentials (design section 2.6, `docs/design/02-public-api.md` in the repository).
    ///
    /// The update is the only request the server authenticates, and it is a write. An update with
    /// an invalid value would test the credentials without storing anything only because the
    /// server validates the value after authentication and before the write; that is what the
    /// server's source does in every release (`update.go`, `validTXT` before `DB.Update`), but the
    /// README does not promise it, and a server that speaks the same API with a looser check would
    /// store the value in one of the two slots and displace a live challenge value. The client
    /// does not take that risk to fill in a report.
    ///
    /// A zone is reported as found when a configured registration's `fulldomain` is within it,
    /// which is what the client can know; every zone's detail says that the credentials were not
    /// tested. The client cannot verify that the application's `_acme-challenge` CNAME points to
    /// a `fulldomain`, or that the server answers for it in DNS.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async { Ok(self.check_zones(&zones)) })
            .await
    }

    /// Stores `value` in the registration whose `fulldomain` is `name`; always `Accepted`.
    ///
    /// Checked before any request: the zone is neither the root nor a wildcard; `name` is within
    /// `zone` (`NameOutsideZone`); no explicit TTL is requested (the server chooses it, so
    /// `RrsetTtl::ProviderDefault` is accepted); `value` is 43 characters of `A-Z a-z 0-9 - _`;
    /// `name` is the `fulldomain` of a configured registration (`InvalidInput`, so the caller
    /// sees that the CNAME or the configuration is wrong).
    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        Call::add_txt_value(zone, name)
            .observe(self, self.add(zone, name, value, ttl))
            .await
    }

    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones().unsupported(self).await
    }

    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        Call::list_rrsets(zone).unsupported(self).await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        Call::get_rrset(zone, name, rtype).unsupported(self).await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        _expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        Call::set_rrset(zone, rrset).unsupported(self).await
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        _expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        Call::delete_rrset(zone, name, rtype)
            .unsupported(self)
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        _value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name).unsupported(self).await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`AcmeDns::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<AcmeDns, Error> {
    AcmeDns::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{context, options};

    /// A connection that cannot be established is a refusal: the transport reports that the
    /// request never reached the server.
    #[tokio::test]
    async fn a_failed_connection_is_a_refusal() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let ctx = context(options());
        let registrations = r#"{"username":"c36f50e8-4632-4000-8000-000000000001","password":"htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KWtest","subdomain":"aaaa","fulldomain":"aaaa.auth.example.org"}"#;
        let client = AcmeDns::new(
            AcmeDnsConfig::new(format!("http://127.0.0.1:{port}")),
            AcmeDnsCredentials::new(SecretString::from(registrations)),
            &ctx,
        )
        .unwrap();
        let registration = client.registrations.first().unwrap();
        let e = client
            .api
            .store(registration, &"A".repeat(VALUE_LEN))
            .await
            .unwrap_err();
        assert_eq!(e.error().kind(), ErrorKind::Transient, "{e:?}");
        assert!(e.certainly_unsent(), "{e:?}");
        assert!(refused(&e), "{e:?}");
    }

    /// A transient error after the request may have reached the server leaves the outcome
    /// unknown; an answer that refuses the request is a refusal.
    #[test]
    fn only_certain_refusals_are_refusals() {
        let transient = SendError::answered(Error::Transient {
            detail: Detail::constant("the request to the provider timed out"),
        });
        assert!(!refused(&transient));
        let rejected = SendError::answered(Error::Rejected {
            status: Some(400),
            detail: Detail::constant("bad value"),
            code: None,
        });
        assert!(refused(&rejected));
        let local = SendError::before_send(Error::Transient {
            detail: Detail::constant("not sent"),
        });
        assert!(refused(&local));
    }

    /// An error the transport raises itself is a refusal only when the transport is certain that
    /// nothing was sent: a refused certificate (`Config`, not certainly unsent) leaves the
    /// outcome unknown, the same kind refused before any connection is a refusal.
    #[test]
    fn transport_errors_count_only_when_certainly_unsent() {
        let certificate = || Error::Config {
            detail: Detail::constant(
                "the provider's TLS certificate, or the client certificate, was not accepted",
            ),
        };
        assert!(!refused(&SendError::answered(certificate())));
        assert!(refused(&SendError::before_send(certificate())));
        let build = || Error::InvalidInput {
            detail: Detail::constant("the HTTP request could not be built"),
            code: None,
        };
        assert!(!refused(&SendError::answered(build())));
        assert!(refused(&SendError::before_send(build())));
    }
}
