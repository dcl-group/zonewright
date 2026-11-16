//! The OVHcloud `/domain/zone` API as this client uses it: the request signature, the server
//! clock, one function per endpoint, the wire types and the classification of answers. Nothing
//! here knows the value layer; `client.rs`, `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3), all read on 2026-11-16:
//!
//! - [Schema]: <https://eu.api.ovh.com/1.0/domain.json>, the provider's API schema for
//!   `/domain`: the paths and operations below with their parameters and answers
//!   (`getZones`: `string[]`; `getRecords`: `long[]` with the optional filters `fieldType`,
//!   "Filter the value of fieldType property (like)", and `subDomain`, "Filter the value of
//!   subDomain property (ilike)"; `getRecord`, `createRecord`, `editRecord`, `deleteRecord`, each
//!   "The change applies after the zone is refreshed"; `refreshZone`, "Applies the pending record
//!   changes to the zone"), the models `domain.zone.Record` (no member `required`; `subDomain`
//!   and `ttl` may be `null`), `domain.zone.RecordCreate` (`fieldType` and `target` required,
//!   `subDomain` and `ttl` optional) and `domain.zone.RecordUpdate` (`subDomain`, `target`,
//!   `ttl`, none required), and the record types of `domain.zone.RecordTypeEnum`.
//! - [Auth schema]: <https://eu.api.ovh.com/1.0/auth.json>: `GET /auth/time`, "Get the current
//!   time of the OVH servers, since UNIX epoch", without authentication.
//! - [go-ovh]: <https://github.com/ovh/go-ovh>, the provider's own client, `ovh/ovh.go`: the
//!   headers `X-Ovh-Application`, `X-Ovh-Consumer`, `X-Ovh-Timestamp`, `X-Ovh-Signature`; the
//!   signature `"$1$" + hex(SHA1(AS + "+" + CK + "+" + METHOD + "+" + URL + "+" + BODY + "+" +
//!   TIMESTAMP))` over the full target URL and the exact body; the timestamp corrected by the
//!   difference between the local clock and `/auth/time`, read once per client and kept;
//!   `ovh/error.go`: the error body `class`, `message`, `details`.
//! - [First steps]: <https://docs.ovhcloud.com/en/guides/manage-and-operate/api/first-steps>:
//!   the same signature formula, `"$1$" + SHA1_HEX(AS+"+"+CK+"+"+METHOD+"+"+QUERY+"+"+BODY+
//!   "+"+TSTAMP)`.
//! - [Service accounts]: <https://docs.ovhcloud.com/en/guides/account-and-service-management/account-information/authenticate-api-with-service-account.md>:
//!   the error body of a refusal, `{"class":"Client::Forbidden","message":"User not granted for
//!   this request"}` with status 403.
//! - lego `providers/dns/ovh/ovh.go`: `POST /domain/zone/{zone}/record` with `fieldType`,
//!   `subDomain` (left out for the apex), `target` (the value itself) and `ttl`, then
//!   `POST /domain/zone/{zone}/refresh`; `DELETE .../record/{id}`, then the refresh.
//! - dns-update `src/providers/ovh.rs`: the list with `fieldType` and `subDomain`, one
//!   `GET .../record/{id}` per identifier, the type checked again on the client's side.
//! - [Terraform]: the provider's Terraform provider,
//!   <https://github.com/ovh/terraform-provider-ovh/blob/master/ovh/resource_domain_zone_record.go>:
//!   a create answer may lack the identifier ("this is an API response BUG known by OVH team");
//!   a read of a record right after its create may answer `404` for a while (it retries such a
//!   read for up to one minute); a refresh after every create, update and delete; the update
//!   body with `target` and `ttl` and, when not empty, `subDomain`.
//!
//! Endpoints used, all below the endpoint (`.../1.0`):
//!
//! | Call          | Request                                        | Answer                 |
//! | ------------- | ---------------------------------------------- | ---------------------- |
//! | server time   | `GET /auth/time`, not signed                   | an integer             |
//! | list zones    | `GET /domain/zone`                             | the zones' names       |
//! | list records  | `GET /domain/zone/{zone}/record?fieldType&subDomain` | the records' ids |
//! | read record   | `GET /domain/zone/{zone}/record/{id}`          | the record             |
//! | create record | `POST /domain/zone/{zone}/record`              | the record (unused)    |
//! | update record | `PUT /domain/zone/{zone}/record/{id}`          | nothing                |
//! | delete record | `DELETE /domain/zone/{zone}/record/{id}`       | nothing                |
//! | refresh zone  | `POST /domain/zone/{zone}/refresh`             | nothing                |
//!
//! `import`, `reset` and the `soa` endpoint are never used: the first two replace the zone's
//! content.
//!
//! [Schema]: https://eu.api.ovh.com/1.0/domain.json
//! [Auth schema]: https://eu.api.ovh.com/1.0/auth.json
//! [go-ovh]: https://github.com/ovh/go-ovh
//! [First steps]: https://docs.ovhcloud.com/en/guides/manage-and-operate/api/first-steps
//! [Service accounts]: https://docs.ovhcloud.com/en/guides/account-and-service-management/account-information/authenticate-api-with-service-account.md
//! [Terraform]: https://github.com/ovh/terraform-provider-ovh

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Method, Url};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::{hex_lower, sha1};
use crate::error::Error;
use crate::http::request::sensitive_value;
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Finish, Http, Outgoing, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// The header that carries the consumer key (go-ovh `NewRequest`).
pub(super) const X_OVH_CONSUMER: HeaderName = HeaderName::from_static("x-ovh-consumer");
/// The header that carries the application key (go-ovh `NewRequest`).
const X_OVH_APPLICATION: HeaderName = HeaderName::from_static("x-ovh-application");
/// The header that carries the signature's timestamp (go-ovh `NewRequest`).
const X_OVH_TIMESTAMP: HeaderName = HeaderName::from_static("x-ovh-timestamp");
/// The header that carries the signature (go-ovh `NewRequest`).
const X_OVH_SIGNATURE: HeaderName = HeaderName::from_static("x-ovh-signature");

/// Most records one read fetches one by one. The listing call answers identifiers only, and
/// every record costs a request of its own (dns-update `list_at`); a zone or a name with more
/// records than this cannot be read, which is `Error::Protocol` rather than a partial read.
pub(super) const MAX_RECORDS: usize = 1000;

/// How many times a record whose identifier is still listed is read before the read gives up.
// Source: Terraform, `ovhDomainZoneRecord`: a record read right after its create may answer
// `404`, and the provider's own Terraform provider retries that read for up to one minute. This
// client reads a listed record at most this often, with pauses of the `read_retry_ms` setting
// doubling (1, 2 and 4 seconds by default), and then fails with `Error::Transient` instead of
// reporting the record as absent.
const READ_ATTEMPTS: u32 = 4;

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// A record as `GET .../record/{id}` returns it. No member is required by the schema; what the
/// client needs is checked by [`Api::record`].
// Source: Schema, `domain.zone.Record`: `id` (long), `zone` (string), `subDomain` (string,
// "canBeNull": true), `fieldType` (enum), `target` (string), `ttl` (long, "canBeNull": true), all
// with "required": false.
#[derive(Clone, Debug, Deserialize)]
struct WireRecord {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default, rename = "subDomain")]
    sub_domain: Option<String>,
    #[serde(default, rename = "fieldType")]
    field_type: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    ttl: Option<i64>,
}

/// A record as the client uses it, checked against the request that read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Record {
    /// The identifier.
    pub(super) id: u64,
    /// `subDomain` as the API stated it: `None` for `null` or a missing member.
    pub(super) sub_domain: Option<String>,
    /// The record type as the API spells it.
    pub(super) field_type: String,
    /// The value.
    pub(super) target: String,
    /// `ttl` as the API stated it: `None` for `null` or a missing member.
    pub(super) ttl: Option<i64>,
}

/// The filters of a listing: what the request determines about every record it answers.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Filter<'a> {
    /// `fieldType`, the API's spelling of the type.
    pub(super) field_type: Option<&'a str>,
    /// `subDomain`, the name relative to the zone; never empty.
    pub(super) sub_domain: Option<&'a str>,
}

/// The body of `POST .../record`.
// Source: Schema, `domain.zone.RecordCreate`: `fieldType` and `target` required, `subDomain`
// and `ttl` optional; `id` and `zone` are read-only and never sent. lego sends the four members
// below and leaves `subDomain` out for the apex.
#[derive(Debug, Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "fieldType")]
    pub(super) field_type: &'a str,
    /// The name relative to the zone; left out for the apex.
    #[serde(rename = "subDomain", skip_serializing_if = "Option::is_none")]
    pub(super) sub_domain: Option<&'a str>,
    /// The value.
    pub(super) target: &'a str,
    /// TTL in seconds: `0`, or left out, for a record created next to records that state no
    /// TTL in that form (see `records.rs`, [`Unstated`](super::records::Unstated)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
}

/// The body of `PUT .../record/{id}`.
// Source: Schema, `domain.zone.RecordUpdate` (`subDomain`, `target`, `ttl`, none required);
// Terraform sends `target` and `ttl` always and `subDomain` when it is not empty. This client
// sends `subDomain` and `ttl` exactly as read when they do not change, so that nothing the
// record holds is dropped; a `ttl` read as `null` is left out. Assumption (not documented, not
// observed against the live API): that a missing `ttl` leaves the record's TTL as it is.
#[derive(Debug, Serialize)]
pub(super) struct RecordUpdate<'a> {
    /// The name relative to the zone, as read; left out for the apex.
    #[serde(rename = "subDomain", skip_serializing_if = "Option::is_none")]
    pub(super) sub_domain: Option<&'a str>,
    /// The value.
    pub(super) target: &'a str,
    /// TTL in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<i64>,
}

/// The answer to an update or a delete.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`. Its meaning is not documented; the caller confirms by a read what is gone, and
    /// returns this refusal when the read does not explain it.
    NotFound(Error),
}

/// How long a reading of the server's clock is used before `/auth/time` is read again. The
/// client's own choice, not a fact of the API: a monotonic clock does not count the time a host
/// was suspended on every platform, so a reading is not trusted for ever.
const CLOCK_MAX_AGE: Duration = Duration::from_secs(3600);

/// One reading of the server's clock: its seconds since the Unix epoch, and the monotonic instant
/// of the reading. A timestamp is the reading plus the time elapsed since, so the local wall
/// clock plays no part once the reading is made.
#[derive(Clone, Copy, Debug)]
struct ServerClock {
    server: i64,
    read_at: Instant,
}

impl ServerClock {
    /// The server's time at `now`, in whole seconds.
    fn timestamp(&self, now: Instant) -> i64 {
        let elapsed = now.saturating_duration_since(self.read_at).as_secs();
        self.server
            .saturating_add(i64::try_from(elapsed).unwrap_or(i64::MAX))
    }

    /// The reading is older than [`CLOCK_MAX_AGE`] at `now`.
    fn stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.read_at) >= CLOCK_MAX_AGE
    }
}

/// Signs every attempt of a request right before the transport sends it, over exactly what the
/// attempt sends, with a timestamp on the server's clock (go-ovh `NewRequest`). A repeated
/// attempt carries a timestamp and a signature of its own.
///
/// The application secret is never sent; the consumer key goes in its own header, set by the
/// transport. Both are registered with the client's scrubber when the client is built.
pub(super) struct Signer {
    application_key: HeaderValue,
    application_secret: SecretString,
    consumer_key: SecretString,
    /// The last reading of the server's clock.
    clock: Mutex<Option<ServerClock>>,
}

impl Signer {
    /// The string the signature is computed over, in a buffer sized up front and wiped when
    /// dropped, so that no reallocation leaves a copy of the secret behind.
    fn signed_text(&self, attempt: &Outgoing<'_>, timestamp: i64) -> Zeroizing<Vec<u8>> {
        let secret = self.application_secret.expose_secret().as_bytes();
        let consumer = self.consumer_key.expose_secret().as_bytes();
        let method = attempt.method.as_str().as_bytes();
        let url = attempt.url.as_str().as_bytes();
        let stamp = timestamp.to_string();
        let capacity = [
            secret.len(),
            consumer.len(),
            method.len(),
            url.len(),
            attempt.body.len(),
            stamp.len(),
            5,
        ]
        .iter()
        .fold(0usize, |sum, n| sum.saturating_add(*n));
        let mut text = Zeroizing::new(Vec::with_capacity(capacity));
        for (i, part) in [
            secret,
            consumer,
            method,
            url,
            attempt.body,
            stamp.as_bytes(),
        ]
        .iter()
        .enumerate()
        {
            if i > 0 {
                text.push(b'+');
            }
            text.extend_from_slice(part);
        }
        text
    }

    /// `"$1$"` and the lowercase hexadecimal SHA-1 of the signed text.
    pub(super) fn signature(&self, attempt: &Outgoing<'_>, timestamp: i64) -> String {
        format!(
            "$1${}",
            hex_lower(&sha1(&self.signed_text(attempt, timestamp)))
        )
    }

    fn reading(&self) -> Option<ServerClock> {
        *self.clock.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Finish for Signer {
    fn finish(&self, attempt: &Outgoing<'_>) -> Result<Vec<(HeaderName, HeaderValue)>, Error> {
        let unsigned = || Error::InvalidInput {
            detail: Detail::constant("the request could not be signed"),
            code: None,
        };
        let clock = self.reading().ok_or_else(unsigned)?;
        let timestamp = clock.timestamp(Instant::now());
        let signature = self.signature(attempt, timestamp);
        Ok(vec![
            (X_OVH_APPLICATION, self.application_key.clone()),
            (
                X_OVH_TIMESTAMP,
                HeaderValue::from_str(&timestamp.to_string()).map_err(|_| unsigned())?,
            ),
            (
                X_OVH_SIGNATURE,
                sensitive_value("", signature.as_bytes()).ok_or_else(unsigned)?,
            ),
        ])
    }
}

/// What this client did in one zone, for the refresh rule of the client (see the client's
/// documentation, "Staged changes and the refresh").
#[derive(Clone, Copy, Debug, Default)]
struct Marks {
    /// Record writes started (counted right before they are sent).
    writes: u64,
    /// Record writes sent and not yet ended (answered, failed or dropped).
    in_flight: u64,
    /// The number of record writes that had ended when the last successful refresh was sent:
    /// every write counted up to it is published. A write still in flight at that moment is not
    /// counted, whatever the order in which the two requests reach the provider.
    published: u64,
    /// Requests about the zone started (reads, writes and refreshes).
    contacts: u64,
}

/// One record write in flight in `zone`, counted in [`Marks::in_flight`] for as long as this
/// value lives: it is dropped when the write is answered, when it fails, and when its future is
/// dropped at any await.
struct Flight<'a> {
    api: &'a Api,
    zone: &'a DomainName,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        // `with_marks` recovers a poisoned mutex, so this cannot panic.
        self.api.with_marks(self.zone, |m| {
            m.in_flight = m.in_flight.saturating_sub(1);
        });
    }
}

/// A snapshot of the counters of one zone, taken when an operation starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Contacts(u64);

/// The client's handle on the API: the transport, the endpoint, the signer, the pause between
/// reads of a listed record, and per zone what this client sent.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    signer: Arc<Signer>,
    read_pause: Duration,
    marks: Mutex<HashMap<DomainName, Marks>>,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .field("server_clock", &self.signer.reading().map(|c| c.server))
            .field("read_pause", &self.read_pause)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`, signing with these keys. `http` sends the consumer key. `read_pause`
    /// is the first pause before a listed record that answered `404` is read again.
    pub(super) fn new(
        http: Http,
        base: Endpoint,
        application_key: &str,
        application_secret: SecretString,
        consumer_key: SecretString,
        read_pause: Duration,
    ) -> Result<Api, Error> {
        let application_key =
            HeaderValue::from_str(application_key).map_err(|_| Error::Config {
                detail: Detail::constant(
                    "application_key contains a character that cannot be sent in an HTTP header",
                ),
            })?;
        Ok(Api {
            http,
            base,
            signer: Arc::new(Signer {
                application_key,
                application_secret,
                consumer_key,
                clock: Mutex::new(None),
            }),
            read_pause,
            marks: Mutex::new(HashMap::new()),
        })
    }

    fn with_marks<R>(&self, zone: &DomainName, f: impl FnOnce(&mut Marks) -> R) -> R {
        let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
        f(marks.entry(zone.clone()).or_default())
    }

    /// The requests about `zone` this client has started so far.
    pub(super) fn contacts(&self, zone: &DomainName) -> Contacts {
        Contacts(self.with_marks(zone, |m| m.contacts))
    }

    /// A refresh of `zone` is owed: this client started a record write there that no successful
    /// refresh has published yet (its outcome may be unknown, or its operation dropped), or one
    /// that was still in flight when the last successful refresh was sent.
    pub(super) fn owed(&self, zone: &DomainName) -> bool {
        self.with_marks(zone, |m| m.writes > m.published)
    }

    /// `GET /auth/time`: the server's clock, in seconds since the Unix epoch. Not signed.
    // Source: Auth schema, `GET /auth/time` ("noAuthentication"); go-ovh `getTime` reads the
    // answer as one integer.
    async fn server_time(&self) -> Result<i64, Error> {
        let url = self.base.url().path("/auth/time").build()?;
        let response = self.http.send(&Request::get(url).anonymous()).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response.json("the provider's time answer is not an integer")
    }

    /// Reads the server's clock before the first signed request, and again once the reading is
    /// older than [`CLOCK_MAX_AGE`]. go-ovh reads it once per client (`getTimeDelta`) and keeps
    /// the difference to the local wall clock; this client keeps the reading with a monotonic
    /// instant instead, so that a step of the local wall clock changes nothing. A failed read is
    /// not remembered. No documented refusal names the timestamp as its cause, so a refusal does
    /// not trigger a new reading.
    ///
    /// The answer is not signed and is trusted as it comes, over the same connection policy as
    /// every other request: whoever can forge it can make every signed request fail, or make
    /// the client sign requests with a future timestamp, which that party could replay (each
    /// one exact request: method, URL, body) for as long as the server accepts the timestamp.
    /// No secret is exposed by it.
    async fn ensure_clock(&self) -> Result<(), Error> {
        let current = self.signer.reading();
        if current.is_none_or(|c| c.stale(Instant::now())) {
            let server = self.server_time().await?;
            let reading = ServerClock {
                server,
                read_at: Instant::now(),
            };
            *self
                .signer
                .clock
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(reading);
        }
        Ok(())
    }

    /// Sends `request` signed on every attempt ([`Signer`]).
    async fn send(&self, request: Request) -> Result<Response, Error> {
        self.ensure_clock().await?;
        self.http
            .send(&request.finish_with(self.signer.clone()))
            .await
    }

    /// [`Api::send`] for a request about `zone`, counted as a contact with it.
    async fn send_in(&self, zone: &DomainName, request: Request) -> Result<Response, Error> {
        self.ensure_clock().await?;
        self.with_marks(zone, |m| m.contacts = m.contacts.saturating_add(1));
        self.send(request).await
    }

    /// [`Api::send_in`] for a record write, counted as one right before it is sent (after the
    /// clock is read, so that a write that never left is not counted), and as in flight until it
    /// ends: answered (after the transport's last attempt), failed, or dropped.
    async fn send_write(&self, zone: &DomainName, request: Request) -> Result<Response, Error> {
        self.ensure_clock().await?;
        self.with_marks(zone, |m| {
            m.writes = m.writes.saturating_add(1);
            m.in_flight = m.in_flight.saturating_add(1);
        });
        let _flight = Flight { api: self, zone };
        self.send_in(zone, request).await
    }

    /// `/domain/zone/{zone}` with the zone's name without its trailing dot (lego and dns-update
    /// name zones so).
    fn zone_url(&self, zone: &DomainName) -> UrlBuilder {
        self.base
            .url()
            .path("/domain/zone")
            .segment(zone.without_dot())
    }

    /// `GET /domain/zone`: the names of every zone of the account, in one answer.
    // Source: Schema, `getZones`: `string[]`, "Returns the names of the DNS zones"; no paging
    // parameter exists.
    pub(super) async fn zones(&self) -> Result<Vec<String>, Error> {
        let url = self.base.url().path("/domain/zone").build()?;
        let response = self.send(Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response.json("the provider's zone listing is not a list of names")
    }

    /// `zone` is one of the account's zones.
    pub(super) async fn has_zone(&self, zone: &DomainName) -> Result<bool, Error> {
        Ok(self
            .zones()
            .await?
            .iter()
            .any(|name| DomainName::parse(name).as_ref() == Ok(zone)))
    }

    /// `refusal` of a request about `zone` that was answered `404`, confirmed by a read
    /// (the meaning of `404` is not documented): `Error::ZoneNotFound` when the zone is not
    /// listed, the refusal as it is otherwise.
    pub(super) async fn zone_missing_or(&self, zone: &DomainName, refusal: Error) -> Error {
        match self.has_zone(zone).await {
            Ok(false) => Error::zone_not_found(zone.clone()),
            Ok(true) => refusal,
            Err(e) => e,
        }
    }

    /// `GET /domain/zone/{zone}/record` with `filter`: the identifiers of the matching records,
    /// distinct and at most [`MAX_RECORDS`].
    // Source: Schema, `getRecords` (`long[]`; `fieldType` "(like)", `subDomain` "(ilike)"). The
    // filters are pattern matches: under every reading (exact, LIKE, case-insensitive ILIKE, a
    // substring) the records whose type and name equal the filter's are among the answer, so
    // the caller compares type and name itself and never relies on the filter's precision.
    // Assumption (not documented, not observed against the live API): that the filters are one
    // of these readings and never leave out a record whose type and name equal them.
    // `subDomain` is never sent empty (for the apex) and never with a backslash, which a LIKE
    // pattern may take as an escape: the effect of either is not documented.
    async fn record_ids(&self, zone: &DomainName, filter: Filter<'_>) -> Result<Vec<u64>, Error> {
        let mut url = self.zone_url(zone).path("/record");
        if let Some(field_type) = filter.field_type {
            url = url.query("fieldType", field_type);
        }
        if let Some(sub_domain) = filter.sub_domain {
            url = url.query("subDomain", sub_domain);
        }
        let response = self.send_in(zone, Request::get(url.build()?)).await?;
        if response.status() == 404 {
            let refusal = self.refusal(&response);
            return Err(self.zone_missing_or(zone, refusal).await);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let ids: Vec<u64> =
            response.json("the provider's record listing is not a list of identifiers")?;
        if ids.len() > MAX_RECORDS {
            return Err(protocol(
                "the listing holds more than 1000 records, the most the client reads one by one",
            ));
        }
        let mut seen = HashSet::with_capacity(ids.len());
        if !ids.iter().all(|id| seen.insert(*id)) {
            return Err(protocol(
                "the provider's record listing repeats an identifier",
            ));
        }
        Ok(ids)
    }

    /// Every record the listing with `filter` answers, read one by one, in the listing's order.
    /// A record that disappears between the listing and its read is left out.
    pub(super) async fn records(
        &self,
        zone: &DomainName,
        filter: Filter<'_>,
    ) -> Result<Vec<Record>, Error> {
        let ids = self.record_ids(zone, filter).await?;
        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(record) = self.record(zone, id, filter).await? {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// `GET /domain/zone/{zone}/record/{id}`, checked against the request. `None` when the read
    /// answers `404` and a new listing with `filter` no longer holds the identifier (the record
    /// was deleted after the listing). While the listing still holds it, the read is repeated
    /// ([`READ_ATTEMPTS`], pauses of `read_pause` doubling); after the last attempt the result is
    /// `Error::Transient`.
    async fn record(
        &self,
        zone: &DomainName,
        id: u64,
        filter: Filter<'_>,
    ) -> Result<Option<Record>, Error> {
        let url = self
            .zone_url(zone)
            .path("/record")
            .id(&id.to_string())
            .build()?;
        let mut pause = self.read_pause;
        for attempt in 1..=READ_ATTEMPTS {
            let response = self.send_in(zone, Request::get(url.clone())).await?;
            if response.is_success() {
                let wire: WireRecord =
                    response.json("the provider's record answer is not in the expected form")?;
                return checked(wire, id, zone, filter).map(Some);
            }
            if response.status() != 404 {
                return Err(self.refusal(&response));
            }
            if !self.record_ids(zone, filter).await?.contains(&id) {
                return Ok(None);
            }
            if attempt < READ_ATTEMPTS {
                tokio::time::sleep(pause).await;
                pause = pause.saturating_mul(2);
            }
        }
        Err(Error::Transient {
            detail: Detail::constant(
                "a record the listing holds could not be read yet; the provider makes a new \
                 record readable after a delay",
            ),
        })
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3). The answer is not read: it may lack
    /// the identifier (Terraform), and nothing the client does needs it. A `404` is
    /// `Error::ZoneNotFound` when the zone is not listed any more, else the refusal.
    // Source: Schema, `createRecord` (200, `domain.zone.Record`); lego `Present`.
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<(), Error> {
        let url = self.zone_url(zone).path("/record").build()?;
        let request = Request::new(Method::POST, url).json(record)?;
        let response = self.send_write(zone, request).await?;
        if response.status() == 404 {
            let refusal = self.refusal(&response);
            return Err(self.zone_missing_or(zone, refusal).await);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        Ok(())
    }

    /// Changes one record. Sent once: design section 5.3 retries only reads and deletes by
    /// identifier.
    // Source: Schema, `editRecord` (200, void); Terraform's update.
    pub(super) async fn update_record(
        &self,
        zone: &DomainName,
        id: u64,
        update: &RecordUpdate<'_>,
    ) -> Result<Written, Error> {
        let url = self.record_url(zone, id)?;
        let request = Request::new(Method::PUT, url).json(update)?;
        let response = self.send_write(zone, request).await?;
        self.written(&response)
    }

    /// Deletes one record by its identifier. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it.
    // Source: Schema, `deleteRecord` (200, void); lego `CleanUp`.
    pub(super) async fn delete_record(&self, zone: &DomainName, id: u64) -> Result<Written, Error> {
        let url = self.record_url(zone, id)?;
        let response = self
            .send_write(zone, Request::new(Method::DELETE, url).idempotent())
            .await?;
        self.written(&response)
    }

    /// `POST /domain/zone/{zone}/refresh`: publishes every staged record change of the zone.
    /// Idempotent: a repeat publishes the same staged state, so the transport may retry it. A
    /// success marks as published every record write this client had started in the zone and
    /// that had ended (answered, failed or dropped) when the refresh was sent; a write still in
    /// flight stays owed. Only a success changes the marks, so a refresh that fails or is
    /// dropped leaves owed what it would have covered.
    // Source: Schema, `refreshZone` ("Applies the pending record changes to the zone", 200,
    // void, no body); lego and Terraform call it after every write. Assumption (not documented,
    // not observed against the live API): that a refresh of a zone without staged changes
    // succeeds.
    pub(super) async fn refresh(&self, zone: &DomainName) -> Result<(), Error> {
        let url = self.zone_url(zone).path("/refresh").build()?;
        // Taken before the request is sent, so it counts only writes that had ended by then
        // (a write that ends in between is left owed, which costs one more refresh at most).
        let covered = self.with_marks(zone, |m| m.writes.saturating_sub(m.in_flight));
        let response = self
            .send_in(zone, Request::new(Method::POST, url).idempotent())
            .await?;
        if response.status() == 404 {
            let refusal = self.refusal(&response);
            return Err(self.zone_missing_or(zone, refusal).await);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        self.with_marks(zone, |m| m.published = m.published.max(covered));
        Ok(())
    }

    fn record_url(&self, zone: &DomainName, id: u64) -> Result<Url, Error> {
        self.zone_url(zone)
            .path("/record")
            .id(&id.to_string())
            .build()
    }

    fn written(&self, response: &Response) -> Result<Written, Error> {
        if response.status() == 404 {
            return Ok(Written::NotFound(self.refusal(response)));
        }
        if !response.is_success() {
            return Err(self.refusal(response));
        }
        Ok(Written::Done)
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the error body of go-ovh
    /// `APIError` and its `class` as the provider code; anything else is an answer the client
    /// cannot interpret.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400..=499 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }

    /// The error of a refresh that failed after the operation's record changes were stored:
    /// `error` with that said first. Kinds without a text of their own (`RateLimited`,
    /// `ZoneNotFound`, `ProxyAuth` and the kinds no refresh returns) are returned as they are.
    pub(super) fn unpublished(&self, error: Error) -> Error {
        let prefixed = |detail: &Detail| {
            self.http
                .detail(&format!("{UNPUBLISHED}: {}", detail.as_str()))
        };
        match error {
            Error::Transient { detail } => Error::Transient {
                detail: prefixed(&detail),
            },
            Error::Rejected {
                status,
                detail,
                code,
            } => Error::Rejected {
                status,
                detail: prefixed(&detail),
                code,
            },
            Error::InvalidInput { detail, code } => Error::InvalidInput {
                detail: prefixed(&detail),
                code,
            },
            Error::Forbidden { detail } => Error::Forbidden {
                detail: prefixed(&detail),
            },
            Error::Auth { detail } => Error::Auth {
                detail: prefixed(&detail),
            },
            Error::Protocol { detail } => Error::Protocol {
                detail: prefixed(&detail),
            },
            Error::Conflict { detail } => Error::Conflict {
                detail: prefixed(&detail),
            },
            Error::PreconditionFailed { detail } => Error::PreconditionFailed {
                detail: prefixed(&detail),
            },
            Error::Config { detail } => Error::Config {
                detail: prefixed(&detail),
            },
            other => other,
        }
    }
}

/// What the error of a failed refresh after stored record changes says first.
pub(super) const UNPUBLISHED: &str = "the record changes are stored at the provider but not \
     published, because the zone refresh failed; this client's next operation in the zone \
     refreshes it, and so does a repeat of this operation that reaches the provider";

/// `wire`, the answer to the read of record `id`, checked against the request: an answer about
/// another record or zone, or of another type than the filter's, is `Error::Protocol`; a member
/// the request determines may be missing.
fn checked(
    wire: WireRecord,
    id: u64,
    zone: &DomainName,
    filter: Filter<'_>,
) -> Result<Record, Error> {
    if wire.id.is_some_and(|stated| stated != id) {
        return Err(protocol(
            "the provider answered with a record other than the one asked for",
        ));
    }
    if let Some(stated) = &wire.zone
        && !stated
            .trim_end_matches('.')
            .eq_ignore_ascii_case(zone.without_dot())
    {
        return Err(protocol(
            "the provider answered with a record of another zone",
        ));
    }
    let field_type = match (wire.field_type, filter.field_type) {
        (Some(stated), _) => stated,
        // `fieldType=<type>` without a pattern character matches that type only.
        (None, Some(filter)) => filter.to_owned(),
        (None, None) => return Err(protocol("the provider answered a record without its type")),
    };
    if filter.sub_domain.is_some() && wire.sub_domain.is_none() {
        // A record without a stated name cannot be placed; the filter is a pattern.
        return Err(protocol("the provider answered a record without its name"));
    }
    // A record without its value cannot be compared or written back; every source shows one.
    let target = wire
        .target
        .ok_or_else(|| protocol("the provider answered a record without its value"))?;
    Ok(Record {
        id,
        sub_domain: wire.sub_domain,
        field_type,
        target,
        ttl: wire.ttl,
    })
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// The owner name a record's `subDomain` states, as an absolute name: `null`, a missing member
/// and `""` are the zone itself, any other name is relative to the zone. `None` for a name the
/// sources do not describe (one with a trailing dot, `@`) or that is not a valid name.
// Source: Schema, `domain.zone.Record.subDomain` ("canBeNull": true); lego leaves `subDomain` out
// for the apex and dns-update sends `""` for it. Assumption (not documented, not observed against
// the live API): that the API states the apex as `null` or `""`. A name read as `None` is never
// taken for ours, so a foreign value cannot be removed by it.
pub(super) fn owner(sub_domain: Option<&str>, zone: &DomainName) -> Option<DomainName> {
    match sub_domain {
        None | Some("") => Some(zone.clone()),
        Some(stated) if stated.ends_with('.') || stated == "@" => None,
        Some(stated) => DomainName::parse(&format!("{stated}.{}", zone.as_str())).ok(),
    }
}

/// The filter of a read of `name`'s records of type `field_type`: the type always, the name
/// relative to the zone unless it is the apex or holds a backslash (see [`Api::record_ids`]).
pub(super) fn filter_for<'a>(relative: &'a str, field_type: &'a str) -> Filter<'a> {
    Filter {
        field_type: Some(field_type),
        sub_domain: (!relative.is_empty() && !relative.contains('\\')).then_some(relative),
    }
}

/// The TTL a record states, for the record layers: a positive number; `null`, a missing member,
/// `0` and anything else read as "not stated".
// Source: Schema, `domain.zone.Record.ttl` ("canBeNull": true); Terraform accepts `0` and sends it
// when no TTL is configured. What `0` and `null` mean is not documented. Assumption (not observed
// against the live API): neither is a TTL in seconds; both are reported as no TTL, and a write
// that keeps such a record sends the value back as read.
pub(super) fn stated_ttl(ttl: Option<i64>) -> Option<u32> {
    ttl.and_then(|t| u32::try_from(t).ok()).filter(|t| *t > 0)
}

/// The provider's error message: `message`, then each member of `details`.
// Source: go-ovh `ovh/error.go`, `APIError` (`message`; `details`, a map of strings; go-ovh
// appends the missing IAM permissions it finds there); Service accounts, the 403 example.
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        details: Option<serde_json::Map<String, Value>>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    let mut text = body.message.filter(|text| !text.is_empty())?;
    for (key, value) in body.details.iter().flatten() {
        if let Some(value) = value.as_str() {
            text.push_str(&format!("; {key}: {value}"));
        }
    }
    Some(text)
}

/// The provider's own code for a refusal: the `class` of the error body, such as
/// `Client::Forbidden`.
// Source: go-ovh `ovh/error.go`, `APIError.Class` (`json:"class"`); Service accounts, the 403
// example (`"class":"Client::Forbidden"`).
pub(super) fn error_class(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        class: Option<String>,
    }
    serde_json::from_str::<ErrorBody>(body).ok()?.class
}

#[cfg(test)]
mod tests {
    use super::{
        CLOCK_MAX_AGE, Filter, Outgoing, ServerClock, Signer, WireRecord, checked, error_class,
        error_message, filter_for, owner, stated_ttl,
    };
    use crate::name::DomainName;
    use reqwest::header::HeaderValue;
    use reqwest::{Method, Url};
    use secrecy::SecretString;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// A timestamp is the server's reading plus the monotonic time elapsed since; the reading is
    /// stale after the bound.
    #[test]
    fn the_server_clock_advances_monotonically() {
        let read_at = Instant::now();
        let clock = ServerClock {
            server: 1_700_000_000,
            read_at,
        };
        assert_eq!(clock.timestamp(read_at), 1_700_000_000);
        assert_eq!(
            clock.timestamp(read_at + Duration::from_millis(2_500)),
            1_700_000_002
        );
        assert!(!clock.stale(read_at));
        assert!(!clock.stale(read_at + CLOCK_MAX_AGE - Duration::from_secs(1)));
        assert!(clock.stale(read_at + CLOCK_MAX_AGE));
        assert_eq!(
            clock.timestamp(read_at + CLOCK_MAX_AGE),
            1_700_000_000 + 3600
        );
    }

    fn signer() -> Signer {
        Signer {
            application_key: HeaderValue::from_static("test-only-ak"),
            application_secret: SecretString::from("test-only-as".to_owned()),
            consumer_key: SecretString::from("test-only-ck".to_owned()),
            clock: Mutex::new(None),
        }
    }

    /// The signature is the formula of go-ovh and of the provider's guide over the exact URL and
    /// body, computed independently here with the crate's SHA-1 over the joined text.
    #[test]
    fn the_signature_follows_the_documented_formula() {
        let signer = signer();
        let url = Url::parse("https://api.eu.ovhcloud.com/1.0/domain/zone/example.org/record?fieldType=TXT&subDomain=_acme-challenge").unwrap();
        let method = Method::GET;
        let attempt = Outgoing {
            method: &method,
            url: &url,
            body: b"",
        };
        let expected = format!(
            "$1${}",
            crate::crypto::hex_lower(&crate::crypto::sha1(
                b"test-only-as+test-only-ck+GET+https://api.eu.ovhcloud.com/1.0/domain/zone/example.org/record?fieldType=TXT&subDomain=_acme-challenge++1457018875"
            ))
        );
        assert_eq!(signer.signature(&attempt, 1_457_018_875), expected);
        assert!(expected.starts_with("$1$") && expected.len() == 43);
        // The body and the timestamp are part of what is signed.
        let post = Method::POST;
        let with_body = Outgoing {
            method: &post,
            url: &url,
            body: br#"{"fieldType":"TXT"}"#,
        };
        assert_ne!(signer.signature(&with_body, 1_457_018_875), expected);
        assert_ne!(signer.signature(&attempt, 1_457_018_876), expected);
    }

    #[test]
    fn error_bodies_give_message_and_class() {
        let body = r#"{"class":"Client::Forbidden","message":"User not granted for this request"}"#;
        assert_eq!(
            error_message(body).as_deref(),
            Some("User not granted for this request")
        );
        assert_eq!(error_class(body).as_deref(), Some("Client::Forbidden"));
        let body = r#"{"class":"Client::Forbidden","message":"m","details":{"unauthorizedActionsByIAM":"dnsZone:apiovh:refresh"}}"#;
        assert_eq!(
            error_message(body).as_deref(),
            Some("m; unauthorizedActionsByIAM: dnsZone:apiovh:refresh")
        );
        assert_eq!(error_message(r#"{"class":"x"}"#), None);
        assert_eq!(error_class("<html>"), None);
    }

    #[test]
    fn stated_names_are_relative_to_the_zone() {
        let zone = DomainName::parse("example.org").unwrap();
        let name = |s: Option<&str>| owner(s, &zone).map(|n| n.as_str().to_owned());
        assert_eq!(name(None).as_deref(), Some("example.org."));
        assert_eq!(name(Some("")).as_deref(), Some("example.org."));
        assert_eq!(
            name(Some("_acme-challenge")).as_deref(),
            Some("_acme-challenge.example.org.")
        );
        assert_eq!(name(Some("*.www")).as_deref(), Some("*.www.example.org."));
        assert_eq!(name(Some("www.example.org.")), None);
        assert_eq!(name(Some("@")), None);
        assert_eq!(name(Some("bad name")), None);
    }

    #[test]
    fn filters_leave_out_the_apex_and_escapes() {
        let f = filter_for("", "TXT");
        assert_eq!((f.field_type, f.sub_domain), (Some("TXT"), None));
        let f = filter_for("_acme-challenge", "TXT");
        assert_eq!(f.sub_domain, Some("_acme-challenge"));
        assert_eq!(filter_for("a\\.b", "A").sub_domain, None);
    }

    #[test]
    fn ttls_are_positive_numbers_only() {
        assert_eq!(stated_ttl(Some(300)), Some(300));
        assert_eq!(stated_ttl(Some(0)), None);
        assert_eq!(stated_ttl(None), None);
        assert_eq!(stated_ttl(Some(-1)), None);
        assert_eq!(stated_ttl(Some(1 << 40)), None);
    }

    fn wire(json: serde_json::Value) -> WireRecord {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn answers_are_checked_against_the_request() {
        let zone = DomainName::parse("example.org").unwrap();
        let filter = Filter {
            field_type: Some("TXT"),
            sub_domain: Some("www"),
        };
        // Every member may be missing where the request determines it.
        let r = checked(
            wire(serde_json::json!({"subDomain": "www", "target": "v"})),
            7,
            &zone,
            filter,
        )
        .unwrap();
        assert_eq!((r.id, r.field_type.as_str()), (7, "TXT"));
        for bad in [
            serde_json::json!({"id": 8, "subDomain": "www", "target": "v"}),
            serde_json::json!({"zone": "example.net", "subDomain": "www", "target": "v"}),
            serde_json::json!({"subDomain": "www"}),
            serde_json::json!({"target": "v"}),
        ] {
            assert!(
                checked(wire(bad.clone()), 7, &zone, filter).is_err(),
                "{bad}"
            );
        }
        assert!(
            checked(
                wire(serde_json::json!({"target": "v"})),
                7,
                &zone,
                Filter::default()
            )
            .is_err()
        );
        let r = checked(
            wire(serde_json::json!({"id": 7, "zone": "Example.org", "fieldType": "A", "subDomain": null, "target": "192.0.2.1", "ttl": null})),
            7,
            &zone,
            Filter::default(),
        )
        .unwrap();
        assert_eq!(r.sub_domain, None);
    }
}
