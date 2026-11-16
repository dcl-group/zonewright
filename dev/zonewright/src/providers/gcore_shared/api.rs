//! The DNS API v2 as this code uses it: one function per endpoint, the wire types, paging and the
//! classification of answers. Nothing here knows the value layer or the record layer.
//!
//! Sources (hard rule 3), per provider:
//!
//! - Gcore: the API reference <https://docs.gcore.com/api-reference/dns> (one page per call, each
//!   with the OpenAPI fragment of that call: `zones/list-of-zones`, `zones/get-zone`,
//!   `rrsets/list-of-rrset`, `rrsets/get-rrset`, `rrsets/create-rrset`, `rrsets/update-rrset`,
//!   `rrsets/delete-rrset`), the provider's Swagger document
//!   <https://api.gcore.com/dns/docs/swagger.yaml> ("the Gcore spec" below), and lego
//!   `providers/dns/internal/gcore/internal/client.go` and `types.go` ("lego" below).
//! - EdgeCenter: the provider's Swagger document
//!   <https://api.edgecenter.ru/dns/docs/swagger-en.yaml> ("the EdgeCenter spec"), its Go SDK
//!   `github.com/Edge-Center/edgecenter-dns-sdk-go` (`client.go`, `client_dto.go`; "the SDK"),
//!   and the same lego client, which lego uses for EdgeCenter with another base URL
//!   (`providers/dns/edgecenter/edgecenter.go`).
//!
//! Endpoints used, all below the `base_url` (`https://api.gcore.com/dns`,
//! `https://api.edgecenter.ru/dns`):
//!
//! | Call                  | Request                                   | Success               |
//! | --------------------- | ----------------------------------------- | --------------------- |
//! | list zones            | `GET /v2/zones?offset[&limit]`            | 200, page             |
//! | one zone              | `GET /v2/zones/{zone}`                    | 200, the zone         |
//! | list rrsets           | `GET /v2/zones/{zone}/rrsets?offset`      | 200, page             |
//! | one rrset             | `GET /v2/zones/{zone}/{name}/{type}`      | 200, the rrset        |
//! | create rrset          | `POST /v2/zones/{zone}/{name}/{type}`     | 200, the rrset        |
//! | replace rrset         | `PUT /v2/zones/{zone}/{name}/{type}`      | 200, the rrset        |
//! | delete rrset          | `DELETE /v2/zones/{zone}/{name}/{type}`   | 200 (Gcore), 204 (EdgeCenter) |
//!
//! Zone and owner names in a path are fully qualified names without the trailing dot, in ASCII
//! (A-labels): "For an apex record it equals `ZONE_NAME`; for a subdomain it is the full FQDN"
//! (<https://docs.gcore.com/dns/dns-records/manage-dns-records-non-advanced-interface-mode>);
//! lego and the SDK send `UnFqdn` of the name and of the zone.

use std::sync::{Mutex, PoisonError};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// The API's spelling of the TXT type.
// Source: the Gcore spec, `OutputRRSet.type` enumeration; lego `AddRRSet` (`/TXT`).
pub(super) const TXT: &str = "TXT";

/// A zone as the API returns it; other fields are ignored.
// Source: the Gcore spec, `OutputZone` and `ItemZoneResponse` (`name`, `enabled` with default
// true); the EdgeCenter spec, `OutputZone` (`name`, `enabled`).
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The zone name, without the trailing dot.
    pub(super) name: String,
    /// A disabled zone is kept but "its records are not resolved" (the EdgeCenter spec,
    /// `OutputZone.enabled`). `None` when the answer does not say.
    #[serde(default)]
    pub(super) enabled: Option<bool>,
}

/// An rrset as the API returns it.
// Source: the Gcore spec, `OutputRRSet` (`name`, `type` and `resource_records` required; `ttl`,
// `meta`, `pickers`, `filter_set_id` optional); the EdgeCenter spec, `OutputRRSet` (no member
// marked required; `filters` in place of `pickers`). `name` and `type` are therefore optional
// here: a single rrset's answer may leave out what its path already says (lego's fixture
// `get_rrset.json` has neither), and a listing, where they are the only identification, requires
// them itself.
#[derive(Deserialize)]
struct WireRrset {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    rtype: Option<String>,
    #[serde(default)]
    ttl: Option<u32>,
    resource_records: Option<Vec<WireRecord>>,
    #[serde(default)]
    meta: Option<Map<String, Value>>,
    #[serde(default)]
    pickers: Option<Vec<Value>>,
    #[serde(default)]
    filters: Option<Vec<Value>>,
    #[serde(default)]
    filter_set_id: Option<u64>,
}

/// One record of an rrset as the API returns it.
// Source: the Gcore spec and the EdgeCenter spec, `OutputResourceRecord` (`content` required;
// `enabled` "default value is true"; `meta`; `id`, which the input form does not have).
#[derive(Deserialize)]
struct WireRecord {
    content: Vec<Value>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    meta: Option<Map<String, Value>>,
}

/// An rrset as read: what a write sends back, and what tells a plain rrset from a dynamic one.
// `pub(crate)`: it is the `Snapshot` of the client's `WholeSet` implementations, crate-wide
// traits.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Rrset {
    /// The owner name as the API spelled it.
    pub(super) name: String,
    /// The type as the API spelled it.
    pub(super) rtype: String,
    /// TTL in seconds; `None` when the answer has none.
    pub(super) ttl: Option<u32>,
    /// The records, disabled ones included.
    pub(super) records: Vec<Record>,
    /// The rrset selects its answers per query: it has pickers (Gcore) or filters (EdgeCenter),
    /// a filter set, or rrset metadata (failover checks, a GeoDNS link). Its answers are not a
    /// plain list of values.
    pub(super) dynamic: bool,
}

/// One record of an rrset: written back exactly as read.
// Source: the Gcore spec and the EdgeCenter spec, `InputResourceRecord`: `content` (required),
// `enabled` (default true), `meta`. The record `id` of an answer is not part of the input form
// and is not sent.
// `pub(crate)`: it is the `Handle` of the client's `WholeSet` implementations.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct Record {
    /// One element per field of the record: strings and numbers.
    pub(super) content: Vec<Value>,
    /// A disabled record is kept but not published. Always sent: the SDK's struct without
    /// `omitempty` would otherwise send `false` (the EdgeCenter dossier's trap), and the client
    /// says what it means.
    pub(super) enabled: bool,
    /// Per-record metadata (GeoDNS, weights, notes), sent back as read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) meta: Option<Map<String, Value>>,
}

impl Record {
    /// A new, enabled record without metadata.
    pub(super) fn new(content: Vec<Value>) -> Record {
        Record {
            content,
            enabled: true,
            meta: None,
        }
    }
}

impl Rrset {
    /// The rrset of an answer, with the owner name and the type it is known by.
    fn from_wire(wire: WireRrset, name: String, rtype: String) -> Rrset {
        let non_empty = |list: &Option<Vec<Value>>| list.as_ref().is_some_and(|l| !l.is_empty());
        // Pickers (Gcore), filters (EdgeCenter) and rrset metadata select answers per query or
        // change them (failover, a GeoDNS link): the specs' descriptions of those members. A
        // non-zero `filter_set_id` is taken for the same: an assumption, not documented (the
        // EdgeCenter spec says "For internal use", the Gcore spec says nothing), chosen because
        // refusing a plain rrset is a visible error while overwriting a dynamic one would
        // silently drop its configuration. Whether a plain rrset carries the member is for a
        // live run to show.
        let dynamic = non_empty(&wire.pickers)
            || non_empty(&wire.filters)
            || wire.filter_set_id.is_some_and(|id| id != 0)
            || wire.meta.as_ref().is_some_and(|meta| !meta.is_empty());
        Rrset {
            name,
            rtype,
            ttl: wire.ttl,
            records: wire
                .resource_records
                .unwrap_or_default()
                .into_iter()
                .map(|record| Record {
                    content: record.content,
                    enabled: record.enabled.unwrap_or(true),
                    meta: record.meta,
                })
                .collect(),
            dynamic,
        }
    }
}

/// The body of a create or a replacement.
// Source: the Gcore spec and the EdgeCenter spec, `InputRRSet` (`resource_records` required,
// `ttl`); lego `RRSet` (`ttl`, `resource_records`). Selection (`pickers`, `filters`) and rrset
// `meta` are never sent: the client does not write a dynamic rrset.
#[derive(Serialize)]
pub(super) struct RrsetBody<'a> {
    /// TTL in seconds.
    pub(super) ttl: u32,
    /// The complete list of records.
    pub(super) resource_records: &'a [Record],
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the zone or the rrset does not exist (any more).
    NotFound,
    /// Another refusal, as the error it maps to.
    Refused(Error),
}

/// The client's handle on the API: the transport and the endpoint.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

/// A name as the path carries it: the canonical ASCII text without the trailing dot.
pub(super) fn path_name(name: &DomainName) -> &str {
    let text = name.as_str();
    text.strip_suffix('.').unwrap_or(text)
}

impl Api {
    /// The API at `base`.
    pub(super) fn new(http: Http, base: Endpoint) -> Api {
        Api { http, base }
    }

    /// One page of the zone listing with at most one zone: a request that every valid token
    /// can make, whatever zones it sees.
    // Source: the Gcore spec and the EdgeCenter spec, `GET /v2/zones` with `limit` ("Max number
    // of records in response").
    pub(super) async fn probe(&self) -> Result<(), Error> {
        let url = self
            .base
            .url()
            .path("/v2/zones")
            .query("limit", "1")
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Value = response.json("the provider's zone listing is not in the expected form")?;
        Ok(())
    }

    /// Every zone of the account, all pages.
    // Source: the Gcore spec, `GET /v2/zones` ("Show created zones with pagination managed by
    // limit and offset params. All query params are optional."); the EdgeCenter spec, the same.
    // Paging: see `list`.
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        let url = |offset: u64| page_query(self.base.url().path("/v2/zones"), offset).build();
        self.list(url, None, "zones").await
    }

    /// The zone `zone`, or `None` when the API does not know it (`404`).
    ///
    /// The Gcore spec describes the answer as the zone itself (`ItemZoneResponse`, as lego and
    /// the SDK read it); the EdgeCenter spec wraps it in `{"zone": …}`. Either form is read,
    /// and the name in it must be the one asked for.
    // Source: the Gcore spec, `GET /v2/zones/{name}` (operationId `Zone`, `ItemZoneResponse`);
    // the EdgeCenter spec, `GET /v2/zones/{name}` (`ItemZoneResponse` with `zone`); lego
    // `GetZone` and the SDK `Zone` decode `{"name": …}` directly. A `404` for a zone that does
    // not exist: lego `guessZone` tries the next candidate on any error, the SDK returns the
    // status, and the EdgeCenter spec documents `404`.
    pub(super) async fn zone(&self, zone: &DomainName) -> Result<Option<Zone>, Error> {
        let url = self
            .base
            .url()
            .path("/v2/zones")
            .segment(path_name(zone))
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let body: Value = response.json("the provider's zone is not in the expected form")?;
        let object = match body.get("zone") {
            Some(inner) if inner.is_object() => inner.clone(),
            _ => body,
        };
        let found: Zone = serde_json::from_value(object).map_err(|_| Error::Protocol {
            detail: Detail::constant("the provider's zone is not in the expected form"),
        })?;
        if DomainName::parse(&found.name).as_ref() != Ok(zone) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with a zone other than the one asked for",
                ),
            });
        }
        Ok(Some(found))
    }

    /// Every rrset of `zone`, of every type, all pages. A `404` is `Error::ZoneNotFound`.
    // Source: the Gcore spec, `GET /v2/zones/{zoneName}/rrsets` (`offset`, `limit`,
    // `order_by`, `order_direction`; `ListRRSetResponse`); the EdgeCenter spec, the same path
    // with the same paging and a `404`. Paging: see `list`. An item must state its name and
    // type: in a listing they are the only identification.
    pub(super) async fn rrsets(&self, zone: &DomainName) -> Result<Vec<Rrset>, Error> {
        let url = |offset: u64| {
            let url = self
                .base
                .url()
                .path("/v2/zones")
                .segment(path_name(zone))
                .path("/rrsets");
            page_query(url, offset).build()
        };
        let wire: Vec<WireRrset> = self.list(url, Some(zone), "rrsets").await?;
        wire.into_iter()
            .map(|wire| match (wire.name.clone(), wire.rtype.clone()) {
                (Some(name), Some(rtype)) => Ok(Rrset::from_wire(wire, name, rtype)),
                _ => Err(Error::Protocol {
                    detail: Detail::constant(
                        "the provider's listing holds an rrset without a name or a type",
                    ),
                }),
            })
            .collect()
    }

    /// The rrset of `name` and `rtype` (the API's spelling), or `None` for a `404`, which the
    /// API answers for a missing rrset and for a missing zone alike.
    // Source: the Gcore spec and the EdgeCenter spec, `GET /v2/zones/{zoneName}/{rrsetName}/
    // {rrsetType}` (`OutputRRSet`); the EdgeCenter spec documents `404`; dns-update
    // (`providers/gcore.rs`, `fetch_rrset`) maps a `404` to "not found".
    pub(super) async fn rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Option<Rrset>, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let wire: WireRrset = response.json("the provider's rrset is not in the expected form")?;
        // The answer must be about the rrset asked for; what it leaves out, the path says.
        let other_name = wire
            .name
            .as_deref()
            .is_some_and(|stated| DomainName::parse(stated).as_ref() != Ok(name));
        let other_type = wire
            .rtype
            .as_deref()
            .is_some_and(|stated| !stated.eq_ignore_ascii_case(rtype));
        if other_name || other_type {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with an rrset other than the one asked for",
                ),
            });
        }
        let stated_name = wire
            .name
            .clone()
            .unwrap_or_else(|| path_name(name).to_owned());
        let stated_type = wire.rtype.clone().unwrap_or_else(|| rtype.to_owned());
        Ok(Some(Rrset::from_wire(wire, stated_name, stated_type)))
    }

    /// Creates an rrset. Sent once: a create is not idempotent.
    // Source: the Gcore spec and the EdgeCenter spec, `POST /v2/zones/{zoneName}/{rrsetName}/
    // {rrsetType}` with `InputRRSet`, 200 with `OutputRRSet`; lego `AddRRSet` creates with
    // `POST` when the read found no rrset.
    pub(super) async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        body: &RrsetBody<'_>,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(body)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Replaces the TTL and the records of an rrset. Sent once: the write carries no
    /// condition, and a repeat would widen the window in which another writer's change is
    /// overwritten (design section 5.3).
    // Source: the Gcore spec and the EdgeCenter spec, `PUT /v2/zones/{zoneName}/{rrsetName}/
    // {rrsetType}` with `InputRRSet`, 200 with `OutputRRSet`; lego `AddRRSet` re-sends every
    // existing record with the new one, which is how a replacement of the whole list works.
    pub(super) async fn replace(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        body: &RrsetBody<'_>,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let response = self
            .http
            .send(&Request::new(Method::PUT, url).json(body)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Deletes an rrset. Sent once: the rrset can hold values of other writers that arrived
    /// after the read, and a repeat would widen that window like a repeated replacement.
    // Source: the Gcore spec, `DELETE /v2/zones/{zoneName}/{rrsetName}/{rrsetType}` (200 with
    // `DeleteRRSetResponse`); the EdgeCenter spec, the same path (204, 404); lego `DeleteRRSet`
    // takes a `404` for "already deleted".
    pub(super) async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let response = self.http.send(&Request::new(Method::DELETE, url)).await?;
        Ok(self.written(&response))
    }

    /// The path of one rrset. A wildcard owner's `*` is percent-encoded (`%2A`) by the path
    /// encoder, as Go's `url.JoinPath` in lego and the SDK encodes it; how the API treats `*` in a
    /// path is not documented: an assumption for a live run to confirm.
    fn rrset_url(&self, zone: &DomainName, name: &DomainName, rtype: &str) -> Result<Url, Error> {
        self.base
            .url()
            .path("/v2/zones")
            .segment(path_name(zone))
            .segment(path_name(name))
            .segment(rtype)
            .build()
    }

    fn written(&self, response: &Response) -> Written {
        match response.status() {
            _ if response.is_success() => Written::Done,
            404 => Written::NotFound,
            _ => Written::Refused(self.refusal(response)),
        }
    }

    /// Reads every page of a listing: the items under `key` of each page. `url` builds the URL
    /// of the page at an offset. A `404` is `Error::ZoneNotFound` for `zone` when one is given,
    /// else a refusal.
    ///
    /// No page size is sent: both specs document `limit` ("Max number of records in response")
    /// but neither its default nor its maximum, so the server's page is taken and `offset`
    /// follows what was received. Neither is `order_by` sent: the order across pages is the
    /// server's. The listing ends on an empty page ([`next_offset`]); a page that repeats the
    /// one before it is `Error::Protocol`, and `pager::collect` stops at its page limit.
    async fn list<T: DeserializeOwned, U>(
        &self,
        url: U,
        zone: Option<&DomainName>,
        key: &'static str,
    ) -> Result<Vec<T>, Error>
    where
        U: Fn(u64) -> Result<Url, Error>,
    {
        let previous: Mutex<Option<Value>> = Mutex::new(None);
        pager::collect(0, |offset| {
            let url = url(offset);
            let previous = &previous;
            async move {
                let response = self.http.send(&Request::get(url?)).await?;
                if response.status() == 404
                    && let Some(zone) = zone
                {
                    return Err(Error::zone_not_found(zone.clone()));
                }
                if !response.is_success() {
                    return Err(self.refusal(&response));
                }
                let page: Value =
                    response.json("the provider's listing is not in the expected form")?;
                let (items, total) = page_parts(&page, key)?;
                {
                    let mut previous = previous.lock().unwrap_or_else(PoisonError::into_inner);
                    let repeated = items.as_array().is_some_and(|list| !list.is_empty())
                        && previous.as_ref() == Some(&items);
                    if repeated {
                        return Err(Error::Protocol {
                            detail: Detail::constant(
                                "the provider's listing repeated a page instead of moving on",
                            ),
                        });
                    }
                    *previous = Some(items.clone());
                }
                let items: Vec<T> = serde_json::from_value(items).map_err(|_| malformed())?;
                let next = next_offset(offset, items.len(), total)?;
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the
    /// transport already. The documented refusals are `Rejected`; anything else is an answer
    /// the client cannot interpret.
    // Source: the Gcore spec documents `400` ("Error message response") for every call; the
    // EdgeCenter spec `400`, `404` and, for a create or a replacement, `409`. `422` is treated
    // like `400`: a refusal of the request's content.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400 | 409 | 422 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

/// Appends `offset`.
fn page_query(url: UrlBuilder, offset: u64) -> UrlBuilder {
    url.query("offset", &offset.to_string())
}

fn malformed() -> Error {
    Error::Protocol {
        detail: Detail::constant("the provider's listing is not in the expected form"),
    }
}

/// The items under `key` of a listing page and the `total_amount` it states, if any.
// Source: the Gcore spec and the EdgeCenter spec, `ListZoneResponse` (`zones`) and
// `ListRRSetResponse` (`rrsets`), each with `total_amount`; no member is marked required. A Go
// server encodes an empty list as `null`, which is read as empty.
fn page_parts(page: &Value, key: &str) -> Result<(Value, Option<u64>), Error> {
    let items = match page.get(key) {
        None | Some(Value::Null) => Value::Array(Vec::new()),
        Some(items @ Value::Array(_)) => items.clone(),
        Some(_) => return Err(malformed()),
    };
    let total = match page.get("total_amount") {
        None | Some(Value::Null) => None,
        Some(total) => Some(total.as_u64().ok_or_else(malformed)?),
    };
    Ok((items, total))
}

/// The offset of the page after the one at `offset` that brought `received` items, or `None`
/// when the listing is complete.
///
/// The listing ends on an empty page. `total_amount` is "the total number ... with the
/// requested parameters" in the EdgeCenter spec (`ListZoneResponse`) and undescribed in the
/// Gcore spec, which leaves open that it counts the page only; it is therefore a cross-check,
/// not the end rule:
///
/// - an empty page before a stated total is reached is a listing that ended short of it:
///   `Error::Protocol`, never a shorter result;
/// - after more than one page, a total equal to everything received can only be the total of
///   the listing, and ends it without the empty page. On the first page that equality also
///   holds for a total that counts the page, so the next (empty) page is read.
// Source: `offset` is "Amount of records to skip before beginning to write in response" (the
// Gcore spec).
fn next_offset(offset: u64, received: usize, total: Option<u64>) -> Result<Option<u64>, Error> {
    let received = u64::try_from(received).unwrap_or(u64::MAX);
    if received == 0 {
        if total.is_some_and(|total| total > offset) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider's listing ended before the number of items it stated",
                ),
            });
        }
        return Ok(None);
    }
    let after = offset.saturating_add(received);
    if offset > 0 && total == Some(after) {
        return Ok(None);
    }
    Ok(Some(after))
}

/// The provider's error message: `error`, a string.
// Source: lego `internal/types.go` (`APIError`, `json:"error"`) and the SDK `client_dto.go`
// (the same); both take the raw body as the message when it is not that JSON, which the
// transport's fallback does too.
pub(crate) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error: Option<Value>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    match body.error {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{error_message, next_offset, page_parts};
    use crate::error::ErrorKind;

    #[test]
    fn error_messages_are_the_error_field() {
        assert_eq!(
            error_message(r#"{"error":"zone not found"}"#).as_deref(),
            Some("zone not found")
        );
        assert_eq!(error_message(r#"{"error":7}"#), None);
        assert_eq!(error_message(r#"{"error":""}"#), None);
        assert_eq!(error_message("<html>oops</html>"), None);
    }

    #[test]
    fn pages_end_on_an_empty_page_or_a_clear_total() {
        assert_eq!(next_offset(0, 10, Some(25)).unwrap(), Some(10));
        assert_eq!(next_offset(10, 10, Some(25)).unwrap(), Some(20));
        // After more than one page the total ends the listing.
        assert_eq!(next_offset(20, 5, Some(25)).unwrap(), None);
        // On the first page it may count the page only: one more request.
        assert_eq!(next_offset(0, 10, Some(10)).unwrap(), Some(10));
        assert_eq!(next_offset(10, 0, Some(10)).unwrap(), None);
        // A total that counts each page never ends the listing early.
        assert_eq!(next_offset(10, 10, Some(10)).unwrap(), Some(20));
        assert_eq!(next_offset(20, 0, Some(0)).unwrap(), None);
        // Without a total, only the empty page ends it.
        assert_eq!(next_offset(0, 10, None).unwrap(), Some(10));
        assert_eq!(next_offset(10, 0, None).unwrap(), None);
        assert_eq!(next_offset(0, 0, Some(0)).unwrap(), None);
        // An empty page short of the stated total.
        let e = next_offset(10, 0, Some(25)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
    }

    #[test]
    fn page_parts_read_null_and_missing_members() {
        let (items, total) =
            page_parts(&json!({"rrsets": null, "total_amount": 3}), "rrsets").unwrap();
        assert_eq!(items, json!([]));
        assert_eq!(total, Some(3));
        let (items, total) = page_parts(&json!({"rrsets": [1]}), "rrsets").unwrap();
        assert_eq!(items, json!([1]));
        assert_eq!(total, None);
        assert!(page_parts(&json!({"rrsets": {}}), "rrsets").is_err());
        assert!(page_parts(&json!({"rrsets": [], "total_amount": -1}), "rrsets").is_err());
    }
}
