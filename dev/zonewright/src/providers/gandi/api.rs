//! The LiveDNS API v5 as this client uses it: one function per endpoint, the wire types, paging
//! and the classification of answers. Nothing here knows the value layer or the record layer.
//!
//! Sources (hard rule 3): the LiveDNS API reference <https://api.gandi.net/docs/livedns/> ("the
//! reference" below), the general reference <https://api.gandi.net/docs/reference/> (rate limit,
//! `Content-Type`, `sharing_id`), lego `providers/dns/gandiv5` (`gandiv5.go`,
//! `internal/client.go`, `internal/types.go`; "lego" below) and dns-update
//! `src/providers/gandiv5.rs`.
//!
//! Endpoints used, all below the `base_url` (`https://api.gandi.net/v5/livedns`):
//!
//! | Call               | Request                                          | Success                 |
//! | ------------------ | ------------------------------------------------ | ----------------------- |
//! | list domains       | `GET /domains?page[&per_page][&sharing_id]`      | 200, array              |
//! | one domain         | `GET /domains/{fqdn}`                            | 200, the domain         |
//! | list rrsets        | `GET /domains/{fqdn}/records?page`               | 200, array              |
//! | one rrset          | `GET /domains/{fqdn}/records/{name}/{type}`      | 200, the rrset          |
//! | create rrset       | `POST /domains/{fqdn}/records/{name}/{type}`     | 201 (200: identical)    |
//! | replace rrset      | `PUT /domains/{fqdn}/records/{name}/{type}`      | 201                     |
//! | add/remove values  | `PATCH /domains/{fqdn}/records/{name}/{type}`    | 200, the rrset; 204     |
//! | delete rrset       | `DELETE /domains/{fqdn}/records/{name}/{type}`   | 204                     |
//!
//! `{fqdn}` is the zone name without the trailing dot, as in every example of the reference and
//! as lego sends it (`dns01.UnFqdn`). `{name}` is the owner name relative to the zone, `@` for
//! the apex (`"rrset_name": "@"`, `"www"` in the reference; the path encoder writes `@` as `%40`,
//! as the reference's `rrset_href` example does); lego sends `dns01.ExtractSubDomain`. A wildcard
//! owner's `*` is written `%2A` by the path encoder, as Go's `url.JoinPath` in lego does; how the
//! API treats `*` in a path is not documented: an assumption for a live run to confirm.
//!
//! Status codes the reference documents: 401 "Bad authentication attempt because of a wrong API
//! Key", 403 "Access to the resource is denied" and "In case the bearer token has expired, does
//! not have enought permission or does not exists" (both mapped by the transport: `Auth` and
//! `Forbidden`), 404 for a read of a missing name/type pair, 409 for a create of an existing
//! pair. A missing domain, a delete or a `PATCH` of a missing rrset, validation errors and rate
//! limiting have no documented status; what the client assumes is said at each call.

use std::sync::{Mutex, PoisonError};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// The API's spelling of the TXT type.
// Source: the reference, `rrset_type` enumeration; lego `getTXTRecord` (`…/records/{name}/TXT`).
pub(super) const TXT: &str = "TXT";

/// A domain as the API lists or returns it; other members are ignored.
// Source: the reference, "List of domains handled by LiveDNS" and "Show domain's properties"
// (`fqdn`, `domain_href`, `domain_records_href`, …). No member is marked required.
#[derive(Debug, Deserialize)]
pub(super) struct Domain {
    /// The domain name, without the trailing dot.
    #[serde(default)]
    pub(super) fqdn: Option<String>,
}

/// An rrset as the API returns it.
// Source: the reference, the 200 answer of "Get a single single record with its name and type"
// and of "List records associated with a domain": `rrset_href`, `rrset_name`, `rrset_type` and
// `rrset_values` before "Optional", `rrset_ttl` optional. `rrset_name` and `rrset_type` are
// optional here: a single rrset's answer may leave out what its path already says, and the
// listing requires them itself. `rrset_href` is not used.
#[derive(Deserialize)]
struct WireRrset {
    #[serde(default)]
    rrset_name: Option<String>,
    #[serde(default)]
    rrset_type: Option<String>,
    #[serde(default)]
    rrset_ttl: Option<u64>,
    rrset_values: Vec<String>,
}

/// An rrset as read.
// `pub(crate)`: it is the `Snapshot` of the client's `WholeSet` implementation, a crate-wide
// trait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rrset {
    /// The owner name as the API spelled it, relative to the zone.
    pub(super) name: String,
    /// The type as the API spelled it.
    pub(super) rtype: String,
    /// TTL in seconds; `None` when the answer has none (or one beyond 32 bits).
    pub(super) ttl: Option<u32>,
    /// The values, exactly as the API returned them.
    pub(super) values: Vec<String>,
}

impl Rrset {
    fn from_wire(wire: WireRrset, name: String, rtype: String) -> Rrset {
        Rrset {
            name,
            rtype,
            ttl: wire.rrset_ttl.and_then(|ttl| u32::try_from(ttl).ok()),
            values: wire.rrset_values,
        }
    }
}

/// The body of a create or a replacement.
// Source: the reference, "Create a new record whose name and type are defined by the path" and
// "Overwrites a single record with {rrset_name} and {rrset_type}": `rrset_values` (required),
// `rrset_ttl` (optional, 300 to 2592000); lego `Record` (`rrset_ttl`, `rrset_values`). The TTL is
// always sent: what the API does without one is not documented.
#[derive(Serialize)]
struct RrsetBody<'a> {
    rrset_values: &'a [String],
    rrset_ttl: u32,
}

/// The body of a value-level change.
// Source: the reference, "Update a record (RRset) in the zone records linked to a domain":
// `add_rrset_values` and `remove_rrset_values` ("Default: []"), `rrset_ttl` optional; the
// reference's only example sends `rrset_ttl` with the value. What the API does with the TTL of a
// change without `rrset_ttl` is not documented (kept, or set to a default), so the caller sends
// the TTL it read whenever the read stated one: right under either reading (design section 3.6).
#[derive(Serialize)]
struct PatchBody<'a> {
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    add_rrset_values: &'a [String],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    remove_rrset_values: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    rrset_ttl: Option<u32>,
}

/// The documented `200` answer of a value-level change: the rrset after it. Only its values are
/// read; `None` when the body does not carry them.
#[derive(Deserialize)]
struct PatchAnswer {
    #[serde(default)]
    rrset_values: Option<Vec<String>>,
}

/// The answer to a create.
#[derive(Debug)]
pub(super) enum Created {
    /// `201`: "Record was created".
    Done,
    /// `409`: "A record with that name / type pair already exists", or `200`: "Same record
    /// already exists. Nothing was changed". Either way an rrset was created by someone else
    /// after the read.
    Exists,
    /// `404`: the domain is gone (not documented for this call; the reading the client takes).
    NotFound,
    /// Another success status, which the reference does not document for this call: whether
    /// the rrset was created is not known.
    Undocumented,
    /// Another refusal, as the error it maps to.
    Refused(Error),
}

/// The answer to a replacement or a delete.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the domain or the rrset does not exist (any more).
    NotFound,
    /// Another refusal, as the error it maps to.
    Refused(Error),
}

/// The answer to a value-level change.
#[derive(Debug)]
pub(super) enum Patched {
    /// `200` (or another success with a body): the rrset exists after the change, with these
    /// values when the body states them (`None`: it does not).
    Present(Option<Vec<String>>),
    /// `204`: "The request was successful, but the resource record set no longer exists at
    /// the end of the operation."
    Gone,
    /// `404`: the domain or the rrset does not exist (any more).
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

/// A zone as the path carries it: the canonical ASCII text without the trailing dot.
pub(super) fn path_zone(zone: &DomainName) -> &str {
    let text = zone.as_str();
    text.strip_suffix('.').unwrap_or(text)
}

impl Api {
    /// The API at `base`.
    pub(super) fn new(http: Http, base: Endpoint) -> Api {
        Api { http, base }
    }

    /// One page of the domain listing with at most one domain: a request that every valid
    /// token can make, whatever domains it sees.
    // Source: the reference, "List of domains handled by LiveDNS": `per_page` ("Minimum: 1"),
    // `sharing_id`.
    pub(super) async fn probe(&self, sharing_id: Option<&str>) -> Result<(), Error> {
        let mut url = self.base.url().path("/domains").query("per_page", "1");
        if let Some(id) = sharing_id {
            url = url.query("sharing_id", id);
        }
        let response = self.http.send(&Request::get(url.build()?)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Vec<Value> =
            response.json("the provider's domain listing is not in the expected form")?;
        Ok(())
    }

    /// Every domain the listing shows, all pages. Without `sharing_id` the API lists "only …
    /// domains directly under your personal organization" (the reference's warning).
    // Source: the reference, "List of domains handled by LiveDNS" (`page`, `per_page`,
    // `sharing_id`). Paging: see `list`.
    pub(super) async fn domains(&self, sharing_id: Option<&str>) -> Result<Vec<Domain>, Error> {
        let url = |page: u32| {
            let mut url = self
                .base
                .url()
                .path("/domains")
                .query("page", &page.to_string());
            if let Some(id) = sharing_id {
                url = url.query("sharing_id", id);
            }
            url.build()
        };
        self.list(url, None).await
    }

    /// The domain `zone`, or `None` when the API does not know it.
    ///
    /// The reference documents no `404` for this call; the client takes a `404` for "no such
    /// domain", as for an rrset: an assumption, for a live run to confirm. The `fqdn` stated
    /// must be the one asked for.
    // Source: the reference, "Show domain's properties" (`GET /domains/{fqdn}`).
    pub(super) async fn domain(&self, zone: &DomainName) -> Result<Option<Domain>, Error> {
        let url = self
            .base
            .url()
            .path("/domains")
            .segment(path_zone(zone))
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let found: Domain = response.json("the provider's domain is not in the expected form")?;
        let other = found
            .fqdn
            .as_deref()
            .is_some_and(|fqdn| DomainName::parse(fqdn).as_ref() != Ok(zone));
        if other {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with a domain other than the one asked for",
                ),
            });
        }
        Ok(Some(found))
    }

    /// Every rrset of `zone`, of every type, all pages. A `404` is `Error::ZoneNotFound`: not
    /// documented for this call, the reading the client takes.
    // Source: the reference, "List records associated with a domain" (`page`, `per_page`,
    // `rrset_type`, `sort_by` with default `rrset_name`). Paging: see `list`. An item must state
    // its name and type: in a listing they are the only identification.
    pub(super) async fn rrsets(&self, zone: &DomainName) -> Result<Vec<Rrset>, Error> {
        let url = |page: u32| {
            self.base
                .url()
                .path("/domains")
                .segment(path_zone(zone))
                .path("/records")
                .query("page", &page.to_string())
                .build()
        };
        let wire: Vec<WireRrset> = self.list(url, Some(zone)).await?;
        wire.into_iter()
            .map(
                |wire| match (wire.rrset_name.clone(), wire.rrset_type.clone()) {
                    (Some(name), Some(rtype)) => Ok(Rrset::from_wire(wire, name, rtype)),
                    _ => Err(Error::Protocol {
                        detail: Detail::constant(
                            "the provider's listing holds an rrset without a name or a type",
                        ),
                    }),
                },
            )
            .collect()
    }

    /// The rrset of `name` (relative, `@` for the apex) and `rtype`, or `None` for a `404`
    /// ("Will return a 404 if the name/type pair does not exist", the reference). The answer
    /// may leave out its name and type; one that states others is `Error::Protocol`.
    pub(super) async fn rrset(
        &self,
        zone: &DomainName,
        name: &str,
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
        let other_name = wire.rrset_name.as_deref().is_some_and(|stated| {
            let stated = DomainName::from_relative(stated, zone);
            let asked = DomainName::from_relative(name, zone);
            stated.is_err() || stated != asked
        });
        let other_type = wire
            .rrset_type
            .as_deref()
            .is_some_and(|stated| !stated.eq_ignore_ascii_case(rtype));
        if other_name || other_type {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with an rrset other than the one asked for",
                ),
            });
        }
        let stated_name = wire.rrset_name.clone().unwrap_or_else(|| name.to_owned());
        let stated_type = wire.rrset_type.clone().unwrap_or_else(|| rtype.to_owned());
        Ok(Some(Rrset::from_wire(wire, stated_name, stated_type)))
    }

    /// Creates an rrset. Sent once: a create is not idempotent.
    // Source: the reference, "Create a new record whose name and type are defined by the path":
    // "Creates a new record. Will raise a 409 conflict if the record already exists, and return
    // a 200 OK if the record already exists with the same values"; 201 "Record was created", 200
    // "Same record already exists. Nothing was changed", 409 "A record with that name / type pair
    // already exists".
    pub(super) async fn create(
        &self,
        zone: &DomainName,
        name: &str,
        rtype: &str,
        values: &[String],
        ttl: u32,
    ) -> Result<Created, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let body = RrsetBody {
            rrset_values: values,
            rrset_ttl: ttl,
        };
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(&body)?)
            .await?;
        Ok(match response.status() {
            201 => Created::Done,
            200 | 409 => Created::Exists,
            404 => Created::NotFound,
            status if (200..300).contains(&status) => Created::Undocumented,
            _ => Created::Refused(self.refusal(&response)),
        })
    }

    /// Replaces the values and the TTL of an rrset. Sent once: the write carries no condition,
    /// and a repeat would widen the window in which another writer's change is overwritten
    /// (design section 5.3).
    // Source: the reference, "Overwrites a single record with {rrset_name} and {rrset_type}"
    // (201 "The resource has been created"); dns-update `put_rrset_url`. Whether it also
    // creates an absent rrset is not documented; the client sends it only for an rrset it read.
    pub(super) async fn replace(
        &self,
        zone: &DomainName,
        name: &str,
        rtype: &str,
        values: &[String],
        ttl: u32,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let body = RrsetBody {
            rrset_values: values,
            rrset_ttl: ttl,
        };
        let response = self
            .http
            .send(&Request::new(Method::PUT, url).json(&body)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Adds `add` and removes `remove` from the values of an rrset, with `ttl` as the rrset's
    /// TTL when given (see `PatchBody`). Sent once: an add is not
    /// idempotent where the provider keeps duplicates (not documented either way).
    // Source: the reference, "Update a record (RRset) in the zone records linked to a domain":
    // "Add or remove some values of a Resource Record set (RRset)"; 200 with the rrset, 204 "the
    // resource record set no longer exists at the end of the operation". What it answers for a
    // missing rrset, for a value to add that is present or one to remove that is absent is not
    // documented: the client sends it only for an rrset it read, a value to add only when the
    // read did not show it and a value to remove only when the read showed it, and takes a `404`
    // for "the rrset is gone" (an assumption).
    pub(super) async fn patch(
        &self,
        zone: &DomainName,
        name: &str,
        rtype: &str,
        add: &[String],
        remove: &[String],
        ttl: Option<u32>,
    ) -> Result<Patched, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let body = PatchBody {
            add_rrset_values: add,
            remove_rrset_values: remove,
            rrset_ttl: ttl,
        };
        let response = self
            .http
            .send(&Request::new(Method::PATCH, url).json(&body)?)
            .await?;
        Ok(match response.status() {
            204 => Patched::Gone,
            404 => Patched::NotFound,
            _ if response.is_success() => Patched::Present(
                serde_json::from_slice::<PatchAnswer>(response.body())
                    .ok()
                    .and_then(|answer| answer.rrset_values),
            ),
            _ => Patched::Refused(self.refusal(&response)),
        })
    }

    /// Deletes an rrset. Sent once: the rrset can hold values of other writers that arrived
    /// after the read.
    // Source: the reference, "Delete record with {rrset_name} and {rrset_type}" (204 "Record was
    // deleted"). A `404` for a missing rrset is not documented (dns-update tolerates
    // `NotFound`); the caller reads again before it concludes anything.
    pub(super) async fn delete(
        &self,
        zone: &DomainName,
        name: &str,
        rtype: &str,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, name, rtype)?;
        let response = self.http.send(&Request::new(Method::DELETE, url)).await?;
        Ok(self.written(&response))
    }

    fn rrset_url(&self, zone: &DomainName, name: &str, rtype: &str) -> Result<Url, Error> {
        self.base
            .url()
            .path("/domains")
            .segment(path_zone(zone))
            .path("/records")
            .segment(name)
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

    /// Reads every page of a listing (a JSON array per page). `url` builds the URL of a page by
    /// its number, from 1. A `404` is `Error::ZoneNotFound` for `zone` when one is given, else a
    /// refusal.
    ///
    /// No page size is sent: the reference gives `per_page` a minimum and neither a default nor
    /// a maximum, so the server's page is taken. "If the number is greater than the last page,
    /// an empty list is returned" (`page`): the listing ends on an empty page. The `Total-Count`
    /// header ("Total number of items") is a cross-check: an empty page before that many items
    /// is `Error::Protocol`, and after more than one page an equal count ends the listing
    /// without the empty page (on the first page the empty page is read, in case the header
    /// counts the page only). A page that repeats the one before it is `Error::Protocol`, and
    /// `pager::collect` stops at its page limit.
    async fn list<T: DeserializeOwned, U>(
        &self,
        url: U,
        zone: Option<&DomainName>,
    ) -> Result<Vec<T>, Error>
    where
        U: Fn(u32) -> Result<Url, Error>,
    {
        let previous: Mutex<Option<Vec<Value>>> = Mutex::new(None);
        let received: Mutex<u64> = Mutex::new(0);
        pager::collect(1u32, |page| {
            let url = url(page);
            let (previous, received) = (&previous, &received);
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
                let total = total_count(&response)?;
                let items: Vec<Value> =
                    response.json("the provider's listing is not in the expected form")?;
                {
                    let mut previous = previous.lock().unwrap_or_else(PoisonError::into_inner);
                    if !items.is_empty() && previous.as_ref() == Some(&items) {
                        return Err(Error::Protocol {
                            detail: Detail::constant(
                                "the provider's listing repeated a page instead of moving on",
                            ),
                        });
                    }
                    *previous = Some(items.clone());
                }
                let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                let so_far = {
                    let mut received = received.lock().unwrap_or_else(PoisonError::into_inner);
                    *received = received.saturating_add(count);
                    *received
                };
                let items: Vec<T> = items
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| malformed())?;
                let next = next_page(page, count, so_far, total)?;
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. `400`, `409` and `422` are refusals of the request (`Rejected`, with the
    /// provider's message and code); anything else is an answer the client cannot interpret.
    // The reference documents no status for a refused request body; `400` and `422` are the
    // statuses HTTP gives a refusal of the request's content, an assumption.
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

fn malformed() -> Error {
    Error::Protocol {
        detail: Detail::constant("the provider's listing is not in the expected form"),
    }
}

/// The `Total-Count` header of a listing page: `None` when absent, `Error::Protocol` when it is
/// not a number.
// Source: the reference, the 200 answers of both listings: "Total-Count integer Total number of
// items", "Filtered-Count integer Number of items returned by the API call".
fn total_count(response: &Response) -> Result<Option<u64>, Error> {
    match response.header("total-count") {
        None => Ok(None),
        Some(text) => text.trim().parse().map(Some).map_err(|_| malformed()),
    }
}

/// The page after `page`, which brought `count` items and `so_far` in all, or `None` when the
/// listing is complete (see `Api::list`).
fn next_page(page: u32, count: u64, so_far: u64, total: Option<u64>) -> Result<Option<u32>, Error> {
    if count == 0 {
        if total.is_some_and(|total| total > so_far) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider's listing ended before the number of items it stated",
                ),
            });
        }
        return Ok(None);
    }
    if page > 1 && total == Some(so_far) {
        return Ok(None);
    }
    Ok(Some(page.saturating_add(1)))
}

/// The provider's error message: `message`, a string.
// Source: the reference, the error bodies of every call (`cause`, `code`, `message`, `object`);
// lego `apiResponse` (`json:"message"`) and `parseError`, which reports `response.Message`.
pub(super) fn error_message(body: &str) -> Option<String> {
    let body: Value = serde_json::from_str(body).ok()?;
    match body.get("message") {
        Some(Value::String(text)) if !text.trim().is_empty() => Some(text.clone()),
        _ => None,
    }
}

/// The provider's error code: `code`, an integer, in decimal.
// Source: the reference, the error bodies of every call: "code integer". Its values are not
// listed; it is carried as the provider states it.
pub(super) fn error_code(body: &str) -> Option<String> {
    let body: Value = serde_json::from_str(body).ok()?;
    match body.get("code") {
        Some(Value::Number(number)) => number
            .as_u64()
            .map(|n| n.to_string())
            .or_else(|| number.as_i64().map(|n| n.to_string())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{error_code, error_message, next_page};
    use crate::error::ErrorKind;

    #[test]
    fn error_bodies_give_message_and_code() {
        let body = r#"{"cause":"Bad Request","code":400,"message":"invalid value","object":"HTTPBadRequest"}"#;
        assert_eq!(error_message(body).as_deref(), Some("invalid value"));
        assert_eq!(error_code(body).as_deref(), Some("400"));
        assert_eq!(error_message(r#"{"message":7}"#), None);
        assert_eq!(error_message(r#"{"message":" "}"#), None);
        assert_eq!(error_code(r#"{"code":"x"}"#), None);
        assert_eq!(error_message("<html>oops</html>"), None);
        assert_eq!(error_code("<html>oops</html>"), None);
    }

    #[test]
    fn pages_end_on_an_empty_page_or_a_clear_total() {
        assert_eq!(next_page(1, 10, 10, Some(25)).unwrap(), Some(2));
        assert_eq!(next_page(2, 10, 20, Some(25)).unwrap(), Some(3));
        assert_eq!(next_page(3, 5, 25, Some(25)).unwrap(), None);
        // On the first page the header may count the page only: one more request.
        assert_eq!(next_page(1, 10, 10, Some(10)).unwrap(), Some(2));
        assert_eq!(next_page(2, 0, 10, Some(10)).unwrap(), None);
        // A header that counts each page never ends the listing early.
        assert_eq!(next_page(2, 10, 20, Some(10)).unwrap(), Some(3));
        assert_eq!(next_page(3, 0, 20, Some(0)).unwrap(), None);
        // Without a header, only the empty page ends it.
        assert_eq!(next_page(1, 10, 10, None).unwrap(), Some(2));
        assert_eq!(next_page(2, 0, 10, None).unwrap(), None);
        // An empty page short of the stated total.
        let e = next_page(2, 0, 10, Some(25)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol);
    }
}
