//! The deSEC API as this client uses it: one function per endpoint, the wire types, paging and
//! the classification of answers. Nothing here knows the value layer or the record layer.
//!
//! Sources (hard rule 3), all read 2026-11-16:
//!
//! - [RRsets]: <https://desec.readthedocs.io/en/latest/dns/rrsets.html> (the source of that page:
//!   `docs/dns/rrsets.rst` in `github.com/desec-io/desec-stack`): the rrset object, the
//!   endpoints, pagination, record content, status codes.
//! - [Domains]: <https://desec.readthedocs.io/en/latest/dns/domains.html>: the domain object,
//!   listing domains, retrieving one.
//! - [Rate limits]: <https://desec.readthedocs.io/en/latest/rate-limits.html>.
//! - [Tokens]: <https://desec.readthedocs.io/en/latest/auth/tokens.html>: `Authorization: Token`.
//! - The Go client lego uses, `github.com/nrdcg/desec` (`desec.go`, `records.go`,
//!   `domains.go`, `pagination.go`, `errors.go`), and lego `providers/dns/desec/desec.go`.
//!
//! Endpoints used, all below the `base_url` (`https://desec.io/api/v1`):
//!
//! | Call          | Request                                          | Success                 |
//! | ------------- | ------------------------------------------------ | ----------------------- |
//! | list domains  | `GET /domains/?cursor=`                          | 200, array, `Link`      |
//! | one domain    | `GET /domains/{name}/`                           | 200, the domain; 404    |
//! | list rrsets   | `GET /domains/{name}/rrsets/?cursor=`            | 200, array, `Link`      |
//! | one rrset     | `GET /domains/{name}/rrsets/{subname}/{type}/`   | 200, the rrset; 404     |
//! | create rrset  | `POST /domains/{name}/rrsets/`                   | 201, the rrset          |
//! | change rrset  | `PATCH /domains/{name}/rrsets/{subname}/{type}/` | 200, the rrset          |
//! | delete rrset  | `DELETE /domains/{name}/rrsets/{subname}/{type}/`| 204, also when absent   |
//!
//! Every path ends with `/`, as every path of the documentation and of nrdcg (`desec.go`, the
//! endpoint builder appends `/`). The zone in a path is its name without the trailing dot, in
//! ASCII ("Internationalized domain names (IDN) currently are supported through their Punycode
//! representation only", Domains). The owner is the `subname`, the name relative to the zone;
//! the apex is `@` in a path ("we reserved the special subname value `@`", RRsets, "Accessing the
//! Zone Apex") and `""` in a body ("the zone apex is referred to by an empty subname string",
//! RRsets, "Bulk Operations"; nrdcg `records.go` sends `"subname"` without `omitempty`). A
//! wildcard owner's `*` is percent-encoded (`%2A`) in a path, which a server decodes before it
//! routes: an assumption, not observed against the live API.

use std::sync::{Mutex, PoisonError};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// The API's spelling of the TXT type.
// Source: RRsets, field `type`: "RRset type (uppercase)".
pub(super) const TXT: &str = "TXT";

/// A domain as the API returns it; other members are ignored.
// Source: Domains, "Domain Field Reference" (`name`, `minimum_ttl`, `keys`, `status`, …).
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The domain name, without the trailing dot.
    pub(super) name: String,
}

/// An rrset as the API returns it.
// Source: RRsets, "RRset Field Reference": `created`, `domain`, `subname`, `name`, `type`,
// `records`, `ttl`, `touched`. No member is documented as optional, and none as required
// either, so only `records` is required here: a single rrset's answer may leave out what its
// path states (a stated owner or type must match it), and a listing item, where they are the
// only identification, must state its owner and type (`Api::rrsets`).
#[derive(Deserialize)]
struct WireRrset {
    #[serde(default)]
    subname: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    rtype: Option<String>,
    #[serde(default)]
    ttl: Option<u32>,
    records: Vec<String>,
}

/// An rrset as read. `records` are written back exactly as read; `created`, `touched` and the
/// read-only names are not part of a write.
// `pub(crate)`: it is the `Snapshot` of the client's `WholeSet` implementations, crate-wide
// traits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rrset {
    /// The owner, fully qualified, as the client resolved it from `name` or `subname`; `None`
    /// when the answer spells a name the crate cannot hold.
    pub(super) owner: Option<DomainName>,
    /// The type as the API spelled it.
    pub(super) rtype: String,
    /// TTL in seconds; `None` when the answer has none.
    pub(super) ttl: Option<u32>,
    /// The record contents, in presentation format.
    pub(super) records: Vec<String>,
}

/// The body of `POST …/rrsets/`.
// Source: RRsets, "Creating an RRset": "`type`, `records`, and `ttl` are mandatory, whereas the
// `subname` field is optional"; the example body `{"subname": "www", "type": "A", "ttl": 3600,
// "records": [...]}`. The apex is sent as `""`.
#[derive(Serialize)]
struct NewRrset<'a> {
    subname: &'a str,
    #[serde(rename = "type")]
    rtype: &'a str,
    ttl: u32,
    records: &'a [String],
}

/// The body of `PATCH …/rrsets/{subname}/{type}/`.
// Source: RRsets, "Modifying an RRset": "The API allows changing the values of `records` and
// `ttl`. When using the `PATCH` method, only fields you would like to modify need to be
// provided." lego (`desec.go`, Present) and nrdcg (`records.go`, `Update`) change an rrset with
// `PATCH`. `records` is never empty here: an empty list would delete the rrset.
#[derive(Serialize)]
struct RrsetChange<'a> {
    ttl: u32,
    records: &'a [String],
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the domain (or, for a change, the rrset) does not exist (any more).
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

/// The owner of `name` relative to `zone`: `""` for the apex. The layers refuse a name outside
/// the zone before any request; this refuses it once more rather than build a wrong path.
pub(super) fn subname<'a>(zone: &DomainName, name: &'a DomainName) -> Result<&'a str, Error> {
    name.relative_to(zone).ok_or(Error::InvalidInput {
        detail: Detail::constant("the name is not within the zone"),
        code: None,
    })
}

impl Api {
    /// The API at `base`.
    pub(super) fn new(http: Http, base: Endpoint) -> Api {
        Api { http, base }
    }

    /// The first page of the domain listing: a request that every valid token can make,
    /// whatever its policies, and that verifies it.
    // Source: Domains, "Listing Domains" (`200`, also with no domain: an empty array); Tokens,
    // https://desec.readthedocs.io/en/latest/auth/tokens.html: "All tokens can, regardless of
    // their policy configuration, read any RRset (for all domains in the account)." Whether a
    // token restricted to some rrsets can list domains is not stated: assumed, not observed.
    pub(super) async fn probe(&self) -> Result<(), Error> {
        let url = self.domains_url().query("cursor", "").build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Vec<Value> =
            response.json("the provider's domain listing is not in the expected form")?;
        Ok(())
    }

    /// Every domain of the account, all pages.
    // Source: Domains, "Listing Domains": "Up to 500 items are returned at a time. If you have a
    // larger number of domains configured, the use of pagination is required"; pagination as in
    // RRsets (see `list`).
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        self.list(|| self.domains_url(), None).await
    }

    /// The domain `zone`, or `None` when the account does not own it (`404`).
    // Source: Domains, "Retrieving a Specific Domain": `200` with the domain object if you own a
    // domain with that name, "Otherwise, the return status code is `404 Not Found`."
    pub(super) async fn zone(&self, zone: &DomainName) -> Result<Option<Zone>, Error> {
        let url = self.zone_url(zone).path("/").build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let found: Zone = response.json("the provider's domain is not in the expected form")?;
        if DomainName::parse(&found.name).as_ref() != Ok(zone) {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with a domain other than the one asked for",
                ),
            });
        }
        Ok(Some(found))
    }

    /// Every rrset of `zone`, all pages. A `404` is `Error::ZoneNotFound`. An item must state
    /// its owner (`name` or `subname`) and its type: in a listing they are its only
    /// identification.
    // Source: RRsets, "Retrieving all RRsets in a Zone" (`200` with an array, also when empty);
    // "When operating on domains that don't exist or you don't own, the API responds with a `404
    // Not Found`". Paging: see `list`.
    pub(super) async fn rrsets(&self, zone: &DomainName) -> Result<Vec<Rrset>, Error> {
        let wire: Vec<WireRrset> = self
            .list(|| self.zone_url(zone).path("/rrsets/"), Some(zone))
            .await?;
        wire.into_iter()
            .map(|wire| {
                let rtype = wire.rtype.clone().ok_or_else(nameless)?;
                let owner = match (&wire.name, &wire.subname) {
                    (Some(name), _) => DomainName::parse(name).ok(),
                    (None, Some(sub)) => DomainName::from_relative(sub, zone).ok(),
                    (None, None) => return Err(nameless()),
                };
                Ok(Rrset {
                    owner,
                    rtype,
                    ttl: wire.ttl,
                    records: wire.records,
                })
            })
            .collect()
    }

    /// The rrset of `name` and `rtype` (the API's spelling), or `None` for a `404`, which the
    /// API answers for a missing rrset and for a domain the account does not own alike.
    // Source: RRsets, "Retrieving a Specific RRset": "The response status code is `200 OK` if the
    // requested RRset exists, and `404 Not Found` otherwise"; the domain rule quoted at `rrsets`.
    pub(super) async fn rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Option<Rrset>, Error> {
        let sub = subname(zone, name)?;
        let url = self.rrset_url(zone, sub, rtype)?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let wire: WireRrset = response.json("the provider's rrset is not in the expected form")?;
        // The answer must be about the rrset asked for; what it leaves out, the path says.
        let other = wire.subname.as_deref().is_some_and(|stated| stated != sub)
            || wire
                .name
                .as_deref()
                .is_some_and(|stated| DomainName::parse(stated).as_ref() != Ok(name))
            || wire.rtype.as_deref().is_some_and(|stated| stated != rtype);
        if other {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the provider answered with an rrset other than the one asked for",
                ),
            });
        }
        Ok(Some(Rrset {
            owner: Some(name.clone()),
            rtype: rtype.to_owned(),
            ttl: wire.ttl,
            records: wire.records,
        }))
    }

    /// Creates an rrset. Sent once: a create is not idempotent.
    // Source: RRsets, "Creating an RRset": `POST` to `…/rrsets/`, "`201 Created`"; "If the
    // operation cannot be performed with the given parameters, the API returns `400 Bad
    // Request`. This can happen, for instance, when there is a conflicting RRset with the same
    // name and type". `400` covers other refusals too, so the caller reads again before it
    // concludes anything.
    pub(super) async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        ttl: u32,
        records: &[String],
    ) -> Result<Written, Error> {
        let body = NewRrset {
            subname: subname(zone, name)?,
            rtype,
            ttl,
            records,
        };
        let url = self.zone_url(zone).path("/rrsets/").build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(&body)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Replaces the records and the TTL of an rrset. Sent once: the write carries no condition,
    /// and a repeat would widen the window in which another writer's change is overwritten
    /// (design section 5.3).
    // Source: RRsets, "Modifying an RRset": `PATCH` on the rrset's endpoint, "the API returns
    // `200 OK` with the updated RRset". What it answers for an rrset that does not exist is not
    // documented; `404`, as for a read of one, is taken as "gone since the read": an assumption,
    // not observed against the live API, and an open question: the crate's public API cannot
    // order a change after another writer's delete, so no live test settles it (a manual `PATCH`
    // of a missing rrset does). Any other refusal is returned as it is, and an answer that
    // created the rrset would be a success with the records intended.
    pub(super) async fn change(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        ttl: u32,
        records: &[String],
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, subname(zone, name)?, rtype)?;
        let body = RrsetChange { ttl, records };
        let response = self
            .http
            .send(&Request::new(Method::PATCH, url).json(&body)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Deletes an rrset. Sent once: the rrset can hold values of other writers that arrived
    /// after the read, and a repeat would widen that window like a repeated change.
    // Source: RRsets, "Deleting an RRset": "Upon success or if the RRset did not exist in the
    // first place, the response status code is `204 No Content`." A `404` is then the domain
    // (the rule quoted at `rrsets`).
    pub(super) async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Written, Error> {
        let url = self.rrset_url(zone, subname(zone, name)?, rtype)?;
        let response = self.http.send(&Request::new(Method::DELETE, url)).await?;
        Ok(self.written(&response))
    }

    fn domains_url(&self) -> UrlBuilder {
        self.base.url().path("/domains/")
    }

    /// `/domains/{name}`, without the trailing `/`.
    fn zone_url(&self, zone: &DomainName) -> UrlBuilder {
        self.base.url().path("/domains").segment(zone.without_dot())
    }

    fn rrset_url(&self, zone: &DomainName, sub: &str, rtype: &str) -> Result<Url, Error> {
        let url = self.zone_url(zone).path("/rrsets");
        let url = if sub.is_empty() {
            url.path("/@")
        } else {
            url.segment(sub)
        };
        url.segment(rtype).path("/").build()
    }

    fn written(&self, response: &Response) -> Written {
        match response.status() {
            _ if response.is_success() => Written::Done,
            404 => Written::NotFound,
            _ => Written::Refused(self.refusal(response)),
        }
    }

    /// Reads every page of a listing at the path `url` builds.
    ///
    /// Pagination (RRsets, "Pagination"): "Up to 500 items are returned at a time. If more than
    /// 500 items would match the query, the use of the `cursor` query parameter is required. The
    /// first page can be retrieved by sending an empty pagination parameter, `cursor=`." So the
    /// first request always carries `cursor=` (as nrdcg's `domains.go` does), and a listing of
    /// any length is in pagination mode. "Once in pagination mode, the URLs to retrieve the next
    /// (or previous) page are given in the `Link:` response header", with opaque cursors; "On the
    /// … last page, the `Link:` header will not contain a … `next` link".
    ///
    /// The listing ends at a page without a `next` link. Every `Link` field line is read (a
    /// list-valued header may arrive as several, RFC 9110 section 5.3; the documentation prints
    /// the three links on three lines); a field that is not readable text or not in the form of
    /// RFC 8288 is `Error::Protocol`, never taken for "no next page". Only the `cursor` of the
    /// `next` link is taken (nrdcg `pagination.go` does the same); the URL itself is never
    /// requested (design section 5.4). No page size is sent: none is documented as a parameter.
    /// A `next` link without a cursor, an empty page with a `next` link, a cursor equal to the
    /// one just used, and a page that repeats the one before it are `Error::Protocol`, and
    /// `pager::collect` stops at its page limit.
    async fn list<T, U>(&self, url: U, zone: Option<&DomainName>) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn() -> UrlBuilder,
    {
        let previous: Mutex<Option<Vec<Value>>> = Mutex::new(None);
        pager::collect(String::new(), |cursor| {
            let request = url().query("cursor", &cursor).build();
            let previous = &previous;
            async move {
                let request = request?;
                let response = self.http.send(&Request::get(request.clone())).await?;
                if response.status() == 404
                    && let Some(zone) = zone
                {
                    return Err(Error::zone_not_found(zone.clone()));
                }
                if !response.is_success() {
                    return Err(self.refusal(&response));
                }
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
                let link = response.header_fields("link")?.join(", ");
                let next = next_cursor((!link.is_empty()).then_some(link.as_str()), &request)?;
                // Under the documented paging an empty page is the last one; one that still
                // names a next page is a listing the client cannot trust to be complete.
                if items.is_empty() && next.is_some() {
                    return Err(Error::Protocol {
                        detail: Detail::constant(
                            "the provider's listing answered an empty page that names a next page",
                        ),
                    });
                }
                let items: Vec<T> =
                    serde_json::from_value(Value::Array(items)).map_err(|_| malformed_listing())?;
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the
    /// transport already. A `400` is the documented refusal (`Rejected`, with the provider's
    /// message); anything else is an answer the client cannot interpret.
    // Source: RRsets, the `400 Bad Request` cases of "Creating an RRset" and "Modifying an
    // RRset"; no other refusal status is documented for these calls (`403` for managed types and
    // a token without permission, mapped by the transport).
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

fn nameless() -> Error {
    Error::Protocol {
        detail: Detail::constant(
            "the provider's listing holds an rrset without an owner name or a type",
        ),
    }
}

fn malformed_listing() -> Error {
    Error::Protocol {
        detail: Detail::constant("the provider's listing is not in the expected form"),
    }
}

/// The cursor of the `next` link of a `Link` header (RFC 8288), or `None` when there is no such
/// link. A link is resolved against the URL of the request, so a relative reference works too;
/// only its `cursor` query parameter is used.
// Source: RRsets, "Pagination" (the `Link` example with `rel="first"`, `rel="prev"` and
// `rel="next"` and the cursor in the `cursor` query parameter); nrdcg `pagination.go`
// (`query.Get("cursor")` of each link).
fn next_cursor(header: Option<&str>, request: &Url) -> Result<Option<String>, Error> {
    let Some(header) = header else {
        return Ok(None);
    };
    let bad = || Error::Protocol {
        detail: Detail::constant("the provider's Link header is not in the expected form"),
    };
    for (target, params) in links(header).ok_or_else(bad)? {
        let next = params.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("rel")
                && value
                    .split_ascii_whitespace()
                    .any(|rel| rel.eq_ignore_ascii_case("next"))
        });
        if !next {
            continue;
        }
        let url = request.join(target).map_err(|_| bad())?;
        let cursor = url
            .query_pairs()
            .find(|(key, _)| key == "cursor")
            .map(|(_, value)| value.into_owned())
            .ok_or_else(bad)?;
        return Ok(Some(cursor));
    }
    Ok(None)
}

/// One link of a `Link` header: its target and its parameters, values unquoted.
type Link<'a> = (&'a str, Vec<(&'a str, String)>);

/// The links of a `Link` header value: `<target>; key=value; key="value", …`. `None` when the
/// value does not have that form.
fn links(header: &str) -> Option<Vec<Link<'_>>> {
    let mut out = Vec::new();
    let mut rest = header.trim_start();
    while !rest.is_empty() {
        let after = rest.strip_prefix('<')?;
        let end = after.find('>')?;
        let target = after.get(..end)?;
        rest = after.get(end + 1..)?.trim_start();
        let mut params = Vec::new();
        while let Some(param) = rest.strip_prefix(';') {
            let param = param.trim_start();
            let key_end = param
                .find(|c: char| c == '=' || c == ';' || c == ',' || c.is_whitespace())
                .unwrap_or(param.len());
            let key = param.get(..key_end)?;
            rest = param.get(key_end..)?.trim_start();
            let mut value = String::new();
            if let Some(after_eq) = rest.strip_prefix('=') {
                let after_eq = after_eq.trim_start();
                if let Some(quoted) = after_eq.strip_prefix('"') {
                    let mut chars = quoted.char_indices();
                    let mut closed = None;
                    while let Some((at, c)) = chars.next() {
                        match c {
                            '\\' => {
                                let (_, escaped) = chars.next()?;
                                value.push(escaped);
                            }
                            '"' => {
                                closed = Some(at + 1);
                                break;
                            }
                            other => value.push(other),
                        }
                    }
                    rest = quoted.get(closed?..)?.trim_start();
                } else {
                    let value_end = after_eq
                        .find(|c: char| c == ';' || c == ',' || c.is_whitespace())
                        .unwrap_or(after_eq.len());
                    value.push_str(after_eq.get(..value_end)?);
                    rest = after_eq.get(value_end..)?.trim_start();
                }
            }
            params.push((key, value));
        }
        out.push((target, params));
        match rest.strip_prefix(',') {
            Some(after) => rest = after.trim_start(),
            None if rest.is_empty() => {}
            None => return None,
        }
    }
    Some(out)
}

/// The provider's error message: `detail`, a string. Other error bodies (a `400` keyed by the
/// fields of the request, a list for a bulk request) have no single message; the transport then
/// takes the strings of the body.
// Source: nrdcg `errors.go` (`NotFoundError{Detail string json:"detail"}`);
// https://desec.readthedocs.io/en/latest/auth/account.html shows error bodies with `detail` and
// with field keys; RRsets, "Input validation" (a list of errors for a bulk request).
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        detail: Option<Value>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    match body.detail {
        Some(Value::String(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use reqwest::Url;

    use super::{error_message, links, next_cursor};
    use crate::error::ErrorKind;

    fn request() -> Url {
        Url::parse("https://desec.io/api/v1/domains/example.org/rrsets/?cursor=").unwrap()
    }

    #[test]
    fn error_messages_are_the_detail_field() {
        assert_eq!(
            error_message(r#"{"detail":"Not found."}"#).as_deref(),
            Some("Not found.")
        );
        assert_eq!(error_message(r#"{"records":["bad"]}"#), None);
        assert_eq!(error_message(r#"{"detail":7}"#), None);
        assert_eq!(error_message("[{}, {\"ttl\": [\"x\"]}]"), None);
        assert_eq!(error_message("<html>oops</html>"), None);
    }

    #[test]
    fn the_next_cursor_is_read_from_the_link_header() {
        // The example of the documentation.
        let header = "<https://desec.io/api/v1/domains/example.org/rrsets/?cursor=>; rel=\"first\", \
             <https://desec.io/api/v1/domains/example.org/rrsets/?cursor=:prev_cursor>; rel=\"prev\", \
             <https://desec.io/api/v1/domains/example.org/rrsets/?cursor=:next_cursor>; rel=\"next\"";
        assert_eq!(
            next_cursor(Some(header), &request()).unwrap().as_deref(),
            Some(":next_cursor")
        );
        // The last page: no `next`.
        let last = "<https://desec.io/api/v1/domains/example.org/rrsets/?cursor=>; rel=\"first\", \
                    <https://desec.io/api/v1/domains/example.org/rrsets/?cursor=p>; rel=\"prev\"";
        assert_eq!(next_cursor(Some(last), &request()).unwrap(), None);
        assert_eq!(next_cursor(None, &request()).unwrap(), None);
        // Unquoted, relative, other parameters, a percent-encoded cursor.
        let odd =
            "</api/v1/domains/example.org/rrsets/?type=A&cursor=a%2Bb>;title=\"x, y\";rel=next";
        assert_eq!(
            next_cursor(Some(odd), &request()).unwrap().as_deref(),
            Some("a+b")
        );
        for bad in [
            "<https://desec.io/api/v1/domains/example.org/rrsets/>; rel=\"next\"",
            "https://desec.io/x; rel=next",
            "<https://desec.io/x; rel=next",
            "<https://desec.io/x>; rel=\"next",
        ] {
            let e = next_cursor(Some(bad), &request()).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Protocol, "{bad}");
        }
        assert_eq!(links("").unwrap().len(), 0);
    }
}
