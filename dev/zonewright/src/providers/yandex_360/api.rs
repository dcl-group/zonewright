//! The Yandex 360 API as this client uses it: one function per endpoint, the wire types, paging
//! and the classification of answers. Nothing here knows the value layer or the record layer;
//! `client.rs`, `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [Create]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create>:
//!   `POST /directory/v1/org/{orgId}/domains/{domain}/dns`; `orgId` an integer, `domain` the full
//!   domain name (Punycode for Cyrillic names); the body fields `type` (enum `A`, `AAAA`,
//!   `CNAME`, `MX`, `TXT`, `SRV`, `NS`, `CAA`), `name` ("record name", example `example`), `ttl`
//!   (all three required) and the optional fields of the types: `address`, `target`,
//!   `exchange`, `preference`, `text`, `port`, `priority`, `weight`, `flag`, `tag`, `value`;
//!   `200` with the record and its `recordId`; `400`, `401`, `403`, `404`, `500` with the error
//!   body `{code, message, details}`. The page states no range for `ttl`.
//! - [List]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List>:
//!   `GET` on the same path with `page` (default 1) and `perPage` (default 50, no maximum
//!   stated); `200` with `records`, `page`, `pages`, `perPage`, `total`; a record (`v1Record`)
//!   has `recordId`, `type`, `name`, `ttl` and the fields of the types listed above; the same
//!   error statuses.
//! - [Edit]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Edit.md>:
//!   `POST /directory/v1/org/{orgId}/domains/{domain}/dns/{recordId}`; the body has `type`,
//!   `name`, `ttl` (required) and `address`, `target`, `exchange`, `preference`, `text`, `port`,
//!   `priority`, `weight` (the CAA fields `flag`, `tag`, `value` are not part of the request);
//!   `200` with the record; the same error statuses.
//! - [Delete]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Delete>:
//!   `DELETE /directory/v1/org/{orgId}/domains/{domain}/dns/{recordId}`; `200` with `{}`; the
//!   same error statuses.
//! - [Domains]: <https://yandex.ru/dev/api360/doc/ru/ref/DomainService/DomainService_List>:
//!   `GET /directory/v1/org/{orgId}/domains` with `page` (default 1) and `perPage` (maximum 10);
//!   `200` with `domains`, `page`, `pages`, `perPage`, `total`; a domain has `name`, `delegated`
//!   ("whether the domain is delegated to Yandex name servers"), `master`, `verified` and more.
//! - [Access]: <https://yandex.ru/dev/api360/doc/ru/access.md>: the header is
//!   `Authorization: OAuth <token>`; the scopes `directory:read_domains` and
//!   `directory:manage_dns`. lego `providers/dns/yandex360/internal/client.go` line 83 sends
//!   the same header; lines 47 to 80 use the create and delete endpoints above.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                                 | Success |
//! | ------------- | ------------------------------------------------------- | ------- |
//! | list domains  | `GET /directory/v1/org/{org}/domains?page&perPage`      | 200     |
//! | list records  | `GET /directory/v1/org/{org}/domains/{domain}/dns?page&perPage` | 200 |
//! | create record | `POST /directory/v1/org/{org}/domains/{domain}/dns`     | 200     |
//! | edit record   | `POST /directory/v1/org/{org}/domains/{domain}/dns/{id}` | 200    |
//! | delete record | `DELETE /directory/v1/org/{org}/domains/{domain}/dns/{id}` | 200  |
//!
//! [Create]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Create
//! [Edit]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Edit.md
//! [List]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_List
//! [Delete]: https://yandex.ru/dev/api360/doc/ru/ref/DomainDNSService/DomainDNSService_Delete
//! [Domains]: https://yandex.ru/dev/api360/doc/ru/ref/DomainService/DomainService_List
//! [Access]: https://yandex.ru/dev/api360/doc/ru/access.md

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Page size of the record listing: the documented default of `perPage`; the page states no
/// maximum, so a larger value is not asked for.
// Source: List, query parameter `perPage` (default 50).
const RECORDS_PER_PAGE: u32 = 50;

/// Page size of the domain listing: the documented maximum of `perPage`.
// Source: Domains, query parameter `perPage` ("maximum 10").
const DOMAINS_PER_PAGE: u32 = 10;

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// The type-specific fields of a record, as the API names them, in a create, an edit and a
/// listing. Each is kept as the JSON value the API stated, so that a field of an unexpected
/// shape makes one value unreadable (non-canonical data) instead of the whole listing, and so
/// that a record can be written back exactly as it was read.
// Source: Create, request body; List, `v1Record`; Edit, request body. The fields per type, as the
// pages describe them: `address` for A and AAAA, `target` for CNAME and SRV, `exchange` and
// `preference` for MX, `text` for TXT, `port`, `priority` and `weight` for SRV, `flag`, `tag` and
// `value` for CAA. lego providers/dns/yandex360/internal/types.go lines 5 to 21 name the same
// fields.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub(crate) struct Fields {
    /// A, AAAA: the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) address: Option<Value>,
    /// CNAME, SRV: the target name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) target: Option<Value>,
    /// MX: the exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) exchange: Option<Value>,
    /// MX: the preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) preference: Option<Value>,
    /// TXT: the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) text: Option<Value>,
    /// SRV: the port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) port: Option<Value>,
    /// SRV: the priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<Value>,
    /// SRV: the weight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) weight: Option<Value>,
    /// CAA: the flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) flag: Option<Value>,
    /// CAA: the tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) tag: Option<Value>,
    /// CAA: the value, "enclosed in double quotes".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) value: Option<Value>,
}

impl Fields {
    /// A string field as text; `None` when absent or not a string.
    pub(super) fn text_of(field: Option<&Value>) -> Option<&str> {
        field.and_then(Value::as_str)
    }

    /// A non-negative integer field; `None` when absent or not such a number.
    pub(super) fn number_of(field: Option<&Value>) -> Option<u64> {
        field.and_then(Value::as_u64)
    }

    /// The fields an edit may carry: these, without the CAA fields, which the edit request does
    /// not have.
    // Source: Edit, request body (no `flag`, `tag` or `value`).
    pub(super) fn for_edit(&self) -> Fields {
        Fields {
            flag: None,
            tag: None,
            value: None,
            ..self.clone()
        }
    }
}

/// A record as the listing returns it; other fields are ignored.
// Source: List, record fields (`recordId`, `type`, `name`, `ttl` and the type's fields).
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Record {
    /// The record's identifier.
    #[serde(rename = "recordId")]
    pub(super) record_id: u64,
    /// The record type.
    #[serde(default, rename = "type")]
    pub(super) rtype: String,
    /// The owner name as the API states it. Its form is not settled by the documentation (see
    /// [`NameForm`]).
    #[serde(default)]
    pub(super) name: String,
    /// TTL in seconds.
    #[serde(default)]
    pub(super) ttl: Option<u32>,
    /// The type's fields.
    #[serde(flatten)]
    pub(super) fields: Fields,
}

impl Record {
    /// The value of a TXT record, when `text` is a string.
    pub(super) fn text(&self) -> Option<&str> {
        Fields::text_of(self.fields.text.as_ref())
    }
}

/// A domain of the organization as the domain listing returns it; other fields are ignored.
// Source: Domains, domain fields `name` and `delegated`.
#[derive(Debug, Deserialize)]
pub(super) struct Domain {
    /// The domain name, in Punycode.
    pub(super) name: String,
    /// Whether the domain is delegated to Yandex name servers. Absent counts as not delegated.
    #[serde(default)]
    pub(super) delegated: bool,
}

/// The body of the create and the edit request.
// Source: Create and Edit, request body: `type`, `name`, `ttl` required, plus the type's fields;
// lego internal/client.go sends a `Record` with `type`, `name`, `ttl` and `text` for a TXT record.
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The owner name relative to the domain, the form lego sends (yandex360.go lines 120 and
    /// 128 pass `ExtractSubDomain`); see [`write_name`] for the apex.
    pub(super) name: &'a str,
    /// TTL in seconds; required by the API.
    pub(super) ttl: u32,
    /// The type's fields.
    #[serde(flatten)]
    pub(super) fields: Fields,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the domain, or for a delete the record, does not exist (any more).
    NotFound,
}

/// The client's handle on the API: the transport, the endpoint and the organization.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    org_id: String,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base` for the organization `org_id` (decimal digits, checked by the
    /// settings), with the token already part of `http`.
    pub(super) fn new(http: Http, base: Endpoint, org_id: String) -> Api {
        Api { http, base, org_id }
    }

    /// `/directory/v1/org/{orgId}`. The organization is the application's own setting, checked
    /// to be digits; `.id` re-checks it before it goes into the path.
    fn org_url(&self) -> UrlBuilder {
        self.base.url().path("/directory/v1/org").id(&self.org_id)
    }

    /// `…/domains/{domain}/dns` with the zone name without its trailing dot.
    // Source: Create, path parameter `domain`: "the full domain name".
    fn dns_url(&self, zone: &DomainName) -> UrlBuilder {
        self.org_url()
            .path("/domains")
            .segment(zone.without_dot())
            .path("/dns")
    }

    /// Every domain of the organization, all pages, delegated or not.
    pub(super) async fn domains(&self) -> Result<Vec<Domain>, Error> {
        let url =
            |page: u32| page_query(self.org_url().path("/domains"), page, DOMAINS_PER_PAGE).build();
        self.list(url, "domains", None).await
    }

    /// Every record of the zone, all pages. A `404` is `Error::ZoneNotFound` for `zone`.
    // Source: List: the listing has no filter by name or type, so the client filters.
    pub(super) async fn records(&self, zone: &DomainName) -> Result<Vec<Record>, Error> {
        let url = |page: u32| page_query(self.dns_url(zone), page, RECORDS_PER_PAGE).build();
        self.list(url, "records", Some(zone)).await
    }

    /// Reads the first record of the zone, to show that the token may read the zone's records:
    /// `false` for `404`.
    // Source: List: `200` with `records`, `404` "not found".
    pub(super) async fn probe(&self, zone: &DomainName) -> Result<bool, Error> {
        let url = page_query(self.dns_url(zone), 1, 1).build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(false);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let body: Value = response.json("the provider's listing is not in the expected form")?;
        if !body.get("records").is_some_and(Value::is_array) {
            return Err(protocol("the provider's listing lacks its list of items"));
        }
        Ok(true)
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3). A `404` is [`Written::NotFound`].
    // Source: Create: `200` with the record, `recordId` among its fields; `404` among the
    // documented answers.
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Written, Error> {
        #[derive(Deserialize)]
        struct Created {
            // Only the presence of the identifier is checked.
            #[serde(rename = "recordId")]
            _record_id: u64,
        }
        let url = self.dns_url(zone).build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        if response.status() == 404 {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Created =
            response.json("the provider's answer to a create is not in the expected form")?;
        Ok(Written::Done)
    }

    /// Edits one record by its identifier: the body replaces its type, name, TTL and the type's
    /// fields. Sent once, as every write but a delete by identifier (design section 5.3). A
    /// `404` is [`Written::NotFound`].
    // Source: Edit: `POST …/dns/{recordId}` with `type`, `name`, `ttl` required; `200` with the
    // record; `404` among the documented answers.
    pub(super) async fn edit_record(
        &self,
        zone: &DomainName,
        record_id: u64,
        record: &NewRecord<'_>,
    ) -> Result<Written, Error> {
        let url = self.dns_url(zone).id(&record_id.to_string()).build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        if response.status() == 404 {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        Ok(Written::Done)
    }

    /// Deletes one record by its identifier. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it.
    // Source: Delete: `200` with `{}`; `404` among the documented answers.
    pub(super) async fn delete_record(
        &self,
        zone: &DomainName,
        record_id: u64,
    ) -> Result<Written, Error> {
        let url = self.dns_url(zone).id(&record_id.to_string()).build()?;
        let response = self
            .http
            .send(&Request::new(Method::DELETE, url).idempotent())
            .await?;
        if response.status() == 404 {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        Ok(Written::Done)
    }

    /// Reads every page of a listing; `url` builds the URL of a page number, `key` is the
    /// field that holds the items. A `404` is `Error::ZoneNotFound` for `zone` when one is
    /// given, else a refusal.
    ///
    /// Complete or an error. The listing states `pages` and `total`: another page follows while
    /// `page < pages`, and at the last page the items received must reach `total`. Fewer, an
    /// absent `pages` or `total`, a `total` that changes between pages (items moved while the
    /// pages were read, so one may have been passed over), an absent list field, or an empty
    /// page before the last is `Error::Protocol`.
    // Source: List and Domains, answer fields `pages` and `total`. Assumption (not documented):
    // that `total` counts every item of the listing and `pages` is at least the number of
    // pages that hold them. Being wrong makes a listing fail, never come back shorter.
    async fn list<T, U>(
        &self,
        url: U,
        key: &'static str,
        zone: Option<&DomainName>,
    ) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u32) -> Result<Url, Error>,
    {
        let received = AtomicU64::new(0);
        // The `total` of the first page; `u64::MAX` until it is read.
        let first_total = AtomicU64::new(u64::MAX);
        pager::collect(1u32, |page| {
            let url = url(page);
            let received = &received;
            let first_total = &first_total;
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
                let body: Value =
                    response.json("the provider's listing is not in the expected form")?;
                let items: Vec<T> = body
                    .get(key)
                    .and_then(|list| serde_json::from_value(list.clone()).ok())
                    .ok_or_else(|| protocol("the provider's listing lacks its list of items"))?;
                let stated = |field: &str| body.get(field).and_then(Value::as_u64);
                let (Some(pages), Some(total)) = (stated("pages"), stated("total")) else {
                    return Err(protocol(
                        "the provider's listing states no page or item count",
                    ));
                };
                if let Err(first) = first_total.compare_exchange(
                    u64::MAX,
                    total,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) && first != total
                {
                    return Err(protocol(
                        "the provider's listing changed its number of items between pages",
                    ));
                }
                let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                let so_far = received
                    .fetch_add(count, Ordering::Relaxed)
                    .saturating_add(count);
                let next = if u64::from(page) < pages {
                    if items.is_empty() {
                        return Err(protocol(
                            "the provider's listing has an empty page before its end",
                        ));
                    }
                    Some(page.saturating_add(1))
                } else if so_far < total {
                    return Err(protocol(
                        "the provider's listing ended before the number of items it stated",
                    ));
                } else {
                    None
                };
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the documented error body;
    /// anything else is an answer the client cannot interpret.
    // Source: Create, List, Delete and Domains: the statuses named are 200, 400, 401, 403, 404
    // and 500, with the body `{code, message, details}` for every error.
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
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// Appends `page` and `perPage`.
fn page_query(url: UrlBuilder, page: u32, per_page: u32) -> UrlBuilder {
    url.query("page", &page.to_string())
        .query("perPage", &per_page.to_string())
}

/// The form in which a listing states owner names without a trailing dot, decided once per
/// listing from every record of the domain.
///
/// The documentation is not explicit about the form: the create page calls the field "record
/// name" (example `example`) and lego sends the name relative to the domain, while the list page
/// describes the field as the "full domain name". A dotless name such as `www.example.org` is the
/// full name in one reading and `www.example.org.example.org` in the other, and guessing wrong
/// files a record under a name that is not its own, where a write to that name would change or
/// delete it. So the client never guesses: a name that only one reading allows decides the form
/// for the whole listing, and a name that both readings allow, in a listing that decides nothing,
/// is refused or skipped.
// Assumption (not documented): one listing states every name in one form. Being wrong makes a
// record at a lookalike name read as relative in a listing that also holds a relative name,
// which is the documented create form; it never makes a name that only the full reading allows
// read as relative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NameForm {
    /// Proven relative: the listing states `@`, or a dotless name that is not within the zone
    /// and therefore cannot be a full name of it.
    Relative,
    /// Nothing in the listing tells the forms apart.
    Undecided,
}

impl NameForm {
    /// The form of a listing of `zone`.
    pub(super) fn of(records: &[Record], zone: &DomainName) -> NameForm {
        let proves_relative = |stated: &str| {
            let stated = stated.trim();
            stated == "@"
                || (!stated.is_empty()
                    && !stated.ends_with('.')
                    && DomainName::parse(stated).is_ok_and(|full| !full.is_within(zone)))
        };
        if records.iter().any(|record| proves_relative(&record.name)) {
            NameForm::Relative
        } else {
            NameForm::Undecided
        }
    }
}

/// The owner a record states, read in the listing's form.
#[derive(Debug, PartialEq, Eq)]
enum Owner {
    /// One reading only.
    Name(DomainName),
    /// A dotless name that reads both as relative and as the full name, in an undecided listing.
    Ambiguous {
        relative: DomainName,
        full: DomainName,
    },
    /// Not a valid name in any reading.
    Invalid,
}

/// Reads the owner a record states: `@` or an empty name is the zone; a name with a trailing dot
/// is absolute; a dotless name is relative to the zone in a relative listing, and in an
/// undecided one it is ambiguous when it is also a name within the zone.
fn read_owner(stated: &str, zone: &DomainName, form: NameForm) -> Owner {
    let stated = stated.trim();
    if stated.is_empty() || stated == "@" {
        return Owner::Name(zone.clone());
    }
    if stated.ends_with('.') {
        return DomainName::parse(stated).map_or(Owner::Invalid, Owner::Name);
    }
    let relative = DomainName::from_relative(stated, zone).ok();
    let full = match form {
        NameForm::Relative => None,
        NameForm::Undecided => DomainName::parse(stated)
            .ok()
            .filter(|full| full.is_within(zone)),
    };
    match (relative, full) {
        (Some(relative), Some(full)) => Owner::Ambiguous { relative, full },
        (None, Some(full)) => Owner::Name(full),
        (Some(relative), None) => Owner::Name(relative),
        (None, None) => Owner::Invalid,
    }
}

/// Whether the owner name a record states is `name`, in a listing of `zone` of the form `form`.
/// A name that may or may not be `name` (ambiguous, and `name` in one of its readings) is
/// `Error::Protocol`: the record cannot be placed, and an operation on `name` that ignored it or
/// took it for its own could miss or destroy data.
pub(super) fn is_owner(
    stated: &str,
    zone: &DomainName,
    form: NameForm,
    name: &DomainName,
) -> Result<bool, Error> {
    match read_owner(stated, zone, form) {
        Owner::Name(owner) => Ok(&owner == name),
        Owner::Ambiguous { relative, full } if &relative == name || &full == name => Err(protocol(
            "the provider stated a record name without a trailing dot that reads both as a \
             relative and as a full name, and nothing in the listing tells the forms apart; \
             the record cannot be placed",
        )),
        Owner::Ambiguous { .. } | Owner::Invalid => Ok(false),
    }
}

/// The owner of a listed record, for the zone listing: `None` for a name that is not valid and
/// for an ambiguous one, which the listing reports in `skipped` instead of placing it at a
/// guessed name.
pub(super) fn listed_owner(stated: &str, zone: &DomainName, form: NameForm) -> Option<DomainName> {
    match read_owner(stated, zone, form) {
        Owner::Name(owner) => Some(owner),
        Owner::Ambiguous { .. } | Owner::Invalid => None,
    }
}

/// `name` as a create or an edit states it: relative to `zone`, `@` for the zone itself.
///
/// Relative names: lego sends the name relative to the zone (providers/dns/yandex360/yandex360.go
/// lines 120 and 128), as the API's example `example` shows.
// Source for `@`: the help page of the DNS editor of Yandex 360 for domains delegated to Yandex,
// <https://yandex.ru/support/yandex-360/business/admin/ru/domains/dns/a.md> ("to point the main
// domain, for example `example.org`, at the site's address, enter `@`"; a subdomain is entered as
// its part left of the domain). The API reference itself does not say how the apex is written;
// the help page describes the same records through the administrator's console. To be confirmed
// against the live API.
pub(super) fn write_name<'a>(name: &'a DomainName, zone: &DomainName) -> Option<&'a str> {
    match name.relative_to(zone)? {
        "" => Some("@"),
        relative => Some(relative),
    }
}

/// The provider's error message: the `message` of the documented error body.
// Source: Create, error body `{code, message, details}`.
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        message: Option<String>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    body.message.filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{NameForm, Record, error_message, is_owner, listed_owner, write_name};
    use crate::error::ErrorKind;
    use crate::name::DomainName;

    fn listed(names: &[&str]) -> Vec<Record> {
        names
            .iter()
            .enumerate()
            .map(|(id, name)| {
                serde_json::from_value(serde_json::json!({
                    "recordId": id, "type": "TXT", "name": name, "ttl": 300
                }))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn the_name_form_is_decided_by_a_name_only_one_reading_allows() {
        let zone = DomainName::parse("example.org").unwrap();
        let form = |names: &[&str]| NameForm::of(&listed(names), &zone);
        assert_eq!(form(&["@"]), NameForm::Relative);
        assert_eq!(form(&["www.example.org", "www"]), NameForm::Relative);
        assert_eq!(form(&["_sip._tcp"]), NameForm::Relative);
        assert_eq!(form(&["*"]), NameForm::Relative);
        assert_eq!(form(&["example.org.sub"]), NameForm::Relative);
        assert_eq!(form(&[]), NameForm::Undecided);
        assert_eq!(
            form(&["www.example.org", "example.org"]),
            NameForm::Undecided
        );
        assert_eq!(
            form(&["www.example.org.", "", "bad name"]),
            NameForm::Undecided
        );
    }

    #[test]
    fn owner_names_are_read_in_every_form() {
        let zone = DomainName::parse("example.org").unwrap();
        let read = |stated: &str, form: NameForm| {
            listed_owner(stated, &zone, form).map(|n| n.as_str().to_owned())
        };
        for (stated, relative, undecided) in [
            ("@", Some("example.org."), Some("example.org.")),
            ("", Some("example.org."), Some("example.org.")),
            ("example.org", Some("example.org.example.org."), None),
            ("example.org.", Some("example.org."), Some("example.org.")),
            ("www", Some("www.example.org."), Some("www.example.org.")),
            ("WWW", Some("www.example.org."), Some("www.example.org.")),
            (
                "www.example.org",
                Some("www.example.org.example.org."),
                None,
            ),
            (
                "www.example.org.",
                Some("www.example.org."),
                Some("www.example.org."),
            ),
            (
                "_sip._tcp",
                Some("_sip._tcp.example.org."),
                Some("_sip._tcp.example.org."),
            ),
            ("*", Some("*.example.org."), Some("*.example.org.")),
            (
                "example.org.sub",
                Some("example.org.sub.example.org."),
                Some("example.org.sub.example.org."),
            ),
            ("other.net.", Some("other.net."), Some("other.net.")),
            ("bad name", None, None),
        ] {
            assert_eq!(
                read(stated, NameForm::Relative).as_deref(),
                relative,
                "{stated:?}"
            );
            assert_eq!(
                read(stated, NameForm::Undecided).as_deref(),
                undecided,
                "{stated:?}"
            );
        }
    }

    #[test]
    fn names_are_written_relative_with_the_apex_as_at() {
        let zone = DomainName::parse("example.org").unwrap();
        let write = |name: &str| {
            let name = DomainName::parse(name).unwrap();
            write_name(&name, &zone).map(str::to_owned)
        };
        assert_eq!(write("example.org").as_deref(), Some("@"));
        assert_eq!(write("www.example.org").as_deref(), Some("www"));
        assert_eq!(write("a.b.example.org").as_deref(), Some("a.b"));
        assert_eq!(write("example.net"), None);
    }

    #[test]
    fn error_messages_are_the_message_field() {
        for (body, expected) in [
            (
                r#"{"code":16,"message":"not authorized","details":[]}"#,
                Some("not authorized"),
            ),
            (r#"{"code":3}"#, None),
            (r#"{"message":""}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn stated_names_are_compared_in_the_listing_form() {
        let zone = DomainName::parse("example.org").unwrap();
        let name = DomainName::parse("_acme-challenge.example.org").unwrap();
        let lookalike = DomainName::parse("_acme-challenge.example.org.example.org").unwrap();
        let is = |stated: &str, form: NameForm, name: &DomainName| {
            is_owner(stated, &zone, form, name).map_err(|e| e.kind())
        };
        for form in [NameForm::Relative, NameForm::Undecided] {
            assert_eq!(is("_acme-challenge", form, &name), Ok(true));
            assert_eq!(is("_ACME-challenge", form, &name), Ok(true));
            assert_eq!(is("_acme-challenge.example.org.", form, &name), Ok(true));
            assert_eq!(is("_acme-challenge.www", form, &name), Ok(false));
            assert_eq!(is("other", form, &name), Ok(false));
            assert_eq!(is("@", form, &name), Ok(false));
            assert_eq!(is("@", form, &zone), Ok(true));
            assert_eq!(is("", form, &zone), Ok(true));
            assert_eq!(is("_acme-challenge", form, &zone), Ok(false));
            assert_eq!(is("www.example.org", form, &name), Ok(false));
        }
        // A relative listing reads a name that repeats the zone as a name below it.
        let relative = NameForm::Relative;
        assert_eq!(
            is("_acme-challenge.example.org", relative, &name),
            Ok(false)
        );
        assert_eq!(
            is("_acme-challenge.example.org", relative, &lookalike),
            Ok(true)
        );
        assert_eq!(is("example.org", relative, &zone), Ok(false));
        // An undecided listing refuses to place it for either of its readings.
        let undecided = NameForm::Undecided;
        for target in [&name, &lookalike] {
            assert_eq!(
                is("_acme-challenge.example.org", undecided, target),
                Err(ErrorKind::Protocol)
            );
        }
        assert_eq!(
            is("example.org", undecided, &zone),
            Err(ErrorKind::Protocol)
        );
        let outside = DomainName::parse("example.net").unwrap();
        assert_eq!(is("example.net", undecided, &outside), Ok(false));
    }
}
