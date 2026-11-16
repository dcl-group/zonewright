//! The DNSimple API v2 as this client uses it: one function per endpoint, the wire types, the
//! account identifier, paging and the classification of answers. Nothing here knows the value
//! layer; `client.rs`, `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3), all read on 2026-11-16:
//!
//! - [Overview]: <https://developer.dnsimple.com/v2/>: the URL `https://api.dnsimple.com/v2/`,
//!   `Authorization: Bearer`, account and user tokens, "The account identifier must be supplied
//!   regardless the authentication mechanism, even if you use an account token", the `whoami`
//!   call for an account token and `listAccounts` for a user token, the answer envelope `data`,
//!   pagination (`page` default 1, `per_page` "default: 30, maximum: 100", the `pagination`
//!   object with `current_page`, `per_page`, `total_entries` and `total_pages`), the statuses
//!   (400, 401, 402, 403, 404, 412, 429, 5xx), error bodies "with at least a message key" and an
//!   optional `errors` object, and the rate limits.
//! - [Identity]: <https://developer.dnsimple.com/v2/identity/>: `GET /whoami`, `data.account`
//!   for an account token, `null` with a user token.
//! - [Zones]: <https://developer.dnsimple.com/v2/zones/>: `GET /:account/zones` and
//!   `GET /:account/zones/:zone`, where `:zone` is the zone name.
//! - [Records]: <https://developer.dnsimple.com/v2/zones/records/>: list (`name`, `name_like`,
//!   `type` filters; 200), create (`name` "without the domain", `""` for the apex, `type`,
//!   `content` required, `ttl`, `priority`, `regions`, `integrated_zones` optional; 201; 400
//!   "if the record cannot be created"), update by PATCH ("You can pass zero or any of them":
//!   `name`, `content`, `ttl`, `priority`, `regions`, `integrated_zones`; 200; 400), delete
//!   (204; 400 "if the record cannot be deleted").
//! - [OpenAPI]: <https://developer.dnsimple.com/v2/openapi.json> (version 2.0.0): the schemas
//!   `ZoneRecord` (every member required: `id`, `zone_id`, `parent_id`, `name`, `content`, `ttl`,
//!   `priority`, `type`, `regions`, `system_record`, `created_at`, `updated_at`), `Zone`,
//!   `Pagination` (all four members required), `Error` (`message` required), the list answers
//!   (`data` and `pagination` required) and the `404` answers of `getZone`, `createZoneRecord`,
//!   `updateZoneRecord` and `deleteZoneRecord`.
//! - lego `providers/dns/dnsimple/dnsimple.go`: `whoami` and its refusal of user tokens ("user
//!   tokens are not supported, please use an account token"), `GET .../zones/<zone without the
//!   trailing dot>`, `POST .../records` with `type`, the relative `name`, `content` and `ttl`.
//!   Its cleanup deletes every TXT record at the name whatever its value; this client does not.
//! - dns-update `src/providers/dnsimple.rs`: list with `name`, `type` and `per_page=100`, create
//!   and delete by identifier, an exact match of `name` and `type` on the client's side.
//! - dnsimple-go `dnsimple/dnsimple.go`: `ListOptions` with `page` and `per_page`, the
//!   `Pagination` fields.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call          | Request                                                  | Success   |
//! | ------------- | -------------------------------------------------------- | --------- |
//! | identity      | `GET /whoami`                                            | 200       |
//! | get zone      | `GET /{account}/zones/{zone}`                            | 200       |
//! | list zones    | `GET /{account}/zones?per_page&page`                     | 200, page |
//! | list records  | `GET /{account}/zones/{zone}/records?type&per_page&page` | 200, page |
//! | create record | `POST /{account}/zones/{zone}/records`                   | 201       |
//! | update record | `PATCH /{account}/zones/{zone}/records/{id}`             | 200       |
//! | delete record | `DELETE /{account}/zones/{zone}/records/{id}`            | 204       |
//!
//! The batch endpoint (`POST .../batch`) is not used: it is a Public Preview, limited to some
//! plans, and its behavior when one of its operations fails is not documented.
//!
//! [Overview]: https://developer.dnsimple.com/v2/
//! [Identity]: https://developer.dnsimple.com/v2/identity/
//! [Zones]: https://developer.dnsimple.com/v2/zones/
//! [Records]: https://developer.dnsimple.com/v2/zones/records/
//! [OpenAPI]: https://developer.dnsimple.com/v2/openapi.json

use std::fmt;
use std::sync::Mutex;

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// Page size of every listing: the documented maximum of `per_page`.
// Source: Overview, "Pagination": `per_page` "(default: 30, maximum: 100)"; dns-update sends
// `per_page=100`. The Overview adds that "Some endpoints can define specific defaults and
// maximum values"; the loop below follows the `pagination` object of each answer, so a smaller
// page the server chooses is read correctly, and a refusal of the size is an error, never a
// shorter listing.
const PAGE_SIZE: u32 = 100;

/// The record type name as the API spells it.
pub(super) const TXT: &str = "TXT";

/// A record as `GET .../records` returns it; other members are ignored.
// Source: OpenAPI `ZoneRecord` (every member below is required there; `priority` is an integer
// or `null`); Records, the list and get examples. `priority` is kept as a JSON value, so that
// one record with an odd priority is carried as non-canonical data instead of failing the whole
// listing.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Record {
    /// The record's identifier.
    pub(super) id: u64,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: String,
    /// The owner name relative to the zone, `""` for the apex.
    pub(super) name: String,
    /// The value, without the priority.
    pub(super) content: String,
    /// TTL in seconds.
    pub(super) ttl: u32,
    /// The priority of MX and SRV records.
    #[serde(default)]
    pub(super) priority: Option<Value>,
    /// The regions the record is published in.
    pub(super) regions: Vec<String>,
    /// A record the provider generated, "not modifiable".
    pub(super) system_record: bool,
}

impl Record {
    /// The record is published everywhere: its `regions` are empty or exactly `global`.
    // Source: OpenAPI `ZoneRecord.regions`: "The regions where this record is active. If empty,
    // the record is active in all regions"; Records, "Record Regions": "If you don't select any,
    // the record will appear in all of them (global)", and the examples answer `["global"]`. A
    // record limited to some regions makes the answers of a name depend on where the query is
    // served, which the model of an rrset cannot hold (design section 3.4).
    pub(super) fn is_global(&self) -> bool {
        match self.regions.as_slice() {
            [] => true,
            [only] => only == "global",
            _ => false,
        }
    }
}

/// A zone as `GET /{account}/zones` and `GET /{account}/zones/{zone}` return it; other members
/// are ignored.
// Source: OpenAPI `Zone`: `name`, `active` ("If false, DNS services are disabled and DNS records
// will not be resolved"), `secondary` ("Returns true for a secondary zone"). Only `name` is
// required here: the get request already names the zone, and the flags only add a warning.
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The zone's name, without a trailing dot.
    #[serde(default)]
    pub(super) name: Option<String>,
    /// DNS services are active for the zone.
    #[serde(default)]
    pub(super) active: Option<bool>,
    /// A secondary zone.
    #[serde(default)]
    pub(super) secondary: Option<bool>,
}

/// The body of `POST .../records`.
// Source: Records, "Create a zone record", Input: `name` (required, "without the domain",
// "an empty string" for the apex), `type` (required), `content` (required), `ttl`, `priority`.
// `regions` and `integrated_zones` are left out: a record without `regions` "will appear in all
// of them (global)", and without `integrated_zones` "the record creation will be applied to the
// DNSimple zone and all integrated zones that support the record type".
#[derive(Serialize)]
pub(super) struct NewRecord<'a> {
    /// The owner name relative to the zone, `""` for the apex.
    pub(super) name: &'a str,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The value.
    pub(super) content: &'a str,
    /// TTL in seconds.
    pub(super) ttl: u32,
    /// MX preference or SRV priority; left out for the other types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u16>,
}

/// The body of `PATCH .../records/{id}`: only the members that change.
// Source: Records, "Update a zone record": "The following fields are updateable. You can pass
// zero or any of them." `name`, `regions` and `integrated_zones` are never sent, so the record
// keeps its name and the regions and integrated zones it has.
#[derive(Serialize)]
pub(super) struct RecordPatch<'a> {
    /// The new value; left out when it stays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) content: Option<&'a str>,
    /// The new TTL; left out when it stays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
    /// The new MX preference or SRV priority, with new content of those types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u16>,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the zone, or for an update or a delete the record, does not exist (any more).
    NotFound,
}

/// What `GET /whoami` says about the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    /// The account of an account token; `None` for a user token.
    pub(super) account: Option<u64>,
}

/// The client's handle on the API: the transport, the endpoint and the account.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    /// The account of the settings, if any.
    configured: Option<u64>,
    /// The account read from the token's identity, once per client.
    discovered: OnceCell<u64>,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .field("configured", &self.configured)
            .field("discovered", &self.discovered.get())
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`, with the token already part of `http`.
    pub(super) fn new(http: Http, base: Endpoint, configured: Option<u64>) -> Api {
        Api {
            http,
            base,
            configured,
            discovered: OnceCell::new(),
        }
    }

    /// `GET /whoami`: a real authenticated request, so a success proves that the token is
    /// accepted now.
    // Source: Identity, "Who am I": `{"data":{"user":null,"account":{"id":1,...}}}` for an
    // account token, `{"data":{"user":{...},"account":null}}` for a user token. Only `id` of the
    // account is read; `data` is required, `account` may be `null` or absent.
    pub(super) async fn whoami(&self) -> Result<Identity, Error> {
        #[derive(Deserialize)]
        struct Answer {
            data: Data,
        }
        #[derive(Deserialize)]
        struct Data {
            #[serde(default)]
            account: Option<Account>,
        }
        #[derive(Deserialize)]
        struct Account {
            id: u64,
        }
        let url = self.base.url().path("/whoami").build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let answer: Answer =
            response.json("the provider's identity answer is not in the expected form")?;
        Ok(Identity {
            account: answer.data.account.map(|account| account.id),
        })
    }

    /// Checks the account of the settings against `identity` and remembers the account of an
    /// account token. A user token without `account_id` and an account token of another
    /// account than the configured one are `Error::Config`.
    pub(super) fn adopt(&self, identity: Identity) -> Result<u64, Error> {
        match (self.configured, identity.account) {
            (Some(configured), Some(token)) if configured != token => Err(config(
                "account_id is not the account of the token; correct account_id or use a token \
                 of that account",
            )),
            (Some(configured), _) => Ok(configured),
            (None, Some(token)) => {
                // A second set of the same value is harmless: the account of a token does not
                // change.
                let _ = self.discovered.set(token);
                Ok(token)
            }
            (None, None) => Err(user_token()),
        }
    }

    /// The account of every path: the configured one, or the account of an account token,
    /// read once per client with `whoami`.
    // Source: Overview, "Account scope": "The account identifier must be supplied regardless
    // the authentication mechanism, even if you use an account token"; "If you use an account
    // token ... perform a whoami API call". For a user token the Overview says to list the
    // accounts and "Select the relevant account based on a known criteria (e.g. the name or an
    // user input)": the client has no such criterion, so a user token needs `account_id`.
    pub(super) async fn account(&self) -> Result<u64, Error> {
        if let Some(configured) = self.configured {
            return Ok(configured);
        }
        let id = self
            .discovered
            .get_or_try_init(|| async {
                let identity = self.whoami().await?;
                identity.account.ok_or_else(user_token)
            })
            .await?;
        Ok(*id)
    }

    /// `GET /{account}/zones/{zone}`: the zone, or `None` for `404`.
    // Source: Zones, "Retrieve a zone": `:zone` "The zone name", example
    // `GET https://api.dnsimple.com/v2/1010/zones/example.com`; OpenAPI `getZone`: 200, 404.
    pub(super) async fn zone(&self, zone: &DomainName) -> Result<Option<Zone>, Error> {
        #[derive(Deserialize)]
        struct One {
            data: Zone,
        }
        let url = self.zone_url(zone).await?.build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let one: One = response.json("the provider's zone answer is not in the expected form")?;
        Ok(Some(one.data))
    }

    /// Every zone of the account, all pages.
    // Source: Zones, "List zones"; Overview, "Pagination".
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        let account = self.account().await?;
        let base = || self.base.url().segment(&account.to_string()).path("/zones");
        self.list(|page| page_query(base(), page).build(), None)
            .await
    }

    /// Every record of type `rtype` (the API's spelling) in the zone, all pages. The `name`
    /// filter is not used (see `records.rs`); the caller compares names and types itself. A
    /// `404` is `Error::ZoneNotFound` for `zone`.
    // Source: Records, "List zone records", filter `type` ("Only include records with record
    // type equal to given string"); example `GET .../zones/example.com/records?type=TXT`.
    pub(super) async fn records(
        &self,
        zone: &DomainName,
        rtype: &str,
    ) -> Result<Vec<Record>, Error> {
        let account = self.account().await?;
        let url = |page: u32| {
            let url = self
                .zone_builder(account, zone)
                .path("/records")
                .query("type", rtype);
            page_query(url, page).build()
        };
        self.list(url, Some(zone)).await
    }

    /// Every record of the zone, all pages, without filters. A `404` is `Error::ZoneNotFound`
    /// for `zone`.
    // Source: Records, "List zone records".
    pub(super) async fn all_records(&self, zone: &DomainName) -> Result<Vec<Record>, Error> {
        let account = self.account().await?;
        let url =
            |page: u32| page_query(self.zone_builder(account, zone).path("/records"), page).build();
        self.list(url, Some(zone)).await
    }

    /// Creates a record. Sent once: a create is not idempotent, and a repeat after an unknown
    /// outcome could add a second copy (design section 5.3). A `404` is [`Written::NotFound`]
    /// (the zone does not exist); another refusal is an error.
    // Source: Records, "Create a zone record": 201 with `data`, the record with its generated
    // `id`; 400 "if the record cannot be created"; OpenAPI `createZoneRecord`: 201, 400, 404.
    pub(super) async fn create_record(
        &self,
        zone: &DomainName,
        record: &NewRecord<'_>,
    ) -> Result<Written, Error> {
        #[derive(Deserialize)]
        struct Created {
            // Only the presence of the record with its identifier is checked.
            #[serde(rename = "data")]
            _record: Identified,
        }
        #[derive(Deserialize)]
        struct Identified {
            #[serde(rename = "id")]
            _id: u64,
        }
        let url = self.zone_url(zone).await?.path("/records").build()?;
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

    /// Changes the members of one record that `patch` names. Sent once: design section 5.3
    /// retries only reads and deletes by identifier. A `404` is [`Written::NotFound`] (the
    /// record, or the zone, does not exist any more).
    // Source: Records, "Update a zone record": 200 with `data`; 400 "if the record cannot be
    // updated"; OpenAPI `updateZoneRecord`: 200, 400, 404.
    pub(super) async fn update_record(
        &self,
        zone: &DomainName,
        id: u64,
        patch: &RecordPatch<'_>,
    ) -> Result<Written, Error> {
        #[derive(Deserialize)]
        struct Updated {
            // Only the presence of the record is checked.
            #[serde(rename = "data")]
            _record: serde::de::IgnoredAny,
        }
        let url = self
            .zone_url(zone)
            .await?
            .path("/records")
            .id(&id.to_string())
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::PATCH, url).json(patch)?)
            .await?;
        if response.status() == 404 {
            return Ok(Written::NotFound);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let _: Updated =
            response.json("the provider's answer to an update is not in the expected form")?;
        Ok(Written::Done)
    }

    /// Deletes one record by its identifier. Idempotent: repeating it leaves the same state, so
    /// the transport may retry it.
    // Source: Records, "Delete a zone record": 204, no body; 400 "if the record cannot be
    // deleted"; OpenAPI `deleteZoneRecord`: 204, 404.
    pub(super) async fn delete_record(&self, zone: &DomainName, id: u64) -> Result<Written, Error> {
        let url = self
            .zone_url(zone)
            .await?
            .path("/records")
            .id(&id.to_string())
            .build()?;
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

    /// `/{account}/zones/{zone}` with the zone name without its trailing dot (Zones, `:zone`
    /// "the zone name, such as example.com"; lego `dns01.UnFqdn`).
    async fn zone_url(&self, zone: &DomainName) -> Result<UrlBuilder, Error> {
        let account = self.account().await?;
        Ok(self.zone_builder(account, zone))
    }

    /// [`Api::zone_url`] for an account already known.
    fn zone_builder(&self, account: u64, zone: &DomainName) -> UrlBuilder {
        self.base
            .url()
            .segment(&account.to_string())
            .path("/zones")
            .segment(zone.without_dot())
    }

    /// Reads every page of a listing; `url` builds the URL of a page number. A `404` is
    /// `Error::ZoneNotFound` for `zone` when one is given, else a refusal.
    ///
    /// Complete or an error. Pages are fetched by number, from 1, while the page read is below
    /// `pagination.total_pages`. Every answer must state the page that was asked for in
    /// `current_page`; `total_pages` and `total_entries` must stay the same from page to page
    /// (items moved while the pages were read, so one may have been passed over); a page before
    /// the last must not be empty and must not repeat the identifiers of the page before it; and
    /// the items received must add up to `total_entries`. Anything else is `Error::Protocol`.
    /// At most [`pager::MAX_PAGES`] pages are read.
    // Source: Overview, "Pagination" (`current_page` "The page currently returned",
    // `total_entries` "The total number of entries available in the entire collection",
    // `total_pages` "The total number of pages available given the current per_page value");
    // OpenAPI `Pagination` (all four members required) and the list answers (`data` and
    // `pagination` required). Assumption (not documented): that `total_entries` counts the
    // items under the request's filters. Being wrong makes a listing fail, never come back
    // shorter.
    async fn list<T, U>(&self, url: U, zone: Option<&DomainName>) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u32) -> Result<Url, Error>,
    {
        #[derive(Deserialize)]
        struct Pagination {
            current_page: u64,
            total_entries: u64,
            total_pages: u64,
        }
        #[derive(Deserialize)]
        struct Answer {
            data: Vec<Value>,
            pagination: Pagination,
        }
        // What the pages before stated: the totals, the identifiers of the last page and the
        // number of items received.
        struct Seen {
            totals: Option<(u64, u64)>,
            last_ids: Vec<Option<u64>>,
            received: u64,
        }
        let seen = Mutex::new(Seen {
            totals: None,
            last_ids: Vec::new(),
            received: 0,
        });
        pager::collect(1u32, |page| {
            let url = url(page);
            let seen = &seen;
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
                let answer: Answer =
                    response.json("the provider's listing is not in the expected form")?;
                let p = &answer.pagination;
                if p.current_page != u64::from(page) {
                    return Err(protocol(
                        "the provider's listing answered another page than the one asked for",
                    ));
                }
                let ids: Vec<Option<u64>> = answer
                    .data
                    .iter()
                    .map(|item| item.get("id").and_then(Value::as_u64))
                    .collect();
                let count = u64::try_from(ids.len()).unwrap_or(u64::MAX);
                let next = {
                    let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                    let totals = (p.total_entries, p.total_pages);
                    if seen.totals.is_some_and(|first| first != totals) {
                        return Err(protocol(
                            "the provider's listing changed its number of items between pages",
                        ));
                    }
                    seen.totals = Some(totals);
                    if page > 1 && !ids.is_empty() && ids == seen.last_ids {
                        return Err(protocol("the provider's listing repeated a page"));
                    }
                    seen.last_ids = ids;
                    seen.received = seen.received.saturating_add(count);
                    if u64::from(page) < p.total_pages {
                        if count == 0 {
                            return Err(protocol(
                                "the provider's listing has an empty page before its end",
                            ));
                        }
                        Some(page.saturating_add(1))
                    } else if seen.received != p.total_entries {
                        return Err(protocol(
                            "the provider's listing does not hold the number of items it stated",
                        ));
                    } else {
                        None
                    }
                };
                let items = answer
                    .data
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<Vec<T>, _>>()
                    .map_err(|_| {
                        protocol("an item of the provider's listing is not in the expected form")
                    })?;
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the documented error body;
    /// anything else is an answer the client cannot interpret.
    // Source: Overview, "Errors": "All responses with an 4xx and 5xx response code will have a
    // JSON object as body, with at least a message key"; no machine-readable code is documented.
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

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

/// A user token without `account_id` in the settings.
// Source: Overview, "Account scope" (a user token reaches every account of the user; the
// account is chosen "based on a known criteria"); lego refuses user tokens ("user tokens are
// not supported, please use an account token").
fn user_token() -> Error {
    config(
        "the token is a user token, which is not bound to one account; set account_id to the \
         account whose zones the client manages",
    )
}

/// Appends `per_page` and `page`.
fn page_query(url: UrlBuilder, page: u32) -> UrlBuilder {
    url.query("per_page", &PAGE_SIZE.to_string())
        .query("page", &page.to_string())
}

/// The owner name a record's `name` states, as an absolute name: `""` is the zone itself, any
/// other name is relative to the zone. `None` for a name the documentation does not describe
/// (one with a trailing dot, `@`) or that is not a valid name.
// Source: Records, `name`: "The record name, without the domain. The domain will be
// automatically appended. Use an empty string to create a record for the apex."; the examples
// answer `""` and `"www"`. A name read as `None` is never taken for ours, so a foreign value
// cannot be removed by it.
pub(super) fn normalize_name(stated: &str, zone: &DomainName) -> Option<DomainName> {
    if stated.is_empty() {
        return Some(zone.clone());
    }
    if stated.ends_with('.') || stated == "@" {
        return None;
    }
    DomainName::parse(&format!("{stated}.{}", zone.as_str())).ok()
}

/// The name as a request states it: relative to the zone, `""` for the apex.
pub(super) fn relative_name<'a>(name: &'a DomainName, zone: &DomainName) -> Option<&'a str> {
    name.relative_to(zone)
}

/// The provider's error message: `message`, and the members of `errors` when present.
// Source: Overview, "Errors" (`message` always; for 400 "the response may include an errors key
// with more details", an object of field names to lists of strings, such as
// `{"ttl": ["is not a number"]}`).
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        errors: Option<Value>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    let mut text = body.message.filter(|text| !text.is_empty())?;
    let errors = body.errors.as_ref().and_then(Value::as_object);
    for (field, problems) in errors.into_iter().flatten() {
        let problems: Vec<&str> = match problems {
            Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
            Value::String(one) => vec![one.as_str()],
            _ => Vec::new(),
        };
        if !problems.is_empty() {
            text.push_str(&format!("; {field}: {}", problems.join(", ")));
        }
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::{error_message, normalize_name};
    use crate::name::DomainName;

    #[test]
    fn error_messages_carry_the_field_errors() {
        for (body, expected) in [
            (
                r#"{"message":"Authentication failed"}"#,
                Some("Authentication failed"),
            ),
            (
                r#"{"message":"Validation failed","errors":{"ttl":["is not a number"],"content":["can't be blank","is short"]}}"#,
                Some("Validation failed; content: can't be blank, is short; ttl: is not a number"),
            ),
            (r#"{"message":"m","errors":{}}"#, Some("m")),
            (r#"{"message":"m","errors":[{"message":"x"}]}"#, Some("m")),
            (r#"{"errors":{"a":["b"]}}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn stated_names_are_relative_to_the_zone() {
        let zone = DomainName::parse("example.org").unwrap();
        let name = |s: &str| normalize_name(s, &zone).map(|n| n.as_str().to_owned());
        assert_eq!(name("").as_deref(), Some("example.org."));
        assert_eq!(
            name("_acme-challenge").as_deref(),
            Some("_acme-challenge.example.org.")
        );
        assert_eq!(name("*.www").as_deref(), Some("*.www.example.org."));
        // A name with a trailing dot or `@` is not the documented form.
        assert_eq!(name("www.example.org."), None);
        assert_eq!(name("@"), None);
        assert_eq!(name("bad name"), None);
        // Without the trailing dot a name is relative, whatever it ends with.
        assert_eq!(
            name("a.example.org").as_deref(),
            Some("a.example.org.example.org.")
        );
    }
}
