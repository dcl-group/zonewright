//! The Hetzner Cloud API (zones, RRSets, RRSet actions, actions) as this client uses it: one
//! function per endpoint, the wire types, paging, action polling and the classification of
//! answers. Nothing here knows the value layer or the record layer; `client.rs`, `rrset.rs`,
//! `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3), all opened for this client:
//!
//! - The Hetzner Cloud API reference, <https://docs.hetzner.cloud/reference/cloud>, and its
//!   published OpenAPI description, <https://docs.hetzner.cloud/cloud.spec.json> ("the
//!   reference" below): the sections Zones, Zone RRSets, Zone RRSet Actions and Actions, and
//!   the general sections Authentication, Errors, Pagination, Rate Limiting and Actions.
//! - The changelog, <https://docs.hetzner.cloud/changelog> (entry "All
//!   `GET /<resource>/{id}/actions/{action_id}` operations are deprecated"): `GET
//!   /actions/{action_id}` is the way to read an action.
//! - Hetzner's DNS documentation, <https://docs.hetzner.com/networking/dns/record-types/txt-record/>:
//!   "The value has to be quoted."
//! - lego `providers/dns/hetzner/internal/hetznerv1/internal/client.go` (the two rrset actions at
//!   lines 49 and 69 with the zone name in the path, `GET /actions/{id}` at line 89) and
//!   `types.go` (the error body at lines 8 to 51), `hetznerv1.go` (the wait at lines 187 to 209).
//! - hcloud-go `hcloud/zone_rrset.go`, `GetRRSetByNameAndType` (line 83): the answer
//!   `not_found` to a read of an rrset means that the rrset is absent.
//! - The provider's command-line client, `github.com/hetznercloud/cli`,
//!   `internal/cmd/zone/rrset/set_records.go` (commit `06903a4`): to make an rrset hold a given
//!   set of records it reads the rrset, creates it with `POST /zones/{id}/rrsets` when there is
//!   none and otherwise sends `set_records`; the provider's Terraform provider,
//!   `github.com/hetznercloud/terraform-provider-hcloud`, `internal/zonerrset/resource.go`
//!   (commit `06cf2c1`), changes the TTL of an existing rrset with `change_ttl` and its records
//!   with `set_records`, two actions.
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call            | Request                                                           | Success |
//! | --------------- | ----------------------------------------------------------------- | ------- |
//! | probe           | `GET /zones?per_page=1`                                           | 200     |
//! | get zone        | `GET /zones/{id_or_name}`                                         | 200     |
//! | list zones      | `GET /zones?mode=primary&per_page=50&page`                        | 200     |
//! | list rrsets     | `GET /zones/{id}/rrsets?per_page=50&page`                         | 200     |
//! | get rrset       | `GET /zones/{id}/rrsets/{rr_name}/{rr_type}`                      | 200     |
//! | create rrset    | `POST /zones/{id}/rrsets`                                         | 201     |
//! | delete rrset    | `DELETE /zones/{id}/rrsets/{rr_name}/{rr_type}`                   | 201     |
//! | set records     | `POST /zones/{id}/rrsets/{rr_name}/{rr_type}/actions/set_records` | 201     |
//! | change TTL      | `POST /zones/{id}/rrsets/{rr_name}/{rr_type}/actions/change_ttl`  | 201     |
//! | add records     | `POST /zones/{id}/rrsets/{rr_name}/TXT/actions/add_records`       | 201     |
//! | remove records  | `POST /zones/{id}/rrsets/{rr_name}/TXT/actions/remove_records`    | 201     |
//! | get action      | `GET /actions/{id}`                                               | 200     |

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use reqwest::{Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::url::UrlBuilder;
use crate::http::{Endpoint, Http, PollStep, Poller, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// Page size of the zone and rrset listings: the documented maximum of `per_page`.
// Source: the reference, `GET /zones` and `GET /zones/{id_or_name}/rrsets`, query parameter
// `per_page` ("minimum": 1, "maximum": 50, default 25); Pagination: "the maximum is 50, unless
// otherwise specified".
const PAGE_SIZE: u32 = 50;

/// The record type name as the API spells it.
// Source: the reference, path parameter `rr_type` (an enumeration that contains `TXT`).
pub(super) const TXT: &str = "TXT";

/// The zone mode in which RRSets can be read and changed.
// Source: the reference, Zones, "Zone Modes": in primary mode RRSets and RRs are managed via
// the Cloud API; Zone RRSets: "Only applicable for Zones in primary mode".
pub(super) const PRIMARY: &str = "primary";

/// Most records one `add_records`, `remove_records` or `set_records` request can carry.
// Source: the reference, `add_records`, `remove_records` and `set_records`, `records`:
// "maxItems": 50.
pub(super) const MAX_RECORDS_PER_CALL: usize = 50;

/// A zone as `GET /zones` and `GET /zones/{id_or_name}` return it; other fields are ignored.
// Source: the reference, Zones: `id` (integer, 1 to 9007199254740991), `name` (lower case,
// without a trailing dot), `mode` (`primary` or `secondary`).
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The zone's identifier.
    pub(super) id: u64,
    /// The zone name.
    pub(super) name: String,
    /// `primary` or `secondary`.
    pub(super) mode: String,
}

/// An rrset as `GET /zones/{id}/rrsets/{rr_name}/{rr_type}` and the rrset listing return it;
/// other fields (`id`, `labels`, `zone`) are ignored: no write of this client sends them, so
/// the provider keeps them.
// Source: the reference, Zone RRSets: `name` (relative to the zone, `@` for the apex), `type`,
// `ttl` (integer or `null`: "If not set, the Zone's Default TTL is used"), `protection`
// (`change`: "Prevent the Resource from being changed"), `records` (each with a `value` and an
// optional `comment`); `name`, `type`, `ttl`, `protection` and `records` are in the schema's
// `required` list.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Rrset {
    /// The owner name relative to the zone.
    pub(super) name: String,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: String,
    /// The rrset's TTL; `None` when the zone's default applies. The key is required: an
    /// answer without it would make the client send an add without a TTL to an rrset that may
    /// have one (`deserialize_with` keeps serde from defaulting a missing `Option` to `None`).
    #[serde(deserialize_with = "nullable")]
    pub(super) ttl: Option<u32>,
    /// The records.
    pub(super) records: Vec<Record>,
    /// The protection; `None` when the answer has none. Assumption (not documented): an
    /// answer without the key is an rrset without change protection. If that is wrong, the
    /// API refuses the write itself (`423` `protected`), which the client reports as
    /// `Error::Rejected`; nothing else follows from it.
    #[serde(default)]
    pub(super) protection: Option<Protection>,
}

impl Rrset {
    /// The rrset is protected against changes: the API refuses to change or delete it.
    pub(super) fn is_protected(&self) -> bool {
        self.protection.as_ref().is_some_and(|p| p.change)
    }
}

/// The protection of an rrset.
// Source: the reference, Zone RRSets, `protection`: an object with the required boolean
// `change`.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Protection {
    /// "Prevent the Resource from being changed."
    pub(super) change: bool,
}

/// One record of an rrset, as the API returns it and as a write sends it back.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Record {
    /// The value as the API stores it; it identifies the record in the rrset.
    // Source: the reference, "Record": "The `value` is used to identify the record in an
    // RRSet."
    pub(super) value: String,
    /// The record's comment, kept as the API returned it so that a write of the rrset sends it
    /// back unchanged.
    // Source: the reference, "Record": `comment` ("Comment of the record"), an optional string;
    // `set_records` takes records with the same two properties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) comment: Option<String>,
}

/// An action as the write calls and `GET /actions/{id}` return it; other fields are ignored.
// Source: the reference, Actions: `id`, `status` (`running`, `success`, `error`), `error`
// (`null` or an object with `code` and `message`).
#[derive(Debug, Deserialize)]
pub(super) struct Action {
    /// The action's identifier.
    pub(super) id: u64,
    /// `running`, `success` or `error`.
    pub(super) status: String,
    /// What failed, when the status is `error`.
    #[serde(default)]
    pub(super) error: Option<ActionError>,
}

/// The error of a failed action.
#[derive(Debug, Deserialize)]
pub(super) struct ActionError {
    /// The machine-readable code.
    #[serde(default)]
    code: String,
    /// The message for humans.
    #[serde(default)]
    message: String,
}

#[derive(Serialize)]
struct RecordValue<'a> {
    value: &'a str,
}

/// The body of `add_records`.
// Source: the reference, `add_records`: `records` (required, 1 to 50 distinct entries) and
// `ttl` (optional: "If set, and the RRSet being updated already has a TTL, the values must be
// the same"); no other property is allowed.
#[derive(Serialize)]
struct AddRecords<'a> {
    records: [RecordValue<'a>; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

/// The body of `remove_records`.
// Source: the reference, `remove_records`: `records` (required, 1 to 50 distinct entries).
#[derive(Serialize)]
struct RemoveRecords<'a> {
    records: Vec<RecordValue<'a>>,
}

/// The body of `POST /zones/{id}/rrsets`. `labels` is not sent: a new rrset gets none.
// Source: the reference, "Create an RRSet": `name`, `type` and `records` (required; distinct
// values), `ttl` (optional, 60 to 2147483647 or null: "If not set, the Zone's Default TTL is
// used"), `labels` (optional); no other property. Read in the OpenAPI document
// (https://docs.hetzner.cloud/cloud.spec.json, `create_zone_rrset`) on 2026-11-14.
#[derive(Serialize)]
pub(super) struct NewRrset<'a> {
    /// The owner name relative to the zone, `@` for the apex.
    pub(super) name: &'a str,
    /// The record type.
    #[serde(rename = "type")]
    pub(super) rtype: &'a str,
    /// The TTL; left out for the zone's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ttl: Option<u32>,
    /// The records.
    pub(super) records: &'a [Record],
}

/// The body of `set_records`.
// Source: the reference, "Set Records of an RRSet": `records` (required, 1 to 50 distinct
// entries, each a `value` and an optional `comment`); no other property.
#[derive(Serialize)]
struct SetRecords<'a> {
    records: &'a [Record],
}

/// The body of `change_ttl`.
// Source: the reference, "Change an RRSet's TTL": `ttl` (required, type integer or null, 60 to
// 2147483647, "If not set, the Zone's Default TTL is used"); no other property. Read in the
// OpenAPI document (https://docs.hetzner.cloud/cloud.spec.json, `change_zone_rrset_ttl`) on
// 2026-11-14. `null` is how the zone's default is asked for: the key is required and the schema
// allows `null` with that description; the document does not say it in other words, and no live
// run has confirmed it yet.
#[derive(Serialize)]
struct ChangeTtl {
    /// `None` is sent as `null`: the zone's default.
    ttl: Option<u32>,
}

/// The client's handle on the API: the transport and the endpoint.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`, with the token already part of `http`.
    pub(super) fn new(http: Http, base: Endpoint) -> Api {
        Api { http, base }
    }

    /// `GET /zones?per_page=1`: a real authenticated request that names no zone, so a success
    /// proves that the token is accepted now. The answer must hold the list of zones.
    // Source: the reference, `GET /zones` (`per_page` minimum 1); the answer is keyed on
    // `zones`. The reference has no endpoint that only tests a token; the smallest listing is
    // the cheapest authenticated request that names no zone.
    pub(super) async fn probe(&self) -> Result<(), Error> {
        let url = self
            .base
            .url()
            .path("/zones")
            .query("per_page", "1")
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let body: Value =
            response.json("the provider's zone listing is not in the expected form")?;
        match body.get("zones") {
            Some(Value::Array(_)) => Ok(()),
            _ => Err(protocol("the provider's listing lacks its list of items")),
        }
    }

    /// `GET /zones/{name}`: the zone, or `None` for `404`.
    // Source: the reference, `GET /zones/{id_or_name}` ("ID or Name of the Zone"); lego passes
    // the zone name in this position (client.go:49). The `404` status of a missing zone follows
    // from the Errors table (`not_found`, "Entity not found"); hcloud-go treats the code
    // `not_found` as absence.
    pub(super) async fn zone(&self, zone: &DomainName) -> Result<Option<Zone>, Error> {
        #[derive(Deserialize)]
        struct One {
            zone: Zone,
        }
        let url = self
            .base
            .url()
            .path("/zones")
            .segment(zone.without_dot())
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let one: One = response.json("the provider's zone answer is not in the expected form")?;
        Ok(Some(one.zone))
    }

    /// Every zone in primary mode, all pages.
    ///
    /// Complete or an error. Pages are fetched by number, never by a URL from an answer (design
    /// section 5.1). The listing is complete when `next_page` is `null` and the items received
    /// reach `total_entries` where the API states one; fewer, an absent list or pagination
    /// object, an empty page before the end, or a next page that does not advance is
    /// `Error::Protocol`.
    // Source: the reference, `GET /zones`: query parameters `mode` ("Filter resources by their
    // mode"), `page`, `per_page`; the answer's `meta.pagination` with `next_page` ("Can be null
    // if the current page is the last one") and `total_entries` ("Total number of entries that
    // exist for this query. Can be null if unknown.").
    pub(super) async fn primary_zones(&self) -> Result<Vec<Zone>, Error> {
        self.all_pages("zones", None, |page| {
            self.base
                .url()
                .path("/zones")
                .query("mode", PRIMARY)
                .query("per_page", &PAGE_SIZE.to_string())
                .query("page", &page.to_string())
                .build()
        })
        .await
    }

    /// Every rrset of the zone `zone_id`, all pages, with the same completeness rules as the
    /// zone listing. A `404` is `Error::ZoneNotFound` for `zone`: the API does not know the
    /// identifier, which the caller's zone cache treats as possibly stale.
    // Source: the reference, "List RRSets", `GET /zones/{id_or_name}/rrsets`: query parameters
    // `page` and `per_page`; the answer's `rrsets` and `meta.pagination` (`next_page`,
    // `total_entries`), both required. The filters (`name`, `type`, `label_selector`) are not
    // used: the listing is of the whole zone. The `404` of an unknown zone: see `zone`.
    pub(super) async fn rrsets(
        &self,
        zone: &DomainName,
        zone_id: &str,
    ) -> Result<Vec<Rrset>, Error> {
        self.all_pages("rrsets", Some(zone), |page| {
            self.base
                .url()
                .path("/zones")
                .id(zone_id)
                .path("/rrsets")
                .query("per_page", &PAGE_SIZE.to_string())
                .query("page", &page.to_string())
                .build()
        })
        .await
    }

    /// Every item under `key` of a listing read in pages by number.
    ///
    /// Complete or an error. Pages are fetched by number, never by a URL from an answer (design
    /// section 5.1). The listing is complete when `next_page` is `null` and the items received
    /// reach `total_entries` where the API states one; fewer, an absent list or pagination
    /// object, an empty page before the end, or a next page that does not advance is
    /// `Error::Protocol`. A `404` is `Error::ZoneNotFound` for `missing` when given, otherwise
    /// a refusal like any other.
    // Source: the reference, Pagination, and the `meta.pagination` object of the listings:
    // `next_page` ("Can be null if the current page is the last one") and `total_entries`
    // ("Total number of entries that exist for this query. Can be null if unknown.").
    async fn all_pages<T, U>(
        &self,
        key: &'static str,
        missing: Option<&DomainName>,
        url: U,
    ) -> Result<Vec<T>, Error>
    where
        T: DeserializeOwned,
        U: Fn(u32) -> Result<Url, Error>,
    {
        let received = AtomicU64::new(0);
        pager::collect(1u32, |page| {
            let received = &received;
            let url = url(page);
            async move {
                let response = self.http.send(&Request::get(url?)).await?;
                if response.status() == 404
                    && let Some(zone) = missing
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
                let pagination = body
                    .get("meta")
                    .and_then(|meta| meta.get("pagination"))
                    .filter(|pagination| pagination.is_object())
                    .ok_or_else(|| protocol("the provider's listing states no pagination"))?;
                let next = match pagination.get("next_page") {
                    Some(Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_u64()
                            .and_then(|n| u32::try_from(n).ok())
                            .ok_or_else(|| {
                                protocol("the provider's listing states an unusable next page")
                            })?,
                    ),
                    None => {
                        return Err(protocol("the provider's listing states no next page"));
                    }
                };
                let total = pagination.get("total_entries").and_then(Value::as_u64);
                let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
                let so_far = received
                    .fetch_add(count, Ordering::Relaxed)
                    .saturating_add(count);
                let next = match next {
                    Some(next) if next <= page => {
                        return Err(protocol("the provider's pagination did not advance"));
                    }
                    Some(_) if items.is_empty() => {
                        return Err(protocol(
                            "the provider's listing has an empty page before its end",
                        ));
                    }
                    Some(next) => Some(next),
                    None if total.is_some_and(|total| so_far < total) => {
                        return Err(protocol(
                            "the provider's listing ended before the number of items it stated",
                        ));
                    }
                    None => None,
                };
                Ok(Page { items, next })
            }
        })
        .await
    }

    /// `GET /zones/{id}/rrsets/{rr_name}/{rr_type}`: the rrset, or `None` for `404`. The `404`
    /// cannot tell a missing rrset from a missing zone; the caller's zone cache can.
    // Source: the reference, `GET /zones/{id_or_name}/rrsets/{rr_name}/{rr_type}`: `rr_name` is
    // lower case, without a trailing dot or the zone name, `@` for the apex; "Operation specific
    // errors": `422` `incorrect_zone_mode` for a zone that is not in primary mode. The status of
    // an absent rrset is not listed; hcloud-go (`GetRRSetByNameAndType`, zone_rrset.go:97) reads
    // the error code `not_found` as absence, and the Errors table pairs it with `404`.
    pub(super) async fn rrset(
        &self,
        zone_id: &str,
        rr_name: &str,
        rr_type: &str,
    ) -> Result<Option<Rrset>, Error> {
        #[derive(Deserialize)]
        struct One {
            rrset: Rrset,
        }
        let url = self.rrset_url(zone_id, rr_name, rr_type).build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let one: One = response.json("the provider's rrset answer is not in the expected form")?;
        // The answer must be about the rrset asked for.
        if one.rrset.name != rr_name || one.rrset.rtype != rr_type {
            return Err(protocol(
                "the provider answered with an rrset other than the one asked for",
            ));
        }
        Ok(Some(one.rrset))
    }

    /// `add_records` with one value. Sent once: appending is not idempotent in the sense of
    /// design section 5.3, and a repeat after an unknown outcome is the caller's operation,
    /// which starts with a read. Returns the action to wait for, or `None` for `404`.
    // Source: the reference, "Add Records to an RRSet": the rrset "will be automatically
    // created if it doesn't exist. Otherwise, the new records are appended to the existing
    // RRSet"; `201` with an action ("Make sure to wait for the Action completion to ensure your
    // changes are applied"); lego client.go:49.
    pub(super) async fn add_records(
        &self,
        zone_id: &str,
        rr_name: &str,
        value: &str,
        ttl: Option<u32>,
    ) -> Result<Option<Action>, Error> {
        let body = AddRecords {
            records: [RecordValue { value }],
            ttl,
        };
        self.rrset_action(zone_id, rr_name, TXT, "/actions/add_records", &body)
            .await
    }

    /// `remove_records` with the values given, each as the API returned it. Sent once: it can
    /// remove records another writer put there. Returns the action to wait for, or `None` for
    /// `404`.
    // Source: the reference, "Remove Records from an RRSet": the rrset "will be automatically
    // deleted if it doesn't contain any RRs afterwards"; `201` with an action; lego
    // client.go:69.
    pub(super) async fn remove_records(
        &self,
        zone_id: &str,
        rr_name: &str,
        values: &[&str],
    ) -> Result<Option<Action>, Error> {
        let body = RemoveRecords {
            records: values.iter().map(|value| RecordValue { value }).collect(),
        };
        self.rrset_action(zone_id, rr_name, TXT, "/actions/remove_records", &body)
            .await
    }

    /// `set_records`: the records of the existing rrset become exactly `records`. Sent once: it
    /// overwrites what another writer changed after the caller's read. Returns the action to
    /// wait for, or `None` for `404`.
    // Source: the reference, "Set Records of an RRSet": "Overwrites the resource records (RRs)
    // of an existing RRSet"; `201` with an action; hcloud-go `SetRRSetRecords`
    // (zone_rrset.go:388).
    pub(super) async fn set_records(
        &self,
        zone_id: &str,
        rr_name: &str,
        rr_type: &str,
        records: &[Record],
    ) -> Result<Option<Action>, Error> {
        let body = SetRecords { records };
        self.rrset_action(zone_id, rr_name, rr_type, "/actions/set_records", &body)
            .await
    }

    /// `change_ttl` of an existing rrset; `None` asks for the zone's default. Sent once, like
    /// every write. Returns the action to wait for, or `None` for `404`.
    // Source: the reference, "Change an RRSet's TTL": `201` with an action; hcloud-go
    // `ChangeRRSetTTL` (zone_rrset.go:350).
    pub(super) async fn change_ttl(
        &self,
        zone_id: &str,
        rr_name: &str,
        rr_type: &str,
        ttl: Option<u32>,
    ) -> Result<Option<Action>, Error> {
        let body = ChangeTtl { ttl };
        self.rrset_action(zone_id, rr_name, rr_type, "/actions/change_ttl", &body)
            .await
    }

    /// `POST /zones/{id}/rrsets`: creates the rrset. Sent once. Returns the action to wait for,
    /// or `None` for `404`; a refusal is the error.
    // Source: the reference, "Create an RRSet": `201` with `rrset` and `action` (both
    // required); hcloud-go `CreateRRSet` (zone_rrset.go:200). What the API answers when the
    // rrset exists already is not documented for this call (the Errors table has `409`
    // `uniqueness_error` for "fields must be unique"); the caller reads again after a refusal.
    pub(super) async fn create_rrset(
        &self,
        zone_id: &str,
        rrset: &NewRrset<'_>,
    ) -> Result<Option<Action>, Error> {
        #[derive(Deserialize)]
        struct Created {
            action: Action,
        }
        let url = self
            .base
            .url()
            .path("/zones")
            .id(zone_id)
            .path("/rrsets")
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(rrset)?)
            .await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let created: Created = response
            .json("the provider's answer to a write is not in the expected form")
            .map_err(|_| accepted_unreadable())?;
        Ok(Some(created.action))
    }

    /// `DELETE /zones/{id}/rrsets/{rr_name}/{rr_type}`. Sent once: it removes every record of
    /// the rrset, also one another writer added after the caller's read. Returns the action to
    /// wait for, or `None` for `404`.
    // Source: the reference, "Delete an RRSet": `201` with an action; hcloud-go `DeleteRRSet`
    // (zone_rrset.go:272).
    pub(super) async fn delete_rrset(
        &self,
        zone_id: &str,
        rr_name: &str,
        rr_type: &str,
    ) -> Result<Option<Action>, Error> {
        #[derive(Deserialize)]
        struct Deleted {
            action: Action,
        }
        let url = self.rrset_url(zone_id, rr_name, rr_type).build()?;
        let response = self.http.send(&Request::new(Method::DELETE, url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let deleted: Deleted = response
            .json("the provider's answer to a write is not in the expected form")
            .map_err(|_| accepted_unreadable())?;
        Ok(Some(deleted.action))
    }

    async fn rrset_action<B: Serialize>(
        &self,
        zone_id: &str,
        rr_name: &str,
        rr_type: &str,
        action_path: &'static str,
        body: &B,
    ) -> Result<Option<Action>, Error> {
        #[derive(Deserialize)]
        struct Created {
            action: Action,
        }
        let url = self
            .rrset_url(zone_id, rr_name, rr_type)
            .path(action_path)
            .build()?;
        let response = self
            .http
            .send(&Request::new(Method::POST, url).json(body)?)
            .await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let created: Created = response
            .json("the provider's answer to a write is not in the expected form")
            .map_err(|_| accepted_unreadable())?;
        Ok(Some(created.action))
    }

    /// `GET /actions/{id}`.
    // Source: the reference, Actions, "Get an Action"; the changelog entry that makes it the way
    // to read an action; lego client.go:89.
    async fn get_action(&self, id: u64) -> Result<Action, Error> {
        #[derive(Deserialize)]
        struct One {
            action: Action,
        }
        let url = self
            .base
            .url()
            .path("/actions")
            .id(&id.to_string())
            .build()?;
        let response = self.http.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let one: One = response.json("the provider's action answer is not in the expected form")?;
        if one.action.id != id {
            return Err(protocol(
                "the provider answered with an action other than the one asked for",
            ));
        }
        Ok(one.action)
    }

    /// Waits until the action has finished, looking at it again as `poller` says. An action
    /// that failed is `Error::Rejected` with the provider's message; one still running after
    /// the last look, or a look that fails, is `Error::Transient` (design section 3.7).
    // Source: the reference, Actions: "An action should be waited upon, until it reaches either
    // the `success` or `error` state. Avoid polling the action's state too frequently"; lego
    // hetznerv1.go:187 to 209.
    pub(super) async fn wait(&self, poller: &Poller, action: Action) -> Result<(), Error> {
        let id = action.id;
        match self.step(action)? {
            PollStep::Done(()) => Ok(()),
            PollStep::Failed(e) => Err(e),
            PollStep::Pending => {
                poller
                    .run(|| async { self.step(self.get_action(id).await?) })
                    .await
            }
        }
    }

    /// What one look at an action says. An action whose status is none of `running`,
    /// `success` and `error` is `Error::Transient`: the write was accepted and its state cannot
    /// be read, so the outcome is unknown (design section 3.7). It is built as `Transient` here
    /// because the action the write returned is evaluated outside the poller.
    fn step(&self, action: Action) -> Result<PollStep<()>, Error> {
        Ok(match action.status.as_str() {
            "running" => PollStep::Pending,
            "success" => PollStep::Done(()),
            "error" => {
                let (code, message) = action
                    .error
                    .map(|e| (e.code, e.message))
                    .unwrap_or_default();
                PollStep::Failed(Error::Rejected {
                    status: None,
                    detail: self
                        .http
                        .detail(&format!("the action failed: {code}: {message}")),
                })
            }
            _ => {
                return Err(Error::Transient {
                    detail: Detail::constant(
                        "the provider accepted the change, but its action has an unknown \
                         status; the outcome is unknown",
                    ),
                });
            }
        })
    }

    /// `/zones/{id}/rrsets/{rr_name}/{rr_type}`. The apex is written as the literal `@` of the
    /// reference's examples, not as its percent-encoding.
    // Source: the reference, `rr_name`: "For the Zone apex, use `@`"; hcloud-go
    // `hcloud/zone_rrset.go:93` formats the name into the path unescaped (`fmt.Sprintf`), and
    // lego `client.go:49` builds it with Go's `JoinPath`, which leaves `@` unescaped in a path.
    // Other names go through `segment`, which percent-encodes everything but unreserved
    // characters; a wildcard label is sent as `%2A`. Assumption (not documented): the API
    // decodes it as any HTTP server does; if not, the read and the write address a name of
    // their own, and no foreign value is touched.
    // The type is a registry mnemonic (letters and digits only), which `segment` leaves as it
    // is.
    fn rrset_url(&self, zone_id: &str, rr_name: &str, rr_type: &str) -> UrlBuilder {
        let url = self.base.url().path("/zones").id(zone_id).path("/rrsets");
        let url = if rr_name == "@" {
            url.path("/@")
        } else {
            url.segment(rr_name)
        };
        url.segment(rr_type)
    }

    /// An answer the client does not expect. 401, 403, 429 and 5xx were mapped by the transport
    /// already. A 4xx is the provider refusing the request, with the documented error body;
    /// `locked` says that another action is running and the request can be repeated
    /// (`Error::Transient`); `conflict` says that the resource changed during the request, so
    /// nothing was done and a repeat reads the new state (`Error::Conflict`). Anything else is
    /// an answer the client cannot interpret.
    // Source: the reference, Errors: `423` `locked` ("there is already an Action running"),
    // `409` `conflict` ("The resource has changed during the request, please retry"), `422`
    // `incorrect_zone_mode` and the error body `{error: {code, message, details}}`.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400..=499 => match error_code(&response.text()).as_deref() {
                Some("locked") => Error::Transient {
                    detail: self.http.body_detail(response),
                },
                Some("conflict") => Error::Conflict {
                    detail: self.http.body_detail(response),
                },
                _ => self.http.reject(response),
            },
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

/// A field that must be present and may be `null`.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A 2xx answer to a write whose action cannot be read: the provider accepted the change, so
/// the outcome is unknown, which is `Error::Transient`, not `Error::Protocol` (design section
/// 3.7).
fn accepted_unreadable() -> Error {
    Error::Transient {
        detail: Detail::constant(
            "the provider accepted the change, but its answer does not name an action in the \
             expected form; the outcome is unknown",
        ),
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorInfo,
}

#[derive(Deserialize)]
struct ErrorInfo {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// The `code` of the documented error body.
// Source: the reference, Errors: "The error response contains the following keys: `code`,
// `message`, `details`"; lego types.go:8 to 16.
fn error_code(body: &str) -> Option<String> {
    serde_json::from_str::<ErrorBody>(body).ok()?.error.code
}

/// The provider's error message: `code: message` of the documented error body.
pub(super) fn error_message(body: &str) -> Option<String> {
    let info = serde_json::from_str::<ErrorBody>(body).ok()?.error;
    let message = info.message.filter(|text| !text.is_empty())?;
    Some(match info.code.filter(|code| !code.is_empty()) {
        Some(code) => format!("{code}: {message}"),
        None => message,
    })
}

#[cfg(test)]
mod tests {
    use super::{error_code, error_message};

    #[test]
    fn error_messages_join_code_and_message() {
        for (body, expected) in [
            (
                r#"{"error":{"code":"incorrect_zone_mode","message":"zone is secondary","details":null}}"#,
                Some("incorrect_zone_mode: zone is secondary"),
            ),
            (r#"{"error":{"message":"only this"}}"#, Some("only this")),
            (r#"{"error":{"code":"x"}}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn error_codes_are_read_from_the_documented_body() {
        assert_eq!(
            error_code(r#"{"error":{"code":"locked","message":"m"}}"#).as_deref(),
            Some("locked")
        );
        assert_eq!(error_code("{}"), None);
    }
}
