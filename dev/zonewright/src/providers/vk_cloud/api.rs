//! The VK Cloud public DNS API (v2) as this client uses it: authentication, one function per
//! endpoint, the wire types and the classification of answers. Nothing here knows the value
//! layer or the zone cache; `client.rs` and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - The provider's API page,
//!   <https://cloud.vk.ru/docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns>, and
//!   the OpenAPI description it embeds,
//!   <https://cloud.vk.ru/docs/_docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns/assets/public-dns-api.json>
//!   ("the OpenAPI" below, version 2.0.0, read on 2026-11-14): paths, request and answer
//!   schemas, status codes. It documents no error body and no paging.
//! - The provider's token documentation,
//!   <https://cloud.vk.ru/docs/ru/tools-for-using-services/api/rest-api/case-keystone-token>: the
//!   Keystone password exchange scoped to a project ID; the token arrives in `X-Subject-Token`
//!   and is sent to the APIs in `X-Auth-Token`.
//! - lego `providers/dns/vkcloud` at commit `1da5445c` (`vkcloud.go`, `internal/client.go`,
//!   `internal/types.go`; line numbers below refer to it).
//!
//! Endpoints used, all below the `dns_url`. `{type}` is one of the per-type path segments of
//! [`Kind`] (`a`, `aaaa`, `cname`, `mx`, `ns`, `srv`, `txt`); the OpenAPI documents the same four
//! calls for each of them:
//!
//! | Call          | Request                          | Success                 |
//! | ------------- | -------------------------------- | ----------------------- |
//! | list zones    | `GET /`                          | 200, array of zones     |
//! | list records  | `GET /{zone}/{type}/`            | 200, array of records   |
//! | create record | `POST /{zone}/{type}/`           | 201, the new record     |
//! | update CNAME  | `PUT /{zone}/cname/{record}`     | 200, the changed record |
//! | delete record | `DELETE /{zone}/{type}/{record}` | 204                     |
//!
//! The OpenAPI documents `PUT /{zone}/{type}/{record}` for every type. Only the CNAME one is
//! used, to change a CNAME's target in place (its body `CnameRecord_Update` is `content` alone);
//! the documented bodies carry no TTL, and those of A, AAAA and SRV carry only the name (see
//! `records.rs`).
//!
//! The listings return everything in one answer (no paging is documented), so they are
//! bounded by the transport's 4 MiB body limit alone; a larger answer fails, it is never
//! returned in part. The OpenAPI documents `404` ("records not found") for every listing next
//! to `200`; it does not say whether an empty listing is `200 []` or `404`, and for a record
//! listing a `404` can also mean that the zone does not exist. [`Api::records`] therefore
//! reports a `404` as such and leaves its meaning to the caller; [`Api::zones`] treats it as
//! an error, since it cannot be told apart from a wrong `dns_url`.

use std::fmt;

use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::http::keystone::X_AUTH_TOKEN;
use crate::http::{Endpoint, Http, Keystone, Request, Response, TokenSource};
use crate::record::RecordType;
use crate::redact::Detail;

/// A record type of the API: the types the OpenAPI documents, each on its own paths.
// Source: the OpenAPI, the paths `/v2/dns/{DnsUuid}/{a,aaaa,cname,mx,ns,srv,txt}/` and
// `/v2/dns/{DnsUuid}/{type}/{RecordUuid}`, each with `GET`, `POST` (list, create) and `GET`,
// `PUT`, `DELETE` (one record). No other type and no listing of all types is documented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Kind {
    /// `a`.
    A,
    /// `aaaa`.
    Aaaa,
    /// `cname`.
    Cname,
    /// `mx`.
    Mx,
    /// `ns`.
    Ns,
    /// `srv`.
    Srv,
    /// `txt`.
    Txt,
}

impl Kind {
    /// Every type of the API, in the order the zone listing reads them.
    pub(super) const ALL: [Kind; 7] = [
        Kind::A,
        Kind::Aaaa,
        Kind::Cname,
        Kind::Mx,
        Kind::Ns,
        Kind::Srv,
        Kind::Txt,
    ];

    /// The API type of `rtype`, if it has one.
    pub(super) fn of(rtype: RecordType) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.rtype() == rtype)
    }

    /// The record type.
    pub(super) fn rtype(self) -> RecordType {
        match self {
            Kind::A => RecordType::A,
            Kind::Aaaa => RecordType::AAAA,
            Kind::Cname => RecordType::CNAME,
            Kind::Mx => RecordType::MX,
            Kind::Ns => RecordType::NS,
            Kind::Srv => RecordType::SRV,
            Kind::Txt => RecordType::TXT,
        }
    }

    /// The path of the type's collection below the zone, with the trailing slash the OpenAPI
    /// paths have (lego internal/client.go:61, 76 for `txt`).
    fn collection(self) -> &'static str {
        match self {
            Kind::A => "/a/",
            Kind::Aaaa => "/aaaa/",
            Kind::Cname => "/cname/",
            Kind::Mx => "/mx/",
            Kind::Ns => "/ns/",
            Kind::Srv => "/srv/",
            Kind::Txt => "/txt/",
        }
    }

    /// The path below the zone that one record's identifier follows (lego
    /// internal/client.go:87 for `txt`).
    fn member(self) -> &'static str {
        match self {
            Kind::A => "/a",
            Kind::Aaaa => "/aaaa",
            Kind::Cname => "/cname",
            Kind::Mx => "/mx",
            Kind::Ns => "/ns",
            Kind::Srv => "/srv",
            Kind::Txt => "/txt",
        }
    }
}

/// A zone as `GET /` returns it; other fields are ignored.
// Source: the OpenAPI, `Dns_Filter` (`zone`, `tenant`, `status` and the identifier, named
// `DnsUuid`); lego internal/types.go:3-15 (`DNSZone`) names the identifier `uuid`. Both
// spellings are read; `zone` is the name without the trailing dot ("Can contain only digits,
// Latin letters, hyphen and dot").
#[derive(Debug, Deserialize)]
pub(super) struct Zone {
    /// The identifier, as lego reads it.
    #[serde(default)]
    uuid: Option<String>,
    /// The identifier, as the OpenAPI names it.
    #[serde(default, rename = "DnsUuid")]
    dns_uuid: Option<String>,
    /// The zone name.
    pub(super) zone: String,
}

impl Zone {
    /// The zone's identifier: `uuid`, else `DnsUuid`.
    pub(super) fn id(&self) -> Option<&str> {
        self.uuid
            .as_deref()
            .filter(|id| !id.is_empty())
            .or(self.dns_uuid.as_deref().filter(|id| !id.is_empty()))
    }
}

/// A TXT record as `GET /{zone}/txt/` returns it; other fields are ignored. The identifier,
/// the name and the content are required here: a record without them could be neither
/// matched nor deleted, and a listing with one is not a complete read.
// Source: the OpenAPI, `TxtRecord_Filter` (`uuid`, `name`, `dns`, `content`, `ttl`); lego
// internal/types.go:17-23 (`DNSTXTRecord`) and vkcloud.go:215-219, which matches records by
// `Name` and `Content`.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct TxtRecord {
    /// The record's identifier.
    pub(super) uuid: String,
    /// The name relative to the zone; `@` is the apex (the OpenAPI's example of `name`).
    pub(super) name: String,
    /// The value, as written.
    pub(super) content: String,
    /// TTL in seconds.
    #[serde(default)]
    pub(super) ttl: Option<u32>,
}

/// The body of `POST /{zone}/txt/`.
// Source: the OpenAPI, `TxtRecord_Create`: `name`, `content` (at most 255 characters) and `ttl`
// (60 to 2147483648), all three required; lego vkcloud.go:222-226 sends the same three fields,
// the name relative to the zone and the value unquoted.
#[derive(Serialize)]
pub(super) struct NewTxt<'a> {
    /// The name relative to the zone, `@` for the apex.
    pub(super) name: &'a str,
    /// The value, unquoted.
    pub(super) content: &'a str,
    /// TTL in seconds.
    pub(super) ttl: u32,
}

/// A record of any type as `GET /{zone}/{type}/` returns it; other fields are ignored. The
/// identifier and the name are required: a record without them could be neither matched nor
/// deleted, and a listing with one is not a complete read. The value fields are optional here;
/// a record without its type's fields is read as non-canonical data (`records.rs`).
// Source: the OpenAPI, `ARecord_Filter` (`uuid`, `name`, `dns`, `ipv4`, `ttl`),
// `AaaaRecord_Filter` (`ipv6`), `CnameRecord_Filter`, `NsRecord_Filter` and `TxtRecord_Filter`
// (`content`), `MxRecord_Filter` (`priority`, `content`), `SrvRecord_Filter` (`priority`,
// `weight`, `port`, `host`). The numbers are integers there; they are taken as JSON values and
// checked in `records.rs`. `AaaaRecord_Filter` declares its `ttl` with the string schema of
// `name`, unlike every other type; a TTL is therefore read as a number or as a decimal string.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct ApiRecord {
    /// The record's identifier.
    pub(super) uuid: String,
    /// The name relative to the zone; `@` is the apex.
    pub(super) name: String,
    /// CNAME, MX, NS and TXT: the value.
    #[serde(default)]
    pub(super) content: Option<String>,
    /// A: the address.
    #[serde(default)]
    pub(super) ipv4: Option<String>,
    /// AAAA: the address.
    #[serde(default)]
    pub(super) ipv6: Option<String>,
    /// SRV: the target host.
    #[serde(default)]
    pub(super) host: Option<String>,
    /// MX and SRV: the priority.
    #[serde(default)]
    pub(super) priority: Option<Value>,
    /// SRV: the weight.
    #[serde(default)]
    pub(super) weight: Option<Value>,
    /// SRV: the port.
    #[serde(default)]
    pub(super) port: Option<Value>,
    /// TTL in seconds.
    #[serde(default)]
    pub(super) ttl: Option<Value>,
}

/// The body of `POST /{zone}/{type}/`: the name, the type's value fields and the TTL. Fields a
/// type does not have are left out.
// Source: the OpenAPI, `ARecord_Create` (`name`, `ipv4`, `ttl` required), `AaaaRecord_Create`
// (`name`, `ipv6`, `ttl`), `CnameRecord_Create`, `NsRecord_Create` and `TxtRecord_Create`
// (`name`, `content`, `ttl`), `MxRecord_Create` (`name`, `content`, `priority`, `ttl`),
// `SrvRecord_Create` (`name`, `priority`, `weight`, `port`, `host` required, `ttl` optional;
// the client always sends one).
#[derive(Debug, Serialize)]
pub(super) struct NewRecord<'a> {
    /// The name relative to the zone, `@` for the apex.
    pub(super) name: &'a str,
    /// CNAME, MX, NS and TXT: the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) content: Option<&'a str>,
    /// A: the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ipv4: Option<&'a str>,
    /// AAAA: the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ipv6: Option<&'a str>,
    /// MX and SRV: the priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) priority: Option<u16>,
    /// SRV: the weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) weight: Option<u16>,
    /// SRV: the port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) port: Option<u16>,
    /// SRV: the target host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) host: Option<&'a str>,
    /// TTL in seconds.
    pub(super) ttl: u32,
}

/// The answer to a write.
#[derive(Debug)]
pub(super) enum Written {
    /// The provider accepted the write.
    Done,
    /// `404`: the zone or the record does not exist (any more).
    NotFound,
    /// Another refusal, as the error it maps to.
    Refused(Error),
}

/// The client's handle on the API: the transport, the endpoint and the token.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    keystone: Keystone,
    tokens: TokenSource,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`, authenticated with tokens from `keystone`.
    pub(super) fn new(http: Http, base: Endpoint, keystone: Keystone) -> Api {
        Api {
            http,
            base,
            keystone,
            // Keystone states the expiry of each token in `token.expires_at`; no cap beyond it
            // is needed.
            tokens: TokenSource::new(None),
        }
    }

    /// Exchanges the credentials for a new token, even when a valid one is cached: proves that
    /// they are accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        self.tokens
            .renew(|| self.keystone.fetch_token(&self.http))
            .await?;
        Ok(())
    }

    /// Sends `request` with the project-scoped token in `X-Auth-Token`.
    // Source: the API page ("Получите токен доступа X-Auth-Token. Используйте токен в заголовке
    // при отправке запросов") and its curl example.
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &X_AUTH_TOKEN, || {
                self.keystone.fetch_token(&self.http)
            })
            .await
    }

    /// Every zone of the project. A `404` is `Error::Protocol`, not an empty listing: it is
    /// also what a `dns_url` with a wrong path gets, and reading it as "no zones" would turn a
    /// misconfiguration into `ZoneNotFound` for every zone. A project without zones whose
    /// listing answers `404` therefore fails the same way.
    // Source: the OpenAPI, `GET /v2/dns/`: 200 with an array of `Dns_Filter`, 404 "records not
    // found"; lego internal/client.go:45-58 (`ListZones`, `JoinPath("/")`, so the path ends in
    // a slash).
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        let url = self.base.url().path("/").build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Err(Error::Protocol {
                detail: Detail::constant(
                    "the zone listing answered 404: either dns_url does not point at the DNS \
                     API, or the project has no zones; the answer does not tell which",
                ),
            });
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response.json("the provider's zone listing is not in the expected form")
    }

    /// Every TXT record of zone `zone_id`, or `None` for a `404`, which can mean an empty
    /// listing or a zone that does not exist.
    // Source: the OpenAPI, `GET /v2/dns/{DnsUuid}/txt/`: 200 with an array of
    // `TxtRecord_Filter`, 404 "records not found"; lego internal/client.go:60-73
    // (`ListTXTRecords`, `JoinPath(zoneUUID, "txt", "/")`).
    pub(super) async fn txt_records(&self, zone_id: &str) -> Result<Option<Vec<TxtRecord>>, Error> {
        self.records(zone_id, Kind::Txt).await
    }

    /// Every record of type `kind` in zone `zone_id`, or `None` for a `404`, which can mean an
    /// empty listing or a zone that does not exist.
    // Source: the OpenAPI, `GET /v2/dns/{DnsUuid}/{type}/` for each type: 200 with an array of
    // the type's `…_Filter` schema; 400, 401, 404 "records not found".
    pub(super) async fn records<T: DeserializeOwned>(
        &self,
        zone_id: &str,
        kind: Kind,
    ) -> Result<Option<Vec<T>>, Error> {
        let url = self
            .base
            .url()
            .id(zone_id)
            .path(kind.collection())
            .build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response
            .json("the provider's record listing is not in the expected form")
            .map(Some)
    }

    /// Creates a TXT record. Sent once: a create is not idempotent.
    // Source: the OpenAPI, `POST /v2/dns/{DnsUuid}/txt/`: 201 with `TxtRecord_Get`; 400
    // (validation), 401, 409 ("conflict of parameters, duplication or unavailability of the
    // operation"). A 404 is not documented for the create; it is read as a zone that no longer
    // exists, like the 404 of every other call on the zone. lego internal/client.go:75-84.
    pub(super) async fn create_txt(
        &self,
        zone_id: &str,
        record: &NewTxt<'_>,
    ) -> Result<Written, Error> {
        self.create(zone_id, Kind::Txt, record).await
    }

    /// Creates a record of type `kind`. Sent once: a create is not idempotent.
    // Source: the OpenAPI, `POST /v2/dns/{DnsUuid}/{type}/` for each type: 201 with the record;
    // 400 (validation), 401, 409 ("conflict of parameters, duplication or unavailability of the
    // operation"). A 404 is not documented for the create; it is read as a zone that no longer
    // exists, like the 404 of every other call on the zone.
    pub(super) async fn create<B: Serialize>(
        &self,
        zone_id: &str,
        kind: Kind,
        record: &B,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .id(zone_id)
            .path(kind.collection())
            .build()?;
        let response = self
            .send(&Request::new(Method::POST, url).json(record)?)
            .await?;
        Ok(self.written(&response))
    }

    /// Changes the target of the CNAME record `record_id` to `content` (without its trailing
    /// dot). Sent once: a write other than the delete of one record is never repeated (design
    /// section 5.3).
    // Source: the OpenAPI, `PUT /v2/dns/{DnsUuid}/cname/{CnameRecordUuid}` ("Изменить
    // CNAME-запись"): the body `CnameRecord_Update` has the single property `content`
    // (`content-cname`); 200 with `CnameRecord_Update_Response` (`uuid`, `name`, `dns`,
    // `content`, `ttl`); 400, 401, 404 ("record not found"), 409.
    pub(super) async fn update_cname(
        &self,
        zone_id: &str,
        record_id: &str,
        content: &str,
    ) -> Result<Written, Error> {
        #[derive(Serialize)]
        struct CnameUpdate<'a> {
            content: &'a str,
        }
        let url = self
            .base
            .url()
            .id(zone_id)
            .path(Kind::Cname.member())
            .id(record_id)
            .build()?;
        let response = self
            .send(&Request::new(Method::PUT, url).json(&CnameUpdate { content })?)
            .await?;
        Ok(self.written(&response))
    }

    /// Deletes one TXT record by its identifier. Repeating it is safe, so the transport may.
    // Source: the OpenAPI, `DELETE /v2/dns/{DnsUuid}/txt/{TxtRecordUuid}`: 204; 401, 404
    // ("record not found"). lego internal/client.go:86-90.
    pub(super) async fn delete_txt(
        &self,
        zone_id: &str,
        record_id: &str,
    ) -> Result<Written, Error> {
        self.delete(zone_id, Kind::Txt, record_id).await
    }

    /// Deletes one record of type `kind` by its identifier. Repeating it is safe, so the
    /// transport may.
    // Source: the OpenAPI, `DELETE /v2/dns/{DnsUuid}/{type}/{RecordUuid}` for each type: 204;
    // 401, 404 ("record not found").
    pub(super) async fn delete(
        &self,
        zone_id: &str,
        kind: Kind,
        record_id: &str,
    ) -> Result<Written, Error> {
        let url = self
            .base
            .url()
            .id(zone_id)
            .path(kind.member())
            .id(record_id)
            .build()?;
        let response = self
            .send(&Request::new(Method::DELETE, url).idempotent())
            .await?;
        Ok(self.written(&response))
    }

    fn written(&self, response: &Response) -> Written {
        match response.status() {
            _ if response.is_success() => Written::Done,
            404 => Written::NotFound,
            _ => Written::Refused(self.refusal(response)),
        }
    }

    /// An answer the client does not expect. 401, 403, 429, 3xx and 5xx were mapped by the
    /// transport already. The documented refusals are `Rejected`; anything else is an answer
    /// the client cannot interpret.
    // Source: the OpenAPI: 400 ("validation error of the request parameters") on the listings,
    // the creates and the updates, 409 on the creates and the updates. No error body is documented, so the message is taken
    // by the transport's default extractor.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400 | 409 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TxtRecord, Zone};

    #[test]
    fn the_zone_identifier_is_read_under_either_name() {
        let lego: Zone =
            serde_json::from_str(r#"{"uuid":"a-1","zone":"example.org","tenant":"t"}"#).unwrap();
        assert_eq!(lego.id(), Some("a-1"));
        let documented: Zone =
            serde_json::from_str(r#"{"DnsUuid":"b-2","zone":"example.org"}"#).unwrap();
        assert_eq!(documented.id(), Some("b-2"));
        let both: Zone =
            serde_json::from_str(r#"{"uuid":"a-1","DnsUuid":"b-2","zone":"example.org"}"#).unwrap();
        assert_eq!(both.id(), Some("a-1"));
        let empty: Zone = serde_json::from_str(r#"{"uuid":"","zone":"example.org"}"#).unwrap();
        assert_eq!(empty.id(), None);
        let none: Zone = serde_json::from_str(r#"{"zone":"example.org"}"#).unwrap();
        assert_eq!(none.id(), None);
    }

    #[test]
    fn a_record_without_identifier_name_or_content_does_not_parse() {
        for body in [
            r#"{"name":"x","content":"v","ttl":60}"#,
            r#"{"uuid":"u","content":"v","ttl":60}"#,
            r#"{"uuid":"u","name":"x","ttl":60}"#,
        ] {
            assert!(serde_json::from_str::<TxtRecord>(body).is_err(), "{body}");
        }
        let record: TxtRecord =
            serde_json::from_str(r#"{"uuid":"u","name":"x","dns":"/v2/dns/z","content":"v"}"#)
                .unwrap();
        assert_eq!(record.ttl, None);
    }
}
