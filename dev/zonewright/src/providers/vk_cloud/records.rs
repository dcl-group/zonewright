//! Record-level operations: the `PerRecord` shape of the record layer (`crate::rrsets`) over the
//! per-type record API, the listing of a zone, and the mapping between the API's record fields
//! and `RecordData`.
//!
//! The native unit is the individual record with an identifier, on paths of its own for each
//! type (`…/{zone}/a/`, `…/{zone}/mx/`, …), hence the per-record shape,
//! `Preconditions::ReadThenWrite` and no `atomic_rrset_write`: replacing an rrset is several
//! requests, creates first and deletes last (the record layer decides the order). The record
//! layer does the checks, takes the per-name lock, reads, evaluates the expectation and computes
//! the requests; this file turns them into the API's calls:
//!
//! - read: `GET …/{zone}/{type}/`, every record of the type in the zone, filtered here by exact
//!   name, under the zone-ID cache. A `404` ("records not found") or an empty listing is treated
//!   as the TXT value operations treat it (`txt.rs`): empty under a freshly looked-up
//!   identifier, possibly stale under a cached one, so the zone is looked up again and the read
//!   repeated once (design section 3.8);
//! - create: `POST …/{zone}/{type}/`, sent once, with the relative name, the type's fields and
//!   the TTL the layer chose. A `404` means the zone went away (`Error::Conflict`, nothing
//!   written); a refusal is followed by a new read, and the value found there now is
//!   `Error::Conflict` (created by another writer meanwhile);
//! - delete: `DELETE …/{zone}/{type}/{record}`, repeated by the transport (idempotent). A `404`
//!   is success only when a new read under a freshly looked-up zone no longer finds the value,
//!   as in `txt.rs`: the answer can also mean that the zone identifier went stale;
//! - update: only the CNAME target, in place: `PUT …/{zone}/cname/{record}` with `content`
//!   (`CnameRecord_Update`), sent once. A CNAME is a singleton, so the record layer replaces it
//!   by this one update ([`PerRecord::updates_in_place`]) and never by a delete and a create: a
//!   refused update leaves the old record as it was, where a refused create after the delete
//!   would leave the name without its CNAME. A `404` means the record went away after the read
//!   (`Error::Conflict`, nothing written). The OpenAPI's `PUT` bodies (`…_Update`) carry no TTL,
//!   and those of A, AAAA and SRV carry only `name`, so a TTL change of a record that stays (a
//!   CNAME changed in place included) is refused with `Error::InvalidInput` by `check_plan`,
//!   before any write (design section 3.4: refuse what cannot be carried out).
//!
//! `check_plan` also refuses, with `Error::Protocol` and before any write, a plan that deletes a
//! CNAME and then creates one: the record layer never sends that order to a client whose API
//! changes a record in place, and the client does not carry it out if it ever did.
//!
//! # Fields per type
//!
//! Source of every row: the provider's OpenAPI description,
//! <https://cloud.vk.ru/docs/_docs/ru/tools-for-using-services/api/api-spec/network-api/api-dns/assets/public-dns-api.json>
//! (version 2.0.0, read on 2026-11-14; the `…_Create` and `…_Filter` schemas and the field
//! schemas `name`, `name-srv`, `ipv4`, `ipv6`, `content-cname`, `content-mx`, `content-ns`,
//! `content-txt`, `priority`, `weight`, `port`, `host`, `ttl`), opened for this client, and the
//! record form of the console documentation,
//! <https://cloud.vk.ru/docs/en/networks/dns/publicdns> ("Adding resource records"), which
//! describes the same fields per type.
//!
//! | Type  | Canonical text from the API's fields        | Written as                          |
//! | ----- | ------------------------------------------- | ----------------------------------- |
//! | A     | `ipv4`                                      | `ipv4`                              |
//! | AAAA  | `ipv6`                                      | `ipv6`                              |
//! | CNAME | `content`, the target (1)                   | `content` (2)                       |
//! | NS    | `content`, the name server (1)              | `content` (2)                       |
//! | MX    | `<priority> <content>` (1)                  | `priority`, `content` (2)           |
//! | SRV   | `<priority> <weight> <port> <host>` (1)     | `priority`, `weight`, `port`, `host` (2) |
//! | TXT   | `content`, the value itself (3)             | `content` (3)                       |
//!
//! (1) The OpenAPI describes these values as FQDNs and its examples state them without a
//! trailing dot (`mailhost1.example.com`, `ns3.corp.mail.ru`, `example.com`): a host name read
//! with or without its trailing dot is absolute. (2) Written without the trailing dot: the
//! OpenAPI says of `content-cname`, `content-mx` and `content-ns` that the value "cannot start or
//! end with a hyphen or a dot"; `host` follows its example. The root (a null MX, an SRV "no
//! service") and names that need a backslash escape are not sent. A CNAME target must also meet
//! the other rules of `content-cname` that a host name can break: "two or more" labels, and no
//! hyphen at its start or end; a target that does not is refused with `Error::InvalidInput`
//! before any request (its character rule is discussed below). (3) TXT dialect `Raw` on write
//! and `Auto` on read, plain values only (`Txt::is_plain`), as the TXT value operations
//! (`txt.rs`); `content-txt` allows at most 255 characters, which every plain value meets.
//!
//! Names: relative to the zone, `@` for the apex (the OpenAPI's example of `name`), as the TXT
//! value operations send them. SRV names are described as "the symbolic name of the service and
//! the protocol, joined by a dot" (`name-srv`, example `_sip._udp`); the console form takes the
//! service and the protocol in fields of their own next to the name. An SRV owner name whose
//! two leftmost labels are not both underscore labels (the apex among them) cannot be stated in
//! that field and is refused with `Error::InvalidInput` before any write; the labels to the
//! right of them are sent as they are (assumption, not documented: `_sip._tcp.sub` for an owner
//! below a subdomain).
//!
//! Character rules. The OpenAPI describes `name` (and the content of CNAME, MX, NS and TXT) as
//! "only digits, Latin letters, hyphen and dot", which would refuse `_acme-challenge`, a wildcard
//! label and many TXT values. The TXT value operations send such names and values anyway, as
//! lego does; the record level does the same and adds no client-side check stricter than theirs.
//! A value the API refuses is its `400`, `Error::Rejected`.
//!
//! TTL: every record carries one (required on every create except SRV, where the client sends one
//! anyway), 60 to 2147483648 seconds by the OpenAPI, capped at `Ttl::MAX` (2147483647) by the
//! model. The API documents no disabled record, no comment and no other attribute the model does
//! not carry.
//!
//! SOA: the API has no SOA record; the zone object carries the SOA fields (`Dns_Get`), which are
//! not records and not listed. The apex NS set holds the provider's name servers ("By default,
//! two NS entries will be set in the zone", the console documentation); the record layer refuses
//! writes to it before any request.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::Error;
use crate::http::{Attempt, ZoneId};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::{DomainName, TargetName};
use crate::provider::ZoneListing;
use crate::record::{Mx, RecordData, RecordType, RrsetTtl, Srv, Txt, TxtDialect, singleton};
use crate::redact::Detail;
use crate::rrsets::{
    self, Listing, PerRecord, RecordUpdate, RecordsRead, RrsetBase, SetTtl, Step, Stored,
};

use super::api::{ApiRecord, Kind, NewRecord, Written};
use super::client::VkCloud;
use super::txt::{is_name, relative_name, vanished};

/// How TXT content is read: quoted text as presentation format, anything else as the value
/// (the TXT value operations' rule, design section 11.2).
const TXT_READ: TxtDialect = TxtDialect::Auto;

/// How TXT content is written: the value itself (lego vkcloud.go:222-226).
const TXT_WRITE: TxtDialect = TxtDialect::Raw;

// ---- Reading -------------------------------------------------------------------------------------

/// A value as the API returned it: canonical where the type's fields parse, non-canonical
/// otherwise (design section 4.9).
pub(super) fn read_record(kind: Kind, record: &ApiRecord) -> RecordData {
    match kind {
        Kind::A => read_a(record),
        Kind::Aaaa => read_aaaa(record),
        Kind::Cname => read_cname(record),
        Kind::Ns => read_ns(record),
        Kind::Mx => read_mx(record),
        Kind::Srv => read_srv(record),
        Kind::Txt => read_txt(record),
    }
}

/// A field's text, empty when missing.
fn text(field: Option<&String>) -> &str {
    field.map_or("", String::as_str)
}

/// A: the IPv4 address in `ipv4`.
// Source: the OpenAPI, `ARecord_Filter.ipv4` ("IPv4 address", example `8.8.8.8`).
fn read_a(record: &ApiRecord) -> RecordData {
    let ipv4 = text(record.ipv4.as_ref());
    RecordData::from_provider(RecordType::A, ipv4, None, TXT_READ)
}

/// AAAA: the IPv6 address in `ipv6`.
// Source: the OpenAPI, `AaaaRecord_Filter.ipv6` ("IPv6 address", example
// `1050::5:600:300c:326b`).
fn read_aaaa(record: &ApiRecord) -> RecordData {
    let ipv6 = text(record.ipv6.as_ref());
    RecordData::from_provider(RecordType::AAAA, ipv6, None, TXT_READ)
}

/// CNAME: the target in `content`, absolute with or without its trailing dot.
// Source: the OpenAPI, `CnameRecord_Filter.content` (`content-cname`: "FQDN of the destination",
// example `example.com`).
fn read_cname(record: &ApiRecord) -> RecordData {
    let content = text(record.content.as_ref());
    RecordData::from_provider(RecordType::CNAME, content, None, TXT_READ)
}

/// NS: the name server in `content`, absolute with or without its trailing dot.
// Source: the OpenAPI, `NsRecord_Filter.content` (`content-ns`: "address of the NS server",
// example `ns3.corp.mail.ru`).
fn read_ns(record: &ApiRecord) -> RecordData {
    let content = text(record.content.as_ref());
    RecordData::from_provider(RecordType::NS, content, None, TXT_READ)
}

/// MX: `priority` and the exchange in `content`.
// Source: the OpenAPI, `MxRecord_Filter.priority` ("host priority", example 11) and `.content`
// (`content-mx`: "FQDN of the mail server", example `mailhost1.example.com`).
fn read_mx(record: &ApiRecord) -> RecordData {
    let content = text(record.content.as_ref());
    match number(record.priority.as_ref()) {
        Some(priority) => RecordData::from_provider(
            RecordType::MX,
            &format!("{priority} {content}"),
            None,
            TXT_READ,
        ),
        None => RecordData::non_canonical(content),
    }
}

/// SRV: `priority`, `weight`, `port` and the target in `host`.
// Source: the OpenAPI, `SrvRecord_Filter.priority`, `.weight` ("weight for hosts with the same
// priority", example 5), `.port` ("port number the SRV service uses", example 5060) and `.host`
// ("FQDN of the host that provides the service", example `example.com`).
fn read_srv(record: &ApiRecord) -> RecordData {
    let host = text(record.host.as_ref());
    let fields = (
        number(record.priority.as_ref()),
        number(record.weight.as_ref()),
        number(record.port.as_ref()),
    );
    match fields {
        (Some(priority), Some(weight), Some(port)) => RecordData::from_provider(
            RecordType::SRV,
            &format!("{priority} {weight} {port} {host}"),
            None,
            TXT_READ,
        ),
        _ => RecordData::non_canonical(host),
    }
}

/// TXT: the value in `content`, read with the `Auto` rule.
// Source: the OpenAPI, `TxtRecord_Filter.content` (`content-txt`: "text value of the record");
// lego vkcloud.go:216 compares the listed content with the value as it is.
fn read_txt(record: &ApiRecord) -> RecordData {
    let content = text(record.content.as_ref());
    RecordData::from_provider(RecordType::TXT, content, None, TXT_READ)
}

/// A non-negative integer field.
fn number(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

/// A TTL as the API states it: a number, or a decimal string (see `api::ApiRecord`).
fn read_ttl(value: Option<&Value>) -> Option<RrsetTtl> {
    let secs = match value? {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => s.trim().parse::<u64>().ok()?,
        _ => return None,
    };
    RrsetTtl::from_secs(u32::try_from(secs).ok()?).ok()
}

// ---- Writing -------------------------------------------------------------------------------------

/// A value as the API takes it: the type's fields of a create.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Encoded {
    /// CNAME, MX, NS and TXT: `content`.
    content: Option<String>,
    /// A: `ipv4`.
    ipv4: Option<String>,
    /// AAAA: `ipv6`.
    ipv6: Option<String>,
    /// MX and SRV: `priority`.
    priority: Option<u16>,
    /// SRV: `weight`.
    weight: Option<u16>,
    /// SRV: `port`.
    port: Option<u16>,
    /// SRV: `host`.
    host: Option<String>,
}

impl Encoded {
    /// The body of a create of this value at `name` with `ttl`.
    fn body<'a>(&'a self, name: &'a str, ttl: u32) -> NewRecord<'a> {
        NewRecord {
            name,
            content: self.content.as_deref(),
            ipv4: self.ipv4.as_deref(),
            ipv6: self.ipv6.as_deref(),
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            host: self.host.as_deref(),
            ttl,
        }
    }
}

/// The API's fields for a canonical value of `rtype`, or `None` when the client cannot send it
/// (see the module documentation).
pub(super) fn encode(rtype: RecordType, data: &RecordData) -> Option<Encoded> {
    if !data.is_canonical() {
        return None;
    }
    match Kind::of(rtype)? {
        Kind::A => write_a(data),
        Kind::Aaaa => write_aaaa(data),
        Kind::Cname => write_cname(data),
        Kind::Ns => write_ns(data),
        Kind::Mx => write_mx(data),
        Kind::Srv => write_srv(data),
        Kind::Txt => write_txt(data),
    }
}

/// A: the canonical address (four decimal octets) as `ipv4`.
// Source: the OpenAPI, `ARecord_Create` (`name`, `ipv4`, `ttl` required; example `8.8.8.8`).
fn write_a(data: &RecordData) -> Option<Encoded> {
    Some(Encoded {
        ipv4: Some(data.as_str().to_owned()),
        ..Encoded::default()
    })
}

/// AAAA: the canonical address (RFC 5952) as `ipv6`.
// Source: the OpenAPI, `AaaaRecord_Create` (`name`, `ipv6`, `ttl` required; example
// `1050::5:600:300c:326b`, a compressed lowercase form).
fn write_aaaa(data: &RecordData) -> Option<Encoded> {
    Some(Encoded {
        ipv6: Some(data.as_str().to_owned()),
        ..Encoded::default()
    })
}

/// CNAME: the target without its trailing dot as `content`; `None` for a target that breaks a
/// structural rule of `content-cname`.
// Source: the OpenAPI, `CnameRecord_Create` (`name`, `content`, `ttl` required) and
// `content-cname` ("Должен состоять из двух или более поддоменов. Максимальная длина поддомена —
// 63 символа. ... Не может начинаться и заканчиваться на дефис или точку", example
// `example.com`). Labels of at most 63 characters are a property of every `TargetName`; the
// dots at the ends are taken off by `host`.
fn write_cname(data: &RecordData) -> Option<Encoded> {
    let target = TargetName::parse(data.as_str()).ok()?;
    let content = host(&target)?;
    let fits =
        content.split('.').count() >= 2 && !content.starts_with('-') && !content.ends_with('-');
    fits.then(|| Encoded {
        content: Some(content),
        ..Encoded::default()
    })
}

/// NS: the name server without its trailing dot as `content`.
// Source: the OpenAPI, `NsRecord_Create` (`name`, `content`, `ttl` required) and `content-ns`
// ("cannot start or end with a hyphen or a dot", example `ns3.corp.mail.ru`).
fn write_ns(data: &RecordData) -> Option<Encoded> {
    let target = TargetName::parse(data.as_str()).ok()?;
    Some(Encoded {
        content: Some(host(&target)?),
        ..Encoded::default()
    })
}

/// MX: the preference as `priority`, the exchange without its trailing dot as `content`.
// Source: the OpenAPI, `MxRecord_Create` (`name`, `content`, `priority`, `ttl` required) and
// `content-mx` ("cannot start or end with a hyphen or a dot", example
// `mailhost1.example.com`).
fn write_mx(data: &RecordData) -> Option<Encoded> {
    let mx = Mx::from_data(data).ok()?;
    Some(Encoded {
        priority: Some(mx.preference),
        content: Some(host(&mx.exchange)?),
        ..Encoded::default()
    })
}

/// SRV: `priority`, `weight`, `port`, and the target without its trailing dot as `host`.
// Source: the OpenAPI, `SrvRecord_Create` (`name`, `priority`, `weight`, `port`, `host`
// required; `host` example `example.com`).
fn write_srv(data: &RecordData) -> Option<Encoded> {
    let srv = Srv::from_data(data).ok()?;
    Some(Encoded {
        priority: Some(srv.priority),
        weight: Some(srv.weight),
        port: Some(srv.port),
        host: Some(host(&srv.target)?),
        ..Encoded::default()
    })
}

/// TXT: a plain value, itself, as `content`.
// Source: the OpenAPI, `TxtRecord_Create` (`name`, `content`, `ttl` required; `content-txt` at
// most 255 characters); lego vkcloud.go:222-226 writes the value unquoted.
fn write_txt(data: &RecordData) -> Option<Encoded> {
    let txt = Txt::from_data(data).ok().filter(Txt::is_plain)?;
    Some(Encoded {
        content: Some(TXT_WRITE.write(&txt)?),
        ..Encoded::default()
    })
}

/// A host name as the API takes it: without its trailing dot; `None` for the root and for a name
/// whose canonical text needs a backslash escape.
fn host(name: &TargetName) -> Option<String> {
    let text = name.as_str();
    if name.is_root() || text.contains('\\') {
        return None;
    }
    text.strip_suffix('.').map(str::to_owned)
}

/// Whether `relative`, an SRV owner name relative to the zone, can be stated in `name-srv`: its
/// two leftmost labels are the service and the protocol, both underscore labels.
// Source: the OpenAPI, `name-srv` ("the symbolic name of the service and the protocol, joined by
// a dot", example `_sip._udp`); the console documentation's SRV form ("Service: ... for example,
// _sip"; "Protocol: ... for example, _tcp or _udp").
fn srv_name_fits(relative: &str) -> bool {
    let mut labels = relative.split('.');
    let service = labels.next().unwrap_or_default();
    let protocol = labels.next().unwrap_or_default();
    service.len() > 1 && service.starts_with('_') && protocol.len() > 1 && protocol.starts_with('_')
}

// ---- The record layer ----------------------------------------------------------------------------

impl RrsetBase for VkCloud {
    fn provider(&self) -> ProviderId {
        ProviderId::VkCloud
    }

    fn capabilities(&self) -> &Capabilities {
        &super::meta::META.capabilities
    }

    fn locks(&self) -> &NameLocks {
        &self.locks
    }

    fn can_send(&self, rtype: RecordType, data: &RecordData) -> bool {
        encode(rtype, data).is_some()
    }
}

fn not_sendable() -> Error {
    Error::InvalidInput {
        detail: Detail::constant("the provider's encoding of this record data is not established"),
    }
}

/// The API type of `rtype`; the layer has refused every other type already.
fn kind_of(rtype: RecordType) -> Result<Kind, Error> {
    Kind::of(rtype).ok_or_else(|| Error::unsupported_record_type(ProviderId::VkCloud, rtype))
}

impl PerRecord for VkCloud {
    /// The record's identifier.
    type Handle = String;
    /// The zone's identifier the read used.
    type Context = String;

    async fn read(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<RecordsRead<String, String>, Error> {
        let kind = kind_of(rtype)?;
        let (id, records) = self
            .zones
            .read_zone(
                zone,
                || self.resolve_zone(zone),
                |id| self.read_kind(zone, name, kind, id),
            )
            .await?;
        Ok(RecordsRead {
            context: id.id,
            records,
        })
    }

    async fn create(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &String,
        data: &RecordData,
        ttl: SetTtl,
    ) -> Result<(), Error> {
        let kind = kind_of(rtype)?;
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let relative = relative_name(zone, name)?;
        if kind == Kind::Srv && !srv_name_fits(relative) {
            return Err(Error::InvalidInput {
                detail: Detail::constant(
                    "the provider states an SRV owner name as a service and a protocol label \
                     (such as _sip._tcp) relative to the zone; this name does not start with them",
                ),
            });
        }
        let ttl = match ttl {
            SetTtl::Requested(RrsetTtl::Explicit(ttl))
            | SetTtl::Existing(Some(RrsetTtl::Explicit(ttl))) => ttl.as_secs(),
            // A new set, or one whose TTL was not reported: the configured TTL (the API requires
            // one on a create).
            SetTtl::Default
            | SetTtl::Requested(RrsetTtl::ProviderDefault)
            | SetTtl::Existing(None | Some(RrsetTtl::ProviderDefault)) => self.ttl,
        };
        match self
            .api
            .create(context, kind, &encoded.body(relative, ttl))
            .await?
        {
            Written::Done => Ok(()),
            Written::NotFound => {
                self.forget_zone(zone);
                Err(vanished())
            }
            // The documented 409 covers a duplicate among other things, and other refusals are
            // not documented further, so a refused create is followed by a new read (design
            // section 3.5, as in `txt.rs`): the value found there now was created by another
            // writer after this operation's read, and nothing was written.
            Written::Refused(
                e @ Error::Rejected {
                    status: Some(400..=499),
                    ..
                },
            ) => match PerRecord::read(self, zone, name, rtype).await {
                Ok(read) if read.records.iter().any(|r| &r.data == data) => Err(Error::Conflict {
                    detail: Detail::constant(
                        "the record was created by another writer between the read and the write",
                    ),
                }),
                _ => Err(e),
            },
            Written::Refused(e) => Err(e),
        }
    }

    async fn update(
        &self,
        zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        context: &String,
        record: &Stored<String>,
        update: &RecordUpdate<'_>,
    ) -> Result<(), Error> {
        // `check_plan` refused every other update before the first write; checked again so that
        // no request is ever sent for one.
        check_update(rtype, record, update)?;
        let Some(data) = update.data else {
            return Err(no_such_update());
        };
        let encoded = encode(rtype, data).ok_or_else(not_sendable)?;
        let content = encoded.content.as_deref().ok_or_else(not_sendable)?;
        match self
            .api
            .update_cname(context, &record.handle, content)
            .await?
        {
            Written::Done => Ok(()),
            // The record, or the zone with it, went away after the read; nothing was written,
            // and the caller's repeat reads again under a freshly looked-up zone.
            Written::NotFound => {
                self.forget_zone(zone);
                Err(Error::Conflict {
                    detail: Detail::constant(
                        "the record was removed between the read and the update",
                    ),
                })
            }
            // Refused: one request, so the record is as it was.
            Written::Refused(e) => Err(e),
        }
    }

    async fn delete(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        context: &String,
        record: &Stored<String>,
    ) -> Result<(), Error> {
        let kind = kind_of(rtype)?;
        match self.api.delete(context, kind, &record.handle).await? {
            Written::Done => Ok(()),
            // The record is gone, or the zone identifier is (a zone recreated with the record in
            // it). Only a new read under a freshly looked-up zone tells them apart.
            Written::NotFound => {
                self.forget_zone(zone);
                let read = PerRecord::read(self, zone, name, rtype).await?;
                if read.records.iter().any(|r| r.data == record.data) {
                    Err(Error::Conflict {
                        detail: Detail::constant(
                            "the record was found again after its delete was answered \"not \
                             found\"; the zone changed between the read and the delete",
                        ),
                    })
                } else {
                    Ok(())
                }
            }
            Written::Refused(e) => Err(e),
        }
    }

    /// A CNAME's target is changed in place (`PUT …/cname/{record}`); the layer asks for no
    /// other in-place change (it changes content in place for singleton types only).
    fn updates_in_place(&self) -> bool {
        true
    }

    /// Refuses, before any write, every update the API cannot carry out (a TTL change, an
    /// enable, new content of a type other than CNAME) and a plan that deletes a CNAME before it
    /// creates one (see the module documentation).
    fn check_plan(
        &self,
        _zone: &DomainName,
        _name: &DomainName,
        rtype: RecordType,
        _context: &String,
        steps: &[Step<'_, String>],
    ) -> Result<(), Error> {
        check_steps(rtype, steps)
    }
}

/// [`PerRecord::check_plan`] of this client.
fn check_steps(rtype: RecordType, steps: &[Step<'_, String>]) -> Result<(), Error> {
    let mut deleted = false;
    for step in steps {
        match step {
            Step::Update { record, update } => check_update(rtype, record, update)?,
            Step::Delete(_) => deleted = true,
            Step::Create { .. } if deleted && singleton(rtype) => {
                return Err(Error::Protocol {
                    detail: Detail::constant(
                        "the plan deletes the record of a single-record type before it creates \
                         its replacement; a refused create would leave the name without the \
                         record",
                    ),
                });
            }
            Step::Create { .. } => {}
        }
    }
    Ok(())
}

/// The update of `record` the API can carry out: new CNAME content, with no TTL change.
fn check_update(
    rtype: RecordType,
    record: &Stored<String>,
    update: &RecordUpdate<'_>,
) -> Result<(), Error> {
    if let Some(ttl) = update.ttl
        && record.ttl != Some(ttl)
    {
        // No documented call changes the TTL of an existing record (the OpenAPI's `…_Update`
        // bodies have no `ttl`), and replacing the record by a delete and a create would leave
        // the name without the value in between.
        return Err(Error::InvalidInput {
            detail: Detail::constant(
                "the provider's API cannot change the TTL of an existing record; delete the \
                 rrset and set it again with the new TTL",
            ),
        });
    }
    if update.enable || update.data.is_none() || rtype != RecordType::CNAME {
        // The API has no disabled records, and content is changed in place for CNAME only.
        return Err(no_such_update());
    }
    Ok(())
}

fn no_such_update() -> Error {
    Error::Protocol {
        detail: Detail::constant(
            "the client was asked for a record update the provider's API does not offer",
        ),
    }
}

impl VkCloud {
    /// The read phase under the zone cache: the records of `kind` at `name` in the zone `id`. A
    /// `404` or an empty listing is an empty listing under a freshly looked-up identifier and
    /// `Stale` under a cached one, as in `txt.rs`.
    async fn read_kind(
        &self,
        zone: &DomainName,
        name: &DomainName,
        kind: Kind,
        id: ZoneId,
    ) -> Result<Attempt<Vec<Stored<String>>>, Error> {
        match self.api.records::<ApiRecord>(&id.id, kind).await? {
            Some(records) if records.is_empty() && !id.fresh => Ok(Attempt::Stale),
            Some(records) => Ok(Attempt::Done(
                records
                    .iter()
                    .filter(|r| is_name(&r.name, zone, name))
                    .map(|r| Stored {
                        data: read_record(kind, r),
                        // The API has no disabled records.
                        enabled: true,
                        ttl: read_ttl(r.ttl.as_ref()),
                        handle: r.uuid.clone(),
                    })
                    .collect(),
            )),
            None if id.fresh => Ok(Attempt::Done(Vec::new())),
            None => Ok(Attempt::Stale),
        }
    }

    /// Every type's listing of the zone `id`. Under a cached identifier, a zone where every
    /// listing is empty (or `404`) is `Stale`: one record of any type proves the identifier, and
    /// what an identifier that no longer exists gets is not documented.
    async fn list_kinds(&self, id: ZoneId) -> Result<Attempt<Vec<(Kind, Vec<ApiRecord>)>>, Error> {
        let mut all = Vec::with_capacity(Kind::ALL.len());
        for kind in Kind::ALL {
            let records = self
                .api
                .records::<ApiRecord>(&id.id, kind)
                .await?
                .unwrap_or_default();
            all.push((kind, records));
        }
        if !id.fresh && all.iter().all(|(_, records)| records.is_empty()) {
            return Ok(Attempt::Stale);
        }
        Ok(Attempt::Done(all))
    }

    /// `list_rrsets`: one listing per type, each complete or an error, grouped by owner name.
    pub(super) async fn list_zone(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        rrsets::check_list(self, zone)?;
        let (_, all) = self
            .zones
            .read_zone(zone, || self.resolve_zone(zone), |id| self.list_kinds(id))
            .await?;
        let mut listing = Listing::new(zone);
        for (kind, records) in &all {
            // Spellings of one name that mean the same land in one group.
            let mut groups: BTreeMap<String, Group> = BTreeMap::new();
            for record in records {
                let name = DomainName::from_relative(record.name.trim(), zone).ok();
                let key = name
                    .as_ref()
                    .map_or_else(|| format!("raw:{}", record.name), |n| n.as_str().to_owned());
                let group = groups.entry(key).or_insert_with(|| Group {
                    name,
                    ttl: None,
                    records: Vec::new(),
                });
                // The smallest TTL of the set (design section 3.6, `TtlSupport::PerRecord`).
                group.ttl = Listing::smallest_ttl([group.ttl, read_ttl(record.ttl.as_ref())]);
                group.records.push(read_record(*kind, record));
            }
            let type_name = kind.rtype().to_string();
            for group in groups.into_values() {
                listing.push(group.name, &type_name, group.ttl, group.records);
            }
        }
        listing.finish(ProviderId::VkCloud)
    }
}

/// The records of one owner name of one type, as the listing gathers them.
struct Group {
    name: Option<DomainName>,
    ttl: Option<RrsetTtl>,
    records: Vec<RecordData>,
}

#[cfg(test)]
mod tests {
    use super::{Encoded, check_steps, encode, read_record, read_ttl, srv_name_fits};
    use crate::error::ErrorKind;
    use crate::providers::vk_cloud::api::{ApiRecord, Kind};
    use crate::record::{RecordData, RecordType, RrsetTtl};
    use crate::rrsets::{RecordUpdate, SetTtl, Step, Stored};

    fn record(fields: serde_json::Value) -> ApiRecord {
        let mut json = serde_json::json!({"uuid": "u", "name": "www", "ttl": 60});
        if let (Some(target), Some(extra)) = (json.as_object_mut(), fields.as_object()) {
            for (k, v) in extra {
                target.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(json).unwrap()
    }

    fn data(rtype: RecordType, text: &str) -> RecordData {
        RecordData::parse(rtype, text).unwrap()
    }

    #[test]
    fn each_type_reads_into_canonical_text() {
        for (kind, fields, canonical) in [
            (
                Kind::A,
                serde_json::json!({"ipv4": "192.0.2.1"}),
                "192.0.2.1",
            ),
            (
                Kind::Aaaa,
                serde_json::json!({"ipv6": "2001:DB8:0::1"}),
                "2001:db8::1",
            ),
            (
                Kind::Cname,
                serde_json::json!({"content": "Target.example.net"}),
                "target.example.net.",
            ),
            (
                Kind::Cname,
                serde_json::json!({"content": "target.example.net."}),
                "target.example.net.",
            ),
            (
                Kind::Ns,
                serde_json::json!({"content": "ns1.mcs.mail.ru"}),
                "ns1.mcs.mail.ru.",
            ),
            (
                Kind::Mx,
                serde_json::json!({"content": "mail.example.org", "priority": 10}),
                "10 mail.example.org.",
            ),
            (
                Kind::Srv,
                serde_json::json!({"host": "sip.example.org", "priority": 1, "weight": 5, "port": 5060}),
                "1 5 5060 sip.example.org.",
            ),
            (
                Kind::Txt,
                serde_json::json!({"content": "v=spf1 -all"}),
                "\"v=spf1 -all\"",
            ),
        ] {
            let got = read_record(kind, &record(fields));
            assert!(got.is_canonical(), "{kind:?}");
            assert_eq!(got.as_str(), canonical, "{kind:?}");
        }
    }

    #[test]
    fn unparseable_fields_are_non_canonical() {
        for (kind, fields, kept) in [
            (
                Kind::A,
                serde_json::json!({"ipv4": "not an address"}),
                "not an address",
            ),
            (Kind::A, serde_json::json!({"content": "192.0.2.1"}), ""),
            (Kind::Cname, serde_json::json!({"content": "@"}), "@"),
            (
                Kind::Mx,
                serde_json::json!({"content": "mail.example.org"}),
                "mail.example.org",
            ),
            (
                Kind::Mx,
                serde_json::json!({"content": "mail.example.org", "priority": 70000}),
                "70000 mail.example.org",
            ),
            (
                Kind::Srv,
                serde_json::json!({"host": "sip.example.org", "priority": 1, "port": 5060}),
                "sip.example.org",
            ),
        ] {
            let got = read_record(kind, &record(fields));
            assert!(!got.is_canonical(), "{kind:?}");
            assert_eq!(got.as_str(), kept, "{kind:?}");
        }
    }

    #[test]
    fn ttls_are_numbers_or_decimal_strings() {
        let ttl = |v: serde_json::Value| read_ttl(Some(&v));
        assert_eq!(
            ttl(serde_json::json!(60)),
            Some(RrsetTtl::from_secs(60).unwrap())
        );
        assert_eq!(
            ttl(serde_json::json!("300")),
            Some(RrsetTtl::from_secs(300).unwrap())
        );
        assert_eq!(ttl(serde_json::json!(2_147_483_648_u64)), None);
        assert_eq!(ttl(serde_json::json!(-1)), None);
        assert_eq!(ttl(serde_json::json!("x")), None);
        assert_eq!(read_ttl(None), None);
    }

    fn fields(e: &Encoded) -> serde_json::Value {
        let mut value = serde_json::to_value(e.body("n", 60)).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("name");
        object.remove("ttl");
        value
    }

    #[test]
    fn each_type_writes_the_documented_fields() {
        for (rtype, text, expected) in [
            (
                RecordType::A,
                "192.0.2.1",
                serde_json::json!({"ipv4": "192.0.2.1"}),
            ),
            (
                RecordType::AAAA,
                "2001:db8::1",
                serde_json::json!({"ipv6": "2001:db8::1"}),
            ),
            (
                RecordType::CNAME,
                "target.example.net.",
                serde_json::json!({"content": "target.example.net"}),
            ),
            (
                RecordType::NS,
                "ns1.example.net.",
                serde_json::json!({"content": "ns1.example.net"}),
            ),
            (
                RecordType::MX,
                "10 mail.example.org.",
                serde_json::json!({"content": "mail.example.org", "priority": 10}),
            ),
            (
                RecordType::SRV,
                "1 5 5060 sip.example.org.",
                serde_json::json!({
                    "host": "sip.example.org", "priority": 1, "weight": 5, "port": 5060
                }),
            ),
            (
                RecordType::TXT,
                "\"v1\"",
                serde_json::json!({"content": "v1"}),
            ),
        ] {
            let encoded = encode(rtype, &data(rtype, text)).unwrap();
            assert_eq!(fields(&encoded), expected, "{rtype} {text}");
            // Read back through the same fields, the value is the same.
            let kind = Kind::of(rtype).unwrap();
            assert_eq!(
                read_record(kind, &record(expected.clone())),
                data(rtype, text),
                "{rtype}"
            );
        }
    }

    #[test]
    fn values_without_an_established_encoding_are_not_sent() {
        for (rtype, text) in [
            (RecordType::MX, "0 ."),
            (RecordType::SRV, "0 0 0 ."),
            (RecordType::CNAME, "a\\.b.example.net."),
            (RecordType::TXT, "\"two words\""),
            (RecordType::TXT, "\"quo\\\"te\""),
            (RecordType::CAA, "0 issue \"ca.example.net\""),
            (RecordType::TLSA, "3 1 1 0a1b"),
            (
                RecordType::SOA,
                "ns1.example.org. admin.example.org. 1 7200 3600 1209600 300",
            ),
        ] {
            assert!(
                encode(rtype, &data(rtype, text)).is_none(),
                "{rtype} {text}"
            );
        }
        assert!(encode(RecordType::A, &RecordData::non_canonical("x")).is_none());
    }

    #[test]
    fn cname_targets_follow_the_documented_structure() {
        for (text, content) in [
            ("t.example.net.", Some("t.example.net")),
            ("a-b.example.net.", Some("a-b.example.net")),
            ("intranet.", None),
            ("-t.example.net.", None),
            ("t.example-.", None),
        ] {
            let encoded = RecordData::parse(RecordType::CNAME, text)
                .ok()
                .and_then(|data| encode(RecordType::CNAME, &data));
            assert_eq!(
                encoded.and_then(|e| e.content).as_deref(),
                content,
                "{text}"
            );
        }
    }

    fn stored(text: &str, ttl: u32) -> Stored<String> {
        Stored {
            data: data(RecordType::CNAME, text),
            enabled: true,
            ttl: RrsetTtl::from_secs(ttl).ok(),
            handle: "u".to_owned(),
        }
    }

    #[test]
    fn plans_the_api_cannot_carry_out_are_refused() {
        let old = stored("old.example.net.", 300);
        let new = data(RecordType::CNAME, "new.example.net.");
        let same = RrsetTtl::from_secs(300).ok();
        let other = RrsetTtl::from_secs(600).ok();
        let change = |ttl, data| Step::Update {
            record: &old,
            update: RecordUpdate {
                enable: false,
                ttl,
                data,
            },
        };
        let create = Step::Create {
            data: &new,
            ttl: SetTtl::Existing(same),
        };
        let kind = |steps: &[Step<'_, String>]| {
            check_steps(RecordType::CNAME, steps).map_err(|e| e.kind())
        };
        assert_eq!(kind(&[change(None, Some(&new))]), Ok(()));
        assert_eq!(kind(&[change(same, Some(&new))]), Ok(()));
        assert_eq!(
            kind(&[change(other, Some(&new))]),
            Err(ErrorKind::InvalidInput)
        );
        assert_eq!(kind(&[change(other, None)]), Err(ErrorKind::InvalidInput));
        assert_eq!(kind(&[change(None, None)]), Err(ErrorKind::Protocol));
        // A singleton is never deleted before its replacement is created.
        assert_eq!(
            kind(&[Step::Delete(&old), create]),
            Err(ErrorKind::Protocol)
        );
        let create = Step::Create {
            data: &new,
            ttl: SetTtl::Default,
        };
        assert_eq!(kind(&[create]), Ok(()));
        // Other types: creates before deletes, as the layer orders them; new content in place
        // only for a CNAME.
        let a = Stored {
            data: data(RecordType::A, "192.0.2.1"),
            ..stored("old.example.net.", 300)
        };
        let new_a = data(RecordType::A, "192.0.2.2");
        let steps = [
            Step::Delete(&a),
            Step::Create {
                data: &new_a,
                ttl: SetTtl::Default,
            },
        ];
        assert_eq!(
            check_steps(RecordType::A, &steps).map_err(|e| e.kind()),
            Ok(())
        );
        let in_place = [Step::Update {
            record: &a,
            update: RecordUpdate {
                enable: false,
                ttl: None,
                data: Some(&new_a),
            },
        }];
        assert_eq!(
            check_steps(RecordType::A, &in_place).map_err(|e| e.kind()),
            Err(ErrorKind::Protocol)
        );
    }

    #[test]
    fn srv_names_start_with_service_and_protocol() {
        assert!(srv_name_fits("_sip._tcp"));
        assert!(srv_name_fits("_sip._udp.sub"));
        assert!(!srv_name_fits("@"));
        assert!(!srv_name_fits("sip._tcp"));
        assert!(!srv_name_fits("_sip"));
        assert!(!srv_name_fits("_sip.tcp"));
        assert!(!srv_name_fits("_._tcp"));
        assert!(!srv_name_fits("www"));
    }
}
