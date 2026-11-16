//! The code the Gcore and EdgeCenter clients share: the DNS API v2 that Gcore serves and that
//! EdgeCenter serves in a fork of its own.
//!
//! The two services have one ancestry: the EdgeCenter SDK "includes code originally developed by
//! G-Core Labs S.A." (`github.com/Edge-Center/edgecenter-dns-sdk-go`, README), and lego drives
//! both with one client, `providers/dns/internal/gcore`, with another base URL for EdgeCenter
//! (`providers/dns/edgecenter/edgecenter.go`). Their published specifications differ in a few
//! places; this code reads every such difference in a form both providers' answers fit, and
//! [`Flavor`] carries only the provider's identity and capabilities:
//!
//! - what a create of an rrset that exists is answered with is not documented with a meaning at
//!   either (EdgeCenter lists `409` for a create and for a replacement, without saying what it
//!   means): any refused create is followed by a new read;
//! - the zone's answer, flat at Gcore and wrapped in `{"zone": …}` at EdgeCenter, is read in
//!   either form (`api.rs`);
//! - the member that selects answers per query, `pickers` at Gcore and `filters` at EdgeCenter,
//!   is looked for under both names (`api.rs`): an rrset with either is never written.
//!
//! The layout follows the provider modules (described in the Selectel v2 client): `api.rs` (the
//! HTTP API), `content.rs` (record content per type), `records.rs` (the record layer's
//! `WholeSet` shape and the listing), `txt.rs` (the value layer's `WholeSet` shape) and this file
//! (the shared client core, [`Core`]: zone checks, the rrset primitives both layers use). The
//! provider modules hold the metadata, the configuration types, the client type and its
//! `impl Provider`, which calls into [`Core`].
//!
//! The zone name is the key of every path, so there are no zone identifiers to cache and none
//! to go stale.

mod api;
mod content;
mod records;
mod txt;

use std::collections::BTreeSet;

use crate::error::Error;
use crate::http::{Endpoint, Http};
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::meta::Capabilities;
use crate::name::DomainName;
use crate::provider::{CheckReport, ZoneCheck, ZoneInfo};
use crate::redact::Detail;

pub(super) use api::error_message;
use api::{Api, Record, Rrset, RrsetBody, Written};

/// What differs between the providers that serve this API, as far as this code depends on it.
#[derive(Debug)]
pub(super) struct Flavor {
    /// The provider.
    pub(super) provider: ProviderId,
    /// Its capabilities in this version of the crate.
    pub(super) capabilities: &'static Capabilities,
}

/// Why a zone that exists is reported with a remark by `check`.
const ZONE_DISABLED: &str = "the zone is disabled at the provider: its records are not served";

/// The shared client core: the API, the per-name locks and the TTL of a new rrset.
#[derive(Debug)]
pub(super) struct Core {
    flavor: &'static Flavor,
    api: Api,
    locks: NameLocks,
    ttl: u32,
}

impl Core {
    /// A core over `http` at `base`; `ttl` is the TTL of a new rrset.
    pub(super) fn new(
        flavor: &'static Flavor,
        http: Http,
        base: Endpoint,
        locks: NameLocks,
        ttl: u32,
    ) -> Core {
        Core {
            flavor,
            api: Api::new(http, base),
            locks,
            ttl,
        }
    }

    /// `check`: reads one page of the zone listing, which exercises the token on every call,
    /// then looks every zone up afresh.
    pub(super) async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
        self.api.probe().await?;
        let mut checks = Vec::with_capacity(zones.len());
        for zone in zones {
            let check = match self.api.zone(zone).await? {
                None => ZoneCheck::new(zone.clone(), false, None),
                Some(found) if found.enabled == Some(false) => {
                    ZoneCheck::new(zone.clone(), true, Some(Detail::constant(ZONE_DISABLED)))
                }
                Some(_) => ZoneCheck::new(zone.clone(), true, None),
            };
            checks.push(check);
        }
        Ok(CheckReport::new(true, checks))
    }

    /// `list_zones`: every zone of the account, all pages. A zone name the crate cannot hold is
    /// left out.
    pub(super) async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        let names: BTreeSet<DomainName> = self
            .api
            .zones()
            .await?
            .iter()
            .filter_map(|zone| DomainName::parse(&zone.name).ok())
            .collect();
        Ok(names.into_iter().map(ZoneInfo::new).collect())
    }

    /// The rrset of `name` and `rtype` (the API's spelling). A `404` answers a missing rrset and
    /// a missing zone alike; the zone is then looked up, and a missing zone is
    /// `Error::ZoneNotFound`.
    async fn read_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Option<Rrset>, Error> {
        if let Some(rrset) = self.api.rrset(zone, name, rtype).await? {
            return Ok(Some(rrset));
        }
        match self.api.zone(zone).await? {
            Some(_) => Ok(None),
            None => Err(Error::zone_not_found(zone.clone())),
        }
    }

    /// Creates the rrset. Neither provider documents what a create of an rrset that exists is
    /// answered with, so any refusal is followed by a new read: an rrset found there now was
    /// created by someone else after the operation's read, nothing of it was overwritten, and
    /// the result is `Error::Conflict` (design section 3.5); otherwise the refusal is the error,
    /// with the provider's message. When that read fails, its error is returned in place of the
    /// refusal: the state is then unknown, which is what the read's error says.
    async fn create_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        records: &[Record],
        ttl: u32,
    ) -> Result<(), Error> {
        let body = RrsetBody {
            ttl,
            resource_records: records,
        };
        let refusal = match self.api.create(zone, name, rtype, &body).await? {
            Written::Done => return Ok(()),
            Written::NotFound => return Err(vanished()),
            Written::Refused(e) => e,
        };
        match self.read_rrset(zone, name, rtype).await? {
            Some(_) => Err(created_meanwhile()),
            None => Err(refusal),
        }
    }

    /// Replaces the TTL and the records of the rrset.
    async fn replace_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
        records: &[Record],
        ttl: u32,
    ) -> Result<(), Error> {
        let body = RrsetBody {
            ttl,
            resource_records: records,
        };
        match self.api.replace(zone, name, rtype, &body).await? {
            Written::Done => Ok(()),
            Written::NotFound => Err(vanished()),
            Written::Refused(e) => Err(e),
        }
    }

    /// Deletes the rrset. A `404` is success only when a new read finds no rrset: otherwise the
    /// rrset was created again after the read, and its values are published (`Error::Conflict`).
    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: &str,
    ) -> Result<(), Error> {
        match self.api.delete(zone, name, rtype).await? {
            Written::Done => Ok(()),
            Written::NotFound => match self.read_rrset(zone, name, rtype).await? {
                None => Ok(()),
                Some(_) => Err(Error::Conflict {
                    detail: Detail::constant(
                        "the rrset was found again after its delete was answered \
                         \"not found\"; it changed between the read and the delete",
                    ),
                }),
            },
            Written::Refused(e) => Err(e),
        }
    }
}

/// A dynamic rrset at the name and type: it is not read or changed as an rrset (design section
/// 3.4). The TXT value operations refuse it in the same way.
fn not_plain() -> Error {
    Error::Rejected {
        status: None,
        detail: Detail::constant(
            "the rrset selects its answers per query (pickers, filters or metadata); it is not \
             read or changed as an rrset",
        ),
        code: None,
    }
}

/// A write addressed a zone or an rrset that no longer exists: it changed after the read, and
/// nothing was written.
fn vanished() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "the zone or the rrset was removed between the read and the write",
        ),
    }
}

/// A create met an rrset that someone else created after the read.
fn created_meanwhile() -> Error {
    Error::Conflict {
        detail: Detail::constant(
            "an rrset of this name and type was created between the read and the write",
        ),
    }
}
