//! The RFC 2136 client: construction, `Debug`, `check` and the [`Provider`] implementation.
//!
//! The module follows the layout of every provider module (see the Selectel v2 client), with the
//! HTTP-specific `api.rs` replaced by the protocol: `wire.rs` (the DNS message format),
//! `tsig.rs` (RFC 8945 signatures) and `transport.rs` (DNS over TCP with timeouts and bounded
//! repeats). Design section 9, choice 9: a hand-written wire format and TSIG, not a DNS library.
//!
//! Sources: RFC 2136 (DNS UPDATE), RFC 8945 (TSIG), RFC 5936 (AXFR), RFC 7766 and RFC 1035
//! section 4.2.2 (DNS over TCP), RFC 1035 section 4 (the message format), and lego
//! `providers/dns/rfc2136/rfc2136.go`.

use std::fmt;

use secrecy::SecretString;

use crate::context::Context;
use crate::error::Error;
use crate::id::ProviderId;
use crate::locks::NameLocks;
use crate::name::DomainName;
use crate::operation::Call;
use crate::provider::{
    AddOutcome, CheckReport, DeleteOutcome, Expect, Provider, RemoveOutcome, SetOutcome, ZoneCheck,
    ZoneInfo, ZoneListing,
};
use crate::record::{RecordType, RrSet, RrsetTtl, Txt};
use crate::redact::Detail;
use crate::rrsets;
use crate::values;

use super::config::{self, Rfc2136Config, Rfc2136Credentials};
use super::transport::Transport;
use super::txt::{rcode_error, rcode_text};
use super::wire::{Builder, TYPE_SOA, rcode};

/// The client for a name server that accepts DNS UPDATE (RFC 2136) authenticated with TSIG
/// (RFC 8945): BIND, Knot, PowerDNS and others run by the application's operator.
///
/// Talks DNS over TCP to the configured `server`; every request is signed and every answer
/// verified. TXT values are added and removed one RR at a time, so a foreign value is never
/// part of a write (`ValueGuarantee::PerValue`). The protocol has no listing of zones.
///
/// `list_rrsets` transfers the zone (AXFR, RFC 5936) with the same key, so the key needs the
/// server's permission to transfer the zone. The listing holds every rrset in the form
/// `get_rrset` reads it. Sets below a delegation other than its NS set (glue, occluded records)
/// are listed too, but the record-level operations cannot address them (`Error::Rejected`), and
/// SOA and the apex NS set are listed but not writable. The records a DNSSEC signer keeps
/// (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM) are reported in `ZoneListing::skipped`; CDS,
/// CDNSKEY, ZONEMD and private types are listed as plain sets, even where a signer maintains
/// them. One attempt of a transfer is bounded at 64 MiB on the wire, 100 000 messages,
/// 256 MiB of records held once decoded, `request_timeout` per message and 20 times
/// `request_timeout` as a whole; up to 3 attempts are made for a transient failure.
///
/// When the server lets the key update but refuses its queries, the TXT value operations send
/// their change without reading first and report `AddOutcome::Accepted` or
/// `RemoveOutcome::Accepted`.
///
/// The record-level operations `get_rrset`, `set_rrset` and `delete_rrset` accept every type
/// with a type code (SOA read-only, the apex NS RRset not writable). They read by query and
/// write one UPDATE whose prerequisites name the RRset as read, so the server refuses a write
/// to an RRset that changed in between (`Preconditions::Atomic`). They need a key that may
/// query the zone: a refused query is `Error::Forbidden`, since the record model has no outcome
/// for a write whose prior state was not seen.
pub struct Rfc2136 {
    config: Rfc2136Config,
    pub(super) transport: Transport,
    /// The per-name locks of the context.
    pub(super) locks: NameLocks,
    /// TTL of new records.
    pub(super) ttl: u32,
}

impl fmt::Debug for Rfc2136 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The settings hold no secret.
        f.debug_struct("Rfc2136")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Rfc2136 {
    /// Builds the client. Validates the settings and the credentials, including the loopback
    /// policy of the context; makes no request and no name lookup.
    pub fn new(
        config: Rfc2136Config,
        credentials: Rfc2136Credentials,
        ctx: &Context,
    ) -> Result<Rfc2136, Error> {
        let settings = config.validate(&credentials, ctx)?;
        Ok(Rfc2136 {
            transport: Transport::new(settings.server, settings.key, ctx),
            locks: ctx.locks().clone(),
            ttl: settings.ttl,
            config,
        })
    }

    /// One zone of `check`: an UPDATE of the zone whose only content is the prerequisite "the
    /// apex name is in use" (RFC 2136 section 2.4.4). It changes nothing and tells whether the
    /// key is accepted, the server is authoritative for the zone and the zone accepts updates
    /// from this key.
    async fn check_zone(&self, zone: &DomainName) -> Result<ZoneCheck, Error> {
        let mut update = Builder::update(zone);
        update.prereq_name_in_use(zone)?;
        let answer = self.transport.exchange(&update.finish()?, "check").await?;
        let not_found = |text: &'static str| {
            Ok(ZoneCheck::new(
                zone.clone(),
                false,
                Some(Detail::constant(text)),
            ))
        };
        match answer.rcode() {
            rcode::NOERROR => Ok(ZoneCheck::new(zone.clone(), true, None)),
            rcode::SERVFAIL => Err(rcode_error(rcode::SERVFAIL)),
            rcode::REFUSED => not_found(
                "the server refused an update of the zone (REFUSED): its allow-update or \
                 update-policy does not let this key change it",
            ),
            other => not_found(rcode_text(other)),
        }
    }
}

impl Provider for Rfc2136 {
    fn id(&self) -> ProviderId {
        ProviderId::Rfc2136
    }

    /// For each zone, sends a signed UPDATE that changes nothing (see `check_zone`); a verified
    /// answer proves the key. Without zones, sends a signed QUERY for the SOA of the root: the
    /// server signs its answer, whatever it is, only when it accepted the request's signature
    /// (RFC 8945 section 5.3), so that tests the key without naming a zone. A TSIG error is
    /// `Error::Auth`.
    async fn check<'a>(
        &self,
        zones: impl IntoIterator<Item = &'a DomainName> + Send,
    ) -> Result<CheckReport, Error> {
        let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
        Call::check(zones.len())
            .observe(self, async {
                let zones = zones.as_slice();
                if zones.is_empty() {
                    let query = Builder::query(&DomainName::root(), TYPE_SOA).finish()?;
                    let answer = self.transport.exchange(&query, "check").await?;
                    if answer.rcode() == rcode::SERVFAIL {
                        return Err(rcode_error(rcode::SERVFAIL));
                    }
                    return Ok(CheckReport::new(true, Vec::new()));
                }
                let mut checks = Vec::with_capacity(zones.len());
                for zone in zones {
                    checks.push(self.check_zone(zone).await?);
                }
                Ok(CheckReport::new(true, checks))
            })
            .await
    }

    async fn get_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
    ) -> Result<Option<RrSet>, Error> {
        Call::get_rrset(zone, name, rtype)
            .observe(self, rrsets::get_whole_set(self, zone, name, rtype))
            .await
    }

    async fn set_rrset(
        &self,
        zone: &DomainName,
        rrset: &RrSet,
        expect: Expect<'_>,
    ) -> Result<SetOutcome, Error> {
        Call::set_rrset(zone, rrset)
            .observe(self, async {
                if self.set_target_valid(zone, rrset) {
                    self.check_size(zone, rrset, expect)?;
                }
                rrsets::set_whole_set(self, zone, rrset, expect).await
            })
            .await
    }

    async fn delete_rrset(
        &self,
        zone: &DomainName,
        name: &DomainName,
        rtype: RecordType,
        expect: Expect<'_>,
    ) -> Result<DeleteOutcome, Error> {
        Call::delete_rrset(zone, name, rtype)
            .observe(
                self,
                rrsets::delete_whole_set(self, zone, name, rtype, expect),
            )
            .await
    }

    async fn add_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
        ttl: Option<RrsetTtl>,
    ) -> Result<AddOutcome, Error> {
        Call::add_txt_value(zone, name)
            .observe(self, values::add_per_record(self, zone, name, value, ttl))
            .await
    }

    async fn remove_txt_value(
        &self,
        zone: &DomainName,
        name: &DomainName,
        value: &Txt,
    ) -> Result<RemoveOutcome, Error> {
        Call::remove_txt_value(zone, name)
            .observe(self, values::remove_per_record(self, zone, name, value))
            .await
    }

    async fn list_zones(&self) -> Result<Vec<ZoneInfo>, Error> {
        Call::list_zones().unsupported(self).await
    }

    /// One zone transfer (AXFR, RFC 5936) of `zone`, signed with the client's key; every
    /// message of the answer is verified (RFC 8945 section 5.3.1) before any record counts.
    /// A server that refuses the transfer with a signed REFUSED (BIND does) gives
    /// `Error::Forbidden`; a server that answers a denied transfer without a signature (Knot
    /// DNS answers NOTAUTH without TSIG) gives `Error::Protocol`, since an unsigned error is not
    /// believed.
    async fn list_rrsets(&self, zone: &DomainName) -> Result<ZoneListing, Error> {
        Call::list_rrsets(zone)
            .observe(self, self.list_zone(zone))
            .await
    }
}

/// Builds the client from stored configuration: deserializes both objects and calls
/// [`Rfc2136::new`].
pub(crate) fn from_json(
    settings: &str,
    credentials: &SecretString,
    ctx: &Context,
) -> Result<Rfc2136, Error> {
    Rfc2136::new(
        config::parse_settings(settings)?,
        config::parse_credentials(credentials)?,
        ctx,
    )
}
