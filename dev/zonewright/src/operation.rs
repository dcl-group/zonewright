//! The operation event: one `tracing` event per call of a [`Provider`] method of a client of this
//! crate (design section 5.6).
//!
//! Every client's implementation of the trait runs the work of each method through
//! [`Call::observe`], and answers a method it does not support through [`Call::unsupported`], so
//! that every call of every method is reported once. [`AnyProvider`](crate::AnyProvider) forwards
//! to the client and emits nothing of its own. A method's body names its call with the
//! constructor of the same name (`Call::add_txt_value` in `add_txt_value`); a source scan of the
//! conformance tests holds every client to that.
//!
//! The event names the provider, the operation, the zone (for `check`, the number of zones), the
//! owner name and the record type where the operation has them, the outcome (`ok` or the error's
//! kind) and the wall time. It never carries a record value, a TTL, the text of an error, the
//! provider's error code (it is read from a response body; the caller has it on the error), or
//! anything else from a request, a response or the configuration.

use std::future::Future;
use std::time::Instant;

use tracing::field;

use crate::error::{Error, Operation};
use crate::name::DomainName;
use crate::provider::Provider;
use crate::record::{RecordType, RrSet};

/// The target of the operation event.
const TARGET: &str = "zonewright::operation";

/// What an operation is about: the names the event reports.
#[derive(Clone, Copy)]
enum Subject<'a> {
    /// No zone (`list_zones`).
    Account,
    /// The number of zones of a `check`.
    Zones(usize),
    /// One zone (`list_rrsets`).
    Zone(&'a DomainName),
    /// One rrset of a zone: the zone, the owner name and the type.
    Rrset(&'a DomainName, &'a DomainName, RecordType),
}

/// One call of a `Provider` method, as the operation event reports it. Built by the constructor
/// named like the method; holds only borrowed names, never a value or a TTL.
#[derive(Clone, Copy)]
pub(crate) struct Call<'a> {
    operation: Operation,
    subject: Subject<'a>,
}

impl<'a> Call<'a> {
    /// `check` with `zones` zones.
    pub(crate) fn check(zones: usize) -> Call<'a> {
        Call {
            operation: Operation::Check,
            subject: Subject::Zones(zones),
        }
    }

    /// `list_zones`.
    pub(crate) fn list_zones() -> Call<'a> {
        Call {
            operation: Operation::ListZones,
            subject: Subject::Account,
        }
    }

    /// `list_rrsets` of `zone`.
    pub(crate) fn list_rrsets(zone: &'a DomainName) -> Call<'a> {
        Call {
            operation: Operation::ListRrsets,
            subject: Subject::Zone(zone),
        }
    }

    /// `get_rrset` of `name` and `rtype` in `zone`.
    pub(crate) fn get_rrset(
        zone: &'a DomainName,
        name: &'a DomainName,
        rtype: RecordType,
    ) -> Call<'a> {
        Call {
            operation: Operation::GetRrset,
            subject: Subject::Rrset(zone, name, rtype),
        }
    }

    /// `set_rrset` of `rrset` in `zone`: its name and type, not its records.
    pub(crate) fn set_rrset(zone: &'a DomainName, rrset: &'a RrSet) -> Call<'a> {
        Call {
            operation: Operation::SetRrset,
            subject: Subject::Rrset(zone, rrset.name(), rrset.rtype()),
        }
    }

    /// `delete_rrset` of `name` and `rtype` in `zone`.
    pub(crate) fn delete_rrset(
        zone: &'a DomainName,
        name: &'a DomainName,
        rtype: RecordType,
    ) -> Call<'a> {
        Call {
            operation: Operation::DeleteRrset,
            subject: Subject::Rrset(zone, name, rtype),
        }
    }

    /// `add_txt_value` at `name` in `zone`; the value is not part of the call.
    pub(crate) fn add_txt_value(zone: &'a DomainName, name: &'a DomainName) -> Call<'a> {
        Call {
            operation: Operation::AddTxtValue,
            subject: Subject::Rrset(zone, name, RecordType::TXT),
        }
    }

    /// `remove_txt_value` at `name` in `zone`; the value is not part of the call.
    pub(crate) fn remove_txt_value(zone: &'a DomainName, name: &'a DomainName) -> Call<'a> {
        Call {
            operation: Operation::RemoveTxtValue,
            subject: Subject::Rrset(zone, name, RecordType::TXT),
        }
    }

    /// Runs `work`, the body of this method of `client`, and emits the operation event when it
    /// completes. The result is returned unchanged.
    ///
    /// Nothing is allocated for the event, and besides `work` only the borrowed names and the
    /// start time are held across the `.await`, so the future is `Send` whenever `work` is.
    pub(crate) async fn observe<P, T, F>(self, client: &P, work: F) -> Result<T, Error>
    where
        P: Provider + ?Sized,
        F: Future<Output = Result<T, Error>>,
    {
        let provider = client.id().as_str();
        let start = Instant::now();
        let result = work.await;
        if tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
            self.emit(provider, start, &result);
        }
        result
    }

    /// This method of `client`, which the client does not support: `Error::Unsupported` for the
    /// operation, reported like any other call.
    // Only the clients that leave an operation out call it.
    #[cfg_attr(
        not(any(
            feature = "acme_dns",
            feature = "beget",
            feature = "regru",
            feature = "rfc2136"
        )),
        allow(dead_code)
    )]
    pub(crate) async fn unsupported<P, T>(self, client: &P) -> Result<T, Error>
    where
        P: Provider + ?Sized,
    {
        let provider = client.id();
        self.observe(client, async move {
            Err(Error::unsupported(provider, self.operation))
        })
        .await
    }

    /// Emits the operation event for a completed call.
    fn emit<T>(self, provider: &str, start: Instant, result: &Result<T, Error>) {
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (zones, zone, name, rtype) = match self.subject {
            Subject::Account => (None, None, None, None),
            Subject::Zones(count) => (Some(count), None, None, None),
            Subject::Zone(zone) => (None, Some(zone.as_str()), None, None),
            Subject::Rrset(zone, name, rtype) => (
                None,
                Some(zone.as_str()),
                Some(name.as_str()),
                Some(field::display(rtype)),
            ),
        };
        let outcome = match result {
            Ok(_) => "ok",
            Err(err) => err.kind().as_str(),
        };
        tracing::debug!(
            target: TARGET,
            provider,
            operation = self.operation.as_str(),
            zones,
            zone,
            name,
            rtype,
            outcome,
            elapsed_ms,
            "provider operation"
        );
    }
}
