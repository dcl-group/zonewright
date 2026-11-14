//! The propagation inspector: observe DNS at authoritative name servers and resolvers.
//!
//! Compiled with the feature `inspector`. The inspector holds no secrets and has no connection
//! to the provider clients. It
//!
//! - finds the authoritative name servers of a zone, through recursive resolvers or from a list
//!   the application gives ([`NsDiscovery`]);
//! - asks any question of any record type at one server ([`Inspector::query_server`]), at every
//!   configured resolver ([`Inspector::query_recursive`]) or at every server of a zone
//!   ([`Inspector::observe`]);
//! - waits until every server of a zone satisfies a set of [`Expectation`]s in the same round
//!   ([`Inspector::wait`]) and reports per server ([`Report`]);
//! - implements [`CnameLookup`](crate::dns01::CnameLookup) over the resolvers with a quorum of
//!   two, for [`follow_cname`](crate::dns01::follow_cname).
//!
//! Values are [`RecordData`] in the crate's canonical text, built from the wire through the same
//! code that parses provider text, so a value a provider client returned compares directly with
//! the value a server answered.
//!
//! Queries go out over UDP with EDNS (1232 octets), are repeated without EDNS after `FORMERR`
//! and over TCP after truncation, each question on a new socket with an unpredictable ID. The
//! inspector does not validate DNSSEC and does not use DNS over TLS or HTTPS. It needs a `tokio`
//! runtime with the I/O and time drivers enabled.
//!
//! Events go to the `tracing` target `zonewright::inspector`: one `DEBUG` event per question
//! with the server address, the record type, the recursion flag, the kind of answer and the
//! duration — no question name and no record value — and one `WARN` event per discovered
//! name server that is not asked (an address the policy refuses, or an NS name without an
//! address in the configured families), with the zone, the NS name, the address when there is
//! one and the reason — and one `WARN` event when a wait is satisfied with servers that cannot
//! be asked left out ([`WaitOptions::ignore_unaskable_name_servers`]), with the zone, the
//! number left out, the rounds and the elapsed time. NS names and their addresses are public
//! delegation data, not secrets; no event carries a value of a record the application asks
//! about.

mod answer;
mod cname;
mod config;
mod discovery;
mod exchange;
#[cfg(test)]
mod testing;
mod wait;

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::future::join_all;
use tokio::time::Instant;

pub use config::{
    AddressRefusal, InspectorConfig, IpFamilies, NameServer, NotAsked, NsDiscovery,
    PUBLIC_RESOLVERS,
};
pub use wait::{Report, ServerReport, WaitOptions};

use answer::{Mode, classify};
use discovery::NsCache;
use exchange::{Ask, NetTransport, Transport, bounded};

use crate::name::{DomainName, TargetName};
use crate::record::{RecordData, RecordType, Ttl};

/// The `tracing` target of the inspector's events.
const TARGET: &str = "zonewright::inspector";

/// Observes DNS: discovers name servers, asks questions, waits for expectations.
///
/// One `Inspector` can be shared by any number of concurrent calls; it keeps a cache of
/// discovered name servers.
pub struct Inspector {
    engine: Engine<NetTransport>,
}

impl fmt::Debug for Inspector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inspector")
            .field("config", &self.engine.config)
            .finish_non_exhaustive()
    }
}

/// A question: a name and a record type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name asked about.
    pub name: DomainName,
    /// The record type asked for.
    pub rtype: RecordType,
}

impl Question {
    /// The question for `rtype` at `name`.
    #[must_use]
    pub fn new(name: DomainName, rtype: RecordType) -> Question {
        Question { name, rtype }
    }
}

/// What one server said about one question.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answer {
    /// The rrset, normalized: values in canonical form, deduplicated, sorted. `ttl` is the
    /// smallest TTL among its records.
    Records {
        /// The smallest TTL of the records.
        ttl: Ttl,
        /// The values.
        records: Vec<RecordData>,
    },
    /// The name exists, there is no rrset of this type.
    NoData,
    /// The name does not exist.
    NxDomain,
    /// The name is a CNAME; the server did not answer the question itself.
    Cname(TargetName),
    /// The server refused the question.
    Refused,
    /// The server failed to answer (SERVFAIL).
    ServFail,
    /// An answer without the AA flag, or a referral, from a server queried as authoritative.
    NotAuthoritative,
    /// No acceptable answer arrived within the query timeout.
    Timeout,
    /// Anything else: another response code, a malformed message, a network error. The text is
    /// at most 512 bytes without control characters and quotes no record data.
    Failed(String),
    /// The server was not asked, for this reason (see [`NameServer`]). Appears only in the
    /// results of [`Inspector::observe`] and [`Inspector::wait`]; it satisfies nothing.
    NotAsked(NotAsked),
}

impl Answer {
    /// A short name of the variant, for events.
    fn kind(&self) -> &'static str {
        match self {
            Answer::Records { .. } => "records",
            Answer::NoData => "nodata",
            Answer::NxDomain => "nxdomain",
            Answer::Cname(_) => "cname",
            Answer::Refused => "refused",
            Answer::ServFail => "servfail",
            Answer::NotAuthoritative => "not_authoritative",
            Answer::Timeout => "timeout",
            Answer::Failed(_) => "failed",
            Answer::NotAsked(_) => "not_asked",
        }
    }
}

/// What the rrset of a question must look like at a server.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Condition {
    /// The rrset contains all of these values; other values may be present.
    Present(Vec<RecordData>),
    /// The rrset is exactly this set. An empty list means: there is no such rrset.
    Exact(Vec<RecordData>),
    /// The rrset contains none of these values, or does not exist.
    Absent(Vec<RecordData>),
}

/// A question and the condition its answer must satisfy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    /// The question asked at every server.
    pub question: Question,
    /// The condition the answer must satisfy.
    pub condition: Condition,
}

impl Expectation {
    /// The expectation that the answer to `question` satisfies `condition`.
    #[must_use]
    pub fn new(question: Question, condition: Condition) -> Expectation {
        Expectation {
            question,
            condition,
        }
    }
}

/// An error of the inspector. Details are at most 512 bytes without control characters.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InspectorError {
    /// The configuration is not usable.
    #[error("invalid inspector configuration: {detail}")]
    Config {
        /// What is wrong.
        detail: String,
    },
    /// The request is not valid: no or too many questions, a name outside the zone, a
    /// non-canonical expected value, a type that cannot be asked.
    #[error("invalid request: {detail}")]
    InvalidInput {
        /// What is wrong.
        detail: String,
    },
    /// Discovery could not establish the complete list of servers: no resolver returned an NS
    /// set for the zone, no resolver answered an address question for one of its NS names (a
    /// lookup failure, as opposed to an answer that there is no address), a resolver returned
    /// an unreadable value, or the discovery timeout passed. Usually transient; nothing is
    /// cached.
    #[error("no usable name servers for zone {zone}: {detail}")]
    NoNameServers {
        /// The zone.
        zone: DomainName,
        /// Why.
        detail: String,
    },
    /// The zone has more name servers than the limits allow; the list is never truncated.
    #[error("zone {zone} has {count} name server addresses, more than the configured limit")]
    TooManyNameServers {
        /// The zone.
        zone: DomainName,
        /// The number found at the step that exceeded a limit: NS names (more than 16),
        /// addresses of one NS name and family (more than 8), or servers in all, those that are
        /// not asked included (more than `max_servers`).
        count: usize,
    },
    /// The expectations were not met within the timeout.
    #[error("expectations not met within the timeout")]
    Timeout {
        /// The report of the last round.
        report: Report,
    },
}

impl InspectorError {
    fn config(detail: &str) -> InspectorError {
        InspectorError::Config {
            detail: bounded(detail),
        }
    }

    fn invalid(detail: &str) -> InspectorError {
        InspectorError::InvalidInput {
            detail: bounded(detail),
        }
    }

    fn no_servers(zone: &DomainName, detail: &str) -> InspectorError {
        InspectorError::NoNameServers {
            zone: zone.clone(),
            detail: bounded(detail),
        }
    }
}

impl Inspector {
    /// An inspector with this configuration. Fails with [`InspectorError::Config`] for a zero
    /// timeout, `max_servers` of zero, more than 16 resolvers, a resolver listed twice,
    /// recursive discovery without
    /// resolvers, or a static list that is empty or longer than `max_servers`.
    ///
    /// No socket is opened here.
    pub fn new(config: InspectorConfig) -> Result<Inspector, InspectorError> {
        Ok(Inspector {
            engine: Engine::new(config, NetTransport)?,
        })
    }

    /// The authoritative servers of `zone`, by the configured discovery. With recursive
    /// discovery the list also holds the servers that are not asked, with the reason
    /// ([`NameServer::not_asked`]); a static list is returned as given.
    pub async fn name_servers(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError> {
        self.engine.name_servers(zone).await
    }

    /// One question to one server, recursion not desired. A type that cannot be asked
    /// (ALIAS, ANAME, OPT, the query and meta types) is answered [`Answer::Failed`] without a
    /// query. The address is the caller's choice: no address policy applies, as for a static
    /// list. A [`NameServer`] that is not asked has no [`NameServer::query_addr`] to pass.
    pub async fn query_server(&self, server: SocketAddr, question: &Question) -> Answer {
        match ask_for(question, false) {
            Ok(ask) => self.engine.ask(server, &ask, Mode::Server).await,
            Err(detail) => Answer::Failed(detail),
        }
    }

    /// One question to every configured resolver, recursion desired, all at once. The result
    /// is in the order of the configuration. A CNAME chain inside an answer is followed to the
    /// records of the asked type (at most 8 links).
    pub async fn query_recursive(&self, question: &Question) -> Vec<(SocketAddr, Answer)> {
        self.engine.query_recursive(question).await
    }

    /// One round: every question at every name server of the zone, at most 128 questions in
    /// flight at a time. The answers of a server are in the order of `questions`; a server that
    /// is not asked has an [`Answer::NotAsked`] for each. 1 to 32 questions, every name within
    /// the zone, at most 1,024 questions in all.
    ///
    /// `observe` returns the answers only and judges nothing: there is no "every server
    /// agrees" verdict, so [`WaitOptions::ignore_unaskable_name_servers`] has no counterpart
    /// here. A caller that wants the same rule leaves out the rows whose
    /// [`NameServer::not_asked`] is set and requires at least one row to remain.
    pub async fn observe(
        &self,
        zone: &DomainName,
        questions: &[Question],
    ) -> Result<Vec<(NameServer, Vec<Answer>)>, InspectorError> {
        self.engine.observe(zone, questions).await
    }

    /// Polls until every name server of the zone satisfies every expectation in the same round
    /// (design section 8.6). A server that is not asked never satisfies anything, so with one
    /// the wait ends in [`InspectorError::Timeout`], whose report names the reason — unless
    /// [`WaitOptions::ignore_unaskable_name_servers`] is on, which leaves such servers out of
    /// the condition (but never all of them: a zone none of whose servers can be asked still
    /// ends in the timeout) and counts them in [`Report::unaskable_ignored`]. At least
    /// one round runs; the last round starts no later than `options.timeout` after the start.
    /// A pause is cut to the deadline but never below `options.interval` less the jitter: when
    /// less time than that is left, the wait ends without a further round. An
    /// `options.interval` below [`WaitOptions::MIN_INTERVAL`] is
    /// [`InspectorError::InvalidInput`]. Dropping the future cancels every query it started.
    pub async fn wait(
        &self,
        zone: &DomainName,
        expectations: &[Expectation],
        options: &WaitOptions,
    ) -> Result<Report, InspectorError> {
        self.engine.wait(zone, expectations, options).await
    }
}

/// The inspector's logic over any [`Transport`].
pub(crate) struct Engine<T> {
    config: InspectorConfig,
    transport: T,
    cache: NsCache,
}

impl<T: Transport> Engine<T> {
    pub(crate) fn new(config: InspectorConfig, transport: T) -> Result<Engine<T>, InspectorError> {
        config.validate()?;
        Ok(Engine {
            config,
            transport,
            cache: NsCache::default(),
        })
    }

    /// One question to one address, bounded by the query timeout, classified per `mode`.
    pub(crate) async fn ask(&self, server: SocketAddr, ask: &Ask, mode: Mode) -> Answer {
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            self.config.query_timeout,
            self.transport.exchange(server, ask),
        )
        .await
        .unwrap_or(Err(exchange::Failure::Timeout));
        let answer = classify(outcome, ask, mode);
        tracing::debug!(
            target: TARGET,
            server = %server,
            rtype = %RecordType::from_code(ask.rtype),
            recursion = ask.recursion,
            answer = answer.kind(),
            duration_ms = duration_ms(started.elapsed()),
            "dns query"
        );
        answer
    }

    async fn query_recursive(&self, question: &Question) -> Vec<(SocketAddr, Answer)> {
        let ask = match ask_for(question, true) {
            Ok(ask) => ask,
            Err(detail) => {
                return self
                    .config
                    .resolvers
                    .iter()
                    .map(|resolver| (*resolver, Answer::Failed(detail.clone())))
                    .collect();
            }
        };
        let ask = &ask;
        join_all(self.config.resolvers.iter().map(|resolver| async move {
            let answer = self
                .ask(*resolver, ask, Mode::Resolver { follow: true })
                .await;
            (*resolver, answer)
        }))
        .await
    }
}

/// Milliseconds for an event field, saturating.
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The transport's form of a question; refuses types that cannot be asked.
fn ask_for(question: &Question, recursion: bool) -> Result<Ask, String> {
    let rtype = askable(question.rtype)?;
    Ok(Ask {
        name: TargetName::from(&question.name).wire().to_vec(),
        rtype,
        recursion,
    })
}

/// The type code of a type that can be asked: not a pseudo-type, not OPT, not a query or meta
/// type (RFC 6895 section 3.1).
fn askable(rtype: RecordType) -> Result<u16, String> {
    match rtype.code() {
        Some(code) if !rtype.is_meta() => Ok(code),
        Some(_) => Err(format!(
            "{rtype} is a query or meta type and cannot be asked"
        )),
        None => Err(format!(
            "{rtype} is a provider pseudo-type and cannot be asked"
        )),
    }
}
