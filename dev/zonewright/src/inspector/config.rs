//! Configuration of the inspector (design section 8.2).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use super::InspectorError;
use crate::name::TargetName;

/// Cloudflare (1.1.1.1), Google (8.8.8.8) and Quad9 (9.9.9.9), port 53.
pub const PUBLIC_RESOLVERS: &[SocketAddr] = &[
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53)),
];

/// Upper bound on the resolvers of one configuration. Every resolver may be asked during one
/// discovery and one CNAME lookup, so the list is kept short.
pub(crate) const MAX_RESOLVERS: usize = 16;

/// How the inspector finds the authoritative name servers of a zone.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NsDiscovery {
    /// Ask the resolvers for the zone's NS rrset and the servers' addresses (design section
    /// 8.3).
    Recursive,
    /// Use exactly these servers for every zone. The list is used as given: no address filter
    /// and no cache apply, because the application chose the addresses. Their answers need the
    /// AA flag unless [`InspectorConfig::accept_static_without_aa`] is set.
    Static(Vec<NameServer>),
}

/// Address families of discovered name servers to query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpFamilies {
    /// IPv4 only (`A` records of the NS names).
    V4,
    /// IPv6 only (`AAAA` records of the NS names).
    V6,
    /// Both. Every address is a server that has to agree, so a host without working IPv6 egress
    /// should not choose this.
    Both,
}

impl IpFamilies {
    pub(crate) fn wants_v4(self) -> bool {
        matches!(self, IpFamilies::V4 | IpFamilies::Both)
    }

    pub(crate) fn wants_v6(self) -> bool {
        matches!(self, IpFamilies::V6 | IpFamilies::Both)
    }
}

/// One authoritative name server: an address, and the NS name it was found under when known.
///
/// Discovery also returns the servers it cannot ask (design section 8.3): an NS name for which
/// the resolvers answered that it has no address in the configured families, and every address
/// the address policy refuses. Such an entry has [`not_asked`](NameServer::not_asked) set; it is
/// never queried, and in [`Inspector::observe`](super::Inspector::observe) and
/// [`Inspector::wait`](super::Inspector::wait) it is a row whose answers are
/// [`Answer::NotAsked`](super::Answer::NotAsked) and which never satisfies anything. A wait
/// over a zone with such a server therefore runs to its timeout, and the report says why,
/// unless [`WaitOptions::ignore_unaskable_name_servers`](super::WaitOptions::ignore_unaskable_name_servers)
/// leaves such servers out of the condition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NameServer {
    /// The NS name, when known.
    pub name: Option<TargetName>,
    /// The address queries are sent to, on port 53 for discovered servers. For a server that is
    /// not asked: the refused address, or `None` when the NS name has no address in the
    /// configured families.
    pub addr: Option<SocketAddr>,
    /// Why this server is not asked; `None` for a server that is asked.
    pub not_asked: Option<NotAsked>,
}

impl NameServer {
    /// A server at `addr` that is asked, optionally with its NS name.
    #[must_use]
    pub fn new(name: Option<TargetName>, addr: SocketAddr) -> NameServer {
        NameServer {
            name,
            addr: Some(addr),
            not_asked: None,
        }
    }

    /// A server that is not asked, for the given reason.
    pub(crate) fn unasked(
        name: Option<TargetName>,
        addr: Option<SocketAddr>,
        reason: NotAsked,
    ) -> NameServer {
        NameServer {
            name,
            addr,
            not_asked: Some(reason),
        }
    }

    /// The address to query: `addr` when the server is asked, `None` otherwise.
    #[must_use]
    pub fn query_addr(&self) -> Option<SocketAddr> {
        match self.not_asked {
            Some(_) => None,
            None => self.addr,
        }
    }

    /// Why the server is not asked, `None` when it is. An entry without an address counts as
    /// [`NotAsked::NoAddress`] whatever `not_asked` says.
    pub(crate) fn reason(&self) -> Option<NotAsked> {
        match (self.not_asked, self.addr) {
            (Some(reason), _) => Some(reason),
            (None, None) => Some(NotAsked::NoAddress),
            (None, Some(_)) => None,
        }
    }
}

/// Why a name server is not asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NotAsked {
    /// The resolvers answered that the NS name has no address in the configured
    /// [`IpFamilies`] (NODATA or NXDOMAIN for every family asked).
    NoAddress,
    /// The address policy refuses the address (design section 8.3, step 4).
    AddressRefused(AddressRefusal),
}

impl NotAsked {
    /// A short stable description.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NotAsked::NoAddress => "no address in the configured address families",
            NotAsked::AddressRefused(reason) => reason.as_str(),
        }
    }
}

impl std::fmt::Display for NotAsked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotAsked::NoAddress => f.write_str(self.as_str()),
            NotAsked::AddressRefused(reason) => write!(f, "address refused: {}", reason.as_str()),
        }
    }
}

/// Why the address policy refuses a discovered name-server address (design section 8.3, step
/// 4). The reasons marked "private" are lifted by `allow_private_addresses`; the others apply
/// regardless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AddressRefusal {
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `240.0.0.0/4` with the limited broadcast address.
    Reserved,
    /// The parts of `192.0.0.0/24` and `2001::/23` (IETF protocol assignments) the registries do
    /// not mark globally reachable.
    ProtocolAssignment,
    /// `192.88.99.0/24`, the deprecated 6to4 relay anycast block (RFC 7526).
    Relay6to4,
    /// `198.18.0.0/15`, `2001:2::/48`.
    Benchmarking,
    /// An IPv6 address outside the global unicast space `2000::/3`, not covered by another
    /// reason.
    NotGlobalUnicast,
    /// `::ffff:0:0/96`: an IPv4 address written as IPv6, which the registry marks as neither a
    /// destination nor globally reachable.
    Ipv4Mapped,
    /// `::/96`: the IPv4-compatible form, deprecated by RFC 4291 section 2.5.5.1.
    Ipv4Compatible,
    /// Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918).
    Private,
    /// Private: `100.64.0.0/10` (RFC 6598).
    SharedAddressSpace,
    /// Private: `fc00::/7` (RFC 4193).
    UniqueLocal,
    /// Private: the deprecated site-local `fec0::/10` (RFC 3879).
    SiteLocal,
    /// Private: `64:ff9b:1::/48`, the local-use IPv4/IPv6 translation prefix (RFC 8215).
    LocalTranslation,
}

impl AddressRefusal {
    /// A short stable description.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AddressRefusal::Unspecified => "unspecified",
            AddressRefusal::Loopback => "loopback",
            AddressRefusal::LinkLocal => "link-local",
            AddressRefusal::Multicast => "multicast",
            AddressRefusal::Reserved => "broadcast or reserved",
            AddressRefusal::ProtocolAssignment => "IETF protocol assignment",
            AddressRefusal::Relay6to4 => "deprecated 6to4 relay anycast",
            AddressRefusal::Benchmarking => "benchmarking",
            AddressRefusal::NotGlobalUnicast => "not global unicast",
            AddressRefusal::Ipv4Mapped => "IPv4-mapped",
            AddressRefusal::Ipv4Compatible => "IPv4-compatible",
            AddressRefusal::Private => "private",
            AddressRefusal::SharedAddressSpace => "shared address space",
            AddressRefusal::UniqueLocal => "unique-local",
            AddressRefusal::SiteLocal => "site-local",
            AddressRefusal::LocalTranslation => "local-use translation",
        }
    }
}

impl std::fmt::Display for AddressRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration of an [`Inspector`](super::Inspector).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InspectorConfig {
    /// Recursive resolvers, tried in order. Default: [`PUBLIC_RESOLVERS`]. At most 16, each
    /// address once.
    pub resolvers: Vec<SocketAddr>,
    /// How name servers are found. Default: [`NsDiscovery::Recursive`].
    pub discovery: NsDiscovery,
    /// Address families of discovered name servers to query. Default: [`IpFamilies::V4`].
    pub ip_families: IpFamilies,
    /// Limit for one question to one server, including a TCP retry. Default 3 s.
    pub query_timeout: Duration,
    /// How long a discovered server list is reused. Default 300 s. Zero disables the cache.
    pub ns_cache_ttl: Duration,
    /// Upper bound on the name servers (addresses) of one zone. Default 32.
    pub max_servers: usize,
    /// Limit for the whole discovery of one zone's servers. Default 10 s.
    pub discovery_timeout: Duration,
    /// Accept discovered name-server addresses in private ranges (RFC 1918, RFC 6598, RFC 4193,
    /// the deprecated site-local `fec0::/10` and the local-use translation prefix
    /// `64:ff9b:1::/48`), also when embedded in a 6to4, Teredo, NAT64 or ISATAP address.
    /// Default false. The other reasons
    /// of [`AddressRefusal`] apply regardless (design section 8.3). A refused address is not
    /// left out: it is reported as a server that is not asked.
    pub allow_private_addresses: bool,
    /// Read an answer without the AA flag from a server of a static list
    /// ([`NsDiscovery::Static`]) by its content, as if the flag were set. Default false.
    ///
    /// Off, an answer without AA is [`Answer::NotAuthoritative`](super::Answer::NotAuthoritative)
    /// and satisfies nothing, from every server. On, an answer without AA from a server of the
    /// static list is classified like an authoritative one: records of the asked type are
    /// [`Answer::Records`](super::Answer::Records), an empty NOERROR answer is
    /// [`Answer::NoData`](super::Answer::NoData), NXDOMAIN is
    /// [`Answer::NxDomain`](super::Answer::NxDomain), a CNAME is
    /// [`Answer::Cname`](super::Answer::Cname). This serves a static list that points at a test
    /// DNS server which answers correctly but never sets AA.
    ///
    /// **Risk.** With the option on, whatever a server of the static list answers is believed.
    /// A recursive resolver, a forwarder or a caching server in the list counts as the zone's
    /// authority: its cached or stale answer can satisfy a wait. Put only servers in the list
    /// that answer from the zone's own data.
    ///
    /// What stays as it is: the ID and question checks, the response-code handling (REFUSED,
    /// SERVFAIL, other codes), the truncation and `FORMERR` retries, the CNAME rules and the
    /// size limits. A referral stays [`Answer::NotAuthoritative`](super::Answer::NotAuthoritative):
    /// an answer without AA whose answer section is empty and whose authority section holds NS
    /// records and no SOA is never read as NODATA or NXDOMAIN, whatever its response code
    /// (RFC 2308 sections 2.1 and 2.2.1: without AA, such a negative answer cannot be told from
    /// a referral). An answer with the AA flag is read exactly as with the option off.
    ///
    /// The option never applies to discovered servers ([`NsDiscovery::Recursive`]): for them
    /// the AA flag is always required, because a recursive or lame server must never count as
    /// the zone's authority. With recursive discovery the option has no effect. It does not
    /// apply to [`Inspector::query_server`](super::Inspector::query_server) either, which takes
    /// an address of the caller's choice, not a member of the static list: that call always
    /// requires AA.
    pub accept_static_without_aa: bool,
    /// Most questions (for [`Inspector::observe`](super::Inspector::observe)) or expectations
    /// (for [`Inspector::wait`](super::Inspector::wait)) in one call. Default 32; at least 1 and
    /// at most [`InspectorConfig::QUESTIONS_CEILING`] (256), and not more than
    /// `max_questions_per_round`. A call with more is
    /// [`InspectorError::InvalidInput`](super::InspectorError::InvalidInput) before anything is
    /// sent.
    pub max_questions: usize,
    /// Most questions in one round: the servers that are asked times the distinct questions of
    /// the call. Default 1024; at least `max_questions` and at most
    /// [`InspectorConfig::QUESTIONS_PER_ROUND_CEILING`] (8192). A call whose round would hold
    /// more is [`InspectorError::InvalidInput`](super::InspectorError::InvalidInput) after
    /// discovery and before any question is sent to a name server.
    ///
    /// This is the load one round puts on name servers the application usually does not run,
    /// and it bounds the duration of a round. A round sends at most `max_questions_per_round`
    /// questions, each of them at most 3 network exchanges (UDP, UDP without EDNS, TCP), at most
    /// [`InspectorConfig::QUESTIONS_IN_FLIGHT`] (128) at a time, each bounded by
    /// `query_timeout`. One round therefore takes at most
    /// `ceil(max_questions_per_round / 128) × query_timeout`, and more precisely
    /// `ceil(asked servers × distinct questions / 128) × query_timeout`. With the defaults:
    /// 1024 questions, 8 × 3 s = 24 s. At the ceiling: 8192 questions, 64 × `query_timeout`.
    pub max_questions_per_round: usize,
}

impl Default for InspectorConfig {
    fn default() -> InspectorConfig {
        InspectorConfig {
            resolvers: PUBLIC_RESOLVERS.to_vec(),
            discovery: NsDiscovery::Recursive,
            ip_families: IpFamilies::V4,
            query_timeout: Duration::from_secs(3),
            ns_cache_ttl: Duration::from_secs(300),
            max_servers: 32,
            discovery_timeout: Duration::from_secs(10),
            allow_private_addresses: false,
            accept_static_without_aa: false,
            max_questions: 32,
            max_questions_per_round: 1024,
        }
    }
}

impl InspectorConfig {
    /// The largest accepted `max_questions`: 256. It is several times what one zone's
    /// propagation check needs, and at the default `max_servers` (32) it fills the largest
    /// round, [`InspectorConfig::QUESTIONS_PER_ROUND_CEILING`].
    pub const QUESTIONS_CEILING: usize = 256;

    /// The largest accepted `max_questions_per_round`: 8192, that is
    /// [`InspectorConfig::QUESTIONS_CEILING`] questions at 32 servers. A round of that size
    /// takes at most 64 × `query_timeout` and is load on name servers the application does not
    /// run, which is why there is a ceiling at all.
    pub const QUESTIONS_PER_ROUND_CEILING: usize = 8192;

    /// Questions of one round in flight at the same time: 128, fixed. Each holds one socket.
    pub const QUESTIONS_IN_FLIGHT: usize = 128;

    /// True when answers from the configured servers are read without requiring the AA flag:
    /// only for a static list with [`InspectorConfig::accept_static_without_aa`] set.
    pub(crate) fn reads_without_aa(&self) -> bool {
        self.accept_static_without_aa && matches!(self.discovery, NsDiscovery::Static(_))
    }

    /// Checks the configuration; the reasons are the `Config` errors of [`Inspector::new`].
    ///
    /// [`Inspector::new`]: super::Inspector::new
    pub(crate) fn validate(&self) -> Result<(), InspectorError> {
        let fail = |detail: &str| Err(InspectorError::config(detail));
        if self.query_timeout.is_zero() {
            return fail("query_timeout must be greater than zero");
        }
        if self.discovery_timeout.is_zero() {
            return fail("discovery_timeout must be greater than zero");
        }
        if self.max_servers == 0 {
            return fail("max_servers must be at least 1");
        }
        if self.max_questions == 0 {
            return fail("max_questions must be at least 1");
        }
        if self.max_questions > Self::QUESTIONS_CEILING {
            return Err(InspectorError::config(&format!(
                "max_questions is {}, more than the ceiling of {}",
                self.max_questions,
                Self::QUESTIONS_CEILING
            )));
        }
        if self.max_questions_per_round > Self::QUESTIONS_PER_ROUND_CEILING {
            return Err(InspectorError::config(&format!(
                "max_questions_per_round is {}, more than the ceiling of {}",
                self.max_questions_per_round,
                Self::QUESTIONS_PER_ROUND_CEILING
            )));
        }
        // Otherwise a call with max_questions questions could not run even at one server.
        if self.max_questions_per_round < self.max_questions {
            return Err(InspectorError::config(&format!(
                "max_questions_per_round ({}) is less than max_questions ({})",
                self.max_questions_per_round, self.max_questions
            )));
        }
        if self.resolvers.len() > MAX_RESOLVERS {
            return fail("more than 16 resolvers");
        }
        // A resolver listed twice would count twice toward the CNAME quorum (design 8.7).
        for (at, resolver) in self.resolvers.iter().enumerate() {
            if self
                .resolvers
                .iter()
                .skip(at + 1)
                .any(|other| other == resolver)
            {
                return fail("a resolver is listed more than once");
            }
        }
        match &self.discovery {
            NsDiscovery::Recursive => {
                if self.resolvers.is_empty() {
                    return fail("recursive discovery needs at least one resolver");
                }
            }
            NsDiscovery::Static(servers) => {
                if servers.is_empty() {
                    return fail("the static name-server list is empty");
                }
                if servers.len() > self.max_servers {
                    return fail("the static name-server list is longer than max_servers");
                }
                // The application chose these servers to be asked.
                if servers.iter().any(|server| server.query_addr().is_none()) {
                    return fail("a static name server has no address or is marked not asked");
                }
            }
        }
        Ok(())
    }
}
