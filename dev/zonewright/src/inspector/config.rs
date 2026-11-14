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
    /// and no cache apply, because the application chose the addresses.
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
        }
    }
}

impl InspectorConfig {
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
