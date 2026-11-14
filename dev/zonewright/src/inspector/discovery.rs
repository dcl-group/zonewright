//! Name-server discovery (design section 8.3).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use tokio::time::Instant;

use super::answer::Mode;
use super::exchange::{Ask, Transport};
use super::{Answer, Engine, InspectorError, NameServer, NsDiscovery, TARGET};
use crate::name::{DomainName, TargetName};
use crate::record::RecordType;

/// Most distinct NS names of one zone.
pub(crate) const MAX_NS_NAMES: usize = 16;
/// Most addresses of one NS name and family.
pub(crate) const MAX_ADDRESSES_PER_NAME: usize = 8;
/// Address lookups running at the same time during one discovery.
pub(crate) const ADDRESS_LOOKUPS_AT_ONCE: usize = 8;
/// Most zones in the cache.
pub(crate) const MAX_CACHED_ZONES: usize = 256;

/// The port discovered servers are queried on.
const DNS_PORT: u16 = 53;

/// Discovered server lists by zone, with the time they were stored. Failures are not cached.
#[derive(Debug, Default)]
pub(crate) struct NsCache {
    entries: Mutex<HashMap<DomainName, (Instant, Vec<NameServer>)>>,
}

impl NsCache {
    /// The list stored for `zone` if it is younger than `ttl`.
    fn get(&self, zone: &DomainName, ttl: Duration) -> Option<Vec<NameServer>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.get(zone) {
            Some((stored, servers)) if stored.elapsed() < ttl => Some(servers.clone()),
            Some(_) => {
                entries.remove(zone);
                None
            }
            None => None,
        }
    }

    /// Stores the list for `zone`, evicting the oldest entry when the cache is full.
    fn put(&self, zone: &DomainName, servers: Vec<NameServer>) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if !entries.contains_key(zone) && entries.len() >= MAX_CACHED_ZONES {
            let oldest = entries
                .iter()
                .min_by_key(|(_, (stored, _))| *stored)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(zone.clone(), (Instant::now(), servers));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Why an address is refused, or `None` when it is usable.
pub(crate) fn refusal(ip: IpAddr, allow_private: bool) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => refusal_v4(v4, allow_private),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => refusal_v4(v4, allow_private),
            None => refusal_v6(v6, allow_private),
        },
    }
}

fn refusal_v4(ip: Ipv4Addr, allow_private: bool) -> Option<&'static str> {
    let [a, b, _, _] = ip.octets();
    if a == 0 {
        Some("unspecified")
    } else if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_link_local() {
        Some("link-local")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if a >= 240 {
        // 240.0.0.0/4 is reserved and holds the limited broadcast address.
        Some("broadcast or reserved")
    } else if allow_private {
        None
    } else if ip.is_private() {
        Some("private")
    } else if a == 100 && (64..128).contains(&b) {
        Some("shared address space")
    } else {
        None
    }
}

fn refusal_v6(ip: Ipv6Addr, allow_private: bool) -> Option<&'static str> {
    let first = ip.segments().first().copied().unwrap_or(0);
    if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_loopback() {
        Some("loopback")
    } else if first & 0xffc0 == 0xfe80 {
        Some("link-local")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if allow_private {
        None
    } else if first & 0xfe00 == 0xfc00 {
        Some("unique-local")
    } else {
        None
    }
}

impl<T: Transport> Engine<T> {
    /// The authoritative servers of `zone`, by the configured discovery.
    pub(crate) async fn name_servers(
        &self,
        zone: &DomainName,
    ) -> Result<Vec<NameServer>, InspectorError> {
        let NsDiscovery::Static(servers) = &self.config.discovery else {
            return self.discover_cached(zone).await;
        };
        Ok(servers.clone())
    }

    async fn discover_cached(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError> {
        let ttl = self.config.ns_cache_ttl;
        if !ttl.is_zero()
            && let Some(servers) = self.cache.get(zone, ttl)
        {
            return Ok(servers);
        }
        let servers = tokio::time::timeout(self.config.discovery_timeout, self.discover(zone))
            .await
            .unwrap_or_else(|_| {
                Err(InspectorError::no_servers(
                    zone,
                    "discovery did not finish within the discovery timeout",
                ))
            })?;
        if !ttl.is_zero() {
            self.cache.put(zone, servers.clone());
        }
        Ok(servers)
    }

    /// Steps 1 to 5 of design section 8.3.
    async fn discover(&self, zone: &DomainName) -> Result<Vec<NameServer>, InspectorError> {
        let names = self.ns_names(zone).await?;
        if names.len() > MAX_NS_NAMES {
            return Err(InspectorError::TooManyNameServers {
                zone: zone.clone(),
                count: names.len(),
            });
        }
        let mut lookups = stream::iter(names.into_iter().map(|name| async move {
            let addresses = self.addresses_of(zone, &name).await;
            (name, addresses)
        }))
        .buffered(ADDRESS_LOOKUPS_AT_ONCE);

        let mut servers: Vec<NameServer> = Vec::new();
        let mut seen: HashSet<IpAddr> = HashSet::new();
        while let Some((name, addresses)) = lookups.next().await {
            let mut usable = 0usize;
            for ip in addresses? {
                if let Some(reason) = refusal(ip, self.config.allow_private_addresses) {
                    tracing::warn!(
                        target: TARGET,
                        zone = %zone,
                        ns = %name,
                        address = %ip,
                        reason,
                        "name-server address refused"
                    );
                    continue;
                }
                usable += 1;
                if seen.insert(ip) {
                    servers.push(NameServer::new(
                        Some(name.clone()),
                        SocketAddr::new(ip, DNS_PORT),
                    ));
                }
            }
            if usable == 0 {
                tracing::warn!(
                    target: TARGET,
                    zone = %zone,
                    ns = %name,
                    "name server has no usable address"
                );
            }
        }
        if servers.is_empty() {
            return Err(InspectorError::no_servers(
                zone,
                "no NS name of the zone has a usable address",
            ));
        }
        if servers.len() > self.config.max_servers {
            return Err(InspectorError::TooManyNameServers {
                zone: zone.clone(),
                count: servers.len(),
            });
        }
        Ok(servers)
    }

    /// Step 1: the NS names of the first resolver whose answer holds an NS rrset owned by the
    /// zone itself. Resolvers are asked one at a time.
    async fn ns_names(&self, zone: &DomainName) -> Result<Vec<TargetName>, InspectorError> {
        let ask = Ask {
            name: TargetName::from(zone).wire().to_vec(),
            rtype: RecordType::NS.code().unwrap_or(2),
            recursion: true,
        };
        let mut outcomes: Vec<String> = Vec::new();
        for resolver in &self.config.resolvers {
            // Not following CNAMEs: only NS records owned by the zone itself count.
            let answer = self
                .ask(*resolver, &ask, Mode::Resolver { follow: false })
                .await;
            if let Answer::Records { records, .. } = &answer {
                let names: Vec<TargetName> = records
                    .iter()
                    .filter_map(|data| TargetName::parse(data.as_str()).ok())
                    .collect();
                if !names.is_empty() {
                    return Ok(names);
                }
            }
            outcomes.push(format!("{resolver}: {}", answer.kind()));
        }
        Err(InspectorError::no_servers(
            zone,
            &format!(
                "no resolver returned an NS set for the zone ({})",
                outcomes.join(", ")
            ),
        ))
    }

    /// Step 3 for one NS name: its addresses per configured family, each family from the first
    /// resolver that answers (a negative answer counts as an answer).
    async fn addresses_of(
        &self,
        zone: &DomainName,
        name: &TargetName,
    ) -> Result<Vec<IpAddr>, InspectorError> {
        let families = self.config.ip_families;
        let mut types: Vec<RecordType> = Vec::with_capacity(2);
        if families.wants_v4() {
            types.push(RecordType::A);
        }
        if families.wants_v6() {
            types.push(RecordType::AAAA);
        }
        let mut out: Vec<IpAddr> = Vec::new();
        for rtype in types {
            let ask = Ask {
                name: name.wire().to_vec(),
                rtype: rtype.code().unwrap_or(1),
                recursion: true,
            };
            for resolver in &self.config.resolvers {
                match self
                    .ask(*resolver, &ask, Mode::Resolver { follow: true })
                    .await
                {
                    Answer::Records { records, .. } => {
                        if records.len() > MAX_ADDRESSES_PER_NAME {
                            return Err(InspectorError::TooManyNameServers {
                                zone: zone.clone(),
                                count: records.len(),
                            });
                        }
                        out.extend(
                            records
                                .iter()
                                .filter_map(|data| data.as_str().parse::<IpAddr>().ok()),
                        );
                        break;
                    }
                    Answer::NoData | Answer::NxDomain => break,
                    _ => continue,
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::inspector::IpFamilies;
    use crate::inspector::exchange::Failure;
    use crate::inspector::testing::{
        Behavior, Fake, addr, config_with, nodata, nxdomain, ok, rec, reply,
    };

    fn zone() -> DomainName {
        DomainName::parse("example.org").unwrap()
    }

    fn engine(config: InspectorConfig) -> Engine<Fake> {
        Engine::new(config, Fake::default()).unwrap()
    }

    use crate::inspector::InspectorConfig;

    fn ns_set(fake: &Fake, resolver: SocketAddr, names: &[&str]) {
        let records = names
            .iter()
            .map(|name| rec("example.org", RecordType::NS, 300, name))
            .collect();
        fake.reply(resolver, "example.org", RecordType::NS, ok(records));
    }

    fn a(fake: &Fake, resolver: SocketAddr, name: &str, addresses: &[&str]) {
        let records = addresses
            .iter()
            .map(|ip| rec(name, RecordType::A, 300, ip))
            .collect();
        fake.reply(resolver, name, RecordType::A, ok(records));
    }

    #[test]
    fn the_address_filter_follows_the_design() {
        let refused = |text: &str, allow: bool| refusal(text.parse().unwrap(), allow);
        for (ip, reason) in [
            ("0.0.0.0", "unspecified"),
            ("0.1.2.3", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link-local"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "broadcast or reserved"),
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("ff02::1", "multicast"),
            ("::ffff:127.0.0.1", "loopback"),
            ("::ffff:169.254.0.1", "link-local"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), Some(reason), "{ip} with private allowed");
        }
        for (ip, reason) in [
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("100.64.0.1", "shared address space"),
            ("100.127.255.255", "shared address space"),
            ("fd00::1", "unique-local"),
            ("::ffff:10.0.0.1", "private"),
        ] {
            assert_eq!(refused(ip, false), Some(reason), "{ip}");
            assert_eq!(refused(ip, true), None, "{ip} with private allowed");
        }
        for ip in ["192.0.2.1", "100.128.0.1", "8.8.8.8", "2001:db8::1"] {
            assert_eq!(refused(ip, false), None, "{ip}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_resolver_with_an_ns_set_owned_by_the_zone_wins() {
        let (r1, r2, r3) = (addr(1), addr(2), addr(3));
        let e = engine(config_with(vec![r1, r2, r3]));
        e.transport
            .on(r1, "example.org", RecordType::NS, Behavior::Hang);
        // An NS set owned by another name does not count.
        e.transport.reply(
            r2,
            "example.org",
            RecordType::NS,
            ok(vec![rec(
                "evil.example",
                RecordType::NS,
                300,
                "ns.evil.example.",
            )]),
        );
        ns_set(&e.transport, r3, &["ns1.example.net.", "ns2.example.net."]);
        for resolver in [r1, r2, r3] {
            a(&e.transport, resolver, "ns1.example.net", &["192.0.2.53"]);
            a(
                &e.transport,
                resolver,
                "ns2.example.net",
                &["198.51.100.53"],
            );
        }
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(
            servers,
            vec![
                NameServer::new(
                    Some(TargetName::parse("ns1.example.net.").unwrap()),
                    "192.0.2.53:53".parse().unwrap()
                ),
                NameServer::new(
                    Some(TargetName::parse("ns2.example.net.").unwrap()),
                    "198.51.100.53:53".parse().unwrap()
                ),
            ]
        );
        // Resolvers are asked one at a time for NS; address lookups use the first resolver
        // that answers.
        assert_eq!(e.transport.calls_of(RecordType::NS), 3);
        assert_eq!(e.transport.calls_of(RecordType::A), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn no_ns_set_from_any_resolver_is_no_name_servers() {
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(config_with(vec![r1, r2]));
        e.transport
            .reply(r1, "example.org", RecordType::NS, nxdomain());
        e.transport
            .reply(r2, "example.org", RecordType::NS, nodata());
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(
            matches!(&err, InspectorError::NoNameServers { detail, .. } if detail.contains("nxdomain") && detail.contains("nodata")),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn more_than_sixteen_ns_names_fail_before_any_address_lookup() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        let names: Vec<String> = (0..17).map(|i| format!("ns{i}.example.net.")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        ns_set(&e.transport, r1, &refs);
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(matches!(
            err,
            InspectorError::TooManyNameServers { count: 17, .. }
        ));
        assert_eq!(e.transport.calls_of(RecordType::A), 0);
        // Exactly sixteen is accepted.
        let e = engine(config_with(vec![r1]));
        ns_set(&e.transport, r1, &refs[..16]);
        for name in &refs[..16] {
            a(&e.transport, r1, name, &["192.0.2.1"]);
        }
        // All sixteen names share one address: one server.
        assert_eq!(e.name_servers(&zone()).await.unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn more_than_eight_addresses_per_name_is_too_many() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        ns_set(&e.transport, r1, &["ns.example.net."]);
        let ips: Vec<String> = (1..=9).map(|i| format!("192.0.2.{i}")).collect();
        let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
        a(&e.transport, r1, "ns.example.net", &refs);
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(matches!(
            err,
            InspectorError::TooManyNameServers { count: 9, .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn more_servers_than_max_servers_is_an_error_not_a_truncated_list() {
        let r1 = addr(1);
        let mut config = config_with(vec![r1]);
        config.max_servers = 3;
        let e = engine(config);
        ns_set(&e.transport, r1, &["a.example.net.", "b.example.net."]);
        a(
            &e.transport,
            r1,
            "a.example.net",
            &["192.0.2.1", "192.0.2.2"],
        );
        a(
            &e.transport,
            r1,
            "b.example.net",
            &["192.0.2.3", "192.0.2.4"],
        );
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert!(matches!(
            err,
            InspectorError::TooManyNameServers { count: 4, .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn refused_addresses_are_dropped_and_private_ones_need_the_option() {
        let r1 = addr(1);
        let setup = |allow: bool| {
            let mut config = config_with(vec![r1]);
            config.allow_private_addresses = allow;
            let e = engine(config);
            ns_set(&e.transport, r1, &["a.example.net.", "b.example.net."]);
            a(
                &e.transport,
                r1,
                "a.example.net",
                &["127.0.0.1", "10.0.0.1"],
            );
            a(&e.transport, r1, "b.example.net", &["169.254.0.1"]);
            e
        };
        let err = setup(false).name_servers(&zone()).await.unwrap_err();
        assert!(matches!(err, InspectorError::NoNameServers { .. }));
        let servers = setup(true).name_servers(&zone()).await.unwrap();
        let addrs: Vec<SocketAddr> = servers.iter().map(|s| s.addr).collect();
        assert_eq!(addrs, vec!["10.0.0.1:53".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test(start_paused = true)]
    async fn address_families_follow_the_configuration() {
        let r1 = addr(1);
        let mut config = config_with(vec![r1]);
        config.ip_families = IpFamilies::Both;
        let e = engine(config);
        ns_set(&e.transport, r1, &["ns.example.net."]);
        a(&e.transport, r1, "ns.example.net", &["192.0.2.1"]);
        e.transport.reply(
            r1,
            "ns.example.net",
            RecordType::AAAA,
            ok(vec![rec(
                "ns.example.net",
                RecordType::AAAA,
                60,
                "2001:db8::1",
            )]),
        );
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[1].addr, "[2001:db8::1]:53".parse().unwrap());

        let mut config = config_with(vec![r1]);
        config.ip_families = IpFamilies::V6;
        let e = engine(config);
        ns_set(&e.transport, r1, &["ns.example.net."]);
        e.transport.reply(
            r1,
            "ns.example.net",
            RecordType::AAAA,
            ok(vec![rec(
                "ns.example.net",
                RecordType::AAAA,
                60,
                "2001:db8::1",
            )]),
        );
        assert_eq!(e.name_servers(&zone()).await.unwrap().len(), 1);
        assert_eq!(e.transport.calls_of(RecordType::A), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_eight_address_lookups_run_at_once() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        let names: Vec<String> = (0..16).map(|i| format!("ns{i}.example.net.")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        ns_set(&e.transport, r1, &refs);
        for (i, name) in refs.iter().enumerate() {
            a(&e.transport, r1, name, &[&format!("192.0.2.{}", i + 1)]);
        }
        *e.transport.delay.lock().unwrap() = Duration::from_millis(500);
        let servers = e.name_servers(&zone()).await.unwrap();
        assert_eq!(servers.len(), 16);
        assert_eq!(
            e.transport.peak.load(Ordering::SeqCst),
            ADDRESS_LOOKUPS_AT_ONCE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_is_bounded_by_the_discovery_timeout() {
        let resolvers = vec![addr(1), addr(2), addr(3)];
        let e = engine(config_with(resolvers.clone()));
        let names: Vec<String> = (0..16).map(|i| format!("ns{i}.example.net.")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        ns_set(&e.transport, addr(1), &refs);
        for resolver in &resolvers {
            for name in &refs {
                e.transport
                    .on(*resolver, name, RecordType::A, Behavior::Hang);
            }
        }
        let started = Instant::now();
        let err = e.name_servers(&zone()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert!(
            matches!(&err, InspectorError::NoNameServers { detail, .. } if detail.contains("timeout")),
            "{err:?}"
        );
        // Every hanging lookup is cut at the 3 s query timeout: the first eight names take
        // 9 s over three resolvers, the second eight are at their first resolver when the
        // deadline passes.
        assert_eq!(e.transport.calls_of(RecordType::A), 8 * 3 + 8);
    }

    #[tokio::test(start_paused = true)]
    async fn results_are_cached_failures_are_not() {
        let r1 = addr(1);
        let e = engine(config_with(vec![r1]));
        e.transport.on(
            r1,
            "example.org",
            RecordType::NS,
            Behavior::Seq(vec![
                Err(Failure::Timeout),
                ok(vec![rec(
                    "example.org",
                    RecordType::NS,
                    300,
                    "ns.example.net.",
                )]),
            ]),
        );
        a(&e.transport, r1, "ns.example.net", &["192.0.2.1"]);
        assert!(e.name_servers(&zone()).await.is_err());
        assert_eq!(e.cache.len(), 0);
        assert!(e.name_servers(&zone()).await.is_ok());
        let calls = e.transport.total_calls();
        assert!(e.name_servers(&zone()).await.is_ok());
        assert_eq!(e.transport.total_calls(), calls, "served from the cache");
        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(e.name_servers(&zone()).await.is_ok());
        assert_eq!(
            e.transport.total_calls(),
            calls + 2,
            "expired after the TTL"
        );

        let mut config = config_with(vec![r1]);
        config.ns_cache_ttl = Duration::ZERO;
        let e = engine(config);
        ns_set(&e.transport, r1, &["ns.example.net."]);
        a(&e.transport, r1, "ns.example.net", &["192.0.2.1"]);
        e.name_servers(&zone()).await.unwrap();
        e.name_servers(&zone()).await.unwrap();
        assert_eq!(e.transport.total_calls(), 4);
        assert_eq!(e.cache.len(), 0);
    }

    #[test]
    fn the_cache_holds_at_most_256_zones_and_evicts_the_oldest() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cache = NsCache::default();
            let ttl = Duration::from_secs(3600);
            for i in 0..=MAX_CACHED_ZONES {
                let zone = DomainName::parse(&format!("z{i}.example")).unwrap();
                cache.put(&zone, Vec::new());
                tokio::time::advance(Duration::from_millis(1)).await;
            }
            assert_eq!(cache.len(), MAX_CACHED_ZONES);
            let first = DomainName::parse("z0.example").unwrap();
            assert!(cache.get(&first, ttl).is_none());
            let last = DomainName::parse(&format!("z{MAX_CACHED_ZONES}.example")).unwrap();
            assert!(cache.get(&last, ttl).is_some());
        });
    }

    #[tokio::test(start_paused = true)]
    async fn a_static_list_is_used_as_given() {
        let server = NameServer::new(None, "127.0.0.1:5353".parse().unwrap());
        let mut config = config_with(Vec::new());
        config.discovery = NsDiscovery::Static(vec![server.clone()]);
        let e = engine(config);
        assert_eq!(e.name_servers(&zone()).await.unwrap(), vec![server]);
        assert_eq!(e.transport.total_calls(), 0);
        let _ = reply(0, true, Vec::new());
    }
}
