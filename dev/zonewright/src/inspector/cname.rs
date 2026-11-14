//! CNAME lookup by quorum over the resolvers (design section 8.7).

use super::answer::Mode;
use super::exchange::{Ask, Transport};
use super::{Answer, Engine, Inspector};
use crate::dns01::{CnameLookup, LookupError};
use crate::name::{DomainName, TargetName};
use crate::record::RecordType;

/// Agreeing resolvers needed for a CNAME answer, or all of them when fewer are configured.
pub(crate) const CNAME_QUORUM: usize = 2;

impl CnameLookup for Inspector {
    /// Asks the resolvers in order for the CNAME of `name` until two agree (or all have
    /// answered, if fewer than two are configured). A negative answer is a vote for "no CNAME";
    /// timeouts and failures are not votes; two different votes are an error at once. A target
    /// that is not a valid owner name is an error.
    async fn cname(&self, name: &DomainName) -> Result<Option<DomainName>, LookupError> {
        self.engine.cname(name).await
    }
}

impl<T: Transport> Engine<T> {
    pub(crate) async fn cname(&self, name: &DomainName) -> Result<Option<DomainName>, LookupError> {
        let ask = Ask {
            name: TargetName::from(name).wire().to_vec(),
            rtype: RecordType::CNAME.code().unwrap_or(5),
            recursion: true,
        };
        let resolvers = &self.config.resolvers;
        let needed = resolvers.len().min(CNAME_QUORUM);
        if needed == 0 {
            return Err(LookupError::new("no resolvers are configured"));
        }
        let mut agreed: Option<Option<TargetName>> = None;
        let mut votes = 0usize;
        for resolver in resolvers {
            let answer = self
                .ask(*resolver, &ask, Mode::Resolver { follow: false })
                .await;
            let vote = match answer {
                // The classification keeps only CNAME records owned by the asked name.
                Answer::Records { records, .. } => {
                    let mut target: Option<TargetName> = None;
                    for data in &records {
                        let parsed = TargetName::parse(data.as_str()).map_err(|_| {
                            LookupError::new(format!("{resolver} returned an unreadable CNAME"))
                        })?;
                        if target.as_ref().is_some_and(|known| *known != parsed) {
                            return Err(LookupError::new(format!(
                                "{resolver} returned more than one CNAME target"
                            )));
                        }
                        target = Some(parsed);
                    }
                    target
                }
                Answer::NoData | Answer::NxDomain => None,
                _ => continue,
            };
            match &agreed {
                Some(known) if *known != vote => {
                    return Err(LookupError::new("the resolvers disagree about the CNAME"));
                }
                _ => agreed = Some(vote.clone()),
            }
            votes += 1;
            if votes >= needed {
                return match vote {
                    None => Ok(None),
                    Some(target) => target.to_domain_name().map(Some).ok_or_else(|| {
                        LookupError::new("the CNAME target is not a valid owner name")
                    }),
                };
            }
        }
        Err(LookupError::new(format!(
            "{votes} of {needed} required resolvers answered ({} configured)",
            resolvers.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::dns01::follow_cname;
    use crate::inspector::InspectorConfig;
    use crate::inspector::exchange::Failure;
    use crate::inspector::testing::{Behavior, Fake, addr, config_with, nodata, nxdomain, ok, rec};

    fn engine(resolvers: &[SocketAddr]) -> Engine<Fake> {
        Engine::new(config_with(resolvers.to_vec()), Fake::default()).unwrap()
    }

    const NAME: &str = "_acme-challenge.example.org";

    fn cname_to(target: &str) -> Result<crate::inspector::exchange::Reply, Failure> {
        ok(vec![rec(NAME, RecordType::CNAME, 60, target)])
    }

    fn name() -> DomainName {
        DomainName::parse(NAME).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn two_agreeing_resolvers_decide() {
        let (r1, r2, r3) = (addr(1), addr(2), addr(3));
        let e = engine(&[r1, r2, r3]);
        e.transport
            .reply(r1, NAME, RecordType::CNAME, cname_to("x.example.net."));
        e.transport
            .reply(r2, NAME, RecordType::CNAME, cname_to("x.example.net."));
        let target = e.cname(&name()).await.unwrap();
        assert_eq!(target, Some(DomainName::parse("x.example.net").unwrap()));
        assert_eq!(e.transport.total_calls(), 2, "the third is not asked");

        let e = engine(&[r1, r2]);
        e.transport.reply(r1, NAME, RecordType::CNAME, nxdomain());
        e.transport.reply(r2, NAME, RecordType::CNAME, nodata());
        assert_eq!(e.cname(&name()).await.unwrap(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn disagreement_is_an_error_at_once() {
        let (r1, r2, r3) = (addr(1), addr(2), addr(3));
        let e = engine(&[r1, r2, r3]);
        e.transport
            .reply(r1, NAME, RecordType::CNAME, cname_to("x.example.net."));
        e.transport.reply(r2, NAME, RecordType::CNAME, nodata());
        let err = e.cname(&name()).await.unwrap_err();
        assert!(err.detail().contains("disagree"));
        assert_eq!(e.transport.total_calls(), 2);

        let e = engine(&[r1, r2]);
        e.transport
            .reply(r1, NAME, RecordType::CNAME, cname_to("x.example.net."));
        e.transport
            .reply(r2, NAME, RecordType::CNAME, cname_to("y.example.net."));
        assert!(e.cname(&name()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn timeouts_and_failures_are_not_votes() {
        let (r1, r2, r3, r4) = (addr(1), addr(2), addr(3), addr(4));
        let e = engine(&[r1, r2, r3, r4]);
        e.transport.on(r1, NAME, RecordType::CNAME, Behavior::Hang);
        e.transport
            .reply(r2, NAME, RecordType::CNAME, cname_to("x.example.net."));
        e.transport.reply(
            r3,
            NAME,
            RecordType::CNAME,
            Ok(crate::inspector::testing::reply(2, false, Vec::new())),
        );
        e.transport
            .reply(r4, NAME, RecordType::CNAME, cname_to("x.example.net."));
        let target = e.cname(&name()).await.unwrap();
        assert_eq!(target, Some(DomainName::parse("x.example.net").unwrap()));

        let e = engine(&[r1, r2, r3]);
        e.transport.on(r1, NAME, RecordType::CNAME, Behavior::Hang);
        e.transport
            .reply(r2, NAME, RecordType::CNAME, cname_to("x.example.net."));
        e.transport
            .reply(r3, NAME, RecordType::CNAME, Err(Failure::Timeout));
        let err = e.cname(&name()).await.unwrap_err();
        assert_eq!(
            err.detail(),
            "1 of 2 required resolvers answered (3 configured)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn one_configured_resolver_is_enough_and_none_is_an_error() {
        let r1 = addr(1);
        let e = engine(&[r1]);
        e.transport
            .reply(r1, NAME, RecordType::CNAME, cname_to("x.example.net."));
        assert!(e.cname(&name()).await.unwrap().is_some());
        let mut config = InspectorConfig {
            discovery: crate::inspector::NsDiscovery::Static(vec![
                crate::inspector::NameServer::new(None, r1),
            ]),
            ..InspectorConfig::default()
        };
        config.resolvers.clear();
        let e = Engine::new(config, Fake::default()).unwrap();
        assert!(e.cname(&name()).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_cname_at_another_owner_is_no_vote_for_a_target() {
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(&[r1, r2]);
        for r in [r1, r2] {
            e.transport.reply(
                r,
                NAME,
                RecordType::CNAME,
                ok(vec![rec(
                    "other.example.org",
                    RecordType::CNAME,
                    60,
                    "evil.example.",
                )]),
            );
        }
        assert_eq!(e.cname(&name()).await.unwrap(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_target_that_cannot_be_an_owner_name_is_an_error() {
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(&[r1, r2]);
        for r in [r1, r2] {
            e.transport.reply(
                r,
                NAME,
                RecordType::CNAME,
                cname_to("bad\\032label.example."),
            );
        }
        let err = e.cname(&name()).await.unwrap_err();
        assert!(err.detail().contains("not a valid owner name"));
    }

    #[tokio::test(start_paused = true)]
    async fn follow_cname_over_the_quorum_lookup_detects_a_loop() {
        let (r1, r2) = (addr(1), addr(2));
        let e = engine(&[r1, r2]);
        for r in [r1, r2] {
            e.transport
                .reply(r, NAME, RecordType::CNAME, cname_to("a.example.net."));
            e.transport.reply(
                r,
                "a.example.net",
                RecordType::CNAME,
                ok(vec![rec("a.example.net", RecordType::CNAME, 60, NAME)]),
            );
        }
        struct ByEngine<'a>(&'a Engine<Fake>);
        impl CnameLookup for ByEngine<'_> {
            async fn cname(&self, name: &DomainName) -> Result<Option<DomainName>, LookupError> {
                self.0.cname(name).await
            }
        }
        let err = follow_cname(&ByEngine(&e), &name(), 8).await.unwrap_err();
        assert!(matches!(err, crate::dns01::CnameError::Loop { .. }));
    }
}
