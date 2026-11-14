//! A table-driven [`Transport`] for the unit tests of discovery, classification, quorum and the
//! wait loop. It runs on tokio's clock, so tests with a paused clock are instant and exact.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::InspectorConfig;
use super::exchange::{Ask, Failure, Reply, ReplyRecord, Transport};
use crate::name::TargetName;
use crate::record::{RecordData, RecordType};

/// What the fake does for one (server, name, type).
#[derive(Clone, Debug)]
pub(crate) enum Behavior {
    /// These outcomes in turn; the last one repeats.
    Seq(Vec<Result<Reply, Failure>>),
    /// Never answers.
    Hang,
}

/// A scripted question: the server asked, the name on the wire and the type code.
type Key = (SocketAddr, Vec<u8>, u16);

#[derive(Default)]
pub(crate) struct Fake {
    table: Mutex<HashMap<Key, (Behavior, usize)>>,
    pub(crate) calls: Mutex<Vec<(SocketAddr, Ask)>>,
    in_flight: AtomicUsize,
    pub(crate) peak: AtomicUsize,
    pub(crate) delay: Mutex<Duration>,
}

impl Fake {
    pub(crate) fn on(&self, server: SocketAddr, name: &str, rtype: RecordType, behavior: Behavior) {
        let key = (server, wire(name), rtype.code().unwrap());
        self.table.lock().unwrap().insert(key, (behavior, 0));
    }

    pub(crate) fn reply(
        &self,
        server: SocketAddr,
        name: &str,
        rtype: RecordType,
        outcome: Result<Reply, Failure>,
    ) {
        self.on(server, name, rtype, Behavior::Seq(vec![outcome]));
    }

    pub(crate) fn calls_of(&self, rtype: RecordType) -> usize {
        let code = rtype.code().unwrap();
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, ask)| ask.rtype == code)
            .count()
    }

    pub(crate) fn total_calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

struct Flight<'a>(&'a AtomicUsize);

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Transport for Fake {
    async fn exchange(&self, server: SocketAddr, ask: &Ask) -> Result<Reply, Failure> {
        self.calls.lock().unwrap().push((server, ask.clone()));
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        let _flight = Flight(&self.in_flight);
        let delay = *self.delay.lock().unwrap();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let behavior = {
            let mut table = self.table.lock().unwrap();
            match table.get_mut(&(server, ask.name.clone(), ask.rtype)) {
                None => Some(Err(Failure::Network("no entry in the fake".to_owned()))),
                Some((Behavior::Hang, _)) => None,
                Some((Behavior::Seq(outcomes), used)) => {
                    let index = (*used).min(outcomes.len() - 1);
                    *used += 1;
                    Some(outcomes[index].clone())
                }
            }
        };
        match behavior {
            Some(outcome) => outcome,
            None => std::future::pending().await,
        }
    }
}

pub(crate) fn addr(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 53))
}

pub(crate) fn wire(name: &str) -> Vec<u8> {
    TargetName::parse(name).unwrap().wire().to_vec()
}

pub(crate) fn data(rtype: RecordType, text: &str) -> RecordData {
    RecordData::parse(rtype, text).unwrap()
}

pub(crate) fn rec(owner: &str, rtype: RecordType, ttl: u32, text: &str) -> ReplyRecord {
    ReplyRecord {
        owner: wire(owner),
        rtype: rtype.code().unwrap(),
        ttl,
        data: Ok(data(rtype, text)),
    }
}

pub(crate) fn reply(rcode: u16, authoritative: bool, records: Vec<ReplyRecord>) -> Reply {
    Reply {
        rcode,
        authoritative,
        records,
    }
}

pub(crate) fn ok(records: Vec<ReplyRecord>) -> Result<Reply, Failure> {
    Ok(reply(0, true, records))
}

pub(crate) fn nodata() -> Result<Reply, Failure> {
    Ok(reply(0, true, Vec::new()))
}

pub(crate) fn nxdomain() -> Result<Reply, Failure> {
    Ok(reply(3, true, Vec::new()))
}

pub(crate) fn config_with(resolvers: Vec<SocketAddr>) -> InspectorConfig {
    InspectorConfig {
        resolvers,
        ..InspectorConfig::default()
    }
}
