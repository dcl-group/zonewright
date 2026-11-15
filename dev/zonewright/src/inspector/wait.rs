//! Expectations, one-round observation and the wait loop (design section 8.6).

use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use tokio::time::Instant;

use super::answer::Mode;
use super::exchange::{Ask, Transport};
use super::{
    Answer, Condition, Engine, Expectation, InspectorConfig, InspectorError, NameServer, Question,
    ask_for,
};
use crate::name::DomainName;

/// Most questions of one round in flight at the same time; each holds one socket.
pub(crate) const QUESTIONS_AT_ONCE: usize = InspectorConfig::QUESTIONS_IN_FLIGHT;
/// Largest accepted jitter.
const MAX_JITTER_PERCENT: u8 = 50;

/// How long and how often [`Inspector::wait`](super::Inspector::wait) polls.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WaitOptions {
    /// Total time to wait, counted from the start of the first round. At least one round always
    /// runs.
    pub timeout: Duration,
    /// Pause between rounds. Default 5 s; at least [`WaitOptions::MIN_INTERVAL`].
    pub interval: Duration,
    /// The pause varies by up to this percentage either way. Default 20; at most 50.
    pub jitter_percent: u8,
    /// Leave the name servers that cannot be asked out of the condition "every server agrees".
    /// Default false.
    ///
    /// A server that cannot be asked is one discovery reported with
    /// [`NameServer::not_asked`] set — the NS name has no address in the configured address
    /// families ([`NotAsked::NoAddress`](super::NotAsked::NoAddress)) or the address policy
    /// refuses its address ([`NotAsked::AddressRefused`](super::NotAsked::AddressRefused)) —
    /// that is, a server known before any query to be impossible to ask. With this option on,
    /// the wait is satisfied once every server that is asked satisfies every expectation in the
    /// same round; the servers that cannot be asked are not waited for.
    ///
    /// Nothing else is ignored. A server that is asked and times out, refuses, fails, is not
    /// authoritative or answers anything that does not satisfy an expectation still keeps the
    /// wait from being satisfied. The servers that cannot be asked stay in the [`Report`] as
    /// rows with their reason and `satisfied` false, exactly as with the option off, and
    /// [`Report::unaskable_ignored`] counts them.
    ///
    /// The option never makes a wait succeed without a server that was asked: when every name
    /// server of the zone cannot be asked, the wait runs to its timeout and ends in
    /// [`InspectorError::Timeout`], as it does with the option off.
    ///
    /// It has no effect on a static name-server list, every entry of which is asked.
    pub ignore_unaskable_name_servers: bool,
}

impl WaitOptions {
    /// The shortest accepted `interval`, 1 s. A round can ask up to
    /// [`InspectorConfig::max_questions_per_round`] questions (default 1024) of servers the
    /// application does not run; a shorter interval is
    /// [`InspectorError::InvalidInput`]. With the largest jitter the shortest pause is 500 ms.
    pub const MIN_INTERVAL: Duration = Duration::from_secs(1);

    /// Options with this timeout, a 5 s interval, 20 % jitter, and every name server waited
    /// for (`ignore_unaskable_name_servers` false).
    #[must_use]
    pub fn new(timeout: Duration) -> WaitOptions {
        WaitOptions {
            timeout,
            interval: Duration::from_secs(5),
            jitter_percent: 20,
            ignore_unaskable_name_servers: false,
        }
    }
}

/// What one server answered in the last round of a wait.
///
/// A server that is not asked ([`NameServer::not_asked`]) has a row too: `satisfied` is false,
/// every answer is [`Answer::NotAsked`] with the reason, and `first_satisfied_after` is `None`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServerReport {
    /// The server.
    pub server: NameServer,
    /// All expectations held at this server in the last round. Always false for a server that
    /// is not asked.
    pub satisfied: bool,
    /// The last round's answers, one per expectation, in the order given.
    pub answers: Vec<Answer>,
    /// When this server first satisfied all expectations, from the start of the wait.
    pub first_satisfied_after: Option<Duration>,
}

/// The outcome of a wait: the state of every server in the last round.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Report {
    /// One entry per name server, in the order discovery returned them, those that are not
    /// asked included.
    pub servers: Vec<ServerReport>,
    /// Rounds run.
    pub rounds: u32,
    /// Time from the start of the first round to the end of the last.
    pub elapsed: Duration,
    /// How many servers that cannot be asked were left out of the condition because
    /// [`WaitOptions::ignore_unaskable_name_servers`] was on: the number of rows with
    /// [`NameServer::not_asked`] set. Always zero with the option off. A report of a satisfied
    /// wait with a non-zero count means the expectations were met at every server that was
    /// asked, and these servers were not checked.
    pub unaskable_ignored: usize,
}

/// True when `answer` satisfies `condition` (the table of design section 8.6). Only an answer
/// that says something about the rrset can satisfy anything: an unreachable, refusing, failing
/// or non-authoritative server never counts as "absent".
pub(crate) fn holds(condition: &Condition, answer: &Answer) -> bool {
    match (condition, answer) {
        (Condition::Present(values), Answer::Records { records, .. }) => {
            values.iter().all(|value| records.contains(value))
        }
        (Condition::Exact(values), Answer::Records { records, .. }) => {
            !values.is_empty()
                && values.iter().all(|value| records.contains(value))
                && records.iter().all(|record| values.contains(record))
        }
        (Condition::Exact(values), Answer::NoData | Answer::NxDomain) => values.is_empty(),
        (Condition::Absent(values), Answer::Records { records, .. }) => {
            !values.iter().any(|value| records.contains(value))
        }
        (Condition::Absent(_), Answer::NoData | Answer::NxDomain) => true,
        _ => false,
    }
}

/// Checks the questions of a call: 1 to `max_questions`, every name within the zone, every
/// type askable.
fn validate_questions<'a>(
    zone: &DomainName,
    questions: impl ExactSizeIterator<Item = &'a Question>,
    max_questions: usize,
) -> Result<Vec<Ask>, InspectorError> {
    let count = questions.len();
    if count == 0 {
        return Err(InspectorError::invalid("at least one question is needed"));
    }
    if count > max_questions {
        return Err(InspectorError::invalid(&format!(
            "{count} questions, more than the configured max_questions of {max_questions}"
        )));
    }
    let mut asks = Vec::with_capacity(count);
    for question in questions {
        if !question.name.is_within(zone) {
            return Err(InspectorError::invalid(&format!(
                "{} is not within the zone {zone}",
                question.name
            )));
        }
        asks.push(ask_for(question, false).map_err(|detail| InspectorError::invalid(&detail))?);
    }
    Ok(asks)
}

/// Checks the expected values: canonical, valid for the question's type, and at least one for
/// `Present` and `Absent`.
fn validate_values(expectation: &Expectation) -> Result<(), InspectorError> {
    let (values, needs_one) = match &expectation.condition {
        Condition::Present(values) => (values, true),
        Condition::Exact(values) => (values, false),
        Condition::Absent(values) => (values, true),
    };
    if needs_one && values.is_empty() {
        return Err(InspectorError::invalid(
            "Present and Absent need at least one value",
        ));
    }
    let rtype = expectation.question.rtype;
    for value in values {
        if !value.is_canonical() {
            return Err(InspectorError::invalid(
                "an expected value is not canonical",
            ));
        }
        // A value that has no wire form for the type can never be seen at a server.
        if value.to_wire(rtype).is_err() {
            return Err(InspectorError::invalid(&format!(
                "an expected value is not valid for type {rtype}"
            )));
        }
    }
    Ok(())
}

/// Distinct questions and, per input position, the index of its question among them.
fn dedup(asks: Vec<Ask>) -> (Vec<Ask>, Vec<usize>) {
    let mut unique: Vec<Ask> = Vec::with_capacity(asks.len());
    let mut index = Vec::with_capacity(asks.len());
    for ask in asks {
        match unique.iter().position(|known| *known == ask) {
            Some(position) => index.push(position),
            None => {
                index.push(unique.len());
                unique.push(ask);
            }
        }
    }
    (unique, index)
}

/// The pause before the next round: `interval` varied uniformly by `jitter_percent` either
/// way, cut to `remaining` when it would pass the deadline. `None` when `remaining` is shorter
/// than the shortest pause the jitter allows: a cut pause would then fall below that floor
/// (and below [`WaitOptions::MIN_INTERVAL`] less the jitter), so no further round runs.
pub(crate) fn pause(
    interval: Duration,
    jitter_percent: u8,
    remaining: Duration,
) -> Option<Duration> {
    let interval_ns = u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX);
    let percent = u64::from(jitter_percent.min(MAX_JITTER_PERCENT));
    let span = (interval_ns / 100).saturating_mul(percent);
    let low = interval_ns.saturating_sub(span);
    if remaining < Duration::from_nanos(low) {
        return None;
    }
    let offset = fastrand::u64(0..=span.saturating_mul(2));
    Some(Duration::from_nanos(low.saturating_add(offset)).min(remaining))
}

impl<T: Transport> Engine<T> {
    /// Every question at every server that is asked, at most [`QUESTIONS_AT_ONCE`] in flight.
    /// The answers of a server are in the order of `asks`; a server that is not asked gets
    /// [`Answer::NotAsked`] for each, without a query.
    ///
    /// The servers are those of [`Engine::name_servers`]: the static list when there is one,
    /// whose answers are read without AA when the configuration says so, and discovered
    /// servers otherwise, which always need AA.
    async fn round(&self, servers: &[NameServer], asks: &[Ask]) -> Vec<Vec<Answer>> {
        let mode = Mode::Server {
            require_aa: !self.config.reads_without_aa(),
        };
        // Built with loops rather than closures: a closure here makes the future's `Send`
        // bound fail to be proven for every lifetime. The size is bounded by
        // `check_round_size` before a round runs.
        let mut pending = Vec::with_capacity(servers.len().saturating_mul(asks.len()));
        for server in servers {
            if let Some(addr) = server.query_addr() {
                for ask in asks {
                    pending.push(self.ask(addr, ask, mode));
                }
            }
        }
        let flat: Vec<Answer> = stream::iter(pending)
            .buffered(QUESTIONS_AT_ONCE)
            .collect()
            .await;
        let mut flat = flat.into_iter();
        let mut out = Vec::with_capacity(servers.len());
        for server in servers {
            match server.reason() {
                None => out.push(flat.by_ref().take(asks.len()).collect()),
                Some(reason) => out.push(vec![Answer::NotAsked(reason); asks.len()]),
            }
        }
        out
    }

    /// Fails when a round would hold more than `max_questions_per_round` questions. Only
    /// servers that are asked count.
    fn check_round_size(
        &self,
        servers: &[NameServer],
        questions: usize,
    ) -> Result<(), InspectorError> {
        let limit = self.config.max_questions_per_round;
        let asked = servers
            .iter()
            .filter(|server| server.query_addr().is_some())
            .count();
        let total = asked.saturating_mul(questions);
        if total > limit {
            return Err(InspectorError::invalid(&format!(
                "{asked} servers times {questions} questions is {total}, more than the \
                 configured max_questions_per_round of {limit}"
            )));
        }
        Ok(())
    }

    pub(crate) async fn observe(
        &self,
        zone: &DomainName,
        questions: &[Question],
    ) -> Result<Vec<(NameServer, Vec<Answer>)>, InspectorError> {
        let asks = validate_questions(zone, questions.iter(), self.config.max_questions)?;
        let servers = self.name_servers(zone).await?;
        self.check_round_size(&servers, asks.len())?;
        let answers = self.round(&servers, &asks).await;
        Ok(servers.into_iter().zip(answers).collect())
    }

    pub(crate) async fn wait(
        &self,
        zone: &DomainName,
        expectations: &[Expectation],
        options: &WaitOptions,
    ) -> Result<super::Report, InspectorError> {
        if options.jitter_percent > MAX_JITTER_PERCENT {
            return Err(InspectorError::invalid("jitter_percent is more than 50"));
        }
        if options.interval < WaitOptions::MIN_INTERVAL {
            return Err(InspectorError::invalid("interval is shorter than 1 s"));
        }
        let asks = validate_questions(
            zone,
            expectations.iter().map(|e| &e.question),
            self.config.max_questions,
        )?;
        for expectation in expectations {
            validate_values(expectation)?;
        }
        let (asks, index) = dedup(asks);
        let servers = self.name_servers(zone).await?;
        self.check_round_size(&servers, asks.len())?;

        // Servers that cannot be asked, left out of the condition when the option is on. The
        // list is fixed for the whole wait, so the count is too.
        let ignore = options.ignore_unaskable_name_servers;
        let unaskable_ignored = if ignore {
            servers
                .iter()
                .filter(|server| server.reason().is_some())
                .count()
        } else {
            0
        };
        // With every server left out nothing was asked: never satisfied, never vacuously.
        let any_counted = !ignore || unaskable_ignored < servers.len();

        let start = Instant::now();
        let mut first: Vec<Option<Duration>> = vec![None; servers.len()];
        let mut rounds: u32 = 0;
        loop {
            rounds = rounds.saturating_add(1);
            let answers = self.round(&servers, &asks).await;
            let elapsed = start.elapsed();
            let mut reports = Vec::with_capacity(servers.len());
            for ((server, server_answers), first) in
                servers.iter().zip(answers).zip(first.iter_mut())
            {
                let answers: Vec<Answer> = index
                    .iter()
                    .map(|&at| server_answers.get(at).cloned().unwrap_or(Answer::Timeout))
                    .collect();
                let satisfied = expectations
                    .iter()
                    .zip(&answers)
                    .all(|(expectation, answer)| holds(&expectation.condition, answer));
                if satisfied && first.is_none() {
                    *first = Some(elapsed);
                }
                reports.push(ServerReport {
                    server: server.clone(),
                    satisfied,
                    answers,
                    first_satisfied_after: *first,
                });
            }
            let done = any_counted
                && reports
                    .iter()
                    .all(|report| report.satisfied || (ignore && report.server.reason().is_some()));
            let report = Report {
                servers: reports,
                rounds,
                elapsed,
                unaskable_ignored,
            };
            if done {
                if unaskable_ignored > 0 {
                    tracing::warn!(
                        target: super::TARGET,
                        zone = %zone,
                        unaskable_ignored,
                        rounds,
                        elapsed_ms = super::duration_ms(elapsed),
                        "expectations met with name servers that cannot be asked left out"
                    );
                }
                return Ok(report);
            }
            if elapsed >= options.timeout {
                return Err(InspectorError::Timeout { report });
            }
            let remaining = options.timeout.saturating_sub(elapsed);
            match pause(options.interval, options.jitter_percent, remaining) {
                Some(pause) => tokio::time::sleep(pause).await,
                None => return Err(InspectorError::Timeout { report }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::inspector::exchange::Failure;
    use crate::inspector::testing::{Behavior, Fake, addr, data, nodata, nxdomain, ok, rec};
    use crate::inspector::{InspectorConfig, NsDiscovery};
    use crate::record::{RecordData, RecordType, Ttl};

    fn zone() -> DomainName {
        DomainName::parse("example.org").unwrap()
    }

    fn name() -> &'static str {
        "_acme-challenge.example.org"
    }

    fn txt(value: &str) -> RecordData {
        data(RecordType::TXT, &format!("\"{value}\""))
    }

    fn question() -> Question {
        Question::new(DomainName::parse(name()).unwrap(), RecordType::TXT)
    }

    fn engine(servers: &[SocketAddr]) -> Engine<Fake> {
        let config = InspectorConfig {
            discovery: NsDiscovery::Static(
                servers.iter().map(|a| NameServer::new(None, *a)).collect(),
            ),
            max_servers: servers.len().max(32),
            ..InspectorConfig::default()
        };
        Engine::new(config, Fake::default()).unwrap()
    }

    fn records(values: &[&str]) -> Answer {
        Answer::Records {
            ttl: Ttl::from_secs(60).unwrap(),
            records: values.iter().map(|v| txt(v)).collect(),
        }
    }

    fn txt_reply(values: &[&str]) -> Result<crate::inspector::exchange::Reply, Failure> {
        ok(values
            .iter()
            .map(|v| rec(name(), RecordType::TXT, 60, &format!("\"{v}\"")))
            .collect())
    }

    #[test]
    fn the_condition_table_of_the_design() {
        let present = Condition::Present(vec![txt("a")]);
        let exact = Condition::Exact(vec![txt("a"), txt("b")]);
        let gone = Condition::Exact(Vec::new());
        let absent = Condition::Absent(vec![txt("a")]);
        assert!(holds(&present, &records(&["a", "x"])));
        assert!(!holds(&present, &records(&["x"])));
        assert!(holds(&exact, &records(&["b", "a"])));
        assert!(!holds(&exact, &records(&["a"])));
        assert!(!holds(&exact, &records(&["a", "b", "c"])));
        assert!(holds(&gone, &Answer::NoData));
        assert!(holds(&gone, &Answer::NxDomain));
        assert!(!holds(&gone, &records(&["a"])));
        assert!(holds(&absent, &Answer::NoData));
        assert!(holds(&absent, &Answer::NxDomain));
        assert!(holds(&absent, &records(&["x"])));
        assert!(!holds(&absent, &records(&["a"])));
        let nothing = [
            Answer::Cname(crate::name::TargetName::root()),
            Answer::Refused,
            Answer::ServFail,
            Answer::NotAuthoritative,
            Answer::Timeout,
            Answer::Failed("x".into()),
        ];
        for answer in &nothing {
            for condition in [&present, &exact, &gone, &absent] {
                assert!(!holds(condition, answer), "{condition:?} {answer:?}");
            }
        }
        assert!(!holds(&present, &Answer::NoData));
        assert!(!holds(&exact, &Answer::NxDomain));
    }

    #[test]
    fn the_pause_varies_within_the_jitter_and_never_passes_the_deadline() {
        let interval = Duration::from_secs(10);
        for _ in 0..200 {
            let p = pause(interval, 20, Duration::MAX).unwrap();
            assert!(
                p >= Duration::from_secs(8) && p <= Duration::from_secs(12),
                "{p:?}"
            );
        }
        assert_eq!(pause(interval, 0, Duration::MAX), Some(interval));
        // Cut to the deadline while the cut pause stays within the jitter range.
        for _ in 0..200 {
            let p = pause(interval, 20, Duration::from_secs(9)).unwrap();
            assert!(
                p >= Duration::from_secs(8) && p <= Duration::from_secs(9),
                "{p:?}"
            );
        }
        assert_eq!(
            pause(interval, 20, Duration::from_secs(8)),
            Some(Duration::from_secs(8))
        );
        // Jitter is capped at 50 and huge intervals do not overflow.
        for _ in 0..200 {
            let p = pause(interval, 200, Duration::MAX).unwrap();
            assert!(
                p >= Duration::from_secs(5) && p <= Duration::from_secs(15),
                "{p:?}"
            );
        }
        let _ = pause(Duration::MAX, 50, Duration::MAX);
    }

    #[test]
    fn a_pause_is_never_cut_below_the_floor() {
        // Less left than the shortest pause the jitter allows: no further round.
        let interval = Duration::from_secs(10);
        assert_eq!(pause(interval, 20, Duration::from_secs(1)), None);
        assert_eq!(pause(interval, 20, Duration::from_millis(7_999)), None);
        assert_eq!(pause(interval, 0, Duration::from_millis(9_999)), None);
        // The shortest interval with the largest jitter: 500 ms is the floor.
        let min = WaitOptions::MIN_INTERVAL;
        assert_eq!(pause(min, 50, Duration::from_millis(499)), None);
        assert_eq!(
            pause(min, 50, Duration::from_millis(500)),
            Some(Duration::from_millis(500))
        );
        assert_eq!(pause(min, 0, Duration::from_millis(999)), None);
        assert_eq!(pause(min, 0, Duration::ZERO), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_last_round_never_follows_the_previous_one_sooner_than_the_floor() {
        let s1 = addr(1);
        let e = engine(&[s1]);
        e.transport.reply(s1, name(), RecordType::TXT, nodata());
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        // Rounds at 0, 5 and 10 s; at 10 s only 1 s is left, less than the 5 s pause: the
        // wait ends there instead of asking again after 1 s.
        let mut options = WaitOptions::new(Duration::from_secs(11));
        options.jitter_percent = 0;
        let started = Instant::now();
        let err = e.wait(&zone(), &expectations, &options).await.unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        assert_eq!(report.rounds, 3);
        assert_eq!(report.elapsed, Duration::from_secs(10));
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert_eq!(e.transport.total_calls(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_five_minute_wait_times_out_with_the_last_report() {
        let (s1, s2) = (addr(1), addr(2));
        let e = engine(&[s1, s2]);
        e.transport
            .reply(s1, name(), RecordType::TXT, txt_reply(&["v"]));
        e.transport.reply(s2, name(), RecordType::TXT, nodata());
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        let options = WaitOptions::new(Duration::from_secs(300));
        let started = Instant::now();
        let err = e.wait(&zone(), &expectations, &options).await.unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        // The last round starts no later than the timeout: exactly at it after a cut pause, or
        // less than one shortest pause (4 s) before it when no pause fits.
        let elapsed = started.elapsed();
        assert!(
            elapsed > Duration::from_secs(296) && elapsed <= Duration::from_secs(300),
            "{elapsed:?}"
        );
        assert_eq!(report.elapsed, elapsed);
        assert!((51..=76).contains(&report.rounds), "{}", report.rounds);
        let [a, b] = report.servers.as_slice() else {
            panic!("two servers");
        };
        assert!(a.satisfied);
        assert_eq!(a.first_satisfied_after, Some(Duration::ZERO));
        assert_eq!(a.answers, vec![records(&["v"])]);
        assert!(!b.satisfied);
        assert_eq!(b.first_satisfied_after, None);
        assert_eq!(b.answers, vec![Answer::NoData]);
        // Every round asked every server, the satisfied one included.
        let rounds = usize::try_from(report.rounds).unwrap();
        assert_eq!(e.transport.total_calls(), 2 * rounds);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lagging_server_is_waited_for_and_its_first_success_is_reported() {
        let (s1, s2) = (addr(1), addr(2));
        let e = engine(&[s1, s2]);
        e.transport
            .reply(s1, name(), RecordType::TXT, txt_reply(&["v"]));
        e.transport.on(
            s2,
            name(),
            RecordType::TXT,
            Behavior::Seq(vec![nodata(), nodata(), txt_reply(&["v", "other"])]),
        );
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        let mut options = WaitOptions::new(Duration::from_secs(60));
        options.jitter_percent = 0;
        let report = e.wait(&zone(), &expectations, &options).await.unwrap();
        assert_eq!(report.rounds, 3);
        assert_eq!(report.elapsed, Duration::from_secs(10));
        assert_eq!(
            report.servers[0].first_satisfied_after,
            Some(Duration::ZERO)
        );
        assert_eq!(
            report.servers[1].first_satisfied_after,
            Some(Duration::from_secs(10))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_loses_the_value_is_seen() {
        let (s1, s2) = (addr(1), addr(2));
        let e = engine(&[s1, s2]);
        e.transport.on(
            s1,
            name(),
            RecordType::TXT,
            Behavior::Seq(vec![txt_reply(&["v"]), nodata(), txt_reply(&["v"])]),
        );
        e.transport.on(
            s2,
            name(),
            RecordType::TXT,
            Behavior::Seq(vec![nodata(), txt_reply(&["v"])]),
        );
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        let mut options = WaitOptions::new(Duration::from_secs(60));
        options.jitter_percent = 0;
        let report = e.wait(&zone(), &expectations, &options).await.unwrap();
        // Round 1: s1 only; round 2: s2 only; round 3: both.
        assert_eq!(report.rounds, 3);
        assert_eq!(
            report.servers[0].first_satisfied_after,
            Some(Duration::ZERO)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unreachable_refusing_and_lame_servers_satisfy_nothing_not_even_absence() {
        let servers = [addr(1), addr(2), addr(3), addr(4)];
        let e = engine(&servers);
        e.transport
            .reply(servers[0], name(), RecordType::TXT, nxdomain());
        e.transport
            .on(servers[1], name(), RecordType::TXT, Behavior::Hang);
        e.transport.reply(
            servers[2],
            name(),
            RecordType::TXT,
            Ok(crate::inspector::testing::reply(0, false, Vec::new())),
        );
        e.transport.reply(
            servers[3],
            name(),
            RecordType::TXT,
            Ok(crate::inspector::testing::reply(5, true, Vec::new())),
        );
        let expectations = [Expectation::new(
            question(),
            Condition::Absent(vec![txt("v")]),
        )];
        let options = WaitOptions::new(Duration::ZERO);
        let err = e.wait(&zone(), &expectations, &options).await.unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        assert_eq!(report.rounds, 1, "a zero timeout still runs one round");
        let answers: Vec<&Answer> = report.servers.iter().map(|s| &s.answers[0]).collect();
        assert_eq!(
            answers,
            vec![
                &Answer::NxDomain,
                &Answer::Timeout,
                &Answer::NotAuthoritative,
                &Answer::Refused
            ]
        );
        let satisfied: Vec<bool> = report.servers.iter().map(|s| s.satisfied).collect();
        assert_eq!(satisfied, vec![true, false, false, false]);
        // The round took one query timeout.
        assert_eq!(report.elapsed, Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn identical_questions_are_asked_once_per_server_and_round() {
        let s1 = addr(1);
        let e = engine(&[s1]);
        e.transport
            .reply(s1, name(), RecordType::TXT, txt_reply(&["a", "b"]));
        let expectations = [
            Expectation::new(question(), Condition::Present(vec![txt("a")])),
            Expectation::new(question(), Condition::Exact(vec![txt("b"), txt("a")])),
            Expectation::new(question(), Condition::Absent(vec![txt("c")])),
        ];
        let report = e
            .wait(&zone(), &expectations, &WaitOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!(report.servers[0].answers.len(), 3);
        assert_eq!(e.transport.total_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn requests_are_validated_before_any_query() {
        let s1 = addr(1);
        let e = engine(&[s1]);
        let options = WaitOptions::new(Duration::ZERO);
        let present =
            |values: Vec<RecordData>| Expectation::new(question(), Condition::Present(values));
        let invalid = |result: Result<Report, InspectorError>| {
            matches!(result, Err(InspectorError::InvalidInput { .. }))
        };
        assert!(invalid(e.wait(&zone(), &[], &options).await));
        let many: Vec<Expectation> = (0..33).map(|_| present(vec![txt("a")])).collect();
        assert!(invalid(e.wait(&zone(), &many, &options).await));
        let outside = Expectation::new(
            Question::new(DomainName::parse("example.net").unwrap(), RecordType::TXT),
            Condition::Absent(vec![txt("a")]),
        );
        assert!(invalid(e.wait(&zone(), &[outside], &options).await));
        assert!(invalid(
            e.wait(&zone(), &[present(Vec::new())], &options).await
        ));
        let raw = RecordData::non_canonical("not canonical");
        assert!(invalid(
            e.wait(&zone(), &[present(vec![raw])], &options).await
        ));
        let wrong_type = Expectation::new(
            Question::new(DomainName::parse(name()).unwrap(), RecordType::A),
            Condition::Present(vec![txt("a")]),
        );
        assert!(invalid(e.wait(&zone(), &[wrong_type], &options).await));
        let pseudo = Expectation::new(
            Question::new(zone(), RecordType::ALIAS),
            Condition::Exact(Vec::new()),
        );
        assert!(invalid(e.wait(&zone(), &[pseudo], &options).await));
        let any = Expectation::new(
            Question::new(zone(), RecordType::from_code(255)),
            Condition::Exact(Vec::new()),
        );
        assert!(invalid(e.wait(&zone(), &[any], &options).await));
        let mut jittery = options.clone();
        jittery.jitter_percent = 51;
        assert!(invalid(
            e.wait(&zone(), &[present(vec![txt("a")])], &jittery).await
        ));
        assert!(matches!(
            e.observe(&zone(), &[]).await,
            Err(InspectorError::InvalidInput { .. })
        ));
        assert_eq!(e.transport.total_calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_holds_at_most_1024_questions() {
        let servers: Vec<SocketAddr> = (1..=33).map(addr).collect();
        let e = engine(&servers);
        let questions: Vec<Question> = (0..32)
            .map(|i| {
                Question::new(
                    DomainName::parse(&format!("n{i}.example.org")).unwrap(),
                    RecordType::A,
                )
            })
            .collect();
        let err = e.observe(&zone(), &questions).await.unwrap_err();
        assert!(matches!(err, InspectorError::InvalidInput { .. }));
        assert_eq!(e.transport.total_calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_runs_at_most_128_questions_at_once_and_keeps_the_order() {
        let servers: Vec<SocketAddr> = (1..=32).map(addr).collect();
        let e = engine(&servers);
        *e.transport.delay.lock().unwrap() = Duration::from_secs(1);
        let questions: Vec<Question> = (0..32)
            .map(|i| {
                Question::new(
                    DomainName::parse(&format!("n{i}.example.org")).unwrap(),
                    RecordType::A,
                )
            })
            .collect();
        // Each server answers each question with a value that names both.
        for (s, server) in servers.iter().enumerate() {
            for i in 0..32u8 {
                let owner = format!("n{i}.example.org");
                e.transport.reply(
                    *server,
                    &owner,
                    RecordType::A,
                    ok(vec![rec(
                        &owner,
                        RecordType::A,
                        60,
                        &format!("198.51.{}.{i}", s + 1),
                    )]),
                );
            }
        }
        let started = Instant::now();
        let observed = e.observe(&zone(), &questions).await.unwrap();
        // 1024 questions, 128 at a time, one second each.
        assert_eq!(started.elapsed(), Duration::from_secs(8));
        assert_eq!(
            e.transport.peak.load(std::sync::atomic::Ordering::SeqCst),
            QUESTIONS_AT_ONCE
        );
        assert_eq!(observed.len(), 32);
        for (s, (server, answers)) in observed.iter().enumerate() {
            assert_eq!(server.addr, Some(servers[s]));
            assert_eq!(answers.len(), 32);
            for (i, answer) in answers.iter().enumerate() {
                let expected = data(RecordType::A, &format!("198.51.{}.{i}", s + 1));
                assert!(
                    matches!(answer, Answer::Records { records, .. } if records == &vec![expected]),
                    "{s} {i} {answer:?}"
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_interval_below_one_second_is_refused_and_one_second_is_the_pace() {
        let s1 = addr(1);
        let e = engine(&[s1]);
        e.transport.reply(s1, name(), RecordType::TXT, nodata());
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        // A latency, so that a wait that wrongly accepted a zero interval would still advance
        // the paused clock and end in a timeout instead of spinning.
        *e.transport.delay.lock().unwrap() = Duration::from_millis(100);
        for short in [Duration::ZERO, Duration::from_millis(999)] {
            let mut options = WaitOptions::new(Duration::from_secs(10));
            options.interval = short;
            assert!(
                matches!(
                    e.wait(&zone(), &expectations, &options).await,
                    Err(InspectorError::InvalidInput { detail }) if detail.contains("interval")
                ),
                "{short:?}"
            );
        }
        assert_eq!(e.transport.total_calls(), 0);
        *e.transport.delay.lock().unwrap() = Duration::ZERO;
        let mut options = WaitOptions::new(Duration::from_secs(10));
        options.interval = WaitOptions::MIN_INTERVAL;
        options.jitter_percent = 0;
        let err = e.wait(&zone(), &expectations, &options).await.unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        // Rounds at 0, 1, ..., 10 s.
        assert_eq!(report.rounds, 11);
    }

    /// An engine with recursive discovery through the fake resolver `addr(1)`: the zone has
    /// `ns1` at 192.0.2.53 (asked), `ns2` at 127.0.0.1 (refused) and `ns3` without an IPv4
    /// address. 192.0.2.53 holds the TXT value.
    fn engine_with_unasked_servers() -> Engine<Fake> {
        use crate::inspector::testing::config_with;
        let r1 = addr(1);
        let e = Engine::new(config_with(vec![r1]), Fake::default()).unwrap();
        e.transport.reply(
            r1,
            "example.org",
            RecordType::NS,
            ok(["ns1.example.net.", "ns2.example.net.", "ns3.example.net."]
                .iter()
                .map(|ns| rec("example.org", RecordType::NS, 300, ns))
                .collect()),
        );
        for (host, ip) in [
            ("ns1.example.net", "192.0.2.53"),
            ("ns2.example.net", "127.0.0.1"),
        ] {
            e.transport.reply(
                r1,
                host,
                RecordType::A,
                ok(vec![rec(host, RecordType::A, 300, ip)]),
            );
        }
        e.transport
            .reply(r1, "ns3.example.net", RecordType::A, nodata());
        e.transport
            .reply(addr(53), name(), RecordType::TXT, txt_reply(&["v"]));
        e
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_is_not_asked_is_a_row_that_is_never_satisfied() {
        use crate::inspector::{AddressRefusal, NotAsked};
        let e = engine_with_unasked_servers();
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        let mut options = WaitOptions::new(Duration::from_secs(20));
        options.jitter_percent = 0;
        let err = e.wait(&zone(), &expectations, &options).await.unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        // The wait ran to its timeout: rounds at 0, 5, 10, 15 and 20 s.
        assert_eq!(report.rounds, 5);
        assert_eq!(report.elapsed, Duration::from_secs(20));
        let rows: Vec<(Option<NotAsked>, bool, Vec<Answer>)> = report
            .servers
            .iter()
            .map(|s| (s.server.not_asked, s.satisfied, s.answers.clone()))
            .collect();
        let refused = NotAsked::AddressRefused(AddressRefusal::Loopback);
        assert_eq!(
            rows,
            vec![
                (None, true, vec![records(&["v"])]),
                (Some(refused), false, vec![Answer::NotAsked(refused)]),
                (
                    Some(NotAsked::NoAddress),
                    false,
                    vec![Answer::NotAsked(NotAsked::NoAddress)]
                ),
            ]
        );
        assert!(
            report.servers[1..]
                .iter()
                .all(|s| s.first_satisfied_after.is_none())
        );
        assert_eq!(
            report.servers[1].server.addr,
            Some("127.0.0.1:53".parse().unwrap())
        );
        assert_eq!(report.servers[2].server.addr, None);
        // Only the asked server was queried, once per round; discovery was cached.
        let to_servers = e
            .transport
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(server, _)| *server != addr(1))
            .map(|(server, _)| *server)
            .collect::<Vec<_>>();
        assert_eq!(to_servers, vec![addr(53); 5]);

        // observe: the same rows, one NotAsked answer per question.
        let observed = e.observe(&zone(), &[question(), question()]).await.unwrap();
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0].1, vec![records(&["v"]), records(&["v"])]);
        assert_eq!(
            observed[1].1,
            vec![Answer::NotAsked(refused), Answer::NotAsked(refused)]
        );
        assert_eq!(
            observed[2].1,
            vec![
                Answer::NotAsked(NotAsked::NoAddress),
                Answer::NotAsked(NotAsked::NoAddress)
            ]
        );
    }

    /// An engine with recursive discovery through the fake resolver `addr(1)`: one NS name per
    /// entry, `nsN.example.net` with the given IPv4 address, or with none (NODATA for `A`).
    /// What the servers answer is up to the test.
    fn engine_with(addresses: &[Option<&str>]) -> Engine<Fake> {
        engine_with_config(addresses, |_| {})
    }

    /// [`engine_with`] with the configuration changed by `change`.
    fn engine_with_config(
        addresses: &[Option<&str>],
        change: impl FnOnce(&mut InspectorConfig),
    ) -> Engine<Fake> {
        use crate::inspector::testing::config_with;
        let r1 = addr(1);
        let mut config = config_with(vec![r1]);
        change(&mut config);
        let e = Engine::new(config, Fake::default()).unwrap();
        let hosts: Vec<String> = (1..=addresses.len())
            .map(|i| format!("ns{i}.example.net"))
            .collect();
        e.transport.reply(
            r1,
            "example.org",
            RecordType::NS,
            ok(hosts
                .iter()
                .map(|host| rec("example.org", RecordType::NS, 300, &format!("{host}.")))
                .collect()),
        );
        for (host, ip) in hosts.iter().zip(addresses) {
            let outcome = match ip {
                Some(ip) => ok(vec![rec(host, RecordType::A, 300, ip)]),
                None => nodata(),
            };
            e.transport.reply(r1, host, RecordType::A, outcome);
        }
        e
    }

    fn ignoring(timeout: Duration) -> WaitOptions {
        let mut options = WaitOptions::new(timeout);
        options.jitter_percent = 0;
        options.ignore_unaskable_name_servers = true;
        options
    }

    fn present_v() -> [Expectation; 1] {
        [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )]
    }

    /// The queries that went to name servers rather than to the resolver `addr(1)`.
    fn server_calls(e: &Engine<Fake>) -> Vec<SocketAddr> {
        e.transport
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(server, _)| *server != addr(1))
            .map(|(server, _)| *server)
            .collect()
    }

    #[test]
    fn unaskable_servers_are_waited_for_by_default() {
        assert!(!WaitOptions::new(Duration::from_secs(1)).ignore_unaskable_name_servers);
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_option_off_the_report_counts_nothing_ignored() {
        let e = engine_with_unasked_servers();
        let mut options = WaitOptions::new(Duration::from_secs(5));
        options.jitter_percent = 0;
        let err = e.wait(&zone(), &present_v(), &options).await.unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        assert_eq!(report.unaskable_ignored, 0);
        assert_eq!(report.rounds, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn ignoring_unaskable_servers_is_satisfied_by_the_asked_ones_and_keeps_the_rows() {
        use crate::inspector::{AddressRefusal, NotAsked};
        // ns1 asked and agreeing, ns2 refused (loopback), ns3 without an IPv4 address.
        let e = engine_with_unasked_servers();
        let report = e
            .wait(&zone(), &present_v(), &ignoring(Duration::from_secs(20)))
            .await
            .unwrap();
        assert_eq!(report.rounds, 1);
        assert_eq!(report.elapsed, Duration::ZERO);
        assert_eq!(report.unaskable_ignored, 2);
        type Row = (Option<NotAsked>, bool, Vec<Answer>, Option<Duration>);
        let refused = NotAsked::AddressRefused(AddressRefusal::Loopback);
        let rows: Vec<Row> = report
            .servers
            .iter()
            .map(|s| {
                (
                    s.server.not_asked,
                    s.satisfied,
                    s.answers.clone(),
                    s.first_satisfied_after,
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (None, true, vec![records(&["v"])], Some(Duration::ZERO)),
                (Some(refused), false, vec![Answer::NotAsked(refused)], None),
                (
                    Some(NotAsked::NoAddress),
                    false,
                    vec![Answer::NotAsked(NotAsked::NoAddress)],
                    None
                ),
            ]
        );
        assert_eq!(server_calls(&e), vec![addr(53)]);
    }

    #[tokio::test(start_paused = true)]
    async fn each_reason_alone_is_left_out() {
        use crate::inspector::{AddressRefusal, NotAsked};
        let cases = [
            (
                Some("10.0.0.53"),
                NotAsked::AddressRefused(AddressRefusal::Private),
            ),
            (None, NotAsked::NoAddress),
        ];
        for (address, reason) in cases {
            let e = engine_with(&[Some("192.0.2.53"), address]);
            e.transport
                .reply(addr(53), name(), RecordType::TXT, txt_reply(&["v"]));
            let report = e
                .wait(&zone(), &present_v(), &ignoring(Duration::from_secs(20)))
                .await
                .unwrap();
            assert_eq!(report.rounds, 1, "{reason:?}");
            assert_eq!(report.unaskable_ignored, 1, "{reason:?}");
            assert_eq!(report.servers.len(), 2, "{reason:?}");
            assert_eq!(report.servers[1].server.not_asked, Some(reason));
            assert_eq!(report.servers[1].answers, vec![Answer::NotAsked(reason)]);
            assert!(!report.servers[1].satisfied);

            // The same zone with the option off runs to its timeout.
            let mut off = ignoring(Duration::from_secs(20));
            off.ignore_unaskable_name_servers = false;
            let err = e.wait(&zone(), &present_v(), &off).await.unwrap_err();
            assert!(
                matches!(&err, InspectorError::Timeout { report } if report.rounds == 5),
                "{reason:?} {err:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_asked_server_that_disagrees_or_fails_still_blocks_with_the_option_on() {
        let failures = [
            Behavior::Seq(vec![nodata()]),
            Behavior::Seq(vec![txt_reply(&["other"])]),
            Behavior::Hang,
            Behavior::Seq(vec![Ok(crate::inspector::testing::reply(
                5,
                true,
                Vec::new(),
            ))]),
            Behavior::Seq(vec![Ok(crate::inspector::testing::reply(
                0,
                false,
                Vec::new(),
            ))]),
            Behavior::Seq(vec![Err(Failure::Network("unreachable".to_owned()))]),
        ];
        for behavior in failures {
            // ns1 agrees, ns2 is asked and does not, ns3 has no IPv4 address.
            let e = engine_with(&[Some("192.0.2.53"), Some("192.0.2.54"), None]);
            e.transport
                .reply(addr(53), name(), RecordType::TXT, txt_reply(&["v"]));
            e.transport
                .on(addr(54), name(), RecordType::TXT, behavior.clone());
            let err = e
                .wait(&zone(), &present_v(), &ignoring(Duration::from_secs(20)))
                .await
                .unwrap_err();
            let InspectorError::Timeout { report } = err else {
                panic!("expected a timeout for {behavior:?}");
            };
            assert!(report.rounds >= 3, "{behavior:?} {}", report.rounds);
            assert_eq!(report.unaskable_ignored, 1, "{behavior:?}");
            let satisfied: Vec<bool> = report.servers.iter().map(|s| s.satisfied).collect();
            assert_eq!(satisfied, vec![true, false, false], "{behavior:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_zone_none_of_whose_servers_can_be_asked_is_never_satisfied() {
        use crate::inspector::{AddressRefusal, NotAsked};
        let e = engine_with(&[Some("127.0.0.1"), None]);
        // Absent would hold for any answer that says something; nothing is asked at all.
        let expectations = [Expectation::new(
            question(),
            Condition::Absent(vec![txt("v")]),
        )];
        let started = Instant::now();
        let err = e
            .wait(&zone(), &expectations, &ignoring(Duration::from_secs(20)))
            .await
            .unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        // The wait ran to its timeout: rounds at 0, 5, 10, 15 and 20 s.
        assert_eq!(started.elapsed(), Duration::from_secs(20));
        assert_eq!(report.rounds, 5);
        assert_eq!(report.unaskable_ignored, 2);
        let reasons: Vec<Option<NotAsked>> =
            report.servers.iter().map(|s| s.server.not_asked).collect();
        assert_eq!(
            reasons,
            vec![
                Some(NotAsked::AddressRefused(AddressRefusal::Loopback)),
                Some(NotAsked::NoAddress)
            ]
        );
        assert!(report.servers.iter().all(|s| !s.satisfied));
        assert!(server_calls(&e).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_satisfied_with_servers_left_out_emits_one_warning() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let e = engine_with_unasked_servers();
        e.wait(&zone(), &present_v(), &ignoring(Duration::from_secs(20)))
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
        let ours: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("cannot be asked left out"))
            .collect();
        assert_eq!(ours.len(), 1, "{text}");
        let line = ours[0];
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains("zonewright::inspector"), "{line}");
        assert!(line.contains("zone=example.org"), "{line}");
        assert!(line.contains("unaskable_ignored=2"), "{line}");
        assert!(line.contains("rounds=1"), "{line}");
        assert!(!line.contains("_acme-challenge"), "{line}");

        // A wait with nothing left out emits no such event.
        let s1 = addr(1);
        let plain = engine(&[s1]);
        plain
            .transport
            .reply(s1, name(), RecordType::TXT, txt_reply(&["v"]));
        let report = plain
            .wait(&zone(), &present_v(), &ignoring(Duration::from_secs(20)))
            .await
            .unwrap();
        assert_eq!(report.unaskable_ignored, 0);
        let text = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
        assert_eq!(
            text.matches("cannot be asked left out").count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn not_asked_satisfies_no_condition() {
        use crate::inspector::NotAsked;
        let answer = Answer::NotAsked(NotAsked::NoAddress);
        for condition in [
            Condition::Present(vec![txt("a")]),
            Condition::Exact(vec![txt("a")]),
            Condition::Exact(Vec::new()),
            Condition::Absent(vec![txt("a")]),
        ] {
            assert!(!holds(&condition, &answer), "{condition:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn options_and_questions_are_validated_before_discovery() {
        let e = engine_with_unasked_servers();
        let valid = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        let mut short = WaitOptions::new(Duration::from_secs(10));
        short.interval = Duration::from_millis(999);
        let mut jittery = WaitOptions::new(Duration::from_secs(10));
        jittery.jitter_percent = 51;
        let outside = [Expectation::new(
            Question::new(DomainName::parse("example.net").unwrap(), RecordType::TXT),
            Condition::Present(vec![txt("v")]),
        )];
        let raw = [Expectation::new(
            question(),
            Condition::Present(vec![RecordData::non_canonical("x y")]),
        )];
        let fine = WaitOptions::new(Duration::from_secs(10));
        for (expectations, options) in [
            (&valid[..], &short),
            (&valid[..], &jittery),
            (&outside[..], &fine),
            (&raw[..], &fine),
        ] {
            assert!(matches!(
                e.wait(&zone(), expectations, options).await,
                Err(InspectorError::InvalidInput { .. })
            ));
        }
        assert!(matches!(
            e.observe(&zone(), &[]).await,
            Err(InspectorError::InvalidInput { .. })
        ));
        // Not even the NS question went out.
        assert_eq!(e.transport.total_calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_wait_cancels_its_queries() {
        let s1 = addr(1);
        let e = engine(&[s1]);
        e.transport.on(s1, name(), RecordType::TXT, Behavior::Hang);
        let expectations = [Expectation::new(
            question(),
            Condition::Present(vec![txt("v")]),
        )];
        let options = WaitOptions::new(Duration::from_secs(3600));
        let zone = zone();
        let wait = e.wait(&zone, &expectations, &options);
        let cut = tokio::time::timeout(Duration::from_secs(1), wait).await;
        assert!(cut.is_err());
        // The exchange future was dropped with the wait: nothing is in flight.
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(e.transport.total_calls(), 1);
    }

    /// An engine over a static list of `servers` with the configuration changed by `change`.
    fn engine_cfg(
        servers: &[SocketAddr],
        change: impl FnOnce(&mut InspectorConfig),
    ) -> Engine<Fake> {
        let mut config = InspectorConfig {
            discovery: NsDiscovery::Static(
                servers.iter().map(|a| NameServer::new(None, *a)).collect(),
            ),
            max_servers: servers.len().max(32),
            ..InspectorConfig::default()
        };
        change(&mut config);
        Engine::new(config, Fake::default()).unwrap()
    }

    fn unflagged(
        rcode: u16,
        records: Vec<crate::inspector::exchange::ReplyRecord>,
    ) -> Result<crate::inspector::exchange::Reply, Failure> {
        Ok(crate::inspector::testing::reply(rcode, false, records))
    }

    /// Records at `a`, NODATA at `b`, NXDOMAIN at `c`, all without AA, at `server`.
    fn script_unflagged(e: &Engine<Fake>, server: SocketAddr) -> [Expectation; 3] {
        let at = |label: &str| format!("{label}.example.org");
        e.transport.reply(
            server,
            &at("a"),
            RecordType::TXT,
            unflagged(0, vec![rec(&at("a"), RecordType::TXT, 60, "\"v\"")]),
        );
        e.transport
            .reply(server, &at("b"), RecordType::TXT, unflagged(0, Vec::new()));
        e.transport
            .reply(server, &at("c"), RecordType::TXT, unflagged(3, Vec::new()));
        let q =
            |label: &str| Question::new(DomainName::parse(&at(label)).unwrap(), RecordType::TXT);
        [
            Expectation::new(q("a"), Condition::Present(vec![txt("v")])),
            Expectation::new(q("b"), Condition::Exact(Vec::new())),
            Expectation::new(q("c"), Condition::Absent(vec![txt("v")])),
        ]
    }

    #[test]
    fn answers_without_aa_are_not_accepted_by_default() {
        assert!(!InspectorConfig::default().accept_static_without_aa);
    }

    #[tokio::test(start_paused = true)]
    async fn a_static_server_without_aa_is_not_authoritative_by_default() {
        let s1 = addr(1);
        let e = engine(&[s1]);
        let expectations = script_unflagged(&e, s1);
        let err = e
            .wait(&zone(), &expectations, &WaitOptions::new(Duration::ZERO))
            .await
            .unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        assert_eq!(report.servers[0].answers, vec![Answer::NotAuthoritative; 3]);
        assert!(!report.servers[0].satisfied);
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_option_a_static_server_without_aa_is_read_by_its_content() {
        let s1 = addr(1);
        let e = engine_cfg(&[s1], |c| c.accept_static_without_aa = true);
        let expectations = script_unflagged(&e, s1);
        let report = e
            .wait(&zone(), &expectations, &WaitOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert_eq!(report.rounds, 1);
        assert_eq!(
            report.servers[0].answers,
            vec![records(&["v"]), Answer::NoData, Answer::NxDomain]
        );
        assert!(report.servers[0].satisfied);
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_option_a_referral_without_aa_is_not_absence() {
        let s1 = addr(1);
        let e = engine_cfg(&[s1], |c| c.accept_static_without_aa = true);
        for rcode in [0, 3] {
            let mut referral = crate::inspector::testing::reply(rcode, false, Vec::new());
            referral.referral = true;
            e.transport.reply(s1, name(), RecordType::TXT, Ok(referral));
            for condition in [
                Condition::Exact(Vec::new()),
                Condition::Absent(vec![txt("v")]),
            ] {
                let expectations = [Expectation::new(question(), condition.clone())];
                let err = e
                    .wait(&zone(), &expectations, &WaitOptions::new(Duration::ZERO))
                    .await
                    .unwrap_err();
                let InspectorError::Timeout { report } = err else {
                    panic!("expected a timeout for {rcode} {condition:?}");
                };
                assert_eq!(
                    report.servers[0].answers,
                    vec![Answer::NotAuthoritative],
                    "{rcode} {condition:?}"
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn with_the_option_a_discovered_server_without_aa_is_still_not_authoritative() {
        // ns1 at 192.0.2.53 answers the value without AA.
        let e = engine_with_config(&[Some("192.0.2.53")], |c| {
            c.accept_static_without_aa = true;
        });
        assert!(e.config.accept_static_without_aa);
        e.transport.reply(
            addr(53),
            name(),
            RecordType::TXT,
            unflagged(0, vec![rec(name(), RecordType::TXT, 60, "\"v\"")]),
        );
        let err = e
            .wait(&zone(), &present_v(), &WaitOptions::new(Duration::ZERO))
            .await
            .unwrap_err();
        let InspectorError::Timeout { report } = err else {
            panic!("expected a timeout");
        };
        assert_eq!(report.servers[0].answers, vec![Answer::NotAuthoritative]);
        assert_eq!(server_calls(&e), vec![addr(53)]);
    }

    fn a_questions(count: usize) -> Vec<Question> {
        (0..count)
            .map(|i| {
                Question::new(
                    DomainName::parse(&format!("n{i}.example.org")).unwrap(),
                    RecordType::A,
                )
            })
            .collect()
    }

    fn script_nodata(e: &Engine<Fake>, servers: &[SocketAddr], questions: &[Question]) {
        for server in servers {
            for q in questions {
                e.transport
                    .reply(*server, &q.name.to_string(), RecordType::A, nodata());
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_configured_question_limit_of_100_takes_100_and_refuses_101() {
        let s1 = addr(1);
        let e = engine_cfg(&[s1], |c| c.max_questions = 100);
        let questions = a_questions(101);
        script_nodata(&e, &[s1], &questions);

        // 101 questions or expectations: refused before anything is sent, naming the limit.
        let err = e.observe(&zone(), &questions).await.unwrap_err();
        assert!(
            matches!(&err, InspectorError::InvalidInput { detail } if detail.contains("max_questions of 100")),
            "{err:?}"
        );
        let gone: Vec<Expectation> = questions
            .iter()
            .map(|q| Expectation::new(q.clone(), Condition::Exact(Vec::new())))
            .collect();
        let err = e
            .wait(&zone(), &gone, &WaitOptions::new(Duration::ZERO))
            .await
            .unwrap_err();
        assert!(
            matches!(err, InspectorError::InvalidInput { .. }),
            "{err:?}"
        );
        assert_eq!(e.transport.total_calls(), 0);

        // 100: every one asked.
        let observed = e.observe(&zone(), &questions[..100]).await.unwrap();
        assert_eq!(observed[0].1, vec![Answer::NoData; 100]);
        assert_eq!(e.transport.total_calls(), 100);
        let report = e
            .wait(&zone(), &gone[..100], &WaitOptions::new(Duration::ZERO))
            .await
            .unwrap();
        assert!(report.servers[0].satisfied);
        assert_eq!(e.transport.total_calls(), 200);
    }

    #[tokio::test(start_paused = true)]
    async fn the_configured_round_limit_is_enforced_before_anything_is_sent() {
        let servers: Vec<SocketAddr> = (1..=4).map(addr).collect();
        let e = engine_cfg(&servers, |c| {
            c.max_questions = 100;
            c.max_questions_per_round = 300;
        });
        let questions = a_questions(76);
        script_nodata(&e, &servers, &questions);
        // 4 servers × 76 questions = 304 > 300.
        let err = e.observe(&zone(), &questions).await.unwrap_err();
        assert!(
            matches!(&err, InspectorError::InvalidInput { detail }
                if detail.contains("304") && detail.contains("max_questions_per_round of 300")),
            "{err:?}"
        );
        assert_eq!(e.transport.total_calls(), 0);
        // 4 × 75 = 300: allowed, all asked.
        let observed = e.observe(&zone(), &questions[..75]).await.unwrap();
        assert_eq!(observed.len(), 4);
        assert_eq!(e.transport.total_calls(), 300);
    }

    #[tokio::test(start_paused = true)]
    async fn a_round_at_a_raised_limit_keeps_128_in_flight() {
        // 8 servers × 256 questions = 2048 questions, 128 at a time, one second each.
        let servers: Vec<SocketAddr> = (1..=8).map(addr).collect();
        let e = engine_cfg(&servers, |c| {
            c.max_questions = InspectorConfig::QUESTIONS_CEILING;
            c.max_questions_per_round = 2048;
        });
        *e.transport.delay.lock().unwrap() = Duration::from_secs(1);
        let questions = a_questions(256);
        script_nodata(&e, &servers, &questions);
        let started = Instant::now();
        let observed = e.observe(&zone(), &questions).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(16));
        assert_eq!(
            e.transport.peak.load(std::sync::atomic::Ordering::SeqCst),
            QUESTIONS_AT_ONCE
        );
        assert!(observed.iter().all(|(_, a)| a.len() == 256));
        assert_eq!(e.transport.total_calls(), 2048);
    }

    #[test]
    fn question_limits_are_validated_at_construction() {
        let refused = |change: fn(&mut InspectorConfig)| {
            let mut config = InspectorConfig::default();
            change(&mut config);
            matches!(
                Engine::new(config, Fake::default()),
                Err(InspectorError::Config { .. })
            )
        };
        assert!(refused(|c| c.max_questions = 0));
        assert!(refused(
            |c| c.max_questions = InspectorConfig::QUESTIONS_CEILING + 1
        ));
        assert!(refused(|c| c.max_questions_per_round = 0));
        assert!(refused(|c| {
            c.max_questions_per_round = InspectorConfig::QUESTIONS_PER_ROUND_CEILING + 1;
        }));
        assert!(refused(|c| {
            c.max_questions = 100;
            c.max_questions_per_round = 99;
        }));
        assert!(!refused(|c| {
            c.max_questions = InspectorConfig::QUESTIONS_CEILING;
            c.max_questions_per_round = InspectorConfig::QUESTIONS_PER_ROUND_CEILING;
        }));
        assert!(!refused(|c| {
            c.max_questions = 1;
            c.max_questions_per_round = 1;
        }));
        let defaults = InspectorConfig::default();
        assert_eq!(defaults.max_questions, 32);
        assert_eq!(defaults.max_questions_per_round, 1024);
    }
}
