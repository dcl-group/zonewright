//! Expectations, one-round observation and the wait loop (design section 8.6).

use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream;
use tokio::time::Instant;

use super::answer::Mode;
use super::exchange::{Ask, Transport};
use super::{
    Answer, Condition, Engine, Expectation, InspectorError, NameServer, Question, ask_for,
};
use crate::name::DomainName;

/// Most expectations or questions in one call.
pub(crate) const MAX_QUESTIONS: usize = 32;
/// Most questions in one round: servers times distinct questions.
pub(crate) const MAX_QUESTIONS_PER_ROUND: usize = 1024;
/// Most questions of one round in flight at the same time; each holds one socket.
pub(crate) const QUESTIONS_AT_ONCE: usize = 128;
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
}

impl WaitOptions {
    /// The shortest accepted `interval`, 1 s. A round can ask up to 1024 questions of servers
    /// the application does not run; a shorter interval is
    /// [`InspectorError::InvalidInput`]. With the largest jitter the shortest pause is 500 ms.
    pub const MIN_INTERVAL: Duration = Duration::from_secs(1);

    /// Options with this timeout, a 5 s interval and 20 % jitter.
    #[must_use]
    pub fn new(timeout: Duration) -> WaitOptions {
        WaitOptions {
            timeout,
            interval: Duration::from_secs(5),
            jitter_percent: 20,
        }
    }
}

/// What one server answered in the last round of a wait.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ServerReport {
    /// The server.
    pub server: NameServer,
    /// All expectations held at this server in the last round.
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
    /// One entry per name server, in the order discovery returned them.
    pub servers: Vec<ServerReport>,
    /// Rounds run.
    pub rounds: u32,
    /// Time from the start of the first round to the end of the last.
    pub elapsed: Duration,
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

/// Checks the questions of a call: 1 to 32, every name within the zone, every type askable.
fn validate_questions<'a>(
    zone: &DomainName,
    questions: impl ExactSizeIterator<Item = &'a Question>,
) -> Result<Vec<Ask>, InspectorError> {
    let count = questions.len();
    if count == 0 {
        return Err(InspectorError::invalid("at least one question is needed"));
    }
    if count > MAX_QUESTIONS {
        return Err(InspectorError::invalid("more than 32 questions"));
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
/// way, not past `remaining`.
pub(crate) fn pause(interval: Duration, jitter_percent: u8, remaining: Duration) -> Duration {
    let interval_ns = u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX);
    let percent = u64::from(jitter_percent.min(MAX_JITTER_PERCENT));
    let span = (interval_ns / 100).saturating_mul(percent);
    let low = interval_ns.saturating_sub(span);
    let offset = fastrand::u64(0..=span.saturating_mul(2));
    Duration::from_nanos(low.saturating_add(offset)).min(remaining)
}

impl<T: Transport> Engine<T> {
    /// Every question at every server, at most [`QUESTIONS_AT_ONCE`] in flight. The answers of
    /// a server are in the order of `asks`.
    async fn round(&self, servers: &[NameServer], asks: &[Ask]) -> Vec<Vec<Answer>> {
        // Built with loops rather than closures: a closure here makes the future's `Send`
        // bound fail to be proven for every lifetime.
        let mut pending = Vec::with_capacity(servers.len().saturating_mul(asks.len()));
        for server in servers {
            for ask in asks {
                pending.push(self.ask(server.addr, ask, Mode::Server));
            }
        }
        let flat: Vec<Answer> = stream::iter(pending)
            .buffered(QUESTIONS_AT_ONCE)
            .collect()
            .await;
        let mut flat = flat.into_iter();
        servers
            .iter()
            .map(|_| flat.by_ref().take(asks.len()).collect())
            .collect()
    }

    /// Fails when a round would hold more than 1024 questions.
    fn check_round_size(servers: usize, questions: usize) -> Result<(), InspectorError> {
        if servers.saturating_mul(questions) > MAX_QUESTIONS_PER_ROUND {
            return Err(InspectorError::invalid(
                "servers times questions exceeds 1024 per round",
            ));
        }
        Ok(())
    }

    pub(crate) async fn observe(
        &self,
        zone: &DomainName,
        questions: &[Question],
    ) -> Result<Vec<(NameServer, Vec<Answer>)>, InspectorError> {
        let asks = validate_questions(zone, questions.iter())?;
        let servers = self.name_servers(zone).await?;
        Self::check_round_size(servers.len(), asks.len())?;
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
        let asks = validate_questions(zone, expectations.iter().map(|e| &e.question))?;
        for expectation in expectations {
            validate_values(expectation)?;
        }
        let (asks, index) = dedup(asks);
        let servers = self.name_servers(zone).await?;
        Self::check_round_size(servers.len(), asks.len())?;

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
            let done = reports.iter().all(|report| report.satisfied);
            let report = Report {
                servers: reports,
                rounds,
                elapsed,
            };
            if done {
                return Ok(report);
            }
            if elapsed >= options.timeout {
                return Err(InspectorError::Timeout { report });
            }
            let remaining = options.timeout.saturating_sub(elapsed);
            tokio::time::sleep(pause(options.interval, options.jitter_percent, remaining)).await;
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
            let p = pause(interval, 20, Duration::MAX);
            assert!(
                p >= Duration::from_secs(8) && p <= Duration::from_secs(12),
                "{p:?}"
            );
        }
        assert_eq!(pause(interval, 0, Duration::MAX), interval);
        assert_eq!(
            pause(interval, 20, Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        // Jitter is capped at 50 and huge intervals do not overflow.
        for _ in 0..200 {
            let p = pause(interval, 200, Duration::MAX);
            assert!(
                p >= Duration::from_secs(5) && p <= Duration::from_secs(15),
                "{p:?}"
            );
        }
        let _ = pause(Duration::MAX, 50, Duration::MAX);
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
        // The last round starts no later than the timeout; here it starts exactly at it.
        assert_eq!(started.elapsed(), Duration::from_secs(300));
        assert_eq!(report.elapsed, Duration::from_secs(300));
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
            assert_eq!(server.addr, servers[s]);
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
}
