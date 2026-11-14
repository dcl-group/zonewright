//! Bounded polling of provider-side operations (design section 3.7).

use std::future::Future;
use std::time::Duration;

use crate::error::Error;
use crate::redact::Detail;

/// Floor of every polling interval: a configured value below it would turn the wait into a hot
/// loop against the provider's API.
pub(crate) const MIN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The polling interval: the configured value or `default_ms`, at least [`MIN_POLL_INTERVAL`].
pub(crate) fn poll_interval(configured_ms: Option<u64>, default_ms: u64) -> Duration {
    Duration::from_millis(configured_ms.unwrap_or(default_ms)).max(MIN_POLL_INTERVAL)
}

/// One look at a provider-side operation.
#[derive(Debug)]
pub(crate) enum PollStep<T> {
    /// The operation finished; polling ends with this value.
    Done(T),
    /// Still running; poll again after the interval.
    Pending,
    /// The operation finished with an error (the provider's refusal, or a failed condition the
    /// client handles); polling ends with this error as it is.
    Failed(Error),
}

/// Polls an operation the provider completes asynchronously: at most `max_polls` looks,
/// `interval` apart. The first look is made at once.
///
/// - [`PollStep::Done`] and [`PollStep::Failed`] end the polling with their value.
/// - An operation still running after the last look is `Error::Transient`: the write was
///   accepted and its outcome is unknown.
/// - A look that fails (its future returns `Err`) is `Error::Transient` too, for the same
///   reason, whatever the kind of the failure; its detail is kept.
///
/// The total time is bounded by `interval × (max_polls − 1)` plus the looks themselves, each of
/// which is bounded by the transport's timeouts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Poller {
    interval: Duration,
    max_polls: u32,
}

impl Poller {
    /// A poller with `interval` (raised to [`MIN_POLL_INTERVAL`]) and at most `max_polls` looks
    /// (at least one).
    pub(crate) fn new(interval: Duration, max_polls: u32) -> Poller {
        Poller {
            interval: interval.max(MIN_POLL_INTERVAL),
            max_polls: max_polls.max(1),
        }
    }

    /// Runs `look` until the operation is done, failed, or the polls are used up.
    pub(crate) async fn run<T, F, Fut>(&self, mut look: F) -> Result<T, Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<PollStep<T>, Error>>,
    {
        for poll in 1..=self.max_polls {
            if poll > 1 {
                tokio::time::sleep(self.interval).await;
            }
            match look().await {
                Ok(PollStep::Done(value)) => return Ok(value),
                Ok(PollStep::Failed(e)) => return Err(e),
                Ok(PollStep::Pending) => {}
                Err(e) => return Err(as_transient(e)),
            }
        }
        Err(Error::Transient {
            detail: Detail::constant(
                "the provider accepted the change, but its operation was still running after the last poll",
            ),
        })
    }
}

/// A failed look as `Error::Transient`, keeping the detail where the error has one.
fn as_transient(e: Error) -> Error {
    match e {
        Error::Transient { .. } => e,
        Error::Config { detail }
        | Error::InvalidInput { detail }
        | Error::Auth { detail }
        | Error::Forbidden { detail }
        | Error::PreconditionFailed { detail }
        | Error::Conflict { detail }
        | Error::Rejected { detail, .. }
        | Error::Protocol { detail } => Error::Transient { detail },
        _ => Error::Transient {
            detail: Detail::constant(
                "the provider accepted the change, but polling its operation failed",
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::time::Instant;

    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn intervals_have_a_floor() {
        assert_eq!(poll_interval(Some(1), 1000), MIN_POLL_INTERVAL);
        assert_eq!(poll_interval(Some(0), 1000), Duration::from_millis(250));
        assert_eq!(poll_interval(None, 2000), Duration::from_millis(2000));
        assert_eq!(poll_interval(Some(5000), 1000), Duration::from_millis(5000));
        assert_eq!(Poller::new(Duration::ZERO, 0).max_polls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn done_after_some_pending_looks() {
        let looks = AtomicU32::new(0);
        let start = Instant::now();
        let poller = Poller::new(Duration::from_millis(1000), 60);
        let value = poller
            .run(|| async {
                let n = looks.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(if n < 4 {
                    PollStep::Pending
                } else {
                    PollStep::Done(n)
                })
            })
            .await
            .unwrap();
        assert_eq!(value, 4);
        assert_eq!(start.elapsed(), Duration::from_millis(3000));
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_and_time_are_bounded() {
        let looks = AtomicU32::new(0);
        let start = Instant::now();
        let poller = Poller::new(Duration::from_millis(2000), 60);
        let e = poller
            .run(|| async {
                looks.fetch_add(1, Ordering::SeqCst);
                Ok(PollStep::<()>::Pending)
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient);
        assert_eq!(looks.load(Ordering::SeqCst), 60);
        assert_eq!(start.elapsed(), Duration::from_millis(2000 * 59));
    }

    #[tokio::test(start_paused = true)]
    async fn failures_end_the_polling() {
        let poller = Poller::new(Duration::from_millis(250), 10);
        let rejected = poller
            .run(|| async { Ok(PollStep::<()>::Failed(Error::rejected(None, "refused"))) })
            .await
            .unwrap_err();
        assert_eq!(rejected.kind(), ErrorKind::Rejected);
        let looks = AtomicU32::new(0);
        let failed = poller
            .run(|| async {
                looks.fetch_add(1, Ordering::SeqCst);
                Err::<PollStep<()>, _>(Error::forbidden("poll denied"))
            })
            .await
            .unwrap_err();
        assert_eq!(failed.kind(), ErrorKind::Transient);
        assert!(failed.to_string().contains("poll denied"));
        assert_eq!(looks.load(Ordering::SeqCst), 1);
        let limited = poller
            .run(|| async { Err::<PollStep<()>, _>(Error::rate_limited(None)) })
            .await
            .unwrap_err();
        assert_eq!(limited.kind(), ErrorKind::Transient);
    }
}
