//! Request pacing for providers with undocumented rate limits (design section 5.7).

use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

/// At most one request per interval per client: reg.ru 1000 ms, Beget 1000 ms, nic.ru 500 ms
/// (`min_request_interval_ms`). Callers queue on the gate's lock in arrival order; each waits
/// until the interval since the previous request has passed. Every HTTP attempt passes the gate,
/// retries and token requests included.
#[derive(Debug)]
pub(crate) struct RateGate {
    last: Mutex<Option<Instant>>,
    interval: Duration,
}

impl RateGate {
    /// A gate that spaces requests by `interval`.
    pub(crate) fn new(interval: Duration) -> RateGate {
        RateGate {
            last: Mutex::new(None),
            interval,
        }
    }

    /// Waits until a request may be sent, and records that one is being sent now.
    pub(crate) async fn wait(&self) {
        let mut last = self.last.lock().await;
        if let Some(next) = last.and_then(|previous| previous.checked_add(self.interval)) {
            tokio::time::sleep_until(next).await;
        }
        *last = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn requests_are_spaced_by_the_interval() {
        let gate = RateGate::new(Duration::from_millis(1000));
        let start = Instant::now();
        gate.wait().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        gate.wait().await;
        assert_eq!(start.elapsed(), Duration::from_millis(1000));
        // After a pause longer than the interval, no wait.
        tokio::time::advance(Duration::from_millis(5000)).await;
        let before = Instant::now();
        gate.wait().await;
        assert_eq!(before.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_are_serialized() {
        let gate = Arc::new(RateGate::new(Duration::from_millis(500)));
        let start = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let gate = gate.clone();
            tasks.spawn(async move {
                gate.wait().await;
                start.elapsed()
            });
        }
        let mut times = Vec::new();
        while let Some(t) = tasks.join_next().await {
            times.push(t.unwrap());
        }
        times.sort();
        assert_eq!(
            times,
            [0, 500, 1000, 1500].map(Duration::from_millis).to_vec()
        );
    }
}
