//! A cache for a token obtained by an exchange (design section 5.7).
//!
//! The token is renewed ahead of time, at the expiry minus `max(10 min, 5 % of the lifetime)`
//! but at most half the lifetime, optionally capped by a maximum age; a token without a stated
//! lifetime is assumed to live one hour. A token whose lifetime is under two minutes (a clock
//! that runs ahead makes a stated expiry look close) is still cached for half of it, and one
//! `WARN` event says so, without the token or the answer. Single flight: the fetch runs inside the first caller's future while it holds the
//! source's async lock, and the others wait for the lock. If that future is dropped mid-fetch,
//! the lock is released with nothing stored and the next waiter fetches; there is no detached
//! task and no state a cancelled fetch can leave half-written. Every token has a generation
//! number, and invalidation names the generation, so a late 401 for an old token does not
//! discard a fresh one.
//!
//! Time is `tokio::time`, so tests run the cache under a paused clock. Expiry timestamps are
//! parsed with the private `jiff` dependency and turned into a lifetime immediately.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use secrecy::SecretString;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::error::Error;
use crate::redact::SecretSlot;

/// Lifetime assumed for a token whose answer states none.
pub(crate) const DEFAULT_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Lifetimes below this are implausibly short and logged.
const SHORT_LIFETIME: Duration = Duration::from_secs(2 * 60);

/// Smallest renewal margin before the expiry.
const MIN_MARGIN: Duration = Duration::from_secs(10 * 60);

/// Longest lifetime the cache believes. A provider's answer could state any number; the
/// tokens of the providers in scope live hours, and a longer stated lifetime only delays
/// renewal.
const MAX_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A token as an exchange returns it.
pub(crate) struct Token {
    secret: SecretString,
    lifetime: Option<Duration>,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl Token {
    /// A token valid for `lifetime` from now; `None` when the answer states no expiry.
    pub(crate) fn new(secret: SecretString, lifetime: Option<Duration>) -> Token {
        Token { secret, lifetime }
    }
}

/// The time from now until the RFC 3339 timestamp `expires_at`, zero if it has passed. `None`
/// when the text is not an RFC 3339 timestamp; the caller then states no lifetime.
pub(crate) fn lifetime_until(expires_at: &str) -> Option<Duration> {
    let expires: jiff::Timestamp = expires_at.trim().parse().ok()?;
    let left = expires.duration_since(jiff::Timestamp::now());
    Some(Duration::try_from(left).unwrap_or(Duration::ZERO))
}

/// A token handed out by [`TokenSource::get`].
pub(crate) struct Lease {
    /// The token.
    pub(crate) token: SecretString,
    /// Its generation, for [`TokenSource::invalidate`].
    pub(crate) generation: u64,
    /// True when this call fetched the token, false when it came from the cache.
    pub(crate) fresh: bool,
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("generation", &self.generation)
            .field("fresh", &self.fresh)
            .finish_non_exhaustive()
    }
}

struct Cached {
    token: SecretString,
    refresh_at: Instant,
    generation: u64,
}

/// A cached token with single-flight renewal.
pub(crate) struct TokenSource {
    slot: Mutex<Option<Cached>>,
    generations: AtomicU64,
    max_age: Option<Duration>,
    secrets: SecretSlot,
}

impl std::fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSource")
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

impl TokenSource {
    /// An empty source. `max_age` caps how long a token is used, whatever its lifetime (50 min
    /// for Yandex Cloud).
    pub(crate) fn new(max_age: Option<Duration>) -> TokenSource {
        TokenSource {
            slot: Mutex::new(None),
            generations: AtomicU64::new(0),
            max_age,
            secrets: SecretSlot::new(),
        }
    }

    /// The cached token, or a new one from `fetch` when there is none or it is due for renewal.
    /// Concurrent callers wait for one fetch. A failed fetch stores nothing and its error is
    /// returned to the caller that ran it; the next caller fetches again.
    pub(crate) async fn get<F, Fut>(&self, fetch: F) -> Result<Lease, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Token, Error>>,
    {
        let mut slot = self.slot.lock().await;
        if let Some(cached) = slot.as_ref()
            && Instant::now() < cached.refresh_at
        {
            return Ok(Lease {
                token: cached.token.clone(),
                generation: cached.generation,
                fresh: false,
            });
        }
        // Dropping this future here releases the lock and leaves the slot as it was.
        let token = fetch().await?;
        Ok(self.store(&mut slot, token))
    }

    /// A new token from `fetch`, even when a valid one is cached: for a connection check, which
    /// must prove that the credentials are accepted now. The cached token is discarded before
    /// the fetch, so a failed or cancelled fetch leaves the source empty, and the next caller
    /// fetches again. Concurrent callers of [`TokenSource::get`] wait for this fetch and use its
    /// token.
    pub(crate) async fn renew<F, Fut>(&self, fetch: F) -> Result<Lease, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Token, Error>>,
    {
        let mut slot = self.slot.lock().await;
        *slot = None;
        let token = fetch().await?;
        Ok(self.store(&mut slot, token))
    }

    /// Stores a token just fetched under a new generation and returns its lease.
    fn store(&self, slot: &mut Option<Cached>, token: Token) -> Lease {
        let Token { secret, lifetime } = token;
        let lifetime = lifetime.unwrap_or(DEFAULT_LIFETIME);
        if lifetime < SHORT_LIFETIME {
            tracing::warn!(
                target: "zonewright::http",
                lifetime_s = lifetime.as_secs(),
                "the provider issued a token with an implausibly short lifetime; is the system clock right?"
            );
        }
        let now = Instant::now();
        let generation = self.generations.fetch_add(1, Ordering::Relaxed) + 1;
        *slot = Some(Cached {
            token: secret.clone(),
            refresh_at: now + self.renew_after(lifetime),
            generation,
        });
        Lease {
            token: secret,
            generation,
            fresh: true,
        }
    }

    /// The scrubber slot of this source's tokens: the transport registers each token it uses
    /// here, so the current and the previous token of every source stay registered.
    pub(crate) fn secret_slot(&self) -> &SecretSlot {
        &self.secrets
    }

    /// Discards the cached token if it is still of `generation`.
    pub(crate) async fn invalidate(&self, generation: u64) {
        let mut slot = self.slot.lock().await;
        if slot.as_ref().is_some_and(|c| c.generation == generation) {
            *slot = None;
        }
    }

    /// Discards the cached token if it is still the one `response` answered: for a provider that
    /// rejects a token with an answer the transport passes on (not a 401). `response` comes from
    /// [`Http::send_with_token`](super::Http::send_with_token) with this source; for any other
    /// response nothing happens. A token another call has fetched meanwhile is kept.
    pub(crate) async fn discard_rejected(&self, response: &super::Response) {
        if let Some(generation) = response.token_generation {
            self.invalidate(generation).await;
        }
    }

    /// How long after it was obtained a token of `lifetime` is renewed.
    fn renew_after(&self, lifetime: Duration) -> Duration {
        let lifetime = lifetime.min(MAX_LIFETIME);
        let margin = MIN_MARGIN.max(lifetime / 20).min(lifetime / 2);
        let after = lifetime.saturating_sub(margin);
        match self.max_age {
            Some(max) => after.min(max),
            None => after,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use secrecy::ExposeSecret;

    use super::*;
    use crate::error::ErrorKind;

    fn token(text: &str, lifetime: Option<Duration>) -> Token {
        Token::new(SecretString::from(text), lifetime)
    }

    /// A fetch that counts its calls, takes a second, and issues `tok-<n>`.
    fn counting(
        count: &Arc<AtomicUsize>,
        lifetime: Option<Duration>,
    ) -> impl Future<Output = Result<Token, Error>> + use<> {
        let count = count.clone();
        async move {
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(token(&format!("tok-{n}"), lifetime))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_fetch() {
        let source = Arc::new(TokenSource::new(None));
        let count = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let source = source.clone();
            let count = count.clone();
            tasks.spawn(async move { source.get(|| counting(&count, None)).await.unwrap() });
        }
        let mut fresh = 0;
        while let Some(lease) = tasks.join_next().await {
            let lease = lease.unwrap();
            assert_eq!(lease.token.expose_secret(), "tok-1");
            assert_eq!(lease.generation, 1);
            fresh += usize::from(lease.fresh);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(fresh, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn renew_fetches_even_when_a_token_is_cached() {
        let count = Arc::new(AtomicUsize::new(0));
        let source = TokenSource::new(None);
        let first = source.get(|| counting(&count, None)).await.unwrap();
        assert_eq!(first.token.expose_secret(), "tok-1");
        let renewed = source.renew(|| counting(&count, None)).await.unwrap();
        assert!(renewed.fresh);
        assert_eq!(renewed.token.expose_secret(), "tok-2");
        assert_eq!(renewed.generation, 2);
        // The new token replaced the cached one.
        let cached = source.get(|| counting(&count, None)).await.unwrap();
        assert!(!cached.fresh);
        assert_eq!(cached.token.expose_secret(), "tok-2");
        assert_eq!(count.load(Ordering::SeqCst), 2);
        // A late invalidation of the old generation keeps the new token.
        source.invalidate(first.generation).await;
        assert!(!source.get(|| counting(&count, None)).await.unwrap().fresh);
        // With an empty source, renew is one fetch.
        let empty = TokenSource::new(None);
        assert!(empty.renew(|| counting(&count, None)).await.unwrap().fresh);
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_or_cancelled_renew_leaves_the_source_empty() {
        let count = Arc::new(AtomicUsize::new(0));
        let source = TokenSource::new(None);
        source.get(|| counting(&count, None)).await.unwrap();
        let e = source
            .renew(|| async { Err::<Token, _>(Error::auth("refused")) })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth);
        // The token cached before proves nothing now: the next caller fetches.
        let lease = source.get(|| counting(&count, None)).await.unwrap();
        assert!(lease.fresh);
        assert_eq!(lease.token.expose_secret(), "tok-2");
        // A renew dropped while it fetches stores nothing.
        let renew = source.renew(|| counting(&count, None));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), renew)
                .await
                .is_err()
        );
        assert!(source.get(|| counting(&count, None)).await.unwrap().fresh);
    }

    #[tokio::test(start_paused = true)]
    async fn callers_wait_for_a_renew_and_use_its_token() {
        let count = Arc::new(AtomicUsize::new(0));
        let source = Arc::new(TokenSource::new(None));
        source.get(|| counting(&count, None)).await.unwrap();
        let renewing = {
            let source = source.clone();
            let count = count.clone();
            tokio::spawn(async move { source.renew(|| counting(&count, None)).await.unwrap() })
        };
        tokio::task::yield_now().await;
        let waiting = source.get(|| counting(&count, None)).await.unwrap();
        let renewed = renewing.await.unwrap();
        assert_eq!(renewed.token.expose_secret(), "tok-2");
        assert_eq!(waiting.token.expose_secret(), "tok-2");
        assert!(!waiting.fresh);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_happens_before_the_expiry_with_the_margin() {
        let count = Arc::new(AtomicUsize::new(0));
        // One hour: the margin is the 10-minute floor, so renewal after 50 minutes (counted
        // from the end of the fetch).
        let source = TokenSource::new(None);
        let hour = Some(Duration::from_secs(3600));
        assert!(source.get(|| counting(&count, hour)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(50 * 60 - 1)).await;
        assert!(!source.get(|| counting(&count, hour)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(2)).await;
        let lease = source.get(|| counting(&count, hour)).await.unwrap();
        assert!(lease.fresh);
        assert_eq!(lease.generation, 2);

        // 24 hours: the margin is 5 % (72 minutes).
        let source = TokenSource::new(None);
        let day = Some(Duration::from_secs(24 * 3600));
        source.get(|| counting(&count, day)).await.unwrap();
        tokio::time::advance(Duration::from_secs(24 * 3600 - 72 * 60 - 1)).await;
        assert!(!source.get(|| counting(&count, day)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(source.get(|| counting(&count, day)).await.unwrap().fresh);

        // A maximum age caps the use of a long-lived token.
        let source = TokenSource::new(Some(Duration::from_secs(50 * 60)));
        source.get(|| counting(&count, day)).await.unwrap();
        tokio::time::advance(Duration::from_secs(50 * 60 - 1)).await;
        assert!(!source.get(|| counting(&count, day)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(source.get(|| counting(&count, day)).await.unwrap().fresh);

        // No stated lifetime: one hour is assumed.
        let source = TokenSource::new(None);
        source.get(|| counting(&count, None)).await.unwrap();
        tokio::time::advance(Duration::from_secs(50 * 60 - 1)).await;
        assert!(!source.get(|| counting(&count, None)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(source.get(|| counting(&count, None)).await.unwrap().fresh);

        // Ten minutes: the margin is at most half the lifetime, so renewal after five.
        let source = TokenSource::new(None);
        let ten = Some(Duration::from_secs(600));
        source.get(|| counting(&count, ten)).await.unwrap();
        tokio::time::advance(Duration::from_secs(5 * 60 - 1)).await;
        assert!(!source.get(|| counting(&count, ten)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(source.get(|| counting(&count, ten)).await.unwrap().fresh);

        // An implausibly short lifetime is still cached for half of it.
        let source = TokenSource::new(None);
        let short = Some(Duration::from_secs(60));
        source.get(|| counting(&count, short)).await.unwrap();
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(!source.get(|| counting(&count, short)).await.unwrap().fresh);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(source.get(|| counting(&count, short)).await.unwrap().fresh);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_fetch_leaves_nothing_behind() {
        let source = Arc::new(TokenSource::new(None));
        let started = Arc::new(AtomicUsize::new(0));
        // The first caller's fetch never finishes; its future is dropped by the timeout.
        let first = {
            let started = started.clone();
            source.get(move || async move {
                started.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<Result<Token, Error>>().await
            })
        };
        // A second caller is already waiting for the lock when the first is dropped.
        let waiter = {
            let source = source.clone();
            tokio::spawn(async move {
                source
                    .get(|| async { Ok(token("tok-after-cancel", None)) })
                    .await
                    .unwrap()
            })
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(5), first)
                .await
                .is_err()
        );
        assert_eq!(started.load(Ordering::SeqCst), 1);
        let lease = waiter.await.unwrap();
        assert!(lease.fresh);
        assert_eq!(lease.token.expose_secret(), "tok-after-cancel");
        // The source works normally afterwards.
        let again = source
            .get(|| async { Ok(token("unused", None)) })
            .await
            .unwrap();
        assert!(!again.fresh);
        assert_eq!(again.token.expose_secret(), "tok-after-cancel");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_fetch_stores_nothing() {
        let source = TokenSource::new(None);
        let e = source
            .get(|| async { Err(Error::auth("refused")) })
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Auth);
        let lease = source
            .get(|| async { Ok(token("tok", None)) })
            .await
            .unwrap();
        assert!(lease.fresh);
        assert_eq!(lease.generation, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn invalidation_names_the_generation() {
        let source = TokenSource::new(None);
        let count = Arc::new(AtomicUsize::new(0));
        let first = source.get(|| counting(&count, None)).await.unwrap();
        source.invalidate(first.generation).await;
        let second = source.get(|| counting(&count, None)).await.unwrap();
        assert!(second.fresh);
        assert_eq!(second.token.expose_secret(), "tok-2");
        // A late 401 for the first token does not discard the second.
        source.invalidate(first.generation).await;
        let third = source.get(|| counting(&count, None)).await.unwrap();
        assert!(!third.fresh);
        assert_eq!(third.generation, second.generation);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_implausibly_short_lifetime_is_logged_without_the_token() {
        let (capture, _guard) = crate::http::testing::echo::LogCapture::install();
        let source = TokenSource::new(None);
        let short = Some(Duration::from_secs(30));
        source
            .get(|| async { Ok(token("tok-short-canary", short)) })
            .await
            .unwrap();
        let normal = TokenSource::new(None);
        normal
            .get(|| async { Ok(token("tok-normal-canary", None)) })
            .await
            .unwrap();
        let warnings: Vec<_> = capture
            .entries()
            .into_iter()
            .filter(|e| e.level == tracing::Level::WARN)
            .collect();
        assert_eq!(warnings.len(), 1, "{}", capture.text());
        assert_eq!(warnings[0].field("lifetime_s"), Some("30"));
        assert!(!capture.text().contains("canary"), "{}", capture.text());
    }

    #[test]
    fn lifetimes_from_timestamps() {
        let future = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::from_secs(3600))
            .unwrap()
            .to_string();
        let left = lifetime_until(&future).unwrap();
        assert!(left > Duration::from_secs(3590) && left <= Duration::from_secs(3600));
        assert_eq!(lifetime_until("2000-01-01T00:00:00Z"), Some(Duration::ZERO));
        assert_eq!(
            lifetime_until("2099-01-01T00:00:00.123456+03:00").map(|d| d > Duration::ZERO),
            Some(true)
        );
        assert_eq!(lifetime_until("tomorrow"), None);
        assert!(!format!("{:?}", token("tok-canary", None)).contains("canary"));
    }
}
