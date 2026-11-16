//! Mock of the acme-dns HTTP API (`POST /update`, `GET /health`).
//!
//! Behavior follows the project's source, read on 2026-11-14 at commit
//! `43b0acaacef24d1058d70ed584d6b7275a8344ed` (<https://github.com/joohoi/acme-dns>), and its
//! README, "Update endpoint":
//!
//! - `pkg/api/auth.go`: authentication runs before the handler and answers `401` with
//!   `{"error": "forbidden"}` for every refusal: a user name that is not a UUID, a key that is not
//!   40 characters of `A-Z a-z 0-9 - _`, an unknown user, a wrong password, and a body whose
//!   `subdomain` is not the user's (a body that is not JSON decodes to an empty subdomain);
//! - `pkg/api/update.go`: a subdomain that fails `validSubdomain` is `400` `bad_subdomain`, a
//!   `txt` that fails `validTXT` is `400` `bad_txt`, a valid update is `200` with `{"txt": …}`;
//! - `pkg/api/util.go`: `validSubdomain` is `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`,
//!   `validTXT` is exactly 43 characters of `A-Z a-z 0-9 - _`;
//! - `pkg/database/db.go`, `Update`: the value is written into the registration's row with the
//!   oldest `LastUpdate`, without comparing values; every registration has two rows.
//!
//! Answers this mock invents because the documentation is silent:
//!
//! - the order of the two slots when `LastUpdate` ties: the server stamps rows with whole seconds
//!   and orders by nothing else, so two updates within one second can write the same row. The mock
//!   stamps every write with a counter instead, so the slots alternate strictly, the behavior the
//!   README describes ("rolling update of two TXT records"); the lower slot is written first.
//!   The time of every stored write is kept ([`Control::write_times`]), so that a test can check
//!   that the client keeps its writes to one registration at least a second apart;
//! - [`Seed::any_credential_form`] switches the format check of user names and keys off, for tests
//!   that need awkward credentials. Only the format check: the user name and the key must still
//!   equal those of a registration, so the switch cannot make wrong credentials pass;
//! - the `allowfrom` networks of a registration are not modeled: every source is allowed;
//! - the answer to any path or method other than the two above is the harness's `404`;
//! - error texts of injected faults are the fault's.
//!
//! A test holds an [`AcmeDnsMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = AcmeDnsMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("POST", "/update").status(502));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().values(&mock.control().subdomain(0)), ["…43 characters…"]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records through
//! [`AcmeDnsMock::changes`], and a [`link`](crate::link::link) serves them over DNS. The zone is
//! the server's own domain ([`Seed::domain`]); published is, per registration, the TXT rrset at
//! its `fulldomain` (`<subdomain>.<domain>`) with the values of its two slots, each as one quoted
//! character-string, a value held in both slots once, without a TTL (the mock does not model the
//! TTL of the server's answers). Left out: a slot that was never written (the mock does not model
//! what the server answers for an empty row), and the server's own records (its SOA, NS and A
//! records come from its configuration file, which the mock does not have). [`Control::reset`]
//! returns the mock to its seed.

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::changes::{ChangeSource, Changes, Origin, Published};
use crate::{Faults, MockServer, RequestLog};

/// One registration the server knows.
#[derive(Clone, Debug)]
pub struct Account {
    /// The user name (`X-Api-User`): a UUID.
    pub username: String,
    /// The key (`X-Api-Key`): 40 characters of `A-Z a-z 0-9 - _`.
    pub password: String,
    /// The subdomain the registration is served under.
    pub subdomain: String,
}

/// The state the mock starts from.
#[derive(Clone, Debug)]
pub struct Seed {
    /// The server's own domain, without a trailing dot.
    pub domain: String,
    /// The registrations.
    pub accounts: Vec<Account>,
    /// Test switch: accept user names and keys of any form, so that a test can use credentials
    /// that carry awkward characters. The server itself refuses a user name that is not a UUID
    /// and a key that is not 40 characters of its alphabet, before it looks them up.
    pub any_credential_form: bool,
}

impl Seed {
    /// The domain `auth.example.org` and two registrations.
    pub fn standard() -> Self {
        Self::numbered(2)
    }

    /// The domain `auth.example.org` and `count` registrations with generated credentials.
    pub fn numbered(count: usize) -> Self {
        let accounts = (0..count)
            .map(|i| Account {
                username: format!(
                    "c36f50e8-4632-4{:03x}-8{:03x}-{:012x}",
                    i % 4096,
                    i % 4096,
                    i
                ),
                password: format!("{i:04}htB9mR9DYgcu9bX_afHF62erXaH2TS7bg9KW"),
                subdomain: format!(
                    "8e5700ea-a4bf-4{:03x}-8{:03x}-{:012x}",
                    i % 4096,
                    i % 4096,
                    i
                ),
            })
            .collect();
        Self {
            domain: "auth.example.org".into(),
            accounts,
            any_credential_form: false,
        }
    }
}

/// One row of the server's table: a value and when it was written.
#[derive(Clone, Debug, Default)]
struct Slot {
    value: String,
    stamp: u64,
}

#[derive(Debug)]
struct Inner {
    seed: Seed,
    changes: Changes,
    /// Two slots per account, in the order of `seed.accounts`.
    slots: Vec<[Slot; 2]>,
    /// When each stored write happened, per account, oldest first.
    writes: Vec<Vec<Instant>>,
    clock: u64,
}

impl Inner {
    /// The state of a mock started with `seed`: every slot empty.
    fn new(seed: Seed, changes: Changes) -> Inner {
        let slots = seed.accounts.iter().map(|_| Default::default()).collect();
        let writes = seed.accounts.iter().map(|_| Vec::new()).collect();
        Inner {
            seed,
            changes,
            slots,
            writes,
            clock: 0,
        }
    }

    /// What the server's DNS side would answer (module documentation).
    fn published(&self) -> Published {
        let mut out = Published::new();
        let zone = &self.seed.domain;
        out.zone(zone);
        for (account, slots) in self.seed.accounts.iter().zip(&self.slots) {
            let name = format!("{}.{zone}", account.subdomain);
            for slot in slots.iter().filter(|s| !s.value.is_empty()) {
                // A value the server takes is 43 characters of `A-Z a-z 0-9 - _`: nothing to
                // escape. A control write can hold anything; `"` and `\` are escaped.
                let escaped = slot.value.replace('\\', "\\\\").replace('"', "\\\"");
                out.record(zone, &name, "TXT", None, format!("\"{escaped}\""));
            }
        }
        out
    }

    /// Reports every published rrset that differs from `before`. Called with the state locked,
    /// after a change.
    fn report(&self, before: &Published, origin: Origin) {
        self.changes.emit_diff(before, &self.published(), origin);
    }
}

type Shared = Arc<Mutex<Inner>>;

fn lock(state: &Shared) -> MutexGuard<'_, Inner> {
    // Every state of the mock is usable; a test that panicked elsewhere must not poison it.
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A running acme-dns mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue.
pub struct AcmeDnsMock {
    server: MockServer,
    control: Control,
}

/// Direct access to the mock's state, for assertions and for changes made behind the client's
/// back.
#[derive(Clone)]
pub struct Control {
    state: Shared,
    changes: Changes,
    log: RequestLog,
    faults: Faults,
}

impl Deref for AcmeDnsMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl AcmeDnsMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> AcmeDnsMock {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]).
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> AcmeDnsMock {
        let changes = Changes::new();
        let state: Shared = Arc::new(Mutex::new(Inner::new(seed, changes.clone())));
        let router = Router::new()
            .route("/update", post(update))
            .route("/health", get(|| async { StatusCode::OK }))
            .with_state(state.clone());
        let server = MockServer::start_on(addr, router).await;
        let control = Control {
            state,
            changes,
            log: server.log().clone(),
            faults: server.faults().clone(),
        };
        AcmeDnsMock { server, control }
    }

    /// The mock's state.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for AcmeDnsMock {
    fn changes(&self) -> &Changes {
        &self.control.changes
    }

    fn published(&self) -> Published {
        lock(&self.control.state).published()
    }
}

impl Control {
    /// Runs `f` on the locked state and reports what it changed, with [`Origin::Control`].
    fn change<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut inner = lock(&self.state);
        let before = inner.published();
        let out = f(&mut inner);
        inner.report(&before, Origin::Control);
        out
    }

    /// Returns the mock to the seed it was started with: its registrations with every slot
    /// empty, no recorded write times, an empty request log and no pending faults. Reports the
    /// removal of every rrset that was published.
    pub fn reset(&self) {
        self.faults.clear();
        self.change(|inner| {
            let seed = inner.seed.clone();
            *inner = Inner::new(seed, inner.changes.clone());
        });
        self.log.clear();
    }

    /// The `fulldomain` of registration `i`, without a trailing dot.
    pub fn fulldomain(&self, i: usize) -> String {
        let inner = lock(&self.state);
        let subdomain = inner
            .seed
            .accounts
            .get(i)
            .map(|a| a.subdomain.clone())
            .unwrap_or_default();
        format!("{subdomain}.{}", inner.seed.domain)
    }

    /// The subdomain of registration `i`.
    pub fn subdomain(&self, i: usize) -> String {
        lock(&self.state)
            .seed
            .accounts
            .get(i)
            .map(|a| a.subdomain.clone())
            .unwrap_or_default()
    }

    /// The answer of the server's register call for registration `i`.
    pub fn register_json(&self, i: usize) -> Value {
        let inner = lock(&self.state);
        let account = inner.seed.accounts.get(i);
        let subdomain = account.map(|a| a.subdomain.as_str()).unwrap_or_default();
        json!({
            "allowfrom": [],
            "fulldomain": format!("{subdomain}.{}", inner.seed.domain),
            "password": account.map(|a| a.password.as_str()).unwrap_or_default(),
            "subdomain": subdomain,
            "username": account.map(|a| a.username.as_str()).unwrap_or_default(),
        })
    }

    /// The answers of the register call for every registration, as the credentials' JSON text.
    pub fn registrations_text(&self) -> String {
        let count = lock(&self.state).seed.accounts.len();
        Value::Array((0..count).map(|i| self.register_json(i)).collect()).to_string()
    }

    /// The non-empty values the registration with `subdomain` holds, sorted.
    pub fn values(&self, subdomain: &str) -> Vec<String> {
        let inner = lock(&self.state);
        let mut out: Vec<String> = inner
            .seed
            .accounts
            .iter()
            .zip(&inner.slots)
            .filter(|(account, _)| account.subdomain == subdomain)
            .flat_map(|(_, slots)| slots.iter().map(|s| s.value.clone()))
            .filter(|v| !v.is_empty())
            .collect();
        out.sort();
        out
    }

    /// Writes `value` as another writer would, without a request: into the older slot.
    pub fn write(&self, subdomain: &str, value: &str) {
        self.change(|inner| {
            if let Some(i) = inner
                .seed
                .accounts
                .iter()
                .position(|a| a.subdomain == subdomain)
            {
                write_oldest(inner, i, value);
            }
        });
    }

    /// When each write to the registration with `subdomain` was stored, oldest first.
    pub fn write_times(&self, subdomain: &str) -> Vec<Instant> {
        let inner = lock(&self.state);
        inner
            .seed
            .accounts
            .iter()
            .position(|a| a.subdomain == subdomain)
            .and_then(|i| inner.writes.get(i).cloned())
            .unwrap_or_default()
    }

    /// Number of non-empty values across all registrations.
    pub fn stored(&self) -> usize {
        lock(&self.state)
            .slots
            .iter()
            .flatten()
            .filter(|s| !s.value.is_empty())
            .count()
    }
}

/// Overwrites the slot of account `i` with the oldest stamp, without comparing values.
fn write_oldest(inner: &mut Inner, i: usize, value: &str) {
    inner.clock += 1;
    let stamp = inner.clock;
    if let Some(slots) = inner.slots.get_mut(i) {
        let oldest = if slots[1].stamp < slots[0].stamp {
            1
        } else {
            0
        };
        slots[oldest] = Slot {
            value: value.to_owned(),
            stamp,
        };
    }
    if let Some(times) = inner.writes.get_mut(i) {
        times.push(Instant::now());
    }
}

/// The body of an update; whatever fails to decode leaves the fields empty, as in the server.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Update {
    subdomain: String,
    txt: String,
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(json!({ "error": code }))).into_response()
}

fn alphabet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// `uuid.Parse` as far as a UUID in its canonical spelling goes.
fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_key(key: &str) -> bool {
    key.chars().count() == 40 && key.bytes().all(alphabet)
}

/// `validSubdomain`.
fn valid_subdomain(s: &str) -> bool {
    let bytes = s.as_bytes();
    let edge = |b: &u8| b.is_ascii_alphanumeric();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// `validTXT`.
fn valid_txt(s: &str) -> bool {
    s.chars().count() == 43 && s.bytes().all(alphabet)
}

async fn update(State(state): State<Shared>, headers: HeaderMap, body: String) -> Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let (username, key) = (header("x-api-user"), header("x-api-key"));
    let post: Update = serde_json::from_str(&body).unwrap_or_default();
    let mut inner = lock(&state);
    let account = if inner.seed.any_credential_form || (is_uuid(&username) && valid_key(&key)) {
        inner
            .seed
            .accounts
            .iter()
            .position(|a| a.username == username && a.password == key)
    } else {
        None
    };
    // Authentication: the user, the key and the subdomain of the body.
    let Some(i) = account.filter(|&i| {
        inner
            .seed
            .accounts
            .get(i)
            .is_some_and(|a| a.subdomain == post.subdomain)
    }) else {
        return error(StatusCode::UNAUTHORIZED, "forbidden");
    };
    if !valid_subdomain(&post.subdomain) {
        return error(StatusCode::BAD_REQUEST, "bad_subdomain");
    }
    if !valid_txt(&post.txt) {
        return error(StatusCode::BAD_REQUEST, "bad_txt");
    }
    let before = inner.published();
    write_oldest(&mut inner, i, &post.txt);
    inner.report(&before, Origin::Api);
    (StatusCode::OK, axum::Json(json!({ "txt": post.txt }))).into_response()
}
