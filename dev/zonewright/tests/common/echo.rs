//! Support for the secret tests (design section 12.2): canary credentials, the spellings in which
//! an API can echo them, assertions on text that leaves the crate, and a `tracing` capture.
//!
//! Used by the provider test files through `common`, and by the transport's unit tests, which
//! include this file by path. It therefore uses nothing from `zonewright` and works on text.

use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::DefaultGuard;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

/// A canary API token. Every canary contains `@`, a space, `/` and `+`, so that every encoding
/// changes it.
pub const CANARY_TOKEN: &str = "cAnaryT0ken @ p/q+r";

/// A canary password, with non-ASCII letters as well.
pub const CANARY_PASSWORD: &str = "cAnaryPa55 w@rd/x+y ключ";

/// A canary API key.
pub const CANARY_KEY: &str = "cAnaryK3y+z/w @v";

/// A canary user name or account identifier that arrives in the credentials object.
pub const CANARY_USER: &str = "cAnaryUs3r @dept/a+b";

/// Every canary above.
pub const CANARIES: [&str; 4] = [CANARY_TOKEN, CANARY_PASSWORD, CANARY_KEY, CANARY_USER];

/// The marker a scrubbed secret leaves.
pub const REDACTED: &str = "[redacted]";

/// Length of the fragments of a spelling that must not occur either.
const FRAGMENT: usize = 8;

/// WHATWG form-urlencoding of `s`, with `space` as the spelling of a space.
pub fn form_encode(s: &str, space: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(b));
            }
            b' ' => out.push_str(space),
            b => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Every spelling in which an API can echo `secret`: verbatim; form-urlencoded with `+` and with
/// `%20` for a space; the inside of a JSON string; JSON with `\/` and `\uXXXX` escapes; XML
/// escaped. Written independently of the crate's scrubber.
pub fn spellings(secret: &str) -> Vec<String> {
    let json = serde_json::to_string(secret).expect("a string serializes");
    let json = json[1..json.len() - 1].to_owned();
    let mut php = String::new();
    for c in json.chars() {
        match c {
            '/' => php.push_str("\\/"),
            c if c.is_ascii() => php.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(php, "\\u{unit:04x}");
                }
            }
        }
    }
    let xml = secret
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    let mut out = vec![
        secret.to_owned(),
        form_encode(secret, "+"),
        form_encode(secret, "%20"),
        json,
        php,
        xml,
    ];
    out.sort();
    out.dedup();
    out
}

/// The first spelling, or fragment of a spelling, of any of `secrets` found in `text`.
pub fn find_secret(text: &str, secrets: &[&str]) -> Option<String> {
    for secret in secrets {
        for spelling in spellings(secret) {
            if text.contains(&spelling) {
                return Some(format!("spelling {spelling:?}"));
            }
            let bytes = spelling.as_bytes();
            for start in 0..bytes.len().saturating_sub(FRAGMENT - 1) {
                if let Some(fragment) = spelling.get(start..start + FRAGMENT)
                    && text.contains(fragment)
                {
                    return Some(format!("fragment {fragment:?} of {spelling:?}"));
                }
            }
        }
    }
    None
}

/// Panics if `text` contains any spelling or fragment of `secrets`, or something that looks like
/// a JWT. `what` names the text in the message.
pub fn assert_clean(what: &str, text: &str, secrets: &[&str]) {
    if let Some(found) = find_secret(text, secrets) {
        panic!("{what} leaks a secret ({found}): {text}");
    }
    assert!(!text.contains("eyJ"), "{what} contains a JWT: {text}");
}

/// One `tracing` event or span as captured.
#[derive(Clone, Debug)]
pub struct Captured {
    /// The level.
    pub level: Level,
    /// The target.
    pub target: String,
    /// True for a span, false for an event.
    pub span: bool,
    /// Every field as `(name, value formatted with Debug)`, the message included.
    pub fields: Vec<(String, String)>,
}

impl Captured {
    /// The value of field `name`.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The field names.
    pub fn names(&self) -> Vec<&str> {
        self.fields.iter().map(|(n, _)| n.as_str()).collect()
    }
}

impl fmt::Display for Captured {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.level, self.target)?;
        for (name, value) in &self.fields {
            write!(f, " {name}={value}")?;
        }
        Ok(())
    }
}

struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_owned(), value.to_owned()));
    }
}

/// Keeps a [`LogCapture`] installed; dropping it ends the capture.
pub struct CaptureGuard {
    _default: DefaultGuard,
    _second: tracing::Dispatch,
}

/// Captures every `tracing` event and span, at every level, from every target.
#[derive(Clone, Default)]
pub struct LogCapture {
    entries: Arc<Mutex<Vec<Captured>>>,
}

impl LogCapture {
    /// Installs a capturing subscriber as the default of the current thread until the guard
    /// drops. Use it with a current-thread runtime, so that the code under test runs on this
    /// thread.
    pub fn install() -> (LogCapture, CaptureGuard) {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let default = tracing::subscriber::set_default(subscriber);
        // While exactly one dispatcher is registered, `tracing-core` computes the interest of a
        // callsite registered later from the default of the thread that hits it first. Tests on
        // other threads, without a subscriber, would then switch the transport's callsites off
        // for this capture too. A second registered dispatcher makes the interest consider
        // every registered dispatcher.
        let second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        (
            capture,
            CaptureGuard {
                _default: default,
                _second: second,
            },
        )
    }

    /// Everything captured so far.
    pub fn entries(&self) -> Vec<Captured> {
        self.entries.lock().expect("capture poisoned").clone()
    }

    /// Everything captured so far, one line per entry.
    pub fn text(&self) -> String {
        self.entries().iter().map(|e| format!("{e}\n")).collect()
    }

    fn push(&self, level: Level, target: &str, span: bool, fields: Fields) {
        self.entries
            .lock()
            .expect("capture poisoned")
            .push(Captured {
                level,
                target: target.to_owned(),
                span,
                fields: fields.0,
            });
    }
}

impl<S> Layer<S> for LogCapture
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields(Vec::new());
        event.record(&mut fields);
        let meta = event.metadata();
        self.push(*meta.level(), meta.target(), false, fields);
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        let mut fields = Fields(Vec::new());
        attrs.record(&mut fields);
        let meta = attrs.metadata();
        self.push(*meta.level(), meta.target(), true, fields);
    }

    fn on_record(&self, span: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields(Vec::new());
        values.record(&mut fields);
        let (level, target) = ctx
            .span(span)
            .map(|s| (*s.metadata().level(), s.metadata().target().to_owned()))
            .unwrap_or((Level::TRACE, String::new()));
        self.push(level, &target, true, fields);
    }
}
