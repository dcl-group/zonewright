//! Support for the secret tests (design section 12.2): canary credentials, the spellings in which
//! an API can echo them, assertions on text that leaves the crate, and a `tracing` capture.
//!
//! Used by the provider test files through `common`, and by the transport's unit tests, which
//! include this file by path. It therefore uses nothing from `zonewright` and works on text.
//!
//! The base of every `<id>_secret_echo` test: run the client against an echo server for each of
//! [`dialects`], with the [`CANARIES`] as credentials, and pass every error text, `Debug`
//! output and `ZoneCheck::detail` to [`assert_clean`].

use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::{DefaultGuard, Interest};
use tracing::{Dispatch, Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use zonewright_mock::echo::{self as echo_mock, Echo, Render, Spelling};

/// A canary API token. Every canary contains `@`, a space, `/`, `+`, both quotes,
/// `& < > \ ~ * =`, each next to letters, so that every encoding and escaping changes it and
/// any fragment of an encoded canary is distinctive. The canaries sent in headers (this one and
/// [`CANARY_KEY`]) contain no newline, which a header cannot carry; the others do.
pub const CANARY_TOKEN: &str = "cAnaryT0ken \"Qa' &Rb<Sc>Td\\Ue~Vf*Wg=Xh @ p/q+r";

/// A canary password, with a newline and non-ASCII letters as well.
pub const CANARY_PASSWORD: &str = "cAnaryPa55 \"Ka' &Lb<Mc>Nd\\Oe~Pf*Qg=Rh\nSi w@rd/x+y ключ";

/// A canary API key.
pub const CANARY_KEY: &str = "cAnaryK3y \"Za' &Yb<Xc>Wd\\Ve~Uf*Tg=Sh +z/w @v";

/// A canary user name or account identifier that arrives in the credentials object.
pub const CANARY_USER: &str = "cAnaryUs3r \"Ga' &Hb<Ic>Jd\\Ke~Lf*Mg=Nh\nOi @dept/a+b";

/// Every canary above.
pub const CANARIES: [&str; 4] = [CANARY_TOKEN, CANARY_PASSWORD, CANARY_KEY, CANARY_USER];

/// The marker a scrubbed secret leaves.
pub const REDACTED: &str = "[redacted]";

/// The start of the text of an error whose message was withheld as a whole because it quoted a
/// credential in a spelling that cannot be removed in place.
pub const WITHHELD: &str = "[redacted] (the provider's message was withheld";

/// One way an echo server spells and renders the request it repeats.
#[derive(Clone)]
pub struct Dialect {
    /// A short name for messages.
    pub name: &'static str,
    /// How the echoed text is spelled.
    pub spelling: Spelling,
    /// How the answer is rendered.
    pub render: Render,
}

impl Dialect {
    /// An echo server answering `status` in this dialect, not started yet.
    pub fn echo(&self, status: u16) -> Echo {
        Echo::new(status)
            .spelling(self.spelling)
            .render(self.render.clone())
    }
}

/// XML template of the XML dialects.
const XML_TEMPLATE: &str = "<Error><Code>Echo</Code><Message>{text}</Message></Error>";

/// Every dialect of the secret tests: each renderer with the text verbatim, and each
/// non-verbatim spelling inside JSON and plain text.
pub fn dialects() -> Vec<Dialect> {
    let renderers: Vec<(&'static str, Render)> = vec![
        ("json", echo_mock::json()),
        ("json_ascii", echo_mock::json_ascii()),
        (
            "json_ascii_with_notice",
            echo_mock::json_ascii_with_notice(),
        ),
        ("json_go", echo_mock::json_go()),
        ("json_dotnet", echo_mock::json_dotnet()),
        ("json_unicode", echo_mock::json_unicode()),
        ("json_in_json", echo_mock::json_in_json()),
        ("json_unknown_key", echo_mock::json_unknown_key()),
        ("form_json", echo_mock::form_json()),
        ("xml", echo_mock::xml(XML_TEMPLATE)),
        ("xml_numeric", echo_mock::xml_numeric(XML_TEMPLATE)),
        ("xml_minimal", echo_mock::xml_minimal(XML_TEMPLATE)),
        ("text", echo_mock::text()),
    ];
    let mut out: Vec<Dialect> = renderers
        .into_iter()
        .map(|(name, render)| Dialect {
            name,
            spelling: Spelling::Verbatim,
            render,
        })
        .collect();
    for spelling in Spelling::ALL {
        if spelling == Spelling::Verbatim {
            continue;
        }
        out.push(Dialect {
            name: "json",
            spelling,
            render: echo_mock::json(),
        });
        out.push(Dialect {
            name: "text",
            spelling,
            render: echo_mock::text(),
        });
    }
    out
}

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

/// Every spelling in which an API can echo `secret`: verbatim; form-urlencoded with `+`, with
/// `%20` and with lowercase hex; the percent-encodings of Python, JavaScript, RFC 3986 and Go;
/// form-encoded JSON; the inside of a JSON string as `serde_json`, PHP, Go and .NET write it, with
/// `\uXXXX` and a plain `/`, and nested in a second JSON string; XML with named entities, numeric
/// references, and `&` and `<` only. Written independently of the crate's scrubber.
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
    let percent = |safe: &[u8], space: &str, lower: bool| {
        let mut out = String::new();
        for b in secret.bytes() {
            if b.is_ascii_alphanumeric() || safe.contains(&b) {
                out.push(char::from(b));
            } else if b == b' ' {
                out.push_str(space);
            } else if lower {
                let _ = write!(out, "%{b:02x}");
            } else {
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    };
    let unit_escape = |escape: &dyn Fn(char) -> bool, upper: bool| {
        let mut out = String::new();
        for c in json.chars() {
            if escape(c) {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    if upper {
                        let _ = write!(out, "\\u{unit:04X}");
                    } else {
                        let _ = write!(out, "\\u{unit:04x}");
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    // Go escapes `< > &`; .NET also `' +` and every non-ASCII character (uppercase hex), and
    // `"` as `\u0022` instead of `\"`.
    let go = unit_escape(&|c| matches!(c, '<' | '>' | '&'), false);
    let dotnet = unit_escape(
        &|c| matches!(c, '\'' | '+' | '&' | '<' | '>') || !c.is_ascii(),
        true,
    )
    .replace("\\\"", "\\u0022");
    let unicode = unit_escape(&|c| !c.is_ascii(), false);
    let json_in_json = {
        let twice = serde_json::to_string(&json).expect("a string serializes");
        twice[1..twice.len() - 1].to_owned()
    };
    let numeric = secret
        .replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#x3E;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
        .replace('/', "&#x2F;");
    let minimal = secret.replace('&', "&amp;").replace('<', "&lt;");
    let mut out = vec![
        secret.to_owned(),
        form_encode(secret, "+"),
        form_encode(secret, "%20"),
        percent(b"*-._", "+", true),
        percent(b"_.-~/", "%20", false),
        percent(b"-_.!~*'()", "%20", false),
        percent(b"-._~", "%20", false),
        percent(b"-_.~", "+", false),
        form_encode(&json, "+"),
        json.clone(),
        php,
        go,
        dotnet,
        unicode,
        json_in_json,
        xml,
        numeric,
        minimal,
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
}

/// Captures every `tracing` event and span, at every level, from every target.
#[derive(Clone, Default)]
pub struct LogCapture {
    entries: Arc<Mutex<Vec<Captured>>>,
}

/// A subscriber that is never anybody's default and only takes part in the interest of every
/// callsite, answering "always". See [`pin_interest`].
struct AlwaysInterested;

impl Subscriber for AlwaysInterested {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, _: &Event<'_>) {}

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Makes the cached interest of every callsite in this process "always" or "sometimes", never
/// "never", for the rest of the process.
///
/// `tracing-core` (0.1.36, `callsite.rs`) caches in each callsite the combined interest of the
/// registered dispatchers. While at most one live dispatcher is registered (`has_just_one`),
/// it computes that interest without a lock from the default dispatcher of whichever thread
/// registers the callsite, which on a test thread without a capture is the no-op dispatcher:
/// "never". That computation can store its "never" after a capture's registration has rebuilt
/// the callsite, and the capture then misses every event of the callsite. Two dispatchers that
/// stay registered for the whole process keep `has_just_one` false, so every interest is
/// computed under the dispatcher lock from every live dispatcher; since these two answer
/// "always", the combination is never "never", and the macros ask the current thread's default
/// (the capture, or the no-op dispatcher) whether the event is enabled. They also keep the
/// global maximum level at `TRACE`.
fn pin_interest() {
    static PINNED: OnceLock<[Dispatch; 2]> = OnceLock::new();
    PINNED.get_or_init(|| {
        [
            Dispatch::new(AlwaysInterested),
            Dispatch::new(AlwaysInterested),
        ]
    });
}

impl LogCapture {
    /// Installs a capturing subscriber as the default of the current thread until the guard
    /// drops. Use it with a current-thread runtime, so that the code under test runs on this
    /// thread.
    pub fn install() -> (LogCapture, CaptureGuard) {
        pin_interest();
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let default = tracing::subscriber::set_default(subscriber);
        // A "never" computed before the dispatchers above were registered, by a thread that
        // was preempted in the middle of it, may have landed after their rebuild; this one runs
        // under the dispatcher lock and corrects it.
        tracing::callsite::rebuild_interest_cache();
        (capture, CaptureGuard { _default: default })
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
