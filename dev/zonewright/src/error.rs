//! The error type of provider operations (design section 2.9).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::id::ProviderId;
use crate::name::DomainName;
use crate::record::RecordType;
use crate::redact::Detail;

/// An error of a provider operation, of building a client, or of building a [`Context`].
///
/// `Error` is `Clone + Send + Sync + 'static` and has no `source()`: the errors of the HTTP
/// stack are not exposed, because their text can contain a URL with a query string. Every text it
/// carries is a [`Detail`]: at most 512 bytes, no control characters, and inside the crate built
/// either from a constant or by a scrubber that removed the client's secrets. The one exception
/// is a [`ProviderCode`], which is narrower still.
///
/// [`ErrorKind`] is what an application switches on and maps to its own codes.
///
/// [`Context`]: crate::Context
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Settings or credentials are malformed, the context could not be built, or it cannot do
    /// what is asked of it (no CA certificates to verify an HTTPS endpoint with).
    #[error("invalid provider configuration: {detail}")]
    #[non_exhaustive]
    Config {
        /// What is wrong. Never quotes a configured value.
        detail: Detail,
    },

    /// The provider's cargo feature is not enabled in this build.
    #[error("provider {provider} is not compiled into this build")]
    #[non_exhaustive]
    NotCompiled {
        /// The provider.
        provider: ProviderId,
    },

    /// The provider's client does not offer this operation (its capability flag is false).
    #[error("provider {provider} does not support {operation}")]
    #[non_exhaustive]
    Unsupported {
        /// The provider.
        provider: ProviderId,
        /// The operation.
        operation: Operation,
    },

    /// The record type is outside the provider's `record_types`, or a write was asked for a
    /// read-only type.
    #[error("provider {provider} does not support record type {rtype}")]
    #[non_exhaustive]
    UnsupportedRecordType {
        /// The provider.
        provider: ProviderId,
        /// The record type.
        rtype: RecordType,
    },

    /// The request cannot be sent as given: a value the provider's encoding cannot carry, a TTL
    /// outside the provider's range, a wildcard zone, an rrset over the provider's size limit.
    #[error("invalid request: {detail}")]
    #[non_exhaustive]
    InvalidInput {
        /// What is wrong.
        detail: Detail,
        /// The provider's own code for the refusal, when it gave one.
        code: Option<ProviderCode>,
    },

    /// The owner name is not the zone or below it.
    #[error("name {name} is outside zone {zone}")]
    #[non_exhaustive]
    NameOutsideZone {
        /// The owner name.
        name: DomainName,
        /// The zone.
        zone: DomainName,
    },

    /// The zone does not exist at the provider or is not visible to these credentials.
    #[error("zone {zone} not found at the provider")]
    #[non_exhaustive]
    ZoneNotFound {
        /// The zone.
        zone: DomainName,
    },

    /// The proxy of the context ([`ContextOptions::proxy`]) refused the proxy credentials, or
    /// demanded credentials that were not configured: an HTTP proxy answered `407`, or a SOCKS5
    /// proxy refused the username and password (RFC 1929) or the authentication method offered.
    /// The credentials belong to the configuration of the context, not to the provider, so this
    /// is never [`Error::Auth`]. Not retryable; the text is fixed and names neither the proxy nor
    /// a credential.
    ///
    /// [`ContextOptions::proxy`]: crate::ContextOptions::proxy
    #[error("the proxy refused the proxy credentials; check proxy.username and proxy.password")]
    #[non_exhaustive]
    ProxyAuth {},

    /// The provider did not accept the credentials.
    #[error("provider authentication failed: {detail}")]
    #[non_exhaustive]
    Auth {
        /// The provider's reason, scrubbed.
        detail: Detail,
    },

    /// The credentials are valid but lack a permission.
    #[error("provider denied access: {detail}")]
    #[non_exhaustive]
    Forbidden {
        /// The provider's reason, scrubbed.
        detail: Detail,
    },

    /// The provider's rate limit was reached. `retry_after` is how long to wait, counted from
    /// the moment the error was returned.
    #[error("provider rate limit reached")]
    #[non_exhaustive]
    RateLimited {
        /// How long to wait, when the provider said.
        retry_after: Option<Duration>,
    },

    /// The caller's `Expect` does not hold for the rrset as it is at the provider. Repeating the
    /// same call gives the same answer until someone changes the rrset or the expectation.
    #[error("precondition failed: {detail}")]
    #[non_exhaustive]
    PreconditionFailed {
        /// What did not hold.
        detail: Detail,
    },

    /// The provider detected that the rrset changed between this operation's read and its
    /// write, and nothing was written. Repeating the call reads the new state.
    #[error("concurrent change: {detail}")]
    #[non_exhaustive]
    Conflict {
        /// What changed.
        detail: Detail,
    },

    /// Network failure, timeout, a 5xx answer, or a provider-side operation still running.
    /// The outcome of a write may be unknown.
    #[error("transient provider error: {detail}")]
    #[non_exhaustive]
    Transient {
        /// What failed.
        detail: Detail,
    },

    /// The provider understood the request and refused it. `status` is the HTTP status when the
    /// refusal was an HTTP-level one.
    #[error("provider rejected the request: {detail}")]
    #[non_exhaustive]
    Rejected {
        /// The HTTP status, when there was one.
        status: Option<u16>,
        /// The provider's reason, scrubbed.
        detail: Detail,
        /// The provider's own code for the refusal, when it gave one.
        code: Option<ProviderCode>,
    },

    /// The provider answered with something the client cannot interpret.
    #[error("unexpected provider response: {detail}")]
    #[non_exhaustive]
    Protocol {
        /// What was unexpected.
        detail: Detail,
    },
}

impl Error {
    /// The kind of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Config { .. } => ErrorKind::Config,
            Error::NotCompiled { .. } => ErrorKind::NotCompiled,
            Error::Unsupported { .. } => ErrorKind::Unsupported,
            Error::UnsupportedRecordType { .. } => ErrorKind::UnsupportedRecordType,
            Error::InvalidInput { .. } => ErrorKind::InvalidInput,
            Error::NameOutsideZone { .. } => ErrorKind::NameOutsideZone,
            Error::ZoneNotFound { .. } => ErrorKind::ZoneNotFound,
            Error::ProxyAuth { .. } => ErrorKind::ProxyAuth,
            Error::Auth { .. } => ErrorKind::Auth,
            Error::Forbidden { .. } => ErrorKind::Forbidden,
            Error::RateLimited { .. } => ErrorKind::RateLimited,
            Error::PreconditionFailed { .. } => ErrorKind::PreconditionFailed,
            Error::Conflict { .. } => ErrorKind::Conflict,
            Error::Transient { .. } => ErrorKind::Transient,
            Error::Rejected { .. } => ErrorKind::Rejected,
            Error::Protocol { .. } => ErrorKind::Protocol,
        }
    }

    /// True for `RateLimited`, `Conflict` and `Transient`: repeating the same operation later
    /// can succeed without anyone changing anything.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            ErrorKind::RateLimited | ErrorKind::Conflict | ErrorKind::Transient
        )
    }

    /// The wait the provider asked for, for `RateLimited`; `None` otherwise.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Error::RateLimited { retry_after } => *retry_after,
            _ => None,
        }
    }

    /// The provider's own code for the refusal, for `Rejected` and `InvalidInput` when the
    /// provider gave one; `None` otherwise. See [`ProviderCode`].
    #[must_use]
    pub fn provider_code(&self) -> Option<&ProviderCode> {
        match self {
            Error::Rejected { code, .. } | Error::InvalidInput { code, .. } => code.as_ref(),
            _ => None,
        }
    }

    /// This error with `code` as its provider code, for `Rejected` and `InvalidInput`; any
    /// other error is returned unchanged.
    #[cfg_attr(not(feature = "cloud_ru"), allow(dead_code))]
    pub(crate) fn with_code(mut self, code: Option<ProviderCode>) -> Error {
        if let Error::Rejected { code: slot, .. } | Error::InvalidInput { code: slot, .. } =
            &mut self
        {
            *slot = code;
        }
        self
    }

    // Constructors for implementations of `Provider` outside the crate. Text arguments become a
    // `Detail` through `Detail::new`, which bounds and cleans the text and knows no secret.
    // Provider clients inside the crate never call the ones that take text (a conformance test
    // scans for it); they build their `Detail` through a scrubber or from a constant.

    /// `Error::Config`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn config(detail: &str) -> Error {
        Error::Config {
            detail: Detail::new(detail),
        }
    }

    /// `Error::NotCompiled`.
    #[must_use]
    pub fn not_compiled(provider: ProviderId) -> Error {
        Error::NotCompiled { provider }
    }

    /// `Error::Unsupported`.
    #[must_use]
    pub fn unsupported(provider: ProviderId, operation: Operation) -> Error {
        Error::Unsupported {
            provider,
            operation,
        }
    }

    /// `Error::UnsupportedRecordType`.
    #[must_use]
    pub fn unsupported_record_type(provider: ProviderId, rtype: RecordType) -> Error {
        Error::UnsupportedRecordType { provider, rtype }
    }

    /// `Error::InvalidInput`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn invalid_input(detail: &str) -> Error {
        Error::InvalidInput {
            detail: Detail::new(detail),
            code: None,
        }
    }

    /// `Error::NameOutsideZone`.
    #[must_use]
    pub fn name_outside_zone(name: DomainName, zone: DomainName) -> Error {
        Error::NameOutsideZone { name, zone }
    }

    /// `Error::ZoneNotFound`.
    #[must_use]
    pub fn zone_not_found(zone: DomainName) -> Error {
        Error::ZoneNotFound { zone }
    }

    /// `Error::ProxyAuth`.
    #[must_use]
    pub fn proxy_auth() -> Error {
        Error::ProxyAuth {}
    }

    /// `Error::Auth`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn auth(detail: &str) -> Error {
        Error::Auth {
            detail: Detail::new(detail),
        }
    }

    /// `Error::Forbidden`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn forbidden(detail: &str) -> Error {
        Error::Forbidden {
            detail: Detail::new(detail),
        }
    }

    /// `Error::RateLimited`.
    #[must_use]
    pub fn rate_limited(retry_after: Option<Duration>) -> Error {
        Error::RateLimited { retry_after }
    }

    /// `Error::PreconditionFailed`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn precondition_failed(detail: &str) -> Error {
        Error::PreconditionFailed {
            detail: Detail::new(detail),
        }
    }

    /// `Error::Conflict`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn conflict(detail: &str) -> Error {
        Error::Conflict {
            detail: Detail::new(detail),
        }
    }

    /// `Error::Transient`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn transient(detail: &str) -> Error {
        Error::Transient {
            detail: Detail::new(detail),
        }
    }

    /// `Error::Rejected`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn rejected(status: Option<u16>, detail: &str) -> Error {
        Error::Rejected {
            status,
            detail: Detail::new(detail),
            code: None,
        }
    }

    /// `Error::Protocol`. The caller keeps secrets out of `detail`.
    #[must_use]
    pub fn protocol(detail: &str) -> Error {
        Error::Protocol {
            detail: Detail::new(detail),
        }
    }

    /// The `Config` error for a settings object that does not deserialize, for provider clients.
    ///
    /// The text is built from the position only. The deserializer's own message is not used: it
    /// can quote the input.
    #[cfg(any(
        feature = "acme_dns",
        feature = "beget",
        feature = "cloud_ru",
        feature = "cloudflare",
        feature = "digitalocean",
        feature = "hetzner",
        feature = "nicru",
        feature = "regru",
        feature = "rfc2136",
        feature = "route53",
        feature = "selectel_v2",
        feature = "timeweb_cloud",
        feature = "vk_cloud",
        feature = "yandex_360",
        feature = "yandex_cloud"
    ))]
    pub(crate) fn settings_syntax(line: usize, column: usize) -> Error {
        Error::Config {
            detail: Detail::new(&format!(
                "the settings are not a valid settings object (line {line}, column {column}); \
                 unknown keys are refused"
            )),
        }
    }
}

/// Longest [`ProviderCode`] in bytes.
const PROVIDER_CODE_MAX_BYTES: usize = 64;

/// A provider's own machine-readable code for a refusal, carried by [`Error::Rejected`] and
/// [`Error::InvalidInput`] and returned by [`Error::provider_code`].
///
/// The value is the provider's, as its API sent it: for example reg.ru's
/// `TEXT_CONTAINS_INVALID_CHARACTERS` or a Route 53 `InvalidChangeBatch`; a numeric code, such as
/// Cloudflare's, is carried in decimal. It is stable only as far as the provider keeps it stable,
/// and the same text can mean different things at different providers, so an application matches
/// on the pair of [`ProviderId`] and code. Absence means the provider gave no code, or the crate
/// does not read one for that provider; a refusal the client decides itself, before sending,
/// has none.
///
/// A code is 1 to 64 bytes of ASCII letters, digits and `_ - . :`. The crate takes it only from
/// the field the provider defines as its error code; a text outside these rules, or one that
/// quotes a credential of the client, is not carried at all, never cut or altered.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProviderCode(Arc<str>);

impl ProviderCode {
    /// A code from the provider's text; `None` when it is empty, longer than 64 bytes, or holds
    /// a character outside the alphabet.
    #[cfg_attr(not(feature = "__http"), allow(dead_code))]
    pub(crate) fn new(text: &str) -> Option<ProviderCode> {
        let valid = !text.is_empty()
            && text.len() <= PROVIDER_CODE_MAX_BYTES
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'));
        valid.then(|| ProviderCode(Arc::from(text)))
    }

    /// The code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ProviderCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

/// The kind of an [`Error`], with a stable identifier for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// [`Error::Config`].
    Config,
    /// [`Error::NotCompiled`].
    NotCompiled,
    /// [`Error::Unsupported`].
    Unsupported,
    /// [`Error::UnsupportedRecordType`].
    UnsupportedRecordType,
    /// [`Error::InvalidInput`].
    InvalidInput,
    /// [`Error::NameOutsideZone`].
    NameOutsideZone,
    /// [`Error::ZoneNotFound`].
    ZoneNotFound,
    /// [`Error::ProxyAuth`].
    ProxyAuth,
    /// [`Error::Auth`].
    Auth,
    /// [`Error::Forbidden`].
    Forbidden,
    /// [`Error::RateLimited`].
    RateLimited,
    /// [`Error::PreconditionFailed`].
    PreconditionFailed,
    /// [`Error::Conflict`].
    Conflict,
    /// [`Error::Transient`].
    Transient,
    /// [`Error::Rejected`].
    Rejected,
    /// [`Error::Protocol`].
    Protocol,
}

impl ErrorKind {
    /// Every kind this version of the crate knows, each once, in declaration order.
    ///
    /// An application that maps kinds to its own error codes can walk this list in a test to
    /// notice a kind added by a newer version of the crate, which a `match` with a wildcard arm
    /// (required, since the enum is `#[non_exhaustive]`) would otherwise absorb silently. The
    /// list grows when a kind is added; that is not a breaking change.
    pub const ALL: &'static [ErrorKind] = &[
        ErrorKind::Config,
        ErrorKind::NotCompiled,
        ErrorKind::Unsupported,
        ErrorKind::UnsupportedRecordType,
        ErrorKind::InvalidInput,
        ErrorKind::NameOutsideZone,
        ErrorKind::ZoneNotFound,
        ErrorKind::ProxyAuth,
        ErrorKind::Auth,
        ErrorKind::Forbidden,
        ErrorKind::RateLimited,
        ErrorKind::PreconditionFailed,
        ErrorKind::Conflict,
        ErrorKind::Transient,
        ErrorKind::Rejected,
        ErrorKind::Protocol,
    ];

    /// Stable snake_case identifier: `"config"`, `"not_compiled"`, ..., `"protocol"`. Part of
    /// the public API: applications map these to their own error codes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Config => "config",
            ErrorKind::NotCompiled => "not_compiled",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::UnsupportedRecordType => "unsupported_record_type",
            ErrorKind::InvalidInput => "invalid_input",
            ErrorKind::NameOutsideZone => "name_outside_zone",
            ErrorKind::ZoneNotFound => "zone_not_found",
            ErrorKind::ProxyAuth => "proxy_auth",
            ErrorKind::Auth => "auth",
            ErrorKind::Forbidden => "forbidden",
            ErrorKind::RateLimited => "rate_limited",
            ErrorKind::PreconditionFailed => "precondition_failed",
            ErrorKind::Conflict => "conflict",
            ErrorKind::Transient => "transient",
            ErrorKind::Rejected => "rejected",
            ErrorKind::Protocol => "protocol",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A provider operation: the methods of [`Provider`](crate::Provider).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Operation {
    /// [`Provider::check`](crate::Provider::check).
    Check,
    /// [`Provider::list_zones`](crate::Provider::list_zones).
    ListZones,
    /// [`Provider::list_rrsets`](crate::Provider::list_rrsets).
    ListRrsets,
    /// [`Provider::get_rrset`](crate::Provider::get_rrset).
    GetRrset,
    /// [`Provider::set_rrset`](crate::Provider::set_rrset).
    SetRrset,
    /// [`Provider::delete_rrset`](crate::Provider::delete_rrset).
    DeleteRrset,
    /// [`Provider::add_txt_value`](crate::Provider::add_txt_value).
    AddTxtValue,
    /// [`Provider::remove_txt_value`](crate::Provider::remove_txt_value).
    RemoveTxtValue,
}

impl Operation {
    /// Stable snake_case identifier, the same as `Display`: `"check"`, `"list_zones"`, ...
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Operation::Check => "check",
            Operation::ListZones => "list_zones",
            Operation::ListRrsets => "list_rrsets",
            Operation::GetRrset => "get_rrset",
            Operation::SetRrset => "set_rrset",
            Operation::DeleteRrset => "delete_rrset",
            Operation::AddTxtValue => "add_txt_value",
            Operation::RemoveTxtValue => "remove_txt_value",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind, ProviderCode};
    use crate::redact::Detail;
    use std::time::Duration;

    #[test]
    fn provider_code_accepts_the_alphabet() {
        for text in [
            "TEXT_CONTAINS_INVALID_CHARACTERS",
            "81057",
            "-1",
            "InvalidChangeBatch",
            "a.b:c-d_e",
            "x",
        ] {
            let code = ProviderCode::new(text).expect(text);
            assert_eq!(code.as_str(), text);
            assert_eq!(code.to_string(), text);
            assert_eq!(format!("{code:?}"), format!("{text:?}"));
            assert_eq!(code.clone(), code);
        }
    }

    #[test]
    fn provider_code_refuses_other_texts() {
        for text in [
            "",
            " ",
            "a b",
            "a/b",
            "a\nb",
            "a\u{0}",
            "код",
            "a\"b",
            "a=b",
            "a+b",
            "a%2F",
            "[redacted]",
        ] {
            assert!(ProviderCode::new(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn provider_code_length_boundary() {
        assert!(ProviderCode::new(&"a".repeat(64)).is_some());
        assert!(ProviderCode::new(&"a".repeat(65)).is_none());
    }

    #[test]
    fn provider_code_only_for_rejected_and_invalid_input() {
        let code = ProviderCode::new("E1");
        let rejected = Error::rejected(Some(400), "r").with_code(code.clone());
        assert_eq!(rejected.provider_code(), code.as_ref());
        assert_eq!(rejected.kind(), ErrorKind::Rejected);
        assert_eq!(rejected.to_string(), "provider rejected the request: r");
        let invalid = Error::invalid_input("i").with_code(code.clone());
        assert_eq!(invalid.provider_code(), code.as_ref());
        assert_eq!(invalid.to_string(), "invalid request: i");
        assert_eq!(Error::rejected(None, "r").provider_code(), None);
        assert_eq!(Error::invalid_input("i").provider_code(), None);
        let others = [
            Error::config("c"),
            Error::not_compiled(crate::ProviderId::Cloudflare),
            Error::unsupported(crate::ProviderId::Cloudflare, super::Operation::Check),
            Error::proxy_auth(),
            Error::auth("a"),
            Error::forbidden("f"),
            Error::rate_limited(None),
            Error::precondition_failed("p"),
            Error::conflict("c"),
            Error::transient("t"),
            Error::protocol("p"),
            Error::Protocol {
                detail: Detail::constant("p"),
            },
        ];
        for error in others {
            assert_eq!(
                error.clone().with_code(code.clone()).provider_code(),
                None,
                "{error}"
            );
        }
    }

    #[test]
    fn error_is_send_sync_static_clone() {
        fn assert_traits<T: Send + Sync + Clone + 'static + std::error::Error>() {}
        assert_traits::<Error>();
    }

    #[test]
    fn error_has_no_source() {
        use std::error::Error as _;
        assert!(Error::transient("x").source().is_none());
    }

    #[test]
    fn retryability_follows_the_kind() {
        assert!(Error::rate_limited(None).is_retryable());
        assert!(Error::conflict("c").is_retryable());
        assert!(Error::transient("t").is_retryable());
        assert!(!Error::precondition_failed("p").is_retryable());
        assert!(!Error::rejected(Some(400), "r").is_retryable());
        assert!(!Error::proxy_auth().is_retryable());
        assert_eq!(Error::proxy_auth().retry_after(), None);
        assert_eq!(Error::proxy_auth().kind(), ErrorKind::ProxyAuth);
        assert_eq!(
            Error::rate_limited(Some(Duration::from_secs(3))).retry_after(),
            Some(Duration::from_secs(3))
        );
        assert_eq!(Error::transient("t").retry_after(), None);
    }

    #[test]
    fn all_lists_every_kind_once() {
        // No wildcard arm: a new kind does not compile until it is given the next position
        // here, and then the assertions fail until it is added to `ALL` at that position.
        fn position(kind: ErrorKind) -> usize {
            match kind {
                ErrorKind::Config => 0,
                ErrorKind::NotCompiled => 1,
                ErrorKind::Unsupported => 2,
                ErrorKind::UnsupportedRecordType => 3,
                ErrorKind::InvalidInput => 4,
                ErrorKind::NameOutsideZone => 5,
                ErrorKind::ZoneNotFound => 6,
                ErrorKind::ProxyAuth => 7,
                ErrorKind::Auth => 8,
                ErrorKind::Forbidden => 9,
                ErrorKind::RateLimited => 10,
                ErrorKind::PreconditionFailed => 11,
                ErrorKind::Conflict => 12,
                ErrorKind::Transient => 13,
                ErrorKind::Rejected => 14,
                ErrorKind::Protocol => 15,
            }
        }
        const COUNT: usize = 16;
        assert_eq!(ErrorKind::ALL.len(), COUNT);
        for (i, kind) in ErrorKind::ALL.iter().enumerate() {
            assert_eq!(position(*kind), i, "{kind}");
        }
        let mut names: Vec<&str> = ErrorKind::ALL.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), COUNT);
    }

    #[test]
    fn constructors_bound_the_text() {
        let long = "a\nb".repeat(400);
        let Error::Protocol { detail } = Error::protocol(&long) else {
            panic!("wrong variant");
        };
        assert!(detail.as_str().len() <= 512);
        assert!(!detail.as_str().contains('\n'));
        assert_eq!(Error::protocol("x").kind(), ErrorKind::Protocol);
    }
}
