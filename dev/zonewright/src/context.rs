//! The state shared by all clients of one process (design section 2.8).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::locks::NameLocks;
use crate::redact::Detail;

/// Most characters of [`ContextOptions::user_agent_suffix`].
const USER_AGENT_SUFFIX_MAX: usize = 128;

/// State shared by all clients of one process: the HTTP client, the per-name locks and the
/// process-local memory of the providers that need one. Cheap to clone; clones share the state.
///
/// The application creates one `Context` per process and builds every client from it.
/// Per-name serialization of mutating operations holds between clients that share a `Context`,
/// and not between clients built from different ones.
#[derive(Clone)]
pub struct Context {
    inner: Arc<Inner>,
}

/// The shared state behind a [`Context`].
struct Inner {
    options: ContextOptions,
    /// Per-name locks of all mutating operations (design section 3.3).
    locks: NameLocks,
    // HTTP TRANSPORT (core phase): the transport adds its client here, behind `__http`, as
    // `http: crate::http::Transport`, built in `Context::new` from `options`, together with a
    // `pub(crate)` accessor below. Nothing else in this file needs to change for it.
    /// Process-local memory of the acme-dns client (design section 11.3).
    #[cfg(feature = "acme_dns")]
    acme_dns: crate::providers::acme_dns::State,
    /// Zone locks and staged-change marks of the nic.ru client (design section 11.3).
    #[cfg(feature = "nicru")]
    nicru: crate::providers::nicru::State,
    /// Memory of records the Timeweb Cloud client created (design section 11.3).
    #[cfg(feature = "timeweb_cloud")]
    timeweb_cloud: crate::providers::timeweb_cloud::State,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("options", &self.inner.options)
            .field("locks", &self.inner.locks)
            .finish_non_exhaustive()
    }
}

impl Context {
    /// Builds the shared state. Fails with [`Error::Config`] when an option is invalid.
    pub fn new(options: ContextOptions) -> Result<Context, Error> {
        options.validate()?;
        // HTTP TRANSPORT (core phase): build the HTTP client from `options` here.
        Ok(Context {
            inner: Arc::new(Inner {
                options,
                locks: NameLocks::new(),
                #[cfg(feature = "acme_dns")]
                acme_dns: crate::providers::acme_dns::State::default(),
                #[cfg(feature = "nicru")]
                nicru: crate::providers::nicru::State::default(),
                #[cfg(feature = "timeweb_cloud")]
                timeweb_cloud: crate::providers::timeweb_cloud::State::default(),
            }),
        })
    }

    /// The options the context was built with.
    // TEMPORARY (core phase): read by the transport and the RFC 2136 client, which come later.
    #[allow(dead_code)]
    pub(crate) fn options(&self) -> &ContextOptions {
        &self.inner.options
    }

    /// The per-name locks. A client passes them to the TXT value layer, or takes a lock itself
    /// for a record-level write.
    // TEMPORARY (core phase): used by the first client that is ported.
    #[allow(dead_code)]
    pub(crate) fn locks(&self) -> &NameLocks {
        &self.inner.locks
    }

    /// The acme-dns client's memory.
    #[cfg(feature = "acme_dns")]
    // TEMPORARY (core phase): used by the acme-dns client when it is ported.
    #[allow(dead_code)]
    pub(crate) fn acme_dns(&self) -> &crate::providers::acme_dns::State {
        &self.inner.acme_dns
    }

    /// The nic.ru client's zone locks and staged-change marks.
    #[cfg(feature = "nicru")]
    // TEMPORARY (core phase): used by the nic.ru client when it is ported.
    #[allow(dead_code)]
    pub(crate) fn nicru(&self) -> &crate::providers::nicru::State {
        &self.inner.nicru
    }

    /// The Timeweb Cloud client's memory of created records.
    #[cfg(feature = "timeweb_cloud")]
    // TEMPORARY (core phase): used by the Timeweb Cloud client when it is ported.
    #[allow(dead_code)]
    pub(crate) fn timeweb_cloud(&self) -> &crate::providers::timeweb_cloud::State {
        &self.inner.timeweb_cloud
    }
}

/// Options of a [`Context`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContextOptions {
    /// Appended to the user agent: `zonewright/<version> <suffix>`. At most 128 characters,
    /// printable ASCII.
    pub user_agent_suffix: Option<String>,
    /// TCP and TLS connect timeout. Default 10 s.
    pub connect_timeout: Duration,
    /// Limit for one HTTP request from start to the end of the body. Default 30 s.
    pub request_timeout: Duration,
    /// DER-encoded certificates trusted in addition to the platform's roots.
    pub extra_root_certificates: Vec<Vec<u8>>,
    /// Refuse to connect to anything but loopback addresses. For tests. Default false.
    pub loopback_only: bool,
}

impl Default for ContextOptions {
    fn default() -> ContextOptions {
        ContextOptions {
            user_agent_suffix: None,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            extra_root_certificates: Vec::new(),
            loopback_only: false,
        }
    }
}

impl ContextOptions {
    /// Checks what can be checked without the HTTP stack. The texts name the option, never its
    /// value.
    fn validate(&self) -> Result<(), Error> {
        if let Some(suffix) = &self.user_agent_suffix {
            let printable = suffix.bytes().all(|b| (0x20..=0x7e).contains(&b));
            if suffix.is_empty() || suffix.len() > USER_AGENT_SUFFIX_MAX || !printable {
                return Err(config(
                    "user_agent_suffix must be 1 to 128 printable ASCII characters",
                ));
            }
        }
        if self.connect_timeout.is_zero() {
            return Err(config("connect_timeout must be greater than zero"));
        }
        if self.request_timeout.is_zero() {
            return Err(config("request_timeout must be greater than zero"));
        }
        Ok(())
    }
}

fn config(text: &'static str) -> Error {
    Error::Config {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Context, ContextOptions};
    use crate::error::ErrorKind;

    #[test]
    fn defaults() {
        let options = ContextOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.request_timeout, Duration::from_secs(30));
        assert!(!options.loopback_only);
        let ctx = Context::new(options).unwrap();
        assert_eq!(ctx.locks().len(), 0);
        let _clone = ctx.clone();
    }

    #[test]
    fn invalid_options_are_config_errors_without_the_value() {
        for suffix in ["", "tab\there", "ü", &"a".repeat(129)] {
            let options = ContextOptions {
                user_agent_suffix: Some(suffix.to_owned()),
                ..ContextOptions::default()
            };
            let err = Context::new(options).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config);
            if !suffix.is_empty() {
                assert!(!err.to_string().contains(suffix));
            }
        }
        let ok = ContextOptions {
            user_agent_suffix: Some("app/1.0 (+https://example.org)".to_owned()),
            ..ContextOptions::default()
        };
        assert!(Context::new(ok).is_ok());
        let zero = ContextOptions {
            request_timeout: Duration::ZERO,
            ..ContextOptions::default()
        };
        assert_eq!(Context::new(zero).unwrap_err().kind(), ErrorKind::Config);
    }

    #[test]
    fn context_is_send_sync() {
        fn assert_traits<T: Send + Sync + Clone + 'static>() {}
        assert_traits::<Context>();
    }
}
