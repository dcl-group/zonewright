//! `zonewright`: manage DNS zones at DNS hosting providers.
//!
//! The crate knows how to talk to providers and how to observe DNS. What records should exist,
//! and when, is the business of the application that uses it.

pub mod name;
pub mod record;

// TEMPORARY (core phase): nothing uses these modules until the transport and the clients land.
#[allow(dead_code)]
mod redact;

#[cfg(feature = "__crypto")]
#[allow(dead_code)]
mod crypto;
