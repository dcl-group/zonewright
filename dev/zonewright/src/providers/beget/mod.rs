//! Beget (provider ID `beget`): the Beget.API DNS functions.
//!
//! The metadata is present in every build. The client, `Beget`, with its settings `BegetConfig`
//! and credentials `BegetCredentials`, is compiled with the cargo feature `beget`.
//!
//! This version offers `check`, `list_zones` and the TXT value operations. The TXT value
//! operations accept plain values only, and they read the TXT set of a name and write it back
//! whole: a concurrent writer outside this process can lose its change (see
//! [`ValueGuarantee::ReadThenWrite`](crate::ValueGuarantee::ReadThenWrite)). The write replaces
//! the A, MX and TXT records of the name together, so they work only on names that hold TXT
//! records and nothing else, such as `_acme-challenge` names; any other name is refused. Every call is a
//! `POST` with the login and the API password in the form body; whether the API accepts that
//! for these functions has not been confirmed against the live API.

pub(crate) mod meta;

#[cfg(feature = "beget")]
mod api;
#[cfg(feature = "beget")]
mod client;
#[cfg(feature = "beget")]
mod config;
#[cfg(feature = "beget")]
mod txt;

#[cfg(feature = "beget")]
pub use client::Beget;
#[cfg(feature = "beget")]
pub(crate) use client::from_json;
#[cfg(feature = "beget")]
pub use config::{BegetConfig, BegetCredentials};
