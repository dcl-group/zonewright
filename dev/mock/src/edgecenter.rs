//! Mock of the EdgeCenter DNS API (DNS API v2, a fork of Gcore's).
//!
//! The API, its sources and the answers this mock invents where the documentation is silent are
//! described in the shared core, which the Gcore mock ([`crate::gcore`]) runs too, with Gcore's
//! answers. EdgeCenter's own, from its Swagger document
//! <https://api.edgecenter.ru/dns/docs/swagger-en.yaml> ("the EdgeCenter spec"):
//!
//! - the zone is answered wrapped, `{"zone": …}` (`ItemZoneResponse`);
//! - an rrset's per-query selection is `filters` (`InputRRSet.filters`);
//! - a delete answers `204`;
//! - a create of an rrset that exists answers `409`, a status the spec lists for a create (and a
//!   replacement) without saying what it means;
//! - the record types are those of the provider's control panel, which the spec leaves open
//!   (`type` is a free string): A, AAAA, NS, CNAME, MX, TXT, SRV, CAA
//!   (<https://edgecenter.ru/knowledge-base/dns/advanced-mode-dns-record-creation>), and the SOA
//!   the provider keeps. The panel also offers DNAME; no API source names it, and the mock
//!   refuses it.
//!
//! Other sources: the provider's Go SDK `github.com/Edge-Center/edgecenter-dns-sdk-go` and lego
//! `providers/dns/edgecenter`, which runs lego's Gcore client.
//!
//! What is shared with the Gcore mock (paths, auth, paging, content checks, invented answers):
//!
//! - every path is below `/dns/v2`; the client's `base_url` is [`EdgeCenterMock::base_url`];
//! - the token is sent as `Authorization: APIKey <token>`; anything else is `401`;
//! - zones and rrsets are listed in pages of [`Seed::page_size`] (`offset`, `limit`), with
//!   `total_amount`;
//! - an rrset is addressed by zone, owner name (fully qualified, without the trailing dot) and
//!   type; a missing zone or rrset is `404`; a `PUT` of a missing rrset is `404`;
//! - `content` is checked per type as the SDK writes it; SOA and the apex NS cannot be written;
//! - error bodies are `{"error": "…"}`.
//!
//! The API's rate limit (4 requests per second, the EdgeCenter spec) is not enforced; a test
//! injects `429` answers with the fault queue.
//!
//! A test holds an [`EdgeCenterMock`]. It dereferences to the [`MockServer`], so the request log
//! and the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = EdgeCenterMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("PUT", "/dns/v2/zones/*/*/TXT").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records (enabled
//! records, in every zone) through [`EdgeCenterMock::changes`], and a
//! [`link`](crate::link::link) serves them over DNS. The `enabled` flag of a zone does not change
//! what is published. [`Control::reset`] returns the mock to its seed.

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;

use axum::http::StatusCode;

use crate::MockServer;
use crate::changes::{ChangeSource, Changes, Published};
use crate::gcore_shared::{self, Flavor};

pub use crate::gcore_shared::{API_PATH, Control, Paging, Record, Rrset, Seed, Zone};

/// EdgeCenter's answers where the two forks of the API differ.
static FLAVOR: Flavor = Flavor {
    selection: "filters",
    create_exists: StatusCode::CONFLICT,
    delete_status: StatusCode::NO_CONTENT,
    zone_wrapped: true,
    types: &["A", "AAAA", "NS", "CNAME", "MX", "TXT", "SRV", "CAA", "SOA"],
};

/// A running EdgeCenter mock. Dereferences to its [`MockServer`] for the request log and the
/// fault queue; [`EdgeCenterMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct EdgeCenterMock {
    server: MockServer,
    control: Control,
}

impl Deref for EdgeCenterMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl EdgeCenterMock {
    /// Starts the mock with `seed` on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: Seed) -> Self {
        Self::start_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), seed).await
    }

    /// Starts the mock with `seed` on `addr` ([`MockServer::start_on`]). On an address other than
    /// loopback, for an isolated test network only.
    pub async fn start_on(addr: SocketAddr, seed: Seed) -> Self {
        let (server, control) = gcore_shared::start(addr, seed, &FLAVOR).await;
        Self { server, control }
    }

    /// The API endpoint, for the client's `base_url`.
    pub fn base_url(&self) -> String {
        self.server.url(API_PATH)
    }

    /// The state control.
    pub fn control(&self) -> &Control {
        &self.control
    }
}

impl ChangeSource for EdgeCenterMock {
    fn changes(&self) -> &Changes {
        &self.control.changes
    }

    fn published(&self) -> Published {
        gcore_shared::published(&self.control)
    }
}
