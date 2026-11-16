//! Mock of the Gcore Managed DNS API (DNS API v2).
//!
//! The API, its sources and the answers this mock invents where the documentation is silent are
//! described in the shared core, which the EdgeCenter mock ([`crate::edgecenter`]) runs too, with
//! EdgeCenter's answers. Gcore's own:
//!
//! - the zone is answered as itself (`ItemZoneResponse`, the Gcore spec; lego decodes
//!   `{"name": …}`), not wrapped;
//! - an rrset's per-query selection is `pickers` (`InputRRSet.pickers`, the Gcore spec);
//! - a delete answers `200` with `{}` (`DeleteRRSetResponse`);
//! - a create of an rrset that exists answers `400` (only `400` is documented for the create);
//! - the record types are those of `OutputRRSet.type`: A, AAAA, NS, CNAME, MX, TXT, SRV, SOA, PTR,
//!   SVCB, HTTPS, CAA, DS.
//!
//! Sources: <https://docs.gcore.com/api-reference/dns>, <https://api.gcore.com/dns/docs/swagger.yaml>,
//! lego `providers/dns/internal/gcore` and dns-update `src/providers/gcore.rs`.
//!
//! What is shared with the EdgeCenter mock (paths, auth, paging, content checks, invented
//! answers):
//!
//! - every path is below `/dns/v2`; the client's `base_url` is [`GcoreMock::base_url`];
//! - the token is sent as `Authorization: APIKey <token>`; anything else is `401`;
//! - zones and rrsets are listed in pages of [`Seed::page_size`] (`offset`, `limit`), with
//!   `total_amount`;
//! - an rrset is addressed by zone, owner name (fully qualified, without the trailing dot) and
//!   type; a missing zone or rrset is `404`; a `PUT` of a missing rrset is `404`;
//! - `content` is checked per type as dns-update writes it; SOA and the apex NS cannot be
//!   written;
//! - error bodies are `{"error": "…"}`.
//!
//! A test holds a [`GcoreMock`]. It dereferences to the [`MockServer`], so the request log and
//! the fault queue of the shared harness work as usual:
//!
//! ```text
//! let mock = GcoreMock::start(Seed::standard()).await;
//! mock.faults().push(Fault::on("PUT", "/dns/v2/zones/*/*/TXT").status(500));
//! // ... drive the client against mock.base_url() ...
//! assert_eq!(mock.control().txt_values("_acme-challenge.example.org"), ["v1"]);
//! ```
//!
//! The mock is a [`ChangeSource`]: it reports every change of its published records (enabled
//! records, in every zone) through [`GcoreMock::changes`], and a [`link`](crate::link::link)
//! serves them over DNS. The `enabled` flag of a zone does not change what is published.
//! [`Control::reset`] returns the mock to its seed.

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;

use axum::http::StatusCode;

use crate::MockServer;
use crate::changes::{ChangeSource, Changes, Published};
use crate::gcore_shared::{self, Flavor};

pub use crate::gcore_shared::{API_PATH, Control, Paging, Record, Rrset, Seed, Zone};

/// Gcore's answers where the two forks of the API differ.
static FLAVOR: Flavor = Flavor {
    selection: "pickers",
    create_exists: StatusCode::BAD_REQUEST,
    delete_status: StatusCode::OK,
    zone_wrapped: false,
    types: &[
        "A", "AAAA", "NS", "CNAME", "MX", "TXT", "SRV", "SOA", "PTR", "SVCB", "HTTPS", "CAA", "DS",
    ],
};

/// A running Gcore mock. Dereferences to its [`MockServer`] for the request log and the fault
/// queue; [`GcoreMock::control`] reads and changes the state.
#[derive(Debug)]
pub struct GcoreMock {
    server: MockServer,
    control: Control,
}

impl Deref for GcoreMock {
    type Target = MockServer;

    fn deref(&self) -> &MockServer {
        &self.server
    }
}

impl GcoreMock {
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

impl ChangeSource for GcoreMock {
    fn changes(&self) -> &Changes {
        &self.control.changes
    }

    fn published(&self) -> Published {
        gcore_shared::published(&self.control)
    }
}
