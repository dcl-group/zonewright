//! Tests of the EdgeCenter client (`edgecenter`) against its mock. The cases it shares with the other
//! client of the same API are in `common/gcore_shared.rs`; this file runs them for EdgeCenter under
//! the test names `tests/conformance.rs` looks for, and holds the cases of its own.
#![cfg(feature = "edgecenter")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use secrecy::SecretString;
use zonewright::providers::edgecenter::{EdgeCenter, EdgeCenterConfig, EdgeCenterCredentials};
use zonewright::{Context, Provider, ProviderId};
use zonewright_mock::edgecenter::{Control, EdgeCenterMock, Seed};

use common::gcore_shared;

/// EdgeCenter for the shared cases.
struct Family;

impl gcore_shared::Family for Family {
    type Mock = EdgeCenterMock;
    type Client = EdgeCenter;
    const ID: ProviderId = ProviderId::EdgeCenter;
    const LIVE: &'static str = "ZONEWRIGHT_LIVE_EDGECENTER";
    const DEFAULT_URL: &'static str = "https://api.edgecenter.ru/dns";
    const SELECTION: &'static str = "filters";
    const ZONE_WRAPPED: bool = true;

    async fn start(seed: Seed) -> EdgeCenterMock {
        EdgeCenterMock::start(seed).await
    }

    fn control(mock: &EdgeCenterMock) -> &Control {
        mock.control()
    }

    fn base_url(mock: &EdgeCenterMock) -> String {
        mock.base_url()
    }

    /// Without request spacing: one test checks the spacing.
    fn client(base_url: String, token: &str, ctx: &Context) -> EdgeCenter {
        let mut config = EdgeCenterConfig::default();
        config.base_url = base_url;
        config.min_request_interval_ms = 0;
        EdgeCenter::new(
            config,
            EdgeCenterCredentials::new(SecretString::from(token.to_owned())),
            ctx,
        )
        .unwrap()
    }
}

/// Neither client type nor credentials type can be printed with `Display` or serialized.
/// Checked at compile time: the call is ambiguous if the trait is implemented.
macro_rules! assert_not_impl {
    ($ty:ty: $($tr:path),+ $(,)?) => {
        $(
            const _: () = {
                trait AmbiguousIfImpl<A> {
                    fn some_item() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                #[allow(dead_code)] // Reason: a marker type that is never built.
                struct Invalid;
                impl<T: ?Sized + $tr> AmbiguousIfImpl<Invalid> for T {}
                let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
            };
        )+
    };
}

assert_not_impl!(EdgeCenter: std::fmt::Display, serde::Serialize);
assert_not_impl!(EdgeCenterCredentials: std::fmt::Display, serde::Serialize);

// ---- The shared cases --------------------------------------------------------------------------

#[tokio::test]
async fn edgecenter_secret_echo() {
    gcore_shared::secret_echo::<Family>().await;
}

#[tokio::test(flavor = "current_thread")]
async fn edgecenter_no_secret_in_logs() {
    gcore_shared::no_secret_in_logs::<Family>().await;
}

#[tokio::test]
async fn edgecenter_token_is_sent_as_apikey() {
    gcore_shared::token_is_sent_as_apikey::<Family>().await;
}

#[tokio::test]
async fn edgecenter_name_outside_zone_sends_nothing() {
    gcore_shared::name_outside_zone_sends_nothing::<Family>().await;
}

#[tokio::test]
async fn edgecenter_invalid_input_sends_nothing() {
    gcore_shared::invalid_input_sends_nothing::<Family>().await;
}

#[tokio::test]
async fn edgecenter_add_is_idempotent() {
    gcore_shared::add_is_idempotent::<Family>().await;
}

#[tokio::test]
async fn edgecenter_never_removes_foreign_value() {
    gcore_shared::never_removes_foreign_value::<Family>().await;
}

#[tokio::test]
async fn edgecenter_remove_last_value_deletes_rrset() {
    gcore_shared::remove_last_value_deletes_rrset::<Family>().await;
}

#[tokio::test]
async fn edgecenter_remove_is_idempotent() {
    gcore_shared::remove_is_idempotent::<Family>().await;
}

#[tokio::test]
async fn edgecenter_concurrent_adds_are_serialized() {
    gcore_shared::concurrent_adds_are_serialized::<Family>().await;
}

#[tokio::test]
async fn edgecenter_writes_are_sent_once() {
    gcore_shared::writes_are_sent_once::<Family>().await;
}

#[tokio::test]
async fn edgecenter_delete_not_found_reads_again() {
    gcore_shared::delete_not_found_reads_again::<Family>().await;
}

#[tokio::test]
async fn edgecenter_failed_expectation_is_precondition_failed() {
    gcore_shared::failed_expectation_is_precondition_failed::<Family>().await;
}

#[tokio::test(flavor = "current_thread")]
async fn edgecenter_listing_reports_skipped_sets() {
    gcore_shared::listing_reports_skipped_sets::<Family>().await;
}

#[tokio::test]
async fn edgecenter_request_shapes() {
    gcore_shared::request_shapes::<Family>().await;
}

#[tokio::test]
async fn edgecenter_add_enables_disabled_same_value() {
    gcore_shared::add_enables_disabled_same_value::<Family>().await;
}

#[tokio::test]
async fn edgecenter_dynamic_rrsets_are_not_written() {
    gcore_shared::dynamic_rrsets_are_not_written::<Family>().await;
}

#[tokio::test]
async fn edgecenter_txt_dialect() {
    gcore_shared::txt_dialect::<Family>().await;
}

#[tokio::test]
async fn edgecenter_create_race_is_conflict() {
    gcore_shared::create_race_is_conflict::<Family>().await;
}

#[tokio::test]
async fn edgecenter_replacement_of_a_vanished_rrset_is_conflict() {
    gcore_shared::replacement_of_a_vanished_rrset_is_conflict::<Family>().await;
}

#[tokio::test]
async fn edgecenter_check_reports_zones() {
    gcore_shared::check_reports_zones::<Family>().await;
}

#[tokio::test]
async fn edgecenter_list_zones_reads_every_page() {
    gcore_shared::list_zones_reads_every_page::<Family>().await;
}

#[tokio::test]
async fn edgecenter_listing_reads_every_page() {
    gcore_shared::listing_reads_every_page::<Family>().await;
}

#[tokio::test]
async fn edgecenter_listing_ends_under_every_paging_reading() {
    gcore_shared::listing_ends_under_every_paging_reading::<Family>().await;
}

#[tokio::test]
async fn edgecenter_single_rrset_answer_may_omit_name_and_type() {
    gcore_shared::single_rrset_answer_may_omit_name_and_type::<Family>().await;
}

#[tokio::test]
async fn edgecenter_zone_not_found() {
    gcore_shared::zone_not_found::<Family>().await;
}

#[tokio::test]
async fn edgecenter_rate_limit() {
    gcore_shared::rate_limit::<Family>().await;
}

#[tokio::test]
async fn edgecenter_server_errors_are_retried_then_transient() {
    gcore_shared::server_errors_are_retried_then_transient::<Family>().await;
}

#[tokio::test]
async fn edgecenter_refusals_are_classified() {
    gcore_shared::refusals_are_classified::<Family>().await;
}

#[tokio::test]
async fn edgecenter_from_json_builds_the_client() {
    gcore_shared::from_json_builds_the_client::<Family>().await;
}

#[test]
fn edgecenter_config_errors_name_no_value() {
    gcore_shared::config_errors_name_no_value::<Family>();
}

#[tokio::test]
async fn edgecenter_record_round_trips() {
    gcore_shared::record_round_trips::<Family>().await;
}

#[tokio::test]
async fn edgecenter_reads_provider_spellings() {
    gcore_shared::reads_provider_spellings::<Family>().await;
}

#[tokio::test]
async fn edgecenter_escapes_and_non_canonical_data() {
    gcore_shared::escapes_and_non_canonical_data::<Family>().await;
}

#[tokio::test]
async fn edgecenter_protected_sets_send_nothing() {
    gcore_shared::protected_sets_send_nothing::<Family>().await;
}

#[tokio::test]
async fn edgecenter_record_ttl_bounds() {
    gcore_shared::record_ttl_bounds::<Family>().await;
}

#[tokio::test]
async fn edgecenter_concurrent_sets_are_serialized() {
    gcore_shared::concurrent_sets_are_serialized::<Family>().await;
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_edgecenter_add_and_remove() {
    gcore_shared::live_add_and_remove::<Family>().await;
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_edgecenter_record_round_trip() {
    gcore_shared::live_record_round_trip::<Family>().await;
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_edgecenter_assumptions() {
    gcore_shared::live_assumptions::<Family>().await;
}

#[cfg(feature = "inspector")]
mod dns_link {
    use super::Family;
    use crate::common::gcore_shared::dns_link;

    #[tokio::test]
    async fn edgecenter_txt_value_is_served_over_dns() {
        dns_link::txt_value_is_served_over_dns::<Family>().await;
    }

    #[tokio::test]
    async fn edgecenter_names_in_values_are_served_fully_qualified() {
        dns_link::names_in_values_are_served_fully_qualified::<Family>().await;
    }

    #[tokio::test]
    async fn edgecenter_reset_returns_the_mock_to_its_seed() {
        dns_link::reset_returns_the_mock_to_its_seed::<Family>().await;
    }
}

// ---- EdgeCenter's own --------------------------------------------------------------------------

/// Requests are spaced by `min_request_interval_ms`, 250 ms by default: the API allows 4
/// requests per second.
#[tokio::test]
async fn edgecenter_requests_are_spaced() {
    let mock = EdgeCenterMock::start(Seed::standard()).await;
    let mut config = EdgeCenterConfig::default();
    config.base_url = mock.base_url();
    assert_eq!(config.min_request_interval_ms, 250);
    let credentials = EdgeCenterCredentials::new(SecretString::from("test-only-token".to_owned()));
    let client = EdgeCenter::new(config, credentials, &common::context()).unwrap();
    let start = std::time::Instant::now();
    // Two checks of one zone: four requests, three intervals between them.
    let zone = common::dn("example.org");
    client.check(std::slice::from_ref(&zone)).await.unwrap();
    client.check(&[zone]).await.unwrap();
    assert_eq!(mock.log().len(), 4);
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(750),
        "{:?}",
        start.elapsed()
    );
}
