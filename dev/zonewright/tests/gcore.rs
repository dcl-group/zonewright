//! Tests of the Gcore client (`gcore`) against its mock. The cases it shares with the other
//! client of the same API are in `common/gcore_shared.rs`; this file runs them for Gcore under
//! the test names `tests/conformance.rs` looks for, and holds the cases of its own.
#![cfg(feature = "gcore")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use secrecy::SecretString;
use zonewright::providers::gcore::{Gcore, GcoreConfig, GcoreCredentials};
use zonewright::{Context, ProviderId};
use zonewright_mock::gcore::{Control, GcoreMock, Seed};

use common::gcore_shared;

/// Gcore for the shared cases.
struct Family;

impl gcore_shared::Family for Family {
    type Mock = GcoreMock;
    type Client = Gcore;
    const ID: ProviderId = ProviderId::Gcore;
    const LIVE: &'static str = "ZONEWRIGHT_LIVE_GCORE";
    const DEFAULT_URL: &'static str = "https://api.gcore.com/dns";
    const SELECTION: &'static str = "pickers";
    const ZONE_WRAPPED: bool = false;

    async fn start(seed: Seed) -> GcoreMock {
        GcoreMock::start(seed).await
    }

    fn control(mock: &GcoreMock) -> &Control {
        mock.control()
    }

    fn base_url(mock: &GcoreMock) -> String {
        mock.base_url()
    }

    fn client(base_url: String, token: &str, ctx: &Context) -> Gcore {
        let mut config = GcoreConfig::default();
        config.base_url = base_url;
        Gcore::new(
            config,
            GcoreCredentials::new(SecretString::from(token.to_owned())),
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

assert_not_impl!(Gcore: std::fmt::Display, serde::Serialize);
assert_not_impl!(GcoreCredentials: std::fmt::Display, serde::Serialize);

// ---- The shared cases --------------------------------------------------------------------------

#[tokio::test]
async fn gcore_secret_echo() {
    gcore_shared::secret_echo::<Family>().await;
}

#[tokio::test(flavor = "current_thread")]
async fn gcore_no_secret_in_logs() {
    gcore_shared::no_secret_in_logs::<Family>().await;
}

#[tokio::test]
async fn gcore_token_is_sent_as_apikey() {
    gcore_shared::token_is_sent_as_apikey::<Family>().await;
}

#[tokio::test]
async fn gcore_name_outside_zone_sends_nothing() {
    gcore_shared::name_outside_zone_sends_nothing::<Family>().await;
}

#[tokio::test]
async fn gcore_invalid_input_sends_nothing() {
    gcore_shared::invalid_input_sends_nothing::<Family>().await;
}

#[tokio::test]
async fn gcore_add_is_idempotent() {
    gcore_shared::add_is_idempotent::<Family>().await;
}

#[tokio::test]
async fn gcore_never_removes_foreign_value() {
    gcore_shared::never_removes_foreign_value::<Family>().await;
}

#[tokio::test]
async fn gcore_remove_last_value_deletes_rrset() {
    gcore_shared::remove_last_value_deletes_rrset::<Family>().await;
}

#[tokio::test]
async fn gcore_remove_is_idempotent() {
    gcore_shared::remove_is_idempotent::<Family>().await;
}

#[tokio::test]
async fn gcore_concurrent_adds_are_serialized() {
    gcore_shared::concurrent_adds_are_serialized::<Family>().await;
}

#[tokio::test]
async fn gcore_writes_are_sent_once() {
    gcore_shared::writes_are_sent_once::<Family>().await;
}

#[tokio::test]
async fn gcore_delete_not_found_reads_again() {
    gcore_shared::delete_not_found_reads_again::<Family>().await;
}

#[tokio::test]
async fn gcore_failed_expectation_is_precondition_failed() {
    gcore_shared::failed_expectation_is_precondition_failed::<Family>().await;
}

#[tokio::test(flavor = "current_thread")]
async fn gcore_listing_reports_skipped_sets() {
    gcore_shared::listing_reports_skipped_sets::<Family>().await;
}

#[tokio::test]
async fn gcore_request_shapes() {
    gcore_shared::request_shapes::<Family>().await;
}

#[tokio::test]
async fn gcore_add_enables_disabled_same_value() {
    gcore_shared::add_enables_disabled_same_value::<Family>().await;
}

#[tokio::test]
async fn gcore_dynamic_rrsets_are_not_written() {
    gcore_shared::dynamic_rrsets_are_not_written::<Family>().await;
}

#[tokio::test]
async fn gcore_txt_dialect() {
    gcore_shared::txt_dialect::<Family>().await;
}

#[tokio::test]
async fn gcore_create_race_is_conflict() {
    gcore_shared::create_race_is_conflict::<Family>().await;
}

#[tokio::test]
async fn gcore_replacement_of_a_vanished_rrset_is_conflict() {
    gcore_shared::replacement_of_a_vanished_rrset_is_conflict::<Family>().await;
}

#[tokio::test]
async fn gcore_check_reports_zones() {
    gcore_shared::check_reports_zones::<Family>().await;
}

#[tokio::test]
async fn gcore_list_zones_reads_every_page() {
    gcore_shared::list_zones_reads_every_page::<Family>().await;
}

#[tokio::test]
async fn gcore_listing_reads_every_page() {
    gcore_shared::listing_reads_every_page::<Family>().await;
}

#[tokio::test]
async fn gcore_listing_ends_under_every_paging_reading() {
    gcore_shared::listing_ends_under_every_paging_reading::<Family>().await;
}

#[tokio::test]
async fn gcore_single_rrset_answer_may_omit_name_and_type() {
    gcore_shared::single_rrset_answer_may_omit_name_and_type::<Family>().await;
}

#[tokio::test]
async fn gcore_zone_not_found() {
    gcore_shared::zone_not_found::<Family>().await;
}

#[tokio::test]
async fn gcore_rate_limit() {
    gcore_shared::rate_limit::<Family>().await;
}

#[tokio::test]
async fn gcore_server_errors_are_retried_then_transient() {
    gcore_shared::server_errors_are_retried_then_transient::<Family>().await;
}

#[tokio::test]
async fn gcore_refusals_are_classified() {
    gcore_shared::refusals_are_classified::<Family>().await;
}

#[tokio::test]
async fn gcore_from_json_builds_the_client() {
    gcore_shared::from_json_builds_the_client::<Family>().await;
}

#[test]
fn gcore_config_errors_name_no_value() {
    gcore_shared::config_errors_name_no_value::<Family>();
}

#[tokio::test]
async fn gcore_record_round_trips() {
    gcore_shared::record_round_trips::<Family>().await;
}

#[tokio::test]
async fn gcore_reads_provider_spellings() {
    gcore_shared::reads_provider_spellings::<Family>().await;
}

#[tokio::test]
async fn gcore_escapes_and_non_canonical_data() {
    gcore_shared::escapes_and_non_canonical_data::<Family>().await;
}

#[tokio::test]
async fn gcore_protected_sets_send_nothing() {
    gcore_shared::protected_sets_send_nothing::<Family>().await;
}

#[tokio::test]
async fn gcore_record_ttl_bounds() {
    gcore_shared::record_ttl_bounds::<Family>().await;
}

#[tokio::test]
async fn gcore_concurrent_sets_are_serialized() {
    gcore_shared::concurrent_sets_are_serialized::<Family>().await;
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_gcore_add_and_remove() {
    gcore_shared::live_add_and_remove::<Family>().await;
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_gcore_record_round_trip() {
    gcore_shared::live_record_round_trip::<Family>().await;
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_gcore_assumptions() {
    gcore_shared::live_assumptions::<Family>().await;
}

#[cfg(feature = "inspector")]
mod dns_link {
    use super::Family;
    use crate::common::gcore_shared::dns_link;

    #[tokio::test]
    async fn gcore_txt_value_is_served_over_dns() {
        dns_link::txt_value_is_served_over_dns::<Family>().await;
    }

    #[tokio::test]
    async fn gcore_names_in_values_are_served_fully_qualified() {
        dns_link::names_in_values_are_served_fully_qualified::<Family>().await;
    }

    #[tokio::test]
    async fn gcore_reset_returns_the_mock_to_its_seed() {
        dns_link::reset_returns_the_mock_to_its_seed::<Family>().await;
    }
}
