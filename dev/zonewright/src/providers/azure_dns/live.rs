//! A live check, run only by the maintainer, that the service enforces the conditions every write
//! of this client carries. The public API cannot produce a stale etag (every operation reads
//! first), so the check calls the client's own record set primitives and the API directly.
//!
//! Environment: `ZONEWRIGHT_LIVE_AZURE_DNS_SETTINGS` and `ZONEWRIGHT_LIVE_AZURE_DNS_CREDENTIALS`
//! (the settings and credentials JSON objects), `ZONEWRIGHT_LIVE_AZURE_DNS_ZONE` (a zone of the
//! resource group) and `ZONEWRIGHT_LIVE_AZURE_DNS_PREFIX` (the label prefix of every name the test
//! writes).

// Test code, run by hand: its output is the record of the run.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::sync::Arc;

use secrecy::SecretString;
use serde_json::{Value, json};

use crate::context::{Context, ContextOptions};
use crate::name::DomainName;

use super::api::{Condition, RecordSet, Written};
use super::client::{AzureDns, from_json};

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("set {key} to run the live test"))
}

/// A random 64-bit number without a dependency: the standard library seeds its hasher keys
/// randomly per process.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    hasher.finish()
}

fn strings(set: &RecordSet) -> Vec<Value> {
    set.records().unwrap()
}

/// Under a TXT record set it creates (`<prefix>-<random>-cond.<zone>`): a `PUT` with the etag of
/// an earlier state, a `PUT` with `If-None-Match: *` over the existing set, and a `DELETE` with
/// the earlier etag must each be refused and leave the set as it was. Each refusal's status and
/// `error.code` are printed, so that the run also records the undocumented status of a failed
/// condition. The set is deleted afterwards, also when a step failed; nothing else is touched.
#[tokio::test]
#[ignore = "live API; run only by the maintainer"]
async fn azure_dns_live_conditions_are_enforced() {
    let ctx = Context::new(ContextOptions::default()).unwrap();
    let client = Arc::new(
        from_json(
            &env("ZONEWRIGHT_LIVE_AZURE_DNS_SETTINGS"),
            &SecretString::from(env("ZONEWRIGHT_LIVE_AZURE_DNS_CREDENTIALS")),
            &ctx,
        )
        .unwrap(),
    );
    let zone = DomainName::parse(&env("ZONEWRIGHT_LIVE_AZURE_DNS_ZONE")).unwrap();
    let prefix = env("ZONEWRIGHT_LIVE_AZURE_DNS_PREFIX");
    let name = zone
        .prepend(&format!("{prefix}-{:016x}-cond", random_u64()))
        .unwrap();
    let body = {
        let (client, zone, name) = (client.clone(), zone.clone(), name.clone());
        tokio::spawn(async move { conditions(&client, &zone, &name).await })
    }
    .await;
    // Cleanup: the one record set this test created, under its current etag.
    let mut left = None;
    match client.api.record_set(&zone, &name, "TXT").await {
        Ok(Some(set)) => {
            let etag = set.etag.clone().unwrap_or_default();
            match client.api.delete(&zone, &name, "TXT", &etag).await {
                Ok(Written::Done | Written::NotFound) => {}
                other => left = Some(format!("{other:?}")),
            }
        }
        Ok(None) => {}
        Err(e) => left = Some(format!("{e:?}")),
    }
    if let Err(e) = body {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(left.is_none(), "cleanup left {name} TXT: {left:?}");
}

async fn conditions(client: &AzureDns, zone: &DomainName, name: &DomainName) {
    let record = |text: &str| json!({ "value": [text] });
    client
        .write_record_set(zone, name, "TXT", None, vec![record("first")], Some(300))
        .await
        .unwrap();
    let first = client
        .api
        .record_set(zone, name, "TXT")
        .await
        .unwrap()
        .unwrap();
    client
        .write_record_set(
            zone,
            name,
            "TXT",
            Some(&first),
            vec![record("second")],
            None,
        )
        .await
        .unwrap();
    let second = client
        .api
        .record_set(zone, name, "TXT")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(first.etag, second.etag, "the etag did not change");
    eprintln!("etag as returned: {:?}", second.etag);
    let stale = first.etag.clone().unwrap();

    // A replace with the earlier etag.
    let body = RecordSet::body(Some(&first), "TXT", vec![record("stale")], None, 300).unwrap();
    match client
        .api
        .put(zone, name, "TXT", &body, &Condition::Etag(&stale))
        .await
        .unwrap()
    {
        Written::Refused(e) => eprintln!(
            "PUT with a stale etag refused: {e:?}, code {:?}",
            e.provider_code()
        ),
        other => panic!("PUT with a stale etag was not refused: {other:?}"),
    }
    let now = client
        .api
        .record_set(zone, name, "TXT")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        strings(&now),
        strings(&second),
        "a stale PUT changed the set"
    );
    assert_eq!(now.etag, second.etag);

    // A create over the existing set.
    let body = RecordSet::body(None, "TXT", vec![record("created")], Some(300), 300).unwrap();
    match client
        .api
        .put(zone, name, "TXT", &body, &Condition::Absent)
        .await
        .unwrap()
    {
        Written::Refused(e) => eprintln!(
            "PUT with If-None-Match over a set refused: {e:?}, code {:?}",
            e.provider_code()
        ),
        other => panic!("a create over an existing set was not refused: {other:?}"),
    }
    let now = client
        .api
        .record_set(zone, name, "TXT")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(strings(&now), strings(&second), "a create replaced the set");

    // A delete with the earlier etag.
    match client.api.delete(zone, name, "TXT", &stale).await.unwrap() {
        Written::Refused(e) => eprintln!(
            "DELETE with a stale etag refused: {e:?}, code {:?}",
            e.provider_code()
        ),
        other => panic!("DELETE with a stale etag was not refused: {other:?}"),
    }
    let now = client.api.record_set(zone, name, "TXT").await.unwrap();
    assert_eq!(
        now.as_ref().map(strings),
        Some(strings(&second)),
        "a stale DELETE removed the set"
    );
}
