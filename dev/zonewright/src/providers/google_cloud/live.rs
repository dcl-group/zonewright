//! A live probe of the change semantics the client's guarantees rest on (design section 12.5;
//! run only by the maintainer). It calls `changes.create` directly through the client's API
//! handle, which the public operations never let it do with a wrong condition:
//!
//! 1. a change whose deletion differs from the stored rrset (its TTL) is refused, and the rrset
//!    is unchanged ("Must match existing data exactly", documented);
//! 2. a change that adds an rrset that already exists is refused, and the rrset is unchanged
//!    (assumed, `rrset.rs`, "A new rrset");
//! 3. a change with an addition that is valid and a deletion that matches nothing is refused as
//!    a whole: the addition is not applied ("applied atomically", documented).
//!
//! The status and the reason of each refusal are printed. It reads
//! `ZONEWRIGHT_LIVE_GOOGLE_CLOUD_SETTINGS`, `..._CREDENTIALS`, `..._ZONE` and `..._PREFIX` (a
//! label prefix below the zone), works only on names `<prefix>-<random>-x`, `-y` and `-z`, and
//! deletes afterwards, also when a step failed, exactly the rrsets of those names that hold
//! nothing but what it wrote.

// Test code: a failed assumption is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use secrecy::SecretString;
use serde_json::Value;

use crate::context::{Context, ContextOptions};
use crate::name::DomainName;
use crate::provider::{Expect, Provider as _};
use crate::record::RecordType;

use super::api::Written;
use super::client::{GoogleCloud, from_json};
use super::rrset::new_rrset;

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

/// The TXT rrset of `name` as the API returns it, or `None`.
async fn read(client: &GoogleCloud, zone_id: &str, name: &DomainName) -> Option<Value> {
    let sets = client
        .api
        .rrsets(zone_id, Some((name.as_str(), "TXT")))
        .await
        .unwrap()
        .expect("the managed zone exists");
    assert!(sets.len() <= 1, "{sets:?}");
    sets.into_iter().next()
}

fn txt(text: &str) -> Vec<Value> {
    vec![Value::String(format!("\"{text}\""))]
}

#[tokio::test]
#[ignore = "live API: run only by the maintainer"]
async fn live_google_cloud_change_semantics() {
    let zone = DomainName::parse(&env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_ZONE")).unwrap();
    let prefix = env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_PREFIX");
    let ctx = Context::new(ContextOptions::default()).unwrap();
    let client = std::sync::Arc::new(
        from_json(
            &env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_SETTINGS"),
            &SecretString::from(env("ZONEWRIGHT_LIVE_GOOGLE_CLOUD_CREDENTIALS")),
            &ctx,
        )
        .unwrap(),
    );
    let tag = format!("{prefix}-{:016x}", random_u64());
    let x = zone.prepend(&format!("{tag}-x")).unwrap();
    let y = zone.prepend(&format!("{tag}-y")).unwrap();
    let z = zone.prepend(&format!("{tag}-z")).unwrap();
    let ours = |text: &str| text.contains(&tag);

    let body = tokio::spawn({
        let (client, zone, x, y, z, tag) = (
            client.clone(),
            zone.clone(),
            x.clone(),
            y.clone(),
            z.clone(),
            tag.clone(),
        );
        async move {
            let zone_id = client.resolve_zone(&zone).await.unwrap();
            let created = client
                .api
                .change(
                    &zone_id,
                    &[],
                    &[new_rrset(&x, "TXT", 300, txt(&format!("{tag}-a")))],
                )
                .await
                .unwrap();
            assert!(matches!(created, Written::Done), "{created:?}");
            let stored = read(&client, &zone_id, &x).await.unwrap();
            eprintln!("change probe: stored {stored}");

            // 1: a deletion that differs from the stored rrset in its TTL.
            let mut stale = stored.clone();
            stale["ttl"] = Value::from(301);
            let mut replacement = stored.clone();
            replacement["rrdatas"] = Value::Array(txt(&format!("{tag}-b")));
            let answer = client
                .api
                .change(&zone_id, &[stale], &[replacement])
                .await
                .unwrap();
            eprintln!("change probe 1 (stale deletion): {answer:?}");
            assert!(matches!(answer, Written::Refused { .. }), "{answer:?}");
            assert_eq!(read(&client, &zone_id, &x).await.as_ref(), Some(&stored));

            // 2: an addition of the rrset that exists.
            let answer = client
                .api
                .change(
                    &zone_id,
                    &[],
                    &[new_rrset(&x, "TXT", 300, txt(&format!("{tag}-c")))],
                )
                .await
                .unwrap();
            eprintln!("change probe 2 (addition of an existing rrset): {answer:?}");
            assert!(
                matches!(answer, Written::Refused { .. }),
                "the API accepted an addition of an existing rrset: {answer:?}"
            );
            assert_eq!(read(&client, &zone_id, &x).await.as_ref(), Some(&stored));

            // 3: a valid addition and a deletion that matches nothing, in one change.
            let answer = client
                .api
                .change(
                    &zone_id,
                    &[new_rrset(&y, "TXT", 300, txt(&format!("{tag}-y")))],
                    &[new_rrset(&z, "TXT", 300, txt(&format!("{tag}-z")))],
                )
                .await
                .unwrap();
            eprintln!("change probe 3 (mixed change): {answer:?}");
            assert!(matches!(answer, Written::Refused { .. }), "{answer:?}");
            assert_eq!(
                read(&client, &zone_id, &z).await,
                None,
                "not all-or-nothing"
            );
        }
    })
    .await;

    // Cleanup: the rrsets of the test's names that hold only what the test wrote.
    let mut cleanup = Vec::new();
    for name in [&x, &y, &z] {
        match client.get_rrset(&zone, name, RecordType::TXT).await {
            Ok(Some(current)) if current.records().iter().all(|r| ours(r.as_str())) => {
                if let Err(e) = client
                    .delete_rrset(&zone, name, RecordType::TXT, Expect::Matches(&current))
                    .await
                {
                    cleanup.push(format!("{name}: {e}"));
                }
            }
            Ok(Some(_)) => cleanup.push(format!("{name} holds foreign records")),
            Ok(None) => {}
            Err(e) => cleanup.push(format!("{name}: {e}")),
        }
    }
    if let Err(e) = body {
        std::panic::resume_unwind(e.into_panic());
    }
    assert!(cleanup.is_empty(), "cleanup failed: {cleanup:?}");
}
