// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Checks that span providers (design section 12.3): provider IDs, metadata, `PROVIDERS.md`,
//! agreement of capabilities and behavior, and source scans.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use zonewright::{
    AnyProvider, CheckReport, Detail, DomainName, Error, ErrorKind, Expect, FieldKind, Operation,
    Preconditions, Provider, ProviderId, RecordData, RecordType, RrSet, TtlSupport, Txt, TypeSet,
    ValueGuarantee, ZoneCheck,
};

use common::{context, dn, sample_client};

/// The persisted strings, written out literally: a change here is a change of a persisted value.
const IDS: &[(ProviderId, &str)] = &[
    (ProviderId::AcmeDns, "acme_dns"),
    (ProviderId::Beget, "beget"),
    (ProviderId::CloudRu, "cloud_ru"),
    (ProviderId::Cloudflare, "cloudflare"),
    (ProviderId::DigitalOcean, "digitalocean"),
    (ProviderId::Hetzner, "hetzner"),
    (ProviderId::Nicru, "nicru"),
    (ProviderId::Regru, "regru"),
    (ProviderId::Rfc2136, "rfc2136"),
    (ProviderId::Route53, "route53"),
    (ProviderId::SelectelV2, "selectel_v2"),
    (ProviderId::TimewebCloud, "timeweb_cloud"),
    (ProviderId::VkCloud, "vk_cloud"),
    (ProviderId::Yandex360, "yandex_360"),
    (ProviderId::YandexCloud, "yandex_cloud"),
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ---- Provider IDs ------------------------------------------------------------------------------

#[test]
fn ids_match_the_literal_table() {
    let all: Vec<ProviderId> = IDS.iter().map(|&(id, _)| id).collect();
    assert_eq!(ProviderId::ALL, all.as_slice());
    for &(id, text) in IDS {
        assert_eq!(id.as_str(), text);
        assert_eq!(id.to_string(), text);
        assert_eq!(ProviderId::parse(text), Some(id));
        assert_eq!(text.parse::<ProviderId>().unwrap(), id);
    }
}

#[test]
fn ids_round_trip() {
    for &id in ProviderId::ALL {
        assert_eq!(ProviderId::parse(id.as_str()), Some(id));
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.as_str()));
        assert_eq!(serde_json::from_str::<ProviderId>(&json).unwrap(), id);
    }
}

#[test]
fn parse_is_exact() {
    for text in [
        "",
        "Cloudflare",
        "CLOUDFLARE",
        " cloudflare",
        "cloudflare ",
        "selectel-v2",
        "selectel",
        "yandex360",
        "unmanaged",
    ] {
        assert_eq!(ProviderId::parse(text), None, "{text:?}");
        assert!(text.parse::<ProviderId>().is_err());
        assert!(serde_json::from_str::<ProviderId>(&format!("{text:?}")).is_err());
    }
    let long = "x".repeat(1000);
    let err = long.parse::<ProviderId>().unwrap_err();
    assert!(err.to_string().len() < 100);
}

#[test]
fn available_follows_the_features() {
    let expected = [
        (ProviderId::AcmeDns, cfg!(feature = "acme_dns")),
        (ProviderId::Beget, cfg!(feature = "beget")),
        (ProviderId::CloudRu, cfg!(feature = "cloud_ru")),
        (ProviderId::Cloudflare, cfg!(feature = "cloudflare")),
        (ProviderId::DigitalOcean, cfg!(feature = "digitalocean")),
        (ProviderId::Hetzner, cfg!(feature = "hetzner")),
        (ProviderId::Nicru, cfg!(feature = "nicru")),
        (ProviderId::Regru, cfg!(feature = "regru")),
        (ProviderId::Rfc2136, cfg!(feature = "rfc2136")),
        (ProviderId::Route53, cfg!(feature = "route53")),
        (ProviderId::SelectelV2, cfg!(feature = "selectel_v2")),
        (ProviderId::TimewebCloud, cfg!(feature = "timeweb_cloud")),
        (ProviderId::VkCloud, cfg!(feature = "vk_cloud")),
        (ProviderId::Yandex360, cfg!(feature = "yandex_360")),
        (ProviderId::YandexCloud, cfg!(feature = "yandex_cloud")),
    ];
    for (id, on) in expected {
        assert_eq!(id.available(), on, "{id}");
    }
}

// ---- PROVIDERS.md ------------------------------------------------------------------------------

/// The providers of `PROVIDERS.md` by section: section heading -> (ID -> name column).
fn providers_md() -> BTreeMap<String, BTreeMap<String, String>> {
    let path = manifest_dir().join("../../PROVIDERS.md");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = heading.trim().to_owned();
            sections.entry(section.clone()).or_default();
            continue;
        }
        let Some(row) = line.strip_prefix('|') else {
            continue;
        };
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        if cells.len() < 2 {
            continue;
        }
        let id_cell = cells[1];
        let Some(id) = id_cell
            .strip_prefix('`')
            .and_then(|rest| rest.strip_suffix('`'))
        else {
            continue;
        };
        let previous = sections
            .entry(section.clone())
            .or_default()
            .insert(id.to_owned(), cells[0].to_owned());
        assert!(previous.is_none(), "{id} listed twice in {section}");
    }
    sections
}

#[test]
fn ids_equal_providers_md() {
    let sections = providers_md();
    let mut listed = BTreeSet::new();
    for ids in sections.values() {
        for id in ids.keys() {
            assert!(
                listed.insert(id.clone()),
                "{id} is in more than one section"
            );
        }
    }
    let known: BTreeSet<String> = ProviderId::ALL
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    assert_eq!(listed, known);
}

#[test]
fn names_equal_providers_md() {
    let sections = providers_md();
    for ids in sections.values() {
        for (id, name) in ids {
            let id = ProviderId::parse(id).unwrap();
            assert_eq!(id.meta().name, name, "{id}");
        }
    }
}

#[test]
fn verified_flags_equal_providers_md() {
    let sections = providers_md();
    let verified = sections
        .get("Verified against the live API")
        .expect("PROVIDERS.md has a section \"Verified against the live API\"");
    for &id in ProviderId::ALL {
        assert_eq!(
            id.meta().verified,
            verified.contains_key(id.as_str()),
            "{id}: the verified flag and PROVIDERS.md disagree"
        );
    }
}

// ---- Metadata ----------------------------------------------------------------------------------

/// The client of `id` is still the placeholder of the core phase.
fn is_placeholder(id: ProviderId) -> bool {
    let path = manifest_dir()
        .join("src/providers")
        .join(id.as_str())
        .join("client.rs");
    std::fs::read_to_string(path)
        .map(|text| text.starts_with("// PLACEHOLDER:"))
        .unwrap_or(false)
}

#[test]
fn metadata_is_sane() {
    for &id in ProviderId::ALL {
        let meta = id.meta();
        assert_eq!(meta.id, id);
        assert!(!meta.name.is_empty());
        assert!(!meta.fields.is_empty(), "{id}");
        assert!(
            meta.fields.iter().any(|f| f.secret),
            "{id}: no secret field"
        );
        if let Some(timeout) = meta.default_propagation_timeout {
            assert!(!timeout.is_zero(), "{id}");
        }
        let mut keys = BTreeSet::new();
        for field in meta.fields {
            let key = field.key;
            assert!(keys.insert(key), "{id}: duplicate key {key}");
            assert!(meta.field(key).is_some());
            assert!(
                key.starts_with(|c: char| c.is_ascii_lowercase())
                    && key
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{id}: key {key} is not snake_case"
            );
            assert_ne!(key, "propagation_timeout_s", "{id}: removed by design 11.3");
            assert!(!field.label.is_empty(), "{id}.{key}");
            assert!(
                field.help.ends_with('.'),
                "{id}.{key}: help is one sentence"
            );
            if field.required {
                assert_eq!(field.default, None, "{id}.{key}: required with a default");
            }
            if field.secret {
                assert_eq!(field.default, None, "{id}.{key}: secret with a default");
            }
            if key.ends_with("_url") {
                assert_eq!(field.kind, FieldKind::Url, "{id}.{key}");
            }
            if key == "ttl" || key.ends_with("_ms") {
                assert!(
                    matches!(field.kind, FieldKind::Integer { .. }),
                    "{id}.{key}"
                );
            }
            match field.kind {
                FieldKind::Url => {
                    if let Some(default) = field.default {
                        assert!(
                            default.starts_with("https://"),
                            "{id}.{key}: default endpoint is not https"
                        );
                    }
                }
                FieldKind::Integer { min, max } => {
                    assert!(min <= max, "{id}.{key}");
                    if key.ends_with("_poll_ms") {
                        assert!(min >= 250, "{id}.{key}: polling floor is 250 ms");
                    }
                    if let Some(default) = field.default {
                        let value: i64 = default.parse().unwrap();
                        assert!((min..=max).contains(&value), "{id}.{key}");
                    }
                }
                FieldKind::Text | FieldKind::Multiline => {}
                _ => panic!("{id}.{key}: unknown field kind"),
            }
        }
    }
}

#[test]
fn capabilities_are_consistent() {
    for &id in ProviderId::ALL {
        let caps = &id.meta().capabilities;
        let record_level =
            caps.list_rrsets || caps.get_rrset || caps.set_rrset || caps.delete_rrset;
        if let TypeSet::Listed(types) = caps.record_types {
            assert_eq!(!types.is_empty(), record_level, "{id}");
            for rtype in caps.read_only_types {
                assert!(
                    types.contains(rtype),
                    "{id}: read-only type outside record_types"
                );
            }
        }
        assert_eq!(
            caps.txt_values == ValueGuarantee::NotOffered,
            !caps.add_txt_value,
            "{id}: txt_values and add_txt_value disagree"
        );
        if caps.remove_txt_value {
            assert!(caps.add_txt_value, "{id}");
        }
        match caps.ttl {
            TtlSupport::PerRrset { min, max } | TtlSupport::PerRecord { min, max } => {
                assert!(min <= max, "{id}");
            }
            TtlSupport::NotSettable => {}
            _ => panic!("{id}: unknown TTL support"),
        }
        if caps.preconditions == Preconditions::Atomic && caps.set_rrset {
            assert!(caps.atomic_rrset_write, "{id}");
        }
        if is_placeholder(id) {
            for op in OPERATIONS {
                if op != Operation::Check {
                    assert!(!caps.supports(op), "{id}: placeholder announces {op}");
                }
            }
            assert_eq!(caps.record_types, TypeSet::Listed(&[]), "{id}");
            assert_eq!(caps.txt_values, ValueGuarantee::NotOffered, "{id}");
        }
    }
}

// ---- Behavior agrees with capabilities ---------------------------------------------------------

const OPERATIONS: [Operation; 8] = [
    Operation::Check,
    Operation::ListZones,
    Operation::ListRrsets,
    Operation::GetRrset,
    Operation::SetRrset,
    Operation::DeleteRrset,
    Operation::AddTxtValue,
    Operation::RemoveTxtValue,
];

/// Calls `op` with arguments that pass every other check.
async fn call(client: &AnyProvider, op: Operation) -> Result<(), Error> {
    let zone = dn("example.org");
    let name = dn("_acme-challenge.example.org");
    let value = Txt::new("conformance-value").unwrap();
    let rrset = RrSet::new(
        name.clone(),
        RecordType::TXT,
        None,
        [value.to_data().unwrap()],
    )
    .unwrap();
    match op {
        Operation::Check => client.check(&[zone]).await.map(drop),
        Operation::ListZones => client.list_zones().await.map(drop),
        Operation::ListRrsets => client.list_rrsets(&zone).await.map(drop),
        Operation::GetRrset => client
            .get_rrset(&zone, &name, RecordType::TXT)
            .await
            .map(drop),
        Operation::SetRrset => client.set_rrset(&zone, &rrset, Expect::Any).await.map(drop),
        Operation::DeleteRrset => client
            .delete_rrset(&zone, &name, RecordType::TXT, Expect::Any)
            .await
            .map(drop),
        Operation::AddTxtValue => client
            .add_txt_value(&zone, &name, &value, None)
            .await
            .map(drop),
        Operation::RemoveTxtValue => client
            .remove_txt_value(&zone, &name, &value)
            .await
            .map(drop),
        _ => panic!("unknown operation {op}"),
    }
}

/// Every operation whose capability flag is false returns `Unsupported` for that provider and
/// operation. The context refuses non-loopback connections and no client is pointed at a mock,
/// so no request can leave the test either way.
#[tokio::test]
async fn unsupported_operations_return_unsupported() {
    let ctx = context();
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        let client = sample_client(id, &ctx).unwrap();
        assert_eq!(client.id(), id);
        assert!(std::ptr::eq(client.capabilities(), &id.meta().capabilities));
        assert!(!format!("{client:?}").is_empty());
        let caps = client.capabilities();
        for op in OPERATIONS {
            if caps.supports(op) {
                continue;
            }
            let err = call(&client, op).await.unwrap_err();
            match err {
                Error::Unsupported {
                    provider,
                    operation,
                    ..
                } => {
                    assert_eq!(provider, id);
                    assert_eq!(operation, op);
                }
                other => panic!("{id} {op}: expected Unsupported, got {other:?}"),
            }
        }
    }
}

#[test]
fn ids_without_their_feature_are_not_compiled() {
    let ctx = context();
    for &id in ProviderId::ALL.iter().filter(|id| !id.available()) {
        let err = sample_client(id, &ctx).unwrap_err();
        match err {
            Error::NotCompiled { provider, .. } => assert_eq!(provider, id),
            other => panic!("{id}: expected NotCompiled, got {other:?}"),
        }
    }
}

#[test]
fn malformed_configuration_is_a_config_error_without_the_input() {
    let ctx = context();
    let canary = "canary-Secret-7f3a";
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        for (settings, credentials) in [
            (format!("[\"{canary}\"]"), "{}".to_owned()),
            ("{}".to_owned(), format!("\"{canary}\"")),
            (format!("{{\"a\": \"{canary}\""), "{}".to_owned()),
        ] {
            let err = AnyProvider::from_json(id, &settings, &credentials.into(), &ctx).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config, "{id}");
            assert!(!err.to_string().contains(canary), "{id}");
            assert!(!format!("{err:?}").contains(canary), "{id}");
        }
    }
}

/// The futures of `AnyProvider` are `Send`, whatever is compiled in. Checked at compile time.
#[allow(dead_code)] // Reason: only compiled, never run.
fn any_provider_futures_are_send(client: &AnyProvider, zone: &DomainName, value: &Txt) {
    fn send<T: Send>(_: T) {}
    send(client.check(&[]));
    send(client.list_zones());
    send(client.list_rrsets(zone));
    send(client.get_rrset(zone, zone, RecordType::A));
    send(client.add_txt_value(zone, zone, value, None));
    send(client.remove_txt_value(zone, zone, value));
    send(client.delete_rrset(zone, zone, RecordType::A, Expect::Absent));
}

/// The trait can be implemented outside the crate with the public constructors alone, and its
/// default methods answer `Unsupported`.
#[tokio::test]
async fn provider_trait_is_implementable_outside_the_crate() {
    struct Double;

    impl Provider for Double {
        fn id(&self) -> ProviderId {
            ProviderId::Cloudflare
        }

        async fn check(&self, zones: &[DomainName]) -> Result<CheckReport, Error> {
            let zones = zones
                .iter()
                .map(|zone| ZoneCheck::new(zone.clone(), true, Some(Detail::new("ok"))))
                .collect();
            Ok(CheckReport::new(true, zones))
        }
    }

    let double = Double;
    let report = double.check(&[dn("example.org")]).await.unwrap();
    assert!(report.credentials_verified);
    assert_eq!(report.zones.len(), 1);
    assert!(report.zones[0].found);
    let zone = dn("example.org");
    let err = double.list_zones().await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            operation: Operation::ListZones,
            ..
        }
    ));
    let err = double
        .add_txt_value(&zone, &zone, &Txt::new("v").unwrap(), None)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    let data = RecordData::parse(RecordType::A, "192.0.2.1").unwrap();
    let set = RrSet::new(zone.clone(), RecordType::A, None, [data]).unwrap();
    let err = double
        .set_rrset(&zone, &set, Expect::Matches(&set))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(std::ptr::eq(
        double.capabilities(),
        &ProviderId::Cloudflare.meta().capabilities
    ));
}

#[test]
fn error_kind_identifiers_are_stable() {
    let errors = [
        (Error::config("x"), "config"),
        (Error::not_compiled(ProviderId::Beget), "not_compiled"),
        (
            Error::unsupported(ProviderId::Beget, Operation::Check),
            "unsupported",
        ),
        (
            Error::unsupported_record_type(ProviderId::Beget, RecordType::TLSA),
            "unsupported_record_type",
        ),
        (Error::invalid_input("x"), "invalid_input"),
        (
            Error::name_outside_zone(dn("a.example.net"), dn("example.org")),
            "name_outside_zone",
        ),
        (Error::zone_not_found(dn("example.org")), "zone_not_found"),
        (Error::auth("x"), "auth"),
        (Error::forbidden("x"), "forbidden"),
        (Error::rate_limited(None), "rate_limited"),
        (Error::precondition_failed("x"), "precondition_failed"),
        (Error::conflict("x"), "conflict"),
        (Error::transient("x"), "transient"),
        (Error::rejected(Some(400), "x"), "rejected"),
        (Error::protocol("x"), "protocol"),
    ];
    for (err, text) in errors {
        assert_eq!(err.kind().as_str(), text);
    }
    let ops = [
        "check",
        "list_zones",
        "list_rrsets",
        "get_rrset",
        "set_rrset",
        "delete_rrset",
        "add_txt_value",
        "remove_txt_value",
    ];
    for (op, text) in OPERATIONS.iter().zip(ops) {
        assert_eq!(op.to_string(), text);
    }
    assert_eq!(
        Error::name_outside_zone(dn("a.example.net"), dn("example.org")).to_string(),
        "name a.example.net. is outside zone example.org."
    );
}

// ---- Source scans ------------------------------------------------------------------------------

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Provider clients build error text only through a scrubber or from constants (design section
/// 2.9): no file under `src/providers/` calls `Detail::new` or an `Error` constructor that takes
/// text.
#[test]
fn provider_sources_use_no_text_constructors() {
    let forbidden = [
        "Detail::new(",
        "Error::config(",
        "Error::invalid_input(",
        "Error::auth(",
        "Error::forbidden(",
        "Error::precondition_failed(",
        "Error::conflict(",
        "Error::transient(",
        "Error::rejected(",
        "Error::protocol(",
    ];
    let mut files = Vec::new();
    rust_files(&manifest_dir().join("src/providers"), &mut files);
    assert!(files.len() >= 45, "the scan found too few files");
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        for needle in forbidden {
            assert!(!text.contains(needle), "{} calls {needle}", path.display());
        }
    }
}

/// True when a file of the provider's module under `src/providers/<id>/` contains `needle`.
fn provider_sources_contain(id: ProviderId, needle: &str) -> bool {
    let mut files = Vec::new();
    rust_files(
        &manifest_dir().join("src/providers").join(id.as_str()),
        &mut files,
    );
    files
        .iter()
        .any(|path| std::fs::read_to_string(path).unwrap().contains(needle))
}

/// Every provider whose client is ported defines the tests that sections 12.2 and 12.3 require
/// in its own test file. Placeholders are skipped; the scan applies as soon as one is replaced.
#[test]
fn provider_test_files_define_the_required_tests() {
    for &id in ProviderId::ALL {
        if is_placeholder(id) {
            continue;
        }
        let caps = &id.meta().capabilities;
        let mut required: Vec<&str> = vec!["no_secret_in_logs"];
        // RFC 2136 has no HTTP echo; it has its own secret test (design section 12.2).
        if id != ProviderId::Rfc2136 {
            required.push("secret_echo");
        }
        let writes =
            caps.add_txt_value || caps.remove_txt_value || caps.set_rrset || caps.delete_rrset;
        if writes {
            // Design 12.3: name checks before any request, and the retry rule of section 5.3
            // (a write that is not idempotent is sent once).
            required.extend(["name_outside_zone_sends_nothing", "writes_are_sent_once"]);
        }
        // Design 2.5: an unsupported operation is `Unsupported` before any request.
        if OPERATIONS.iter().any(|&op| !caps.supports(op)) {
            required.push("unsupported_operations_send_nothing");
        }
        // Design 3.8 and 12.3: a client that caches zone identifiers tests a stale one. Whether
        // it caches them is read from its sources: the shared cache is `ZoneCache`.
        if provider_sources_contain(id, "ZoneCache") {
            required.push("stale_zone_id");
        }
        if caps.add_txt_value {
            required.extend(["add_is_idempotent", "concurrent_adds_are_serialized"]);
        }
        if caps.remove_txt_value {
            required.extend([
                "never_removes_foreign_value",
                "remove_last_value_deletes_rrset",
                "remove_is_idempotent",
            ]);
        }
        if caps.txt_values == ValueGuarantee::Conditional {
            required.push("concurrent_change_is_conflict");
        }
        if caps.set_rrset || caps.delete_rrset {
            required.push("failed_expectation_is_precondition_failed");
        }
        if caps.list_rrsets {
            required.push("listing_reports_skipped_sets");
        }
        let path = manifest_dir()
            .join("tests")
            .join(format!("{}.rs", id.as_str()));
        let text = std::fs::read_to_string(&path).unwrap();
        for suffix in required {
            let name = format!("fn {}_{suffix}(", id.as_str());
            assert!(text.contains(&name), "{}: missing {name}", path.display());
        }
    }
}
