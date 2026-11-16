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
    Preconditions, Provider, ProviderDefaultTtl, ProviderId, RecordData, RecordType, RrSet,
    RrsetTtl, Ttl, TtlSupport, Txt, TypeSet, ValueGuarantee, ZoneCheck,
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

/// True when the tests run from the published package rather than from the repository. Cargo adds
/// `.cargo_vcs_info.json` to every package it builds from a git checkout. The checks that compare
/// the crate with files of the repository (`PROVIDERS.md`, the license texts) do not apply there:
/// those files are not in the package.
fn packaged() -> bool {
    manifest_dir().join(".cargo_vcs_info.json").exists()
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
    if packaged() {
        return;
    }
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
    if packaged() {
        return;
    }
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
    if packaged() {
        return;
    }
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
            if key == "ttl" {
                assert!(matches!(field.kind, FieldKind::Ttl { .. }), "{id}.{key}");
            }
            if key.ends_with("_ms") {
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
                FieldKind::Ttl {
                    min,
                    max,
                    provider_default,
                } => {
                    assert!(min <= max, "{id}.{key}");
                    match field.default {
                        Some("provider_default") => assert!(provider_default, "{id}.{key}"),
                        Some(default) => {
                            let value: u32 = default.parse().unwrap();
                            assert!((min..=max).contains(&value), "{id}.{key}");
                        }
                        None => {}
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
    }
}

/// `Capabilities::atomic_rrset_write` per provider: whether replacing an rrset is one request at
/// the provider (design sections 2.5 and 11.1). For a provider without record-level operations
/// the flag says what a set replacement is at its API. Written out, with the reason, so that a
/// change is deliberate.
const ATOMIC_RRSET_WRITE: &[(ProviderId, bool)] = &[
    // No rrset can be replaced: the API only adds a value to a rotating pair.
    (ProviderId::AcmeDns, false),
    // `dns/changeRecords` replaces the TXT set of a name in one request.
    (ProviderId::Beget, true),
    // One record per name and type holds the list of values; one request replaces it.
    (ProviderId::CloudRu, true),
    // Individual records: a replacement is several requests.
    (ProviderId::Cloudflare, false),
    (ProviderId::DigitalOcean, false),
    // `set_records` replaces the records of an rrset in one request and `POST …/rrsets` creates
    // it with its records, but a replacement that also changes the TTL of an existing rrset is
    // `set_records` and then `change_ttl`: two requests.
    (ProviderId::Hetzner, false),
    // Individual records, staged and committed: several requests.
    (ProviderId::Nicru, false),
    (ProviderId::Regru, false),
    // One UPDATE deletes the RRset and adds the new RRs as one transaction (RFC 2136).
    (ProviderId::Rfc2136, true),
    // One change batch, applied atomically.
    (ProviderId::Route53, true),
    // An rrset with an ID, created or replaced in one request.
    (ProviderId::SelectelV2, true),
    (ProviderId::TimewebCloud, false),
    (ProviderId::VkCloud, false),
    (ProviderId::Yandex360, false),
    // One `updateRecordSets` call.
    (ProviderId::YandexCloud, true),
];

#[test]
fn atomic_rrset_write_follows_the_native_unit() {
    assert_eq!(ATOMIC_RRSET_WRITE.len(), ProviderId::ALL.len());
    for &(id, atomic) in ATOMIC_RRSET_WRITE {
        assert_eq!(
            id.meta().capabilities.atomic_rrset_write,
            atomic,
            "{id}: atomic_rrset_write"
        );
    }
}

/// `Capabilities::provider_default_ttl` per provider: whether an rrset or a record can have no
/// explicit TTL at the provider, so that it reads as `RrsetTtl::ProviderDefault`, and whether a
/// write can ask for it (design sections 2.5 and 3.6). Written out, with the reason, so that a
/// change is deliberate.
const PROVIDER_DEFAULT_TTL: &[(ProviderId, ProviderDefaultTtl)] = &[
    // The server serves every value with a TTL of its own choosing: it is the only TTL there is.
    (ProviderId::AcmeDns, ProviderDefaultTtl::Requestable),
    // Every record carries a TTL; no read, so nothing reads as the default.
    (ProviderId::Beget, ProviderDefaultTtl::Absent),
    // A record's `ttl` is a number of seconds.
    (ProviderId::CloudRu, ProviderDefaultTtl::Absent),
    // `1` means automatic, on a create and on a PATCH alike.
    (ProviderId::Cloudflare, ProviderDefaultTtl::Requestable),
    // Every record carries a TTL in the documented answers.
    (ProviderId::DigitalOcean, ProviderDefaultTtl::Absent),
    // An rrset's `ttl` may be `null`: the zone's default applies; a create without `ttl` and a
    // `change_ttl` with `null` ask for it.
    (ProviderId::Hetzner, ProviderDefaultTtl::Requestable),
    // A record's `ttl` is optional; without one the zone's default applies (Docs 4.6). A TTL
    // change stages the record again, with or without `<ttl>`.
    (ProviderId::Nicru, ProviderDefaultTtl::Requestable),
    // No TTL can be set, and the listing states none: the provider's is the only one.
    (ProviderId::Regru, ProviderDefaultTtl::Requestable),
    // Every RR carries a TTL on the wire.
    (ProviderId::Rfc2136, ProviderDefaultTtl::Absent),
    // A plain rrset carries a TTL.
    (ProviderId::Route53, ProviderDefaultTtl::Absent),
    (ProviderId::SelectelV2, ProviderDefaultTtl::Absent),
    // A record may have no `ttl` and a create may leave it out, but whether an update without
    // one clears an explicit TTL is not documented.
    (ProviderId::TimewebCloud, ProviderDefaultTtl::ForNewRecords),
    (ProviderId::VkCloud, ProviderDefaultTtl::Absent),
    (ProviderId::Yandex360, ProviderDefaultTtl::Absent),
    (ProviderId::YandexCloud, ProviderDefaultTtl::Absent),
];

#[test]
fn provider_default_ttl_is_consistent() {
    assert_eq!(PROVIDER_DEFAULT_TTL.len(), ProviderId::ALL.len());
    for &(id, expected) in PROVIDER_DEFAULT_TTL {
        let meta = id.meta();
        let caps = &meta.capabilities;
        assert_eq!(caps.provider_default_ttl, expected, "{id}");
        assert_eq!(
            caps.accepts_ttl(RrsetTtl::ProviderDefault),
            expected.can_request(),
            "{id}"
        );
        // A provider that chooses every TTL itself has nothing but its own TTL, and a request
        // for it is always satisfied.
        if caps.ttl == TtlSupport::NotSettable {
            assert_eq!(
                caps.provider_default_ttl,
                ProviderDefaultTtl::Requestable,
                "{id}: NotSettable without a requestable provider TTL"
            );
            continue;
        }
        // Where a TTL can be set, a write without one falls back on the `ttl` setting (design
        // section 3.6): for a new rrset always, and for an existing one that reads with no TTL
        // where the provider has no TTL of its own. The setting offers the provider's default
        // exactly where a write can ask for it, and no number the capabilities refuse.
        if caps.set_rrset || caps.add_txt_value {
            let field = meta.field("ttl");
            assert!(field.is_some(), "{id}: no ttl setting to fall back on");
            let Some(FieldKind::Ttl {
                min,
                max,
                provider_default,
            }) = field.map(|f| f.kind)
            else {
                panic!("{id}: the ttl setting is not of kind Ttl");
            };
            assert_eq!(provider_default, expected.can_request(), "{id}");
            let (cap_min, cap_max) = match caps.ttl {
                TtlSupport::PerRrset { min, max } | TtlSupport::PerRecord { min, max } => {
                    (min, max)
                }
                _ => panic!("{id}: unknown TTL support"),
            };
            assert!(
                cap_min <= min && max <= cap_max,
                "{id}: the ttl setting allows a TTL the capabilities refuse"
            );
        }
    }
}

/// The `ttl` setting: `"provider_default"` builds a client exactly where the provider has a
/// default a write can ask for, and is a `Config` error naming the key elsewhere; the default,
/// the smallest and the largest number of the metadata build a client everywhere, and a
/// configuration without the key serializes the metadata's default.
#[test]
fn ttl_setting_spells_the_provider_default() {
    let ctx = context();
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        let meta = id.meta();
        let Some(FieldKind::Ttl {
            min,
            max,
            provider_default,
        }) = meta.field("ttl").map(|f| f.kind)
        else {
            continue;
        };
        let (settings, credentials) = common::sample_config(id);
        let build = |ttl: serde_json::Value| {
            let settings = edit_object(settings, "ttl", Some(ttl));
            AnyProvider::from_json(id, &settings, &credentials.to_owned().into(), &ctx)
        };
        match build(serde_json::json!("provider_default")) {
            Ok(_) => assert!(provider_default, "{id}: accepted without the capability"),
            Err(e) => {
                assert!(!provider_default, "{id}: refused with the capability: {e}");
                assert_eq!(e.kind(), ErrorKind::Config, "{id}");
                assert!(e.to_string().contains("ttl"), "{id}: {e}");
            }
        }
        for secs in [min, max] {
            assert!(build(serde_json::json!(secs)).is_ok(), "{id}: {secs}");
        }
        for bad in [
            serde_json::json!("Provider_Default"),
            serde_json::json!("300"),
            serde_json::json!(-1),
        ] {
            let e = build(bad.clone()).map(drop).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Config, "{id}: {bad}");
        }
        let without = edit_object(settings, "ttl", None);
        let object = config_type_object(id, &without).unwrap();
        let default = meta.field("ttl").and_then(|f| f.default);
        let text = match &object["ttl"] {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        };
        assert_eq!(text.as_deref(), default, "{id}");
    }
}

// ---- Metadata fields and configuration types ---------------------------------------------------

/// The provider's `…Config` type with `settings` deserialized into it and serialized again, as
/// a JSON object. Every field of the type is serialized (none is skipped), so its keys are all
/// the type's keys. `None` when the provider is not compiled in.
fn config_type_object(
    id: ProviderId,
    #[allow(unused_variables)] // Reason: unused in a build without providers.
    settings: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    #[allow(dead_code)] // Reason: unused in a build without providers.
    fn keys<T: serde::de::DeserializeOwned + serde::Serialize>(
        settings: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let config: T = serde_json::from_str(settings).unwrap();
        match serde_json::to_value(&config).unwrap() {
            serde_json::Value::Object(map) => map,
            other => panic!("the settings type serializes to {other}"),
        }
    }
    #[allow(unused_imports)] // Reason: unused in a build without providers.
    use zonewright::providers::*;
    match id {
        #[cfg(feature = "acme_dns")]
        ProviderId::AcmeDns => Some(keys::<acme_dns::AcmeDnsConfig>(settings)),
        #[cfg(feature = "beget")]
        ProviderId::Beget => Some(keys::<beget::BegetConfig>(settings)),
        #[cfg(feature = "cloud_ru")]
        ProviderId::CloudRu => Some(keys::<cloud_ru::CloudRuConfig>(settings)),
        #[cfg(feature = "cloudflare")]
        ProviderId::Cloudflare => Some(keys::<cloudflare::CloudflareConfig>(settings)),
        #[cfg(feature = "digitalocean")]
        ProviderId::DigitalOcean => Some(keys::<digitalocean::DigitalOceanConfig>(settings)),
        #[cfg(feature = "hetzner")]
        ProviderId::Hetzner => Some(keys::<hetzner::HetznerConfig>(settings)),
        #[cfg(feature = "nicru")]
        ProviderId::Nicru => Some(keys::<nicru::NicruConfig>(settings)),
        #[cfg(feature = "regru")]
        ProviderId::Regru => Some(keys::<regru::RegruConfig>(settings)),
        #[cfg(feature = "rfc2136")]
        ProviderId::Rfc2136 => Some(keys::<rfc2136::Rfc2136Config>(settings)),
        #[cfg(feature = "route53")]
        ProviderId::Route53 => Some(keys::<route53::Route53Config>(settings)),
        #[cfg(feature = "selectel_v2")]
        ProviderId::SelectelV2 => Some(keys::<selectel_v2::SelectelV2Config>(settings)),
        #[cfg(feature = "timeweb_cloud")]
        ProviderId::TimewebCloud => Some(keys::<timeweb_cloud::TimewebCloudConfig>(settings)),
        #[cfg(feature = "vk_cloud")]
        ProviderId::VkCloud => Some(keys::<vk_cloud::VkCloudConfig>(settings)),
        #[cfg(feature = "yandex_360")]
        ProviderId::Yandex360 => Some(keys::<yandex_360::Yandex360Config>(settings)),
        #[cfg(feature = "yandex_cloud")]
        ProviderId::YandexCloud => Some(keys::<yandex_cloud::YandexCloudConfig>(settings)),
        _ => None,
    }
}

/// The field names of the provider's `…Credentials` type, read from its definition in
/// `src/providers/<id>/config.rs`. The credentials types hold secrets and are not
/// serializable, so their fields are read from the source; a serde attribute that renames a
/// field would make the names differ from the keys and fails the scan.
fn credentials_type_fields(id: ProviderId) -> BTreeSet<String> {
    let path = manifest_dir()
        .join("src/providers")
        .join(id.as_str())
        .join("config.rs");
    let text = std::fs::read_to_string(&path).unwrap();
    let start = text
        .lines()
        .position(|line| line.starts_with("pub struct ") && line.contains("Credentials {"))
        .unwrap_or_else(|| panic!("{}: no pub struct …Credentials", path.display()));
    let mut fields = BTreeSet::new();
    for line in text.lines().skip(start + 1) {
        let line = line.trim();
        if line == "}" {
            break;
        }
        assert!(
            !(line.starts_with("#[serde") && (line.contains("rename") || line.contains("alias"))),
            "{}: a credentials field is renamed",
            path.display()
        );
        if let Some(rest) = line.strip_prefix("pub ") {
            let name = rest.split(':').next().unwrap().trim();
            fields.insert(name.to_owned());
        }
    }
    assert!(
        !fields.is_empty(),
        "{}: no credentials field",
        path.display()
    );
    fields
}

/// `text` (a JSON object) without `key`, or with `key` set to `value`.
fn edit_object(text: &str, key: &str, value: Option<serde_json::Value>) -> String {
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).unwrap();
    match value {
        Some(value) => object.insert(key.to_owned(), value),
        None => object.remove(key),
    };
    serde_json::Value::Object(object).to_string()
}

/// Every metadata field is a key of the provider's `…Config` type (non-secret) or of its
/// `…Credentials` type (secret), and every key of those types is a metadata field. Checked with
/// the types themselves (the settings type serialized, the credentials type read from its
/// definition) and by building the client through `AnyProvider::from_json` from the sample
/// configuration with one key removed, added or put into the wrong object at a time: a
/// required key is required, an optional key with a default accepts it, a secret key is refused
/// in the settings, and an unknown settings key is refused. All misses are reported together.
#[test]
fn metadata_fields_equal_the_configuration_types() {
    // No request is made: the clients are only built. A context without `loopback_only`, so
    // that default endpoints (public https URLs) are accepted.
    let ctx = zonewright::Context::new(zonewright::ContextOptions::default()).unwrap();
    let build = |id: ProviderId, settings: &str, credentials: &str| {
        AnyProvider::from_json(id, settings, &credentials.to_owned().into(), &ctx)
    };
    let mut misses: Vec<String> = Vec::new();
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        let meta = id.meta();
        let (settings, credentials) = common::sample_config(id);
        let settings_fields: BTreeSet<String> = meta
            .fields
            .iter()
            .filter(|f| !f.secret)
            .map(|f| f.key.to_owned())
            .collect();
        let secret_fields: BTreeSet<String> = meta
            .fields
            .iter()
            .filter(|f| f.secret)
            .map(|f| f.key.to_owned())
            .collect();
        let config_keys: BTreeSet<String> = config_type_object(id, settings)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        if config_keys != settings_fields {
            misses.push(format!(
                "{id}: settings fields {settings_fields:?} differ from the config type's keys {config_keys:?}"
            ));
        }
        let credential_keys = credentials_type_fields(id);
        if credential_keys != secret_fields {
            misses.push(format!(
                "{id}: secret fields {secret_fields:?} differ from the credentials type's fields {credential_keys:?}"
            ));
        }
        if let Err(e) = build(id, settings, credentials) {
            misses.push(format!("{id}: the sample configuration is refused: {e}"));
            continue;
        }
        for field in meta.fields {
            let key = field.key;
            let (object, other) = if field.secret {
                (credentials, settings)
            } else {
                (settings, credentials)
            };
            let with = |text: &str| {
                if field.secret {
                    build(id, other, text)
                } else {
                    build(id, text, other)
                }
            };
            if field.required {
                match with(&edit_object(object, key, None)) {
                    Err(e) if e.kind() == ErrorKind::Config => {}
                    Err(e) => misses.push(format!("{id}.{key}: removed, {e:?}")),
                    Ok(_) => misses.push(format!("{id}.{key}: required, but accepted without it")),
                }
            } else if let Some(default) = field.default {
                let value = match field.kind {
                    FieldKind::Integer { .. } => {
                        serde_json::Value::from(default.parse::<i64>().unwrap())
                    }
                    // A TTL is a number, or the string "provider_default".
                    FieldKind::Ttl { .. } => default.parse::<i64>().map_or_else(
                        |_| serde_json::Value::from(default),
                        serde_json::Value::from,
                    ),
                    _ => serde_json::Value::from(default),
                };
                if let Err(e) = with(&edit_object(object, key, Some(value))) {
                    misses.push(format!("{id}.{key}: its default is refused: {e}"));
                }
            }
            if field.secret {
                let misplaced = edit_object(settings, key, Some(serde_json::Value::from("x")));
                match build(id, &misplaced, credentials) {
                    Err(e) if e.kind() == ErrorKind::Config => {}
                    other => misses.push(format!(
                        "{id}.{key}: a secret key in the settings is not refused: {:?}",
                        other.map(drop)
                    )),
                }
            }
        }
        let unknown = edit_object(
            settings,
            "zz_not_a_field",
            Some(serde_json::Value::from("x")),
        );
        if build(id, &unknown, credentials).is_ok() {
            misses.push(format!("{id}: an unknown settings key is accepted"));
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// The defaults the metadata states are the defaults of the `…Config` type: a settings object
/// with only the required keys, deserialized into the type and serialized again, holds the
/// metadata's default at every key that has one (as text, an integer compared by its decimal
/// form). A field the type leaves unset (`null`) while the metadata states a default is a miss,
/// as is a required key that the type fills in on its own. All misses are reported together.
#[test]
fn metadata_defaults_equal_the_configuration_types() {
    let mut misses: Vec<String> = Vec::new();
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        let meta = id.meta();
        let (settings, _) = common::sample_config(id);
        let sample: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(settings).unwrap();
        let required: serde_json::Map<String, serde_json::Value> = sample
            .into_iter()
            .filter(|(key, _)| meta.field(key).is_some_and(|f| f.required && !f.secret))
            .collect();
        let required_text = serde_json::Value::Object(required.clone()).to_string();
        let object = config_type_object(id, &required_text).unwrap();
        for field in meta.fields.iter().filter(|f| !f.secret) {
            let key = field.key;
            let value = object.get(key).unwrap_or(&serde_json::Value::Null);
            match field.default {
                Some(default) => {
                    let text = match value {
                        serde_json::Value::String(text) => Some(text.clone()),
                        serde_json::Value::Number(number) => Some(number.to_string()),
                        serde_json::Value::Bool(flag) => Some(flag.to_string()),
                        _ => None,
                    };
                    if text.as_deref() != Some(default) {
                        misses.push(format!(
                            "{id}.{key}: the metadata's default is {default:?}, the config type's is {value}"
                        ));
                    }
                }
                None if field.required && !required.contains_key(key) => {
                    misses.push(format!(
                        "{id}.{key}: required, but missing from the sample configuration"
                    ));
                }
                None => {}
            }
        }
        // A required key has no default in the type: without it, the settings do not
        // deserialize.
        for field in meta.fields.iter().filter(|f| f.required && !f.secret) {
            let without = edit_object(&required_text, field.key, None);
            if config_deserializes(id, &without) {
                misses.push(format!(
                    "{id}.{}: required, but the config type deserializes without it",
                    field.key
                ));
            }
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// Whether `settings` deserializes into the provider's `…Config` type (no validation).
fn config_deserializes(
    id: ProviderId,
    #[allow(unused_variables)] // Reason: unused in a build without providers.
    settings: &str,
) -> bool {
    #[allow(dead_code)] // Reason: unused in a build without providers.
    fn parses<T: serde::de::DeserializeOwned>(settings: &str) -> bool {
        serde_json::from_str::<T>(settings).is_ok()
    }
    #[allow(unused_imports)] // Reason: unused in a build without providers.
    use zonewright::providers::*;
    match id {
        #[cfg(feature = "acme_dns")]
        ProviderId::AcmeDns => parses::<acme_dns::AcmeDnsConfig>(settings),
        #[cfg(feature = "beget")]
        ProviderId::Beget => parses::<beget::BegetConfig>(settings),
        #[cfg(feature = "cloud_ru")]
        ProviderId::CloudRu => parses::<cloud_ru::CloudRuConfig>(settings),
        #[cfg(feature = "cloudflare")]
        ProviderId::Cloudflare => parses::<cloudflare::CloudflareConfig>(settings),
        #[cfg(feature = "digitalocean")]
        ProviderId::DigitalOcean => parses::<digitalocean::DigitalOceanConfig>(settings),
        #[cfg(feature = "hetzner")]
        ProviderId::Hetzner => parses::<hetzner::HetznerConfig>(settings),
        #[cfg(feature = "nicru")]
        ProviderId::Nicru => parses::<nicru::NicruConfig>(settings),
        #[cfg(feature = "regru")]
        ProviderId::Regru => parses::<regru::RegruConfig>(settings),
        #[cfg(feature = "rfc2136")]
        ProviderId::Rfc2136 => parses::<rfc2136::Rfc2136Config>(settings),
        #[cfg(feature = "route53")]
        ProviderId::Route53 => parses::<route53::Route53Config>(settings),
        #[cfg(feature = "selectel_v2")]
        ProviderId::SelectelV2 => parses::<selectel_v2::SelectelV2Config>(settings),
        #[cfg(feature = "timeweb_cloud")]
        ProviderId::TimewebCloud => parses::<timeweb_cloud::TimewebCloudConfig>(settings),
        #[cfg(feature = "vk_cloud")]
        ProviderId::VkCloud => parses::<vk_cloud::VkCloudConfig>(settings),
        #[cfg(feature = "yandex_360")]
        ProviderId::Yandex360 => parses::<yandex_360::Yandex360Config>(settings),
        #[cfg(feature = "yandex_cloud")]
        ProviderId::YandexCloud => parses::<yandex_cloud::YandexCloudConfig>(settings),
        _ => false,
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
/// operation, before any request: every endpoint of the sample configuration points at a
/// loopback port with a TCP listener and a UDP socket, and neither sees anything.
#[tokio::test]
async fn unsupported_operations_return_unsupported() {
    let ctx = context();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = std::net::UdpSocket::bind(addr).unwrap();
    udp.set_nonblocking(true).unwrap();
    let assert_untouched = |what: &str| {
        let would_block =
            |e: std::io::Error| assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "{what}: {e}");
        match tcp.accept() {
            Ok(_) => panic!("{what}: a TCP connection was made"),
            Err(e) => would_block(e),
        }
        let mut buf = [0u8; 512];
        match udp.recv_from(&mut buf) {
            Ok(_) => panic!("{what}: a UDP datagram was sent"),
            Err(e) => would_block(e),
        }
    };
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        let (settings, credentials) = common::sample_config(id);
        assert!(
            settings.contains("127.0.0.1:9"),
            "{id}: sample has no endpoint"
        );
        let settings = settings.replace("127.0.0.1:9", &addr.to_string());
        let client =
            AnyProvider::from_json(id, &settings, &credentials.to_owned().into(), &ctx).unwrap();
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
            assert_untouched(&format!("{id} {op}"));
        }
    }
}

/// A request for the provider's default TTL, at a provider that has none a write can ask for,
/// is `InvalidInput` before any request, for `set_rrset` and `add_txt_value` alike; an explicit
/// TTL outside the capabilities is refused the same way. Endpoints as in
/// `unsupported_operations_return_unsupported`: a loopback port that must see nothing.
#[tokio::test]
async fn ttl_requests_the_provider_refuses_send_nothing() {
    let ctx = context();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tcp.set_nonblocking(true).unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = std::net::UdpSocket::bind(addr).unwrap();
    udp.set_nonblocking(true).unwrap();
    let assert_untouched = |what: &str| {
        let would_block =
            |e: std::io::Error| assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "{what}: {e}");
        match tcp.accept() {
            Ok(_) => panic!("{what}: a TCP connection was made"),
            Err(e) => would_block(e),
        }
        let mut buf = [0u8; 512];
        match udp.recv_from(&mut buf) {
            Ok(_) => panic!("{what}: a UDP datagram was sent"),
            Err(e) => would_block(e),
        }
    };
    let zone = dn("example.org");
    let name = dn("_acme-challenge.example.org");
    let value = Txt::new("conformance-value").unwrap();
    let mut refused = 0;
    for &id in ProviderId::ALL.iter().filter(|id| id.available()) {
        let (settings, credentials) = common::sample_config(id);
        let settings = settings.replace("127.0.0.1:9", &addr.to_string());
        let client =
            AnyProvider::from_json(id, &settings, &credentials.to_owned().into(), &ctx).unwrap();
        let caps = client.capabilities();
        // Decided from the capability fields themselves, not from `accepts_ttl`, so that a
        // wrong answer of that method cannot hide a request that goes out.
        let mut requests = Vec::new();
        if !caps.ttl.accepts(Ttl::MAX.as_secs()) {
            requests.push(Some(RrsetTtl::Explicit(Ttl::MAX)));
        }
        if !caps.provider_default_ttl.can_request() {
            requests.push(Some(RrsetTtl::ProviderDefault));
        }
        for ttl in requests {
            let rrset = RrSet::new(
                name.clone(),
                RecordType::TXT,
                ttl,
                [value.to_data().unwrap()],
            )
            .unwrap();
            if caps.set_rrset && caps.can_write(RecordType::TXT) {
                let e = client
                    .set_rrset(&zone, &rrset, Expect::Any)
                    .await
                    .unwrap_err();
                assert_eq!(e.kind(), ErrorKind::InvalidInput, "{id} set {ttl:?}: {e}");
                assert_untouched(&format!("{id} set_rrset {ttl:?}"));
                refused += 1;
            }
            if caps.add_txt_value {
                let e = client
                    .add_txt_value(&zone, &name, &value, ttl)
                    .await
                    .unwrap_err();
                assert_eq!(e.kind(), ErrorKind::InvalidInput, "{id} add {ttl:?}: {e}");
                assert_untouched(&format!("{id} add_txt_value {ttl:?}"));
                refused += 1;
            }
        }
    }
    // A single provider may accept every TTL request (Hetzner takes the whole range and the
    // provider's default), so the loop can be empty for one feature alone. With all providers
    // compiled in it must not be: several of them refuse the provider's default.
    if cfg!(feature = "all-providers") {
        assert!(refused > 0);
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

        async fn check<'a>(
            &self,
            zones: impl IntoIterator<Item = &'a DomainName> + Send,
        ) -> Result<CheckReport, Error> {
            let zones: Vec<DomainName> = zones.into_iter().cloned().collect();
            let zones = zones.as_slice();
            let zones = zones
                .iter()
                .map(|zone| ZoneCheck::new(zone.clone(), true, Some(Detail::new("ok"))))
                .collect();
            Ok(CheckReport::new(true, zones))
        }
    }

    fn assert_send<T: Send>(value: T) -> T {
        value
    }

    let double = Double;
    let report = double.check(&[dn("example.org")]).await.unwrap();
    assert!(report.credentials_verified);
    assert_eq!(report.zones.len(), 1);
    assert!(report.zones[0].found);

    // `check` takes any list of zone references, and its future is `Send` for each of them.
    let zones = vec![dn("example.org"), dn("example.net")];
    let one = assert_send(double.check([&zones[0]])).await.unwrap();
    assert_eq!(one.zones.len(), 1);
    let all = assert_send(double.check(&zones)).await.unwrap();
    assert_eq!(all.zones.len(), 2);
    let slice = assert_send(double.check(zones.as_slice())).await.unwrap();
    assert_eq!(slice.zones.len(), 2);
    let tail = assert_send(double.check(zones.iter().skip(1)))
        .await
        .unwrap();
    assert_eq!(tail.zones.len(), 1);
    let none = assert_send(double.check([])).await.unwrap();
    assert!(none.credentials_verified);
    assert!(none.zones.is_empty());
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
        (Error::proxy_auth(), "proxy_auth"),
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

/// Every provider defines the tests that sections 12.2 and 12.3 require in its own test file.
/// Every missing test of every provider is reported together.
#[test]
fn provider_test_files_define_the_required_tests() {
    let mut missing: Vec<String> = Vec::new();
    for &id in ProviderId::ALL {
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
            let name = format!("{}_{suffix}", id.as_str());
            if !defines_test(&text, &name) {
                missing.push(format!(
                    "{}: fn {name} is missing or is not a test that runs",
                    path.display()
                ));
            }
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

/// Whether `text` defines the function `name` as a test that runs: the lines directly above the
/// function (attributes and doc comments) carry `#[test]` or `#[tokio::test`, and none of them is
/// `#[ignore`. A name that only occurs in a comment, a helper function and an ignored test do not
/// count.
fn defines_test(text: &str, name: &str) -> bool {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let sync = format!("fn {name}(");
    let asynchronous = format!("async fn {name}(");
    lines.iter().enumerate().any(|(at, line)| {
        if !line.starts_with(&sync) && !line.starts_with(&asynchronous) {
            return false;
        }
        let above: Vec<&str> = lines[..at]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
            .copied()
            .collect();
        above
            .iter()
            .any(|l| l.starts_with("#[test]") || l.starts_with("#[tokio::test"))
            && !above.iter().any(|l| l.starts_with("#[ignore"))
    })
}

#[test]
fn a_required_test_must_be_a_test_that_runs() {
    let name = "x_secret_echo";
    assert!(defines_test(
        "#[tokio::test]\nasync fn x_secret_echo() {",
        name
    ));
    assert!(defines_test(
        "#[test]\n/// Doc.\nfn x_secret_echo() {",
        name
    ));
    assert!(defines_test(
        "    #[tokio::test(start_paused = true)]\n    async fn x_secret_echo() {",
        name
    ));
    assert!(!defines_test("// fn x_secret_echo() {", name));
    assert!(!defines_test("fn x_secret_echo() {", name));
    assert!(!defines_test(
        "#[test]\n\nfn other() {}\nfn x_secret_echo() {",
        name
    ));
    assert!(!defines_test(
        "#[tokio::test]\n#[ignore = \"live\"]\nasync fn x_secret_echo() {",
        name
    ));
    assert!(!defines_test(
        "#[tokio::test]\nasync fn x_secret_echo_more() {",
        name
    ));
}

/// Both crate directories carry the license texts, so that they are in the published packages;
/// they are copies of the repository's and must not drift from them.
#[test]
fn crate_license_files_equal_the_repository_ones() {
    if packaged() {
        return;
    }
    let root = manifest_dir().join("../..");
    for krate in [manifest_dir(), manifest_dir().join("../mock")] {
        for name in ["LICENSE-MIT", "LICENSE-APACHE"] {
            let ours = std::fs::read(krate.join(name))
                .unwrap_or_else(|e| panic!("{}/{name}: {e}", krate.display()));
            let theirs = std::fs::read(root.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!ours.is_empty(), "{name}");
            assert_eq!(ours, theirs, "{}/{name}", krate.display());
        }
    }
}
