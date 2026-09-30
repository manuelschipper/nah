use std::collections::BTreeSet;
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// Canonical protocol JSON: fixed struct field order, sorted map keys supplied
/// by the protocol types, pretty UTF-8 JSON, and exactly one trailing LF.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    let mut out = serde_json::to_string_pretty(value).expect("protocol serialization cannot fail");
    out.push('\n');
    out
}

/// BLAKE3 identity of a canonical protocol value.
pub fn canonical_hash<T: Serialize>(value: &T) -> String {
    format!(
        "blake3:{}",
        blake3::hash(canonical_json(value).as_bytes()).to_hex()
    )
}

/// Domain-separated identity over a JSON value with lexicographically sorted
/// object keys. Unlike envelope serialization, this does not depend on Rust
/// field declaration order.
pub fn stable_hash<T: Serialize>(domain: &str, value: &T) -> String {
    let value = serde_json::to_value(value).expect("protocol identity must serialize");
    let bytes = serde_json::to_vec(&value).expect("protocol identity must serialize");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"effinterp/stable-id/v1\0");
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    format!("blake3:{}", hasher.finalize().to_hex())
}

// Hash domain tags for `stable_hash`. Plans, goldens and records carry the
// identities these key, so changing a tag's bytes changes those identities.

/// Hash domain for a condition source digest: the identity of the whole source
/// text a condition was recovered from.
pub const CONDITION_SOURCE_HASH_DOMAIN: &str = "effinterp/condition-source/v1";

/// Hash domain for a condition site: the identity of one call site within a
/// condition source, keyed by the source text and its call-site coordinates.
pub const CONDITION_SITE_HASH_DOMAIN: &str = "effinterp/condition-site/v1";

/// Hash domain for a condition call instance: the identity of one path of
/// nested calls, chaining the enclosing call instance with the entered call site.
pub const CONDITION_CALL_HASH_DOMAIN: &str = "effinterp/condition-call/v1";

/// Hash domain for a redacted literal digest: the identity that lets equal
/// literals correlate in a redacted plan without revealing their text.
pub const REDACTED_LITERAL_HASH_DOMAIN: &str = "effinterp/redacted-literal/v1";

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key {key:?}"
                )));
            }
            map.next_value::<UniqueJson>()?;
        }
        Ok(UniqueJson)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJson>()?.is_some() {}
        Ok(UniqueJson)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }
}

/// Reject duplicate keys at any depth before deserializing untrusted protocol JSON.
pub fn reject_duplicate_keys(input: &str) -> Result<(), serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    UniqueJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}
