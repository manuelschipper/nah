use serde::{Deserialize, Deserializer, Serialize};

use crate::ByteSpan;

/// Reusable hashing state for condition identities within one immutable source.
/// Call-site hashes are byte-identical to stable_hash over `(source, ...tail)`.
pub struct ConditionSource {
    digest: String,
    call_prefix: blake3::Hasher,
}

impl ConditionSource {
    pub fn new(source: &str) -> Self {
        let mut call_prefix = blake3::Hasher::new();
        call_prefix.update(b"effinterp/stable-id/v1\0");
        call_prefix.update(crate::CONDITION_SITE_HASH_DOMAIN.as_bytes());
        call_prefix.update(b"\0[");
        call_prefix.update(&serde_json::to_vec(source).expect("source serializes"));
        Self {
            digest: crate::stable_hash(crate::CONDITION_SOURCE_HASH_DOMAIN, &source),
            call_prefix,
        }
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// `tail` must serialize as a nonempty tuple or array of call-site coordinates.
    pub fn call_site(&self, tail: &impl Serialize) -> String {
        let value = serde_json::to_value(tail).expect("call site serializes");
        assert!(value.as_array().is_some_and(|array| !array.is_empty()));
        let bytes = serde_json::to_vec(&value).expect("call site serializes");
        let mut hash = self.call_prefix.clone();
        hash.update(b",");
        hash.update(&bytes[1..]);
        format!("blake3:{}", hash.finalize().to_hex())
    }
}

/// Fixed protocol limits; analysis budgets may widen earlier.
pub const MAX_CONDITION_NODES: usize = 64;
pub const MAX_CONDITION_DEPTH: usize = 16;
pub const MAX_CONDITION_EXCERPT_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionKind {
    Branch,
    ShortCircuit,
    Loop,
    Dispatch,
    UnresolvedExecution,
}

/// Source-local construct identity. Call instances are digest chains, never paths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionOrigin {
    pub source_digest: String,
    pub span: ByteSpan,
    pub kind: ConditionKind,
    pub ordinal: u32,
    pub call_instance: Option<String>,
}

/// Evidence is deliberately absent from the identity projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionEvidence {
    Source {
        path: Option<String>,
        excerpt: Option<String>,
    },
    Redacted {
        path: Option<String>,
        excerpt: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionAtom {
    pub origin: ConditionOrigin,
    pub arm: u32,
    pub arms: u32,
    pub exhaustive: bool,
    pub polarity: Option<bool>,
    pub evidence: ConditionEvidence,
}

/// Bounded reachability formula. Missing conditions alone mean unconditional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    Atom { atom: ConditionAtom },
    All { conditions: Vec<Condition> },
    Any { conditions: Vec<Condition> },
    Widened,
}

struct ConditionSeed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}
impl<'de> serde::de::DeserializeSeed<'de> for ConditionSeed<'_> {
    type Value = Condition;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Condition, D::Error> {
        if self.depth > MAX_CONDITION_DEPTH || *self.remaining == 0 {
            return Err(serde::de::Error::custom("condition bound exceeded"));
        }
        *self.remaining -= 1;
        deserializer.deserialize_map(self)
    }
}
impl<'de> serde::de::Visitor<'de> for ConditionSeed<'_> {
    type Value = Condition;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("bounded condition")
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<Condition, M::Error> {
        let mut kind: Option<String> = None;
        let mut atom = None;
        let mut conditions = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "kind" if kind.is_none() => kind = Some(map.next_value()?),
                "atom" if atom.is_none() => atom = Some(map.next_value()?),
                "conditions" if conditions.is_none() => {
                    conditions = Some(map.next_value_seed(ConditionsSeed {
                        depth: self.depth + 1,
                        remaining: self.remaining,
                    })?)
                }
                _ => {
                    return Err(serde::de::Error::custom(
                        "unknown or duplicate condition field",
                    ));
                }
            }
        }
        let result = match (kind.as_deref(), atom, conditions) {
            (Some("atom"), Some(atom), None) => Condition::Atom { atom },
            (Some("all"), None, Some(conditions)) => Condition::All { conditions },
            (Some("any"), None, Some(conditions)) => Condition::Any { conditions },
            (Some("widened"), None, None) => Condition::Widened,
            _ => return Err(serde::de::Error::custom("invalid condition fields")),
        };
        if !result.is_valid() {
            return Err(serde::de::Error::custom("invalid condition"));
        }
        Ok(result)
    }
}
struct ConditionsSeed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}
impl<'de> serde::de::DeserializeSeed<'de> for ConditionsSeed<'_> {
    type Value = Vec<Condition>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}
impl<'de> serde::de::Visitor<'de> for ConditionsSeed<'_> {
    type Value = Vec<Condition>;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("bounded condition terms")
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut result = Vec::new();
        while let Some(condition) = seq.next_element_seed(ConditionSeed {
            depth: self.depth,
            remaining: self.remaining,
        })? {
            result.push(condition);
        }
        Ok(result)
    }
}
impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::DeserializeSeed;
        ConditionSeed {
            depth: 1,
            remaining: &mut MAX_CONDITION_NODES.clone(),
        }
        .deserialize(deserializer)
    }
}

impl Condition {
    pub fn from_source(
        source: &str,
        span: ByteSpan,
        kind: ConditionKind,
        arm: u32,
        arms: u32,
        exhaustive: bool,
        boolean: bool,
    ) -> Self {
        Self::from_source_with_digest(
            source,
            crate::stable_hash(crate::CONDITION_SOURCE_HASH_DOMAIN, &source),
            span,
            kind,
            arm,
            arms,
            exhaustive,
            boolean,
        )
    }

    /// Reuse the source digest for repeated conditions in one immutable source.
    /// `source_digest` must be the condition-source/v1 stable hash of `source`.
    // The condition facts are independent scalars; a wrapper struct would only
    // move the same argument list one call out.
    #[allow(clippy::too_many_arguments)]
    pub fn from_source_with_digest(
        source: &str,
        source_digest: String,
        span: ByteSpan,
        kind: ConditionKind,
        arm: u32,
        arms: u32,
        exhaustive: bool,
        boolean: bool,
    ) -> Self {
        Self::atom(ConditionAtom {
            origin: ConditionOrigin {
                source_digest,
                span,
                kind,
                ordinal: span.start,
                call_instance: None,
            },
            arm,
            arms,
            exhaustive,
            polarity: boolean.then_some(arm == 0),
            evidence: ConditionEvidence::Source {
                path: None,
                excerpt: source
                    .get(span.start as usize..span.end as usize)
                    .map(|text| {
                        let mut end = text.len().min(MAX_CONDITION_EXCERPT_BYTES);
                        while !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        text[..end].to_string()
                    }),
            },
        })
    }

    pub fn atom(mut atom: ConditionAtom) -> Self {
        if let ConditionEvidence::Source {
            excerpt: Some(excerpt),
            ..
        } = &mut atom.evidence
        {
            let mut end = excerpt.len().min(MAX_CONDITION_EXCERPT_BYTES);
            while !excerpt.is_char_boundary(end) {
                end -= 1;
            }
            excerpt.truncate(end);
        }
        let condition = Self::Atom { atom };
        if condition.is_valid() {
            condition
        } else {
            Self::Widened
        }
    }

    pub fn is_valid(&self) -> bool {
        fn visit(condition: &Condition, depth: usize, nodes: &mut usize) -> bool {
            *nodes += 1;
            if depth > MAX_CONDITION_DEPTH || *nodes > MAX_CONDITION_NODES {
                return false;
            }
            match condition {
                Condition::Widened => true,
                Condition::Atom { atom } => {
                    let origin = &atom.origin;
                    let evidence_valid = match &atom.evidence {
                        ConditionEvidence::Source { excerpt, .. } => excerpt
                            .as_ref()
                            .is_none_or(|s| s.len() <= MAX_CONDITION_EXCERPT_BYTES),
                        ConditionEvidence::Redacted { path, excerpt } => path
                            .iter()
                            .chain(excerpt.iter())
                            .all(|s| redaction_digest(s)),
                    };
                    digest(&origin.source_digest)
                        && origin.span.start <= origin.span.end
                        && origin.call_instance.as_ref().is_none_or(|s| digest(s))
                        && atom.arms >= 1
                        && atom.arm < atom.arms
                        && atom
                            .polarity
                            .is_none_or(|p| atom.arms == 2 && p == (atom.arm == 0))
                        && evidence_valid
                }
                Condition::All { conditions } | Condition::Any { conditions } => {
                    conditions.len() >= 2
                        && conditions.len() < MAX_CONDITION_NODES
                        && conditions.iter().all(|c| visit(c, depth + 1, nodes))
                }
            }
        }
        visit(self, 1, &mut 0)
    }

    /// The identity projection strips source evidence while preserving the formula.
    pub fn identity(&self) -> Self {
        let mut result = self.clone();
        result.map_atoms(&mut |atom| {
            atom.evidence = ConditionEvidence::Source {
                path: None,
                excerpt: None,
            }
        });
        result
    }

    pub fn identity_key(&self) -> String {
        crate::canonical_json(&self.identity())
    }

    pub fn rebind(&mut self, call_site: &str) {
        self.map_atoms(&mut |atom| {
            atom.origin.call_instance = Some(crate::stable_hash(
                crate::CONDITION_CALL_HASH_DOMAIN,
                &(&atom.origin.call_instance, call_site),
            ));
        });
    }

    pub fn redacted(&self) -> Self {
        let mut result = self.clone();
        result.map_atoms(&mut |atom| {
            if let ConditionEvidence::Source { path, excerpt } = &atom.evidence {
                let redact = |text: &String| {
                    crate::stable_hash(crate::REDACTED_LITERAL_HASH_DOMAIN, text)[..23].to_string()
                };
                atom.evidence = ConditionEvidence::Redacted {
                    path: path.as_ref().map(redact),
                    excerpt: excerpt.as_ref().map(redact),
                };
            }
        });
        result
    }

    pub fn is_redacted(&self) -> bool {
        self.is_valid()
            && self
                .atoms()
                .iter()
                .all(|a| matches!(a.evidence, ConditionEvidence::Redacted { .. }))
    }

    pub fn is_widened(&self) -> bool {
        match self {
            Self::Widened => true,
            Self::All { conditions } | Self::Any { conditions } => {
                conditions.iter().any(Self::is_widened)
            }
            Self::Atom { .. } => false,
        }
    }

    fn node_count(&self) -> usize {
        match self {
            Self::All { conditions } | Self::Any { conditions } => {
                1 + conditions.iter().map(Self::node_count).sum::<usize>()
            }
            _ => 1,
        }
    }

    pub fn retained_bytes(&self) -> u64 {
        match self {
            Self::Widened => 32,
            Self::All { conditions } | Self::Any { conditions } => {
                32 + conditions.iter().map(Self::retained_bytes).sum::<u64>()
            }
            Self::Atom { atom } => {
                let (path, excerpt) = match &atom.evidence {
                    ConditionEvidence::Source { path, excerpt }
                    | ConditionEvidence::Redacted { path, excerpt } => (path, excerpt),
                };
                128 + atom.origin.source_digest.len() as u64
                    + atom
                        .origin
                        .call_instance
                        .as_ref()
                        .map_or(0, |s| s.len() as u64)
                    + path.as_ref().map_or(0, |s| s.len() as u64)
                    + excerpt.as_ref().map_or(0, |s| s.len() as u64)
            }
        }
    }

    pub fn atoms(&self) -> Vec<&ConditionAtom> {
        let mut atoms = Vec::new();
        self.collect_atoms(&mut atoms);
        atoms
    }

    fn collect_atoms<'a>(&'a self, atoms: &mut Vec<&'a ConditionAtom>) {
        match self {
            Self::Atom { atom } => atoms.push(atom),
            Self::All { conditions } | Self::Any { conditions } => {
                for c in conditions {
                    c.collect_atoms(atoms);
                }
            }
            Self::Widened => (),
        }
    }

    fn map_atoms(&mut self, f: &mut impl FnMut(&mut ConditionAtom)) {
        match self {
            Self::Atom { atom } => f(atom),
            Self::All { conditions } | Self::Any { conditions } => {
                for c in conditions {
                    c.map_atoms(f);
                }
            }
            Self::Widened => (),
        }
    }

    pub fn compose<'a>(conditions: impl IntoIterator<Item = &'a Condition>) -> Option<Self> {
        Self::combine(conditions, true)
    }

    pub fn disjoin<'a>(conditions: impl IntoIterator<Item = &'a Condition>) -> Option<Self> {
        Self::combine(conditions, false)
    }

    fn combine<'a>(conditions: impl IntoIterator<Item = &'a Condition>, all: bool) -> Option<Self> {
        let mut terms = std::collections::BTreeMap::new();
        let mut nodes = 0;
        for condition in conditions {
            if !condition.is_valid() || condition.is_widened() {
                return Some(Self::Widened);
            }
            let children = match condition {
                Self::All { conditions } if all => conditions.as_slice(),
                Self::Any { conditions } if !all => conditions.as_slice(),
                _ => std::slice::from_ref(condition),
            };
            for child in children {
                let key = child.identity_key();
                if !terms.contains_key(&key) {
                    nodes += child.node_count();
                    if nodes + usize::from(!terms.is_empty()) > MAX_CONDITION_NODES {
                        return Some(Self::Widened);
                    }
                    terms.insert(key, child.clone());
                }
                if terms.len() >= MAX_CONDITION_NODES {
                    return Some(Self::Widened);
                }
            }
        }
        let mut conditions: Vec<_> = terms.into_values().collect();
        if conditions.is_empty() {
            return None;
        }
        if conditions.len() == 1 {
            return conditions.pop();
        }
        let result = if all {
            Self::All { conditions }
        } else {
            Self::Any { conditions }
        };
        Some(if result.is_valid() {
            result
        } else {
            Self::Widened
        })
    }
}

impl std::fmt::Display for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Widened => f.write_str("unknown condition"),
            Self::Atom { atom } => {
                if atom.polarity == Some(false) {
                    f.write_str("!(")?;
                }
                match &atom.evidence {
                    ConditionEvidence::Source {
                        excerpt: Some(text),
                        ..
                    } => {
                        f.write_str(text)?;
                        if atom.polarity.is_none() {
                            write!(f, " [arm {}/{}]", atom.arm + 1, atom.arms)?;
                        }
                    }
                    _ => write!(
                        f,
                        "{:?} {}:{}..{} arm {}/{}",
                        atom.origin.kind,
                        atom.origin.source_digest,
                        atom.origin.span.start,
                        atom.origin.span.end,
                        atom.arm + 1,
                        atom.arms
                    )?,
                }
                if atom.polarity == Some(false) {
                    f.write_str(")")?;
                }
                Ok(())
            }
            Self::All { conditions } | Self::Any { conditions } => {
                let separator = if matches!(self, Self::All { .. }) {
                    " && "
                } else {
                    " || "
                };
                for (index, condition) in conditions.iter().enumerate() {
                    if index > 0 {
                        f.write_str(separator)?;
                    }
                    write!(f, "({condition})")?;
                }
                Ok(())
            }
        }
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn redaction_digest(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(test)]
mod source_identity_tests {
    use super::*;

    // Reusing a hash prefix must preserve exact identities, including JSON escaping
    // and structured coordinates, or composed conditions cease to correlate.
    #[test]
    fn cached_condition_source_preserves_canonical_identities() {
        for source in ["", "print(\"héllo\")\n# \\ path\t", "x"]
            .map(str::to_string)
            .into_iter()
            .chain(["large source\n".repeat(10_000)])
        {
            let cached = ConditionSource::new(&source);
            assert_eq!(
                cached.digest(),
                crate::stable_hash(crate::CONDITION_SOURCE_HASH_DOMAIN, &source)
            );
            assert_eq!(
                cached.call_site(&(3u32,)),
                crate::stable_hash(crate::CONDITION_SITE_HASH_DOMAIN, &(&source, 3u32))
            );
            assert_eq!(
                cached.call_site(&(3u32, 19u32)),
                crate::stable_hash(crate::CONDITION_SITE_HASH_DOMAIN, &(&source, 3u32, 19u32))
            );
            let origin = std::collections::BTreeMap::from([("z", 1), ("a", 2)]);
            assert_eq!(
                cached.call_site(&(Some(4u32), &origin)),
                crate::stable_hash(
                    crate::CONDITION_SITE_HASH_DOMAIN,
                    &(&source, Some(4u32), &origin)
                )
            );
        }
    }
}
