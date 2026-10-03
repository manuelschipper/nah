//! Canonical identity and dependency evidence for immutable repository snapshots.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::index::IndexLimits;

use effinterp_proto::content_digest;

/// Content identity of the protocol, engine, and repository sources in this build.
pub(crate) fn analyzer_build_digest() -> &'static str {
    env!("EFFINTERP_ANALYZER_BUILD_DIGEST")
}

/// One file admitted by the bounded repository crawl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRecord {
    pub path: String,
    pub digest: String,
}

/// The owner of an output-affecting dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    SourceModule,
    SkippedSource,
    EntrypointDiscovery,
    ResolverConfig,
    ParserFrontend,
    Analyzer,
    ModelSet,
    Limit,
}

/// One canonical dependency. Keys are namespaced and stable; the digest is the
/// identity compared during working-tree validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyRecord {
    pub key: String,
    pub kind: DependencyKind,
    pub digest: String,
}

/// Every input and tool identity that can affect a repository snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyManifest {
    records: Vec<DependencyRecord>,
}

impl<'de> Deserialize<'de> for DependencyManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredManifest {
            records: Vec<DependencyRecord>,
        }

        let stored = StoredManifest::deserialize(deserializer)?;
        let canonical = Self::new(stored.records.clone());
        if canonical.records != stored.records {
            return Err(serde::de::Error::custom(
                "dependency manifest records are not canonical",
            ));
        }
        Ok(canonical)
    }
}

impl DependencyManifest {
    pub fn new(mut records: Vec<DependencyRecord>) -> Self {
        records.sort();
        records.dedup_by(|a, b| a.key == b.key);
        Self { records }
    }

    pub fn records(&self) -> &[DependencyRecord] {
        &self.records
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(|record| record.key.as_str())
    }

    pub fn source_paths(&self) -> impl Iterator<Item = &str> {
        self.records.iter().filter_map(|record| {
            (record.kind == DependencyKind::SourceModule)
                .then(|| record.key.strip_prefix("source:"))
                .flatten()
        })
    }

    pub fn skipped_source_paths(&self) -> impl Iterator<Item = &str> {
        self.records.iter().filter_map(|record| {
            (record.kind == DependencyKind::SkippedSource)
                .then(|| record.key.strip_prefix("skipped-source:"))
                .flatten()
        })
    }

    pub fn source_digest(&self, path: &str) -> Option<&str> {
        let key = format!("source:{path}");
        self.records
            .iter()
            .find(|record| record.key == key)
            .map(|record| record.digest.as_str())
    }

    pub fn get(&self, key: &str) -> Option<&DependencyRecord> {
        self.records
            .binary_search_by_key(&key, |record| record.key.as_str())
            .ok()
            .map(|index| &self.records[index])
    }

    /// Canonical dependency keys added, removed, or changed between two
    /// complete manifests.
    pub fn changed_keys(&self, current: &Self) -> Vec<String> {
        self.records
            .iter()
            .filter(|record| current.get(&record.key) != Some(record))
            .chain(
                current
                    .records
                    .iter()
                    .filter(|record| self.get(&record.key) != Some(record)),
            )
            .map(|record| record.key.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Stable frontend/parser identities. A parser or frontend change must update
/// its id so snapshots built by the two implementations cannot share identity.
pub const FRONTEND_IDS: &[(&str, &str)] = &[
    ("go", "effinterp/frontend/go/v1"),
    ("java", "effinterp/frontend/java/v1"),
    ("javascript", "effinterp/frontend/javascript/v1"),
    ("php", "effinterp/frontend/php/v1"),
    ("python", "effinterp/frontend/python/v1"),
    ("ruby", "effinterp/frontend/ruby/v1"),
    ("rust", "effinterp/frontend/rust/v1"),
    ("shell", "effinterp/frontend/shell/v1"),
    ("typescript", "effinterp/frontend/typescript/v1"),
];

fn is_resolver_input(path: &str) -> bool {
    path.ends_with(".gemspec")
        || matches!(
            path.rsplit('/').next().unwrap_or(path),
            "Cargo.toml"
                | "Gemfile"
                | "Gemfile.lock"
                | "composer.json"
                | "go.mod"
                | "go.work"
                | "package.json"
                | "pyproject.toml"
                | "setup.cfg"
                | "tsconfig.json"
        )
}

/// Build the complete dependency manifest from one bounded discovery crawl.
pub(crate) fn dependency_manifest(
    inputs: &[InputRecord],
    skipped_sources: &[crate::index::SkippedPath],
    analyzer_build: &str,
    model_set: &str,
    limits: &IndexLimits,
) -> DependencyManifest {
    let mut records = Vec::new();
    for input in inputs {
        records.push(DependencyRecord {
            key: format!("source:{}", input.path),
            kind: DependencyKind::SourceModule,
            digest: input.digest.clone(),
        });
        records.push(DependencyRecord {
            key: format!("discovery:{}", input.path),
            kind: DependencyKind::EntrypointDiscovery,
            digest: input.digest.clone(),
        });
        if is_resolver_input(&input.path) {
            records.push(DependencyRecord {
                key: format!("resolver:{}", input.path),
                kind: DependencyKind::ResolverConfig,
                digest: input.digest.clone(),
            });
        }
    }
    for skip in skipped_sources {
        records.push(DependencyRecord {
            key: format!("skipped-source:{}", skip.path),
            kind: DependencyKind::SkippedSource,
            digest: content_digest(effinterp_proto::canonical_json(&skip.category).as_bytes()),
        });
    }
    for (language, id) in FRONTEND_IDS {
        records.push(DependencyRecord {
            key: format!("frontend:{language}"),
            kind: DependencyKind::ParserFrontend,
            digest: content_digest(id.as_bytes()),
        });
    }
    records.push(DependencyRecord {
        key: "analyzer".to_string(),
        kind: DependencyKind::Analyzer,
        digest: analyzer_build.to_string(),
    });
    records.push(DependencyRecord {
        key: "model-set".to_string(),
        kind: DependencyKind::ModelSet,
        digest: model_set
            .strip_prefix("builtin:")
            .unwrap_or(model_set)
            .to_string(),
    });
    for (name, value) in all_limits(limits) {
        records.push(DependencyRecord {
            key: format!("limit:{name}"),
            kind: DependencyKind::Limit,
            digest: content_digest(value.to_string().as_bytes()),
        });
    }
    DependencyManifest::new(records)
}

pub(crate) fn all_limits(index: &IndexLimits) -> Vec<(String, u64)> {
    let mut limits: Vec<(String, u64)> = index
        .engine
        .iter()
        .map(|(name, value)| (format!("engine.{name}"), *value))
        .collect();
    limits.extend([
        ("crawl.max_depth".to_string(), index.crawl.max_depth as u64),
        (
            "crawl.max_file_bytes".to_string(),
            index.crawl.max_file_bytes,
        ),
        ("crawl.max_files".to_string(), index.crawl.max_files),
        ("crawl.max_skips".to_string(), index.crawl.max_skips as u64),
        (
            "crawl.max_total_source_bytes".to_string(),
            index.crawl.max_total_source_bytes,
        ),
        (
            "repository.max_repo_work_units".to_string(),
            index.repository.max_repo_work_units,
        ),
        (
            "repository.max_index_bytes".to_string(),
            index.repository.max_index_bytes,
        ),
        (
            "repository.max_compose_steps".to_string(),
            index.repository.max_compose_steps,
        ),
        (
            "repository.max_composed_occurrences".to_string(),
            index.repository.max_composed_occurrences as u64,
        ),
        (
            "repository.max_composed_boundaries".to_string(),
            index.repository.max_composed_boundaries as u64,
        ),
        (
            "repository.max_composed_effects".to_string(),
            index.repository.max_composed_effects as u64,
        ),
        (
            "repository.max_recursion_rounds".to_string(),
            index.repository.max_recursion_rounds as u64,
        ),
        (
            "repository.max_composition_depth".to_string(),
            index.repository.max_composition_depth as u64,
        ),
    ]);
    limits.sort();
    limits
}

/// Snapshot id derived from the entire dependency graph, independent of crawl
/// or event order.
pub fn snapshot_id(manifest: &DependencyManifest) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"effinterp/repo-snapshot/v1\0");
    for record in manifest.records() {
        h.update(record.key.as_bytes());
        h.update(b"\0");
        h.update(serde_json::to_string(&record.kind).unwrap().as_bytes());
        h.update(b"\0");
        h.update(record.digest.as_bytes());
        h.update(b"\x1e");
    }
    format!("blake3:{}", h.finalize().to_hex())
}

pub(crate) fn dependency_keys(
    manifest: &DependencyManifest,
    kinds: &[DependencyKind],
) -> Vec<String> {
    let kinds: BTreeSet<DependencyKind> = kinds.iter().copied().collect();
    manifest
        .records()
        .iter()
        .filter(|record| kinds.contains(&record.kind))
        .map(|record| record.key.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(path: &str, content: &[u8]) -> InputRecord {
        InputRecord {
            path: path.to_string(),
            digest: content_digest(content),
        }
    }

    #[test]
    fn snapshot_identity_is_canonical_and_tracks_every_identity_axis() {
        struct Resolver;
        const SOURCE: &[u8] = b"print('same bytes')\r\n";
        impl effinterp_engine::SourceResolver for Resolver {
            fn source_mutation_disjoint(
                &self,
                _: &effinterp_proto::ResourceExpr,
                _: effinterp_engine::SourceRequest<'_>,
            ) -> bool {
                true
            }

            fn resolve(
                &self,
                _: effinterp_engine::SourceRequest<'_>,
            ) -> effinterp_engine::SourceResponse {
                effinterp_engine::SourceResponse::Source(SOURCE.to_vec())
            }
            fn siblings(&self, _: &str) -> Option<Vec<String>> {
                None
            }
        }
        let plan = effinterp_engine::Engine::new()
            .with_resolver(Box::new(Resolver))
            .analyze(&effinterp_proto::Subject::Exec {
                argv: vec!["python3".to_string(), "/a.py".to_string()],
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        let live = plan
            .execution_graph
            .nodes
            .iter()
            .find_map(|node| {
                node.input.as_ref().filter(|input| {
                    matches!(
                        &input.content,
                        effinterp_proto::ExecutionContent::Observed { .. }
                    )
                })
            })
            .unwrap();
        assert_eq!(
            live.content,
            effinterp_proto::ExecutionContent::Observed {
                digest: input("a.py", SOURCE).digest
            }
        );
        let limits = IndexLimits::default();
        let a = dependency_manifest(
            &[input("b.py", b"two"), input("a.py", b"one")],
            &[],
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "m@1",
            &limits,
        );
        let b = dependency_manifest(
            &[input("a.py", b"one"), input("b.py", b"two")],
            &[],
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "m@1",
            &limits,
        );
        assert_eq!(snapshot_id(&a), snapshot_id(&b));

        let changed = dependency_manifest(
            &[input("a.py", b"changed"), input("b.py", b"two")],
            &[],
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "m@1",
            &limits,
        );
        assert_ne!(snapshot_id(&a), snapshot_id(&changed));
        assert_ne!(
            snapshot_id(&a),
            snapshot_id(&dependency_manifest(
                &[input("a.py", b"one"), input("b.py", b"two")],
                &[],
                "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "m@1",
                &limits,
            ))
        );
    }
}
