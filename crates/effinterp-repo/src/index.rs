//! Building an entrypoint effect index: discover entrypoints, analyze each with
//! the engine, retain the plans, cross-file compositions, the analyzed-input
//! manifest, and what the crawl skipped. Reverse lookups are computed from this
//! index on demand by the query module. [`apply_changes`] updates the index
//! incrementally, reusing unchanged extractions and plans while staying
//! byte-equivalent to a clean [`build_index`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use effinterp_engine::{AnalysisStats, Engine, EngineError, SourceResolver};
use effinterp_proto::{
    AffectedScope, AnalysisGraph, AnalysisStatus, Effect, PartialReason, PathPlatform, Plan,
    ResourceExpr, ResourceIdentity, Subject,
};
use serde::{Deserialize, Serialize};

use crate::compose::{Composition, compose_callable, compose_with_package_init, go_root_effects};
use crate::discover::{LaunchEdge, discover, subject_cwd};
use crate::module::Registry;
use crate::snapshot::{
    DependencyKind, DependencyManifest, InputRecord, analyzer_build_digest, dependency_keys,
    dependency_manifest, snapshot_id,
};

pub(crate) const LAUNCH_COMPOSITION_PREFIX: &str = "\0launch:";

/// Persisted in place of a panic payload: the payload is unstable and can carry
/// source-derived text, so only this stable code reaches the snapshot.
pub const ANALYSIS_PANIC_ERROR: &str = "internal_error: analysis panicked";

fn launch_composition_key(file: &str) -> String {
    format!("{LAUNCH_COMPOSITION_PREFIX}{file}")
}

/// Repository entrypoints can add manifest and interpreter transitions before source execution.
pub(crate) fn repo_analysis_limits() -> effinterp_proto::Limits {
    let mut limits = effinterp_engine::default_limits();
    limits.insert("max_execution_depth".to_string(), 10);
    limits
}

pub(crate) use crate::discover::Entrypoint;

/// Why a path was not analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipCategory {
    /// Deliberately not analyzed (vendored/build dir, symlink, non-candidate).
    Ignored,
    /// A configured crawl limit stopped analysis here.
    Limit,
    /// The path could not be read or parsed.
    Failure,
}

/// Bounds on the repository crawl. Reaching a bound is reported as a skip, not
/// silently applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrawlLimits {
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_source_bytes: u64,
    pub max_depth: u32,
    /// Cap on retained skip records, so an adversarial tree cannot make the
    /// report itself unbounded.
    pub max_skips: usize,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_file_bytes: 1 << 20,
            max_total_source_bytes: 256 << 20,
            max_depth: 64,
            max_skips: 4_096,
        }
    }
}

/// Bounds on repository-wide composition and retained index work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryLimits {
    pub max_repo_work_units: u64,
    pub max_index_bytes: u64,
    pub max_compose_steps: u64,
    pub max_composed_effects: usize,
    pub max_composed_occurrences: usize,
    pub max_composed_boundaries: usize,
    pub max_composition_depth: usize,
    pub max_recursion_rounds: u32,
}

impl Default for RepositoryLimits {
    fn default() -> Self {
        Self {
            max_repo_work_units: 50_000_000,
            max_index_bytes: 512 << 20,
            max_compose_steps: 200_000,
            max_composed_effects: 2_048,
            max_composed_occurrences: 32_768,
            max_composed_boundaries: 8_192,
            max_composition_depth: 32,
            max_recursion_rounds: 3,
        }
    }
}

/// Every deterministic limit that can change a repository snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexLimits {
    pub crawl: CrawlLimits,
    pub engine: effinterp_proto::Limits,
    pub repository: RepositoryLimits,
}

impl<'de> Deserialize<'de> for IndexLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoredLimits {
            crawl: CrawlLimits,
            engine: effinterp_proto::Limits,
            repository: RepositoryLimits,
        }

        let stored = StoredLimits::deserialize(deserializer)?;
        let expected = repo_analysis_limits();
        if stored.engine.keys().ne(expected.keys()) {
            return Err(serde::de::Error::custom(
                "engine limits must contain exactly the supported fields",
            ));
        }
        Ok(Self {
            crawl: stored.crawl,
            engine: stored.engine,
            repository: stored.repository,
        })
    }
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            crawl: CrawlLimits::default(),
            engine: repo_analysis_limits(),
            repository: RepositoryLimits::default(),
        }
    }
}

impl IndexLimits {
    /// Apply one dotted repository-index limit name.
    pub fn set(&mut self, name: &str, value: u64) -> Result<(), String> {
        match name {
            "crawl.max_files" => self.crawl.max_files = value,
            "crawl.max_file_bytes" => self.crawl.max_file_bytes = value,
            "crawl.max_total_source_bytes" => self.crawl.max_total_source_bytes = value,
            "crawl.max_depth" => {
                self.crawl.max_depth = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            "crawl.max_skips" => {
                self.crawl.max_skips = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            "repository.max_repo_work_units" => self.repository.max_repo_work_units = value,
            "repository.max_index_bytes" => self.repository.max_index_bytes = value,
            "repository.max_compose_steps" => self.repository.max_compose_steps = value,
            "repository.max_composed_occurrences" => {
                self.repository.max_composed_occurrences = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            "repository.max_composed_boundaries" => {
                self.repository.max_composed_boundaries = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            "repository.max_composed_effects" => {
                self.repository.max_composed_effects = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            "repository.max_recursion_rounds" => {
                self.repository.max_recursion_rounds = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            "repository.max_composition_depth" => {
                self.repository.max_composition_depth = value
                    .try_into()
                    .map_err(|_| format!("limit {name} value is too large"))?
            }
            _ => {
                let Some(engine_name) = name.strip_prefix("engine.") else {
                    return Err(format!("unknown limit {name}"));
                };
                let Some(engine_limit) = self.engine.get_mut(engine_name) else {
                    return Err(format!("unknown limit {name}"));
                };
                *engine_limit = value;
            }
        }
        Ok(())
    }
}

/// A file or directory the crawl did not analyze, with the reason and category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skip {
    pub path: String,
    pub category: SkipCategory,
    pub reason: String,
}

/// The result of analyzing one entrypoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EntrypointOutcome {
    /// Analyzed to a plan. Boxed to keep the enum small.
    Analyzed { plan: Box<Plan> },
    /// The engine returned a typed failure.
    Failed { error: String },
    /// The repository budget was spent before this entrypoint was processed.
    LimitReached { limit: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedEntrypoint {
    pub entrypoint: Entrypoint,
    pub outcome: EntrypointOutcome,
}

pub(crate) struct IndexBudget {
    limits: RepositoryLimits,
    work_units: u64,
    bytes: u64,
    saturated: Option<&'static str>,
}

impl IndexBudget {
    pub(crate) fn new(limits: RepositoryLimits) -> Self {
        Self {
            limits,
            work_units: 0,
            bytes: 0,
            saturated: None,
        }
    }

    pub(crate) fn charge(&mut self, work_units: u64, bytes: u64) -> Result<(), &'static str> {
        if let Some(limit) = self.saturated {
            return Err(limit);
        }
        if self.work_units.saturating_add(work_units) > self.limits.max_repo_work_units {
            self.saturated = Some("repository.max_repo_work_units");
            return Err("repository.max_repo_work_units");
        }
        if self.bytes.saturating_add(bytes) > self.limits.max_index_bytes {
            self.saturated = Some("repository.max_index_bytes");
            return Err("repository.max_index_bytes");
        }
        self.work_units += work_units;
        self.bytes += bytes;
        Ok(())
    }
}

impl AnalyzedEntrypoint {
    pub fn plan(&self) -> Option<&Plan> {
        match &self.outcome {
            EntrypointOutcome::Analyzed { plan } => Some(plan.as_ref()),
            EntrypointOutcome::Failed { .. } | EntrypointOutcome::LimitReached { .. } => None,
        }
    }
}

/// An entrypoint effect index over a repository. Every query against it is bound
/// to `fingerprint`; a result carries that id so a caller can tell whether it
/// still reflects the analyzed inputs and the same analyzer/model set.
#[derive(Debug, Clone, Serialize)]
pub struct RepoIndex {
    pub root: String,
    /// Fingerprint of the analyzed inputs plus analyzer and model-set identity.
    pub fingerprint: String,
    pub analyzer: String,
    pub model_set: String,
    /// Limits that bounded this snapshot and must accompany query
    /// envelopes produced from a saved index.
    pub limits: IndexLimits,
    /// Every source, discovery/config input, tool identity, and limit that can
    /// affect this immutable snapshot.
    pub dependency_manifest: DependencyManifest,
    /// Canonical source-module ids used to validate persisted module
    /// dependency records without trusting those records to identify themselves.
    #[serde(skip)]
    pub(crate) module_paths: Vec<String>,
    /// Dependency keys for each cached or persisted derived value.
    pub derived_dependencies: BTreeMap<String, Vec<String>>,
    /// Skipped source candidates and the entrypoints whose semantic closure
    /// can reach them. An empty list means no known entrypoint depends on the
    /// candidate; absence means the skip could not be scoped.
    pub skipped_dependencies: BTreeMap<String, Vec<String>>,
    /// Skipped candidates named directly by entrypoint metadata.
    pub skipped_roots: BTreeSet<String>,
    /// Explicit evidence for the snapshot's exact-tree completeness claim.
    pub snapshot_state: AnalysisStatus,
    pub entrypoints: Vec<AnalyzedEntrypoint>,
    pub skipped: Vec<Skip>,
    /// Whether relevant skip evidence exceeded `limits.max_skips`.
    pub skips_truncated: bool,
    /// Wrapper → launched-program edges for bounded repository source targets.
    /// The wrapper's effective surface unions the launched program's surface.
    pub launch_edges: Vec<LaunchEdge>,
    /// Go package-value resolution for each entrypoint source file that is part
    /// of a selected Go build package. A file present with no effects still
    /// says the file's package resolves; an absent file is not Go.
    pub go_root_effects: BTreeMap<String, Vec<GoRootEffect>>,
    /// The source-module registry, retained for cross-file recomposition on an
    /// incremental update. Not serialized (it is an internal analysis cache).
    #[serde(skip)]
    pub registry: Registry,
    /// Cross-file composed effects per entrypoint id: effects reached by
    /// following an entrypoint file's calls into functions in other files.
    #[serde(skip)]
    pub composed: BTreeMap<String, Arc<Composition>>,
}

impl RepoIndex {
    pub fn find(&self, id: &str) -> Option<&AnalyzedEntrypoint> {
        self.entrypoints.iter().find(|e| e.entrypoint.id == id)
    }

    /// Cross-file composition for an entrypoint, if it is an analyzable source
    /// file with functions reaching other files.
    pub fn composition(&self, id: &str) -> Option<&Composition> {
        self.composed.get(id).map(Arc::as_ref)
    }

    pub(crate) fn launch_composition(&self, file: &str) -> Option<&Composition> {
        self.composed
            .get(&launch_composition_key(file))
            .map(Arc::as_ref)
    }
}

/// One effect of a Go entrypoint's root function under the package view: the
/// effect its own file's plan produced, and the effect the package's other
/// files resolve it to by substituting the values they declare.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoRootEffect {
    pub plan: Effect,
    pub resolved: Effect,
}

/// The package view of every Go entrypoint's root function, keyed by source
/// file. Derived here rather than read from the registry at query time,
/// because the registry is an analysis cache that no saved snapshot carries:
/// a loaded index must answer exactly as the live one does.
fn go_root_effects_all(
    entrypoints: &mut [AnalyzedEntrypoint],
    registry: &Registry,
    composed: &mut BTreeMap<String, Arc<Composition>>,
    budget: &mut IndexBudget,
) -> BTreeMap<String, Vec<GoRootEffect>> {
    let mut out: BTreeMap<String, Vec<GoRootEffect>> = BTreeMap::new();
    for analyzed in entrypoints {
        let file = &analyzed.entrypoint.source_file;
        if analyzed.entrypoint.registration.is_some()
            || analyzed.plan().is_none()
            || out.contains_key(file)
        {
            continue;
        }
        let Some(module) = registry.files.get(file) else {
            continue;
        };
        if !registry.go_packages.contains_key(file) {
            continue;
        }
        let effects = if budget.charge(0, 0).is_ok() {
            let Some(composition) = composed.get_mut(&analyzed.entrypoint.id) else {
                continue;
            };
            go_root_effects(registry, module, "main", Arc::make_mut(composition))
                .into_iter()
                .map(|(plan, resolved)| GoRootEffect { plan, resolved })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        match budget.charge(1, effinterp_proto::canonical_json(&effects).len() as u64) {
            Ok(()) => {
                out.insert(file.clone(), effects);
            }
            Err(limit) => {
                analyzed.outcome = EntrypointOutcome::LimitReached {
                    limit: limit.to_string(),
                };
                composed.remove(&analyzed.entrypoint.id);
            }
        }
    }
    out
}

/// Compose cross-file effects for every entrypoint whose source file is in the
/// registry, returning a map from entrypoint id to its composition.
fn compose_all(
    entrypoints: &mut [AnalyzedEntrypoint],
    registry: &Registry,
    limits: RepositoryLimits,
    budget: &mut IndexBudget,
) -> BTreeMap<String, Arc<Composition>> {
    let mut composed = BTreeMap::new();
    let mut saturated = budget.saturated;
    for analyzed in entrypoints.iter_mut() {
        if let Some(limit) = saturated {
            analyzed.outcome = EntrypointOutcome::LimitReached {
                limit: limit.to_string(),
            };
            continue;
        }
        if matches!(analyzed.outcome, EntrypointOutcome::LimitReached { .. }) {
            continue;
        }
        if analyzed.plan().is_none() {
            continue;
        }
        let file = &analyzed.entrypoint.source_file;
        if let Some(module) = registry.files.get(file) {
            let c = compose_with_package_init(
                registry,
                module,
                analyzed.entrypoint.entry_function.as_deref(),
                analyzed.entrypoint.registration.as_ref(),
                &analyzed.entrypoint.package_inits,
                limits,
            );
            let retain =
                !c.effects.is_empty() || !c.boundaries.is_empty() || !c.resolved_calls.is_empty();
            let retained_bytes = if retain { c.retained_bytes() } else { 0 };
            match budget.charge(c.budget.steps, retained_bytes) {
                Ok(()) => {
                    if retain {
                        composed.insert(analyzed.entrypoint.id.clone(), Arc::new(c));
                    }
                }
                Err(limit) => {
                    saturated = Some(limit);
                    analyzed.outcome = EntrypointOutcome::LimitReached {
                        limit: limit.to_string(),
                    };
                }
            }
        }
    }
    composed
}

fn limit_launched_entrypoints(
    entrypoints: &mut [AnalyzedEntrypoint],
    launch_edges: &[LaunchEdge],
    composed: &mut BTreeMap<String, Arc<Composition>>,
    file: &str,
    limit: &str,
) {
    for wrapper in launch_edges
        .iter()
        .filter(|edge| edge.launched == file)
        .map(|edge| edge.wrapper.as_str())
    {
        if let Some(analyzed) = entrypoints
            .iter_mut()
            .find(|entry| entry.entrypoint.id == wrapper)
        {
            analyzed.outcome = EntrypointOutcome::LimitReached {
                limit: limit.to_string(),
            };
            composed.remove(wrapper);
        }
    }
}

fn registry_roots(
    entrypoints: impl IntoIterator<Item = String>,
    launch_edges: &[LaunchEdge],
) -> BTreeSet<String> {
    entrypoints
        .into_iter()
        .chain(launch_edges.iter().map(|edge| edge.launched.clone()))
        .collect()
}

/// Serves file sources (the PHP include graph, `php script.php` operands) to
/// the engine from the repository. Paths are repo-rooted (leading slash) or
/// repo-relative, already lexically normalized by the engine, and never
/// escape the root.
pub(crate) struct RepoResolver {
    pub(crate) root: std::path::PathBuf,
    pub(crate) max_file_bytes: u64,
    pub(crate) admitted: std::collections::BTreeSet<String>,
}

impl SourceResolver for RepoResolver {
    fn matching(&self, pattern: &effinterp_engine::SourcePattern) -> Option<Vec<String>> {
        Some(
            self.admitted
                .iter()
                .filter(|path| pattern.matches(path))
                .cloned()
                .collect(),
        )
    }

    fn source_mutation_disjoint(
        &self,
        resource: &effinterp_proto::ResourceExpr,
        request: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        crate::ShallowSourceResolver::new(&self.root, "", self.max_file_bytes)
            .is_ok_and(|resolver| resolver.source_mutation_disjoint(resource, request))
    }

    fn resolve(
        &self,
        request: effinterp_engine::SourceRequest<'_>,
    ) -> effinterp_engine::SourceResponse {
        use effinterp_engine::{SourceNamespace, SourceRefusal, SourceResponse, UnavailableReason};
        if request.namespace == SourceNamespace::Host {
            return SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NamespaceDenied,
            ));
        }
        if request.purpose == effinterp_engine::SourcePurpose::DependencySource
            && matches!(
                request.requester_language,
                Some("js" | "ts" | "ruby" | "python")
            )
        {
            return SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::DependencyDenied,
            ));
        }
        let rel = request.path.trim_start_matches('/');
        if rel.is_empty() || rel.split('/').any(|s| s == "..") || !self.admitted.contains(rel) {
            return SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing));
        }
        let file = self.root.join(rel);
        // Repository source is untrusted: like the crawl, never follow a
        // symlink out of the tree, and respect the file-size bound.
        let Ok(meta) = std::fs::symlink_metadata(&file) else {
            return SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing));
        };
        if !meta.is_file() || meta.len() > self.max_file_bytes {
            return SourceResponse::Refused(if meta.is_file() {
                SourceRefusal::Limit {
                    limit: "max_source_bytes",
                }
            } else {
                SourceRefusal::Unavailable(UnavailableReason::NotAFile)
            });
        }
        if request.purpose == effinterp_engine::SourcePurpose::ExecutableInput
            && !is_executable(&meta)
        {
            return SourceResponse::Refused(SourceRefusal::Unavailable(
                UnavailableReason::NotAFile,
            ));
        }
        std::fs::read(file).map_or_else(
            |_| SourceResponse::Refused(SourceRefusal::Unavailable(UnavailableReason::Missing)),
            SourceResponse::Source,
        )
    }

    fn python_native_candidates_absent(
        &self,
        request: effinterp_engine::SourceRequest<'_>,
    ) -> bool {
        request.namespace == effinterp_engine::SourceNamespace::Repository
            && crate::shallow::python_native_candidates_absent(
                &self.root,
                request.path.trim_start_matches('/'),
            )
    }

    fn siblings(&self, path: &str) -> Option<Vec<String>> {
        let rel = path.trim_start_matches('/');
        let parent = rel.rsplit_once('/').map_or("", |(parent, _)| parent);
        Some(
            self.admitted
                .iter()
                .filter(|candidate| {
                    candidate.as_str() != rel
                        && candidate
                            .rsplit_once('/')
                            .map_or("", |(candidate_parent, _)| candidate_parent)
                            == parent
                })
                .cloned()
                .collect(),
        )
    }
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_: &std::fs::Metadata) -> bool {
    false
}

/// The engine used for repository analysis: builtin models plus a resolver
/// serving repo files.
fn repo_engine(
    root: &Path,
    limits: &CrawlLimits,
    manifest: &[InputRecord],
    analysis_limits: effinterp_proto::Limits,
) -> Engine {
    // The map comes from `repo_analysis_limits`, i.e. the engine's own
    // defaults with one override, so it is always a complete limits map.
    Engine::with_limits(analysis_limits)
        .map(|engine| engine.with_causality_detail(true))
        .expect("repo analysis limits are the engine defaults")
        .with_resolver(Box::new(RepoResolver {
            root: root.to_path_buf(),
            max_file_bytes: limits.max_file_bytes,
            admitted: manifest.iter().map(|input| input.path.clone()).collect(),
        }))
}

/// Recover the engine's analyzer and model-set identity from a trivial plan.
fn engine_identity(engine: &Engine) -> (String, String) {
    let probe = engine
        .analyze(&Subject::Exec {
            argv: vec!["true".to_string()],
            cwd: None,
            context: Default::default(),
        })
        .expect("probe analysis cannot fail");
    (probe.analysis.engine_version, probe.analysis.model_set)
}

pub(crate) fn snapshot_state(
    entrypoints: &[AnalyzedEntrypoint],
    skipped: &[Skip],
    skips_truncated: bool,
    composed: &BTreeMap<String, Arc<Composition>>,
    launch_edges: &[LaunchEdge],
) -> AnalysisStatus {
    let scope = || {
        AffectedScope::all(vec![
            AnalysisGraph::Effects,
            AnalysisGraph::Execution,
            AnalysisGraph::Occurrences,
            AnalysisGraph::ResourceState,
            AnalysisGraph::Causality,
            AnalysisGraph::Provenance,
        ])
    };
    let mut reasons: Vec<PartialReason> = skipped
        .iter()
        .filter_map(|skip| match skip.category {
            SkipCategory::Ignored => None,
            SkipCategory::Limit => Some(PartialReason::LimitReached {
                limit: skip.reason.clone(),
                scope: scope(),
            }),
            SkipCategory::Failure => Some(PartialReason::UnanalyzedInput {
                path: skip.path.clone(),
                scope: scope(),
            }),
        })
        .collect();
    if skips_truncated {
        reasons.push(PartialReason::LimitReached {
            limit: "crawl.max_skips".to_string(),
            scope: scope(),
        });
    }
    reasons.extend(
        entrypoints
            .iter()
            .filter_map(|entrypoint| match &entrypoint.outcome {
                EntrypointOutcome::Analyzed { .. } => None,
                EntrypointOutcome::Failed { .. } => Some(PartialReason::AnalysisFailure {
                    entrypoint: entrypoint.entrypoint.id.clone(),
                    scope: AffectedScope::entrypoint(
                        entrypoint.entrypoint.id.clone(),
                        scope().graphs,
                    ),
                }),
                EntrypointOutcome::LimitReached { limit } => Some(PartialReason::LimitReached {
                    limit: limit.clone(),
                    scope: AffectedScope::entrypoint(
                        entrypoint.entrypoint.id.clone(),
                        scope().graphs,
                    ),
                }),
            }),
    );
    for entrypoint in entrypoints {
        if let Some(plan) = entrypoint.plan() {
            for limit in plan
                .boundaries
                .iter()
                .filter_map(|boundary| boundary.limit.as_ref())
            {
                reasons.push(PartialReason::LimitReached {
                    limit: limit.clone(),
                    scope: AffectedScope::entrypoint(
                        entrypoint.entrypoint.id.clone(),
                        scope().graphs,
                    ),
                });
            }
        }
    }
    for (id, composition) in composed {
        let mut entrypoints = match id.strip_prefix(LAUNCH_COMPOSITION_PREFIX) {
            Some(file) => launch_edges
                .iter()
                .filter(|edge| edge.launched == file)
                .map(|edge| edge.wrapper.clone())
                .collect(),
            None => vec![id.clone()],
        };
        entrypoints.sort();
        entrypoints.dedup();
        for limit in composition
            .boundaries
            .iter()
            .filter_map(|boundary| boundary.limit.as_ref())
        {
            reasons.push(PartialReason::LimitReached {
                limit: limit.clone(),
                scope: AffectedScope {
                    all_entrypoints: false,
                    entrypoints: entrypoints.clone(),
                    graphs: scope().graphs,
                },
            });
        }
    }
    reasons.sort_by_key(|reason| serde_json::to_string(reason).expect("partial reason serializes"));
    reasons.dedup();
    if reasons.is_empty() {
        AnalysisStatus::Complete
    } else {
        AnalysisStatus::Partial { reasons }
    }
}

fn frontend_key(path: &str) -> Option<String> {
    let extension = Path::new(path).extension().and_then(|value| value.to_str());
    let language = match extension {
        Some("go") => "go",
        Some("java") => "java",
        Some("js" | "jsx" | "mjs" | "cjs") => "javascript",
        Some("php") => "php",
        Some("py") => "python",
        Some("rb") => "ruby",
        Some("rs") => "rust",
        Some("sh") => "shell",
        Some("ts" | "tsx" | "mts" | "cts") => "typescript",
        _ => return None,
    };
    Some(format!("frontend:{language}"))
}

fn module_dependencies(manifest: &DependencyManifest, path: &str) -> Vec<String> {
    let mut keys = vec![format!("source:{path}")];
    if let Some(frontend) = frontend_key(path) {
        keys.push(frontend);
    }
    keys.extend(dependency_keys(manifest, &[DependencyKind::Limit]));
    keys.extend(dependency_keys(manifest, &[DependencyKind::ResolverConfig]));
    keys.sort();
    keys.dedup();
    keys
}

fn entrypoint_dependencies(
    manifest: &DependencyManifest,
    entrypoint: &Entrypoint,
    plan: Option<&Plan>,
    launch_edges: &[LaunchEdge],
) -> Vec<String> {
    let mut keys = dependency_keys(
        manifest,
        &[
            DependencyKind::Analyzer,
            DependencyKind::ModelSet,
            DependencyKind::Limit,
        ],
    );
    keys.push(format!("source:{}", entrypoint.source_file));
    keys.push(format!("discovery:{}", entrypoint.evidence.file));
    keys.extend(dependency_keys(manifest, &[DependencyKind::ResolverConfig]));
    if let Some(frontend) = frontend_key(&entrypoint.source_file) {
        keys.push(frontend);
    }
    if let Some(plan) = plan {
        // Root-file membership is an input to infrastructure discovery, including
        // empty roots. Content-only dependencies miss newly admitted .tf files.
        if plan.provenance.iter().any(|node| matches!(&node.kind,
            effinterp_proto::ProvenanceKind::ModelApplication { model }
                if model.starts_with("infrastructure/terraform@") || model.starts_with("infrastructure/tofu@"))) {
            keys.extend(manifest.source_paths().filter(|path| path.ends_with(".tf") || path.ends_with(".tf.json")).map(|path| format!("source:{path}")));
        }
        keys.extend(plan.execution_graph.nodes.iter().filter_map(|node| {
            let path = node.selected_source_path()?.trim_start_matches('/');
            let effinterp_proto::ExecutionContent::Observed { digest } =
                &node.input.as_ref()?.content
            else {
                return None;
            };
            (manifest.source_digest(path) == Some(digest.as_str()))
                .then(|| format!("source:{path}"))
        }));
        let cwd = subject_cwd(&entrypoint.subject);
        keys.extend(
            plan.effects
                .iter()
                .filter(|effect| effect.operation.0 == "filesystem.read")
                .flat_map(|effect| resource_repo_paths(&effect.resource, cwd))
                .filter(|path| manifest.source_digest(path).is_some())
                .map(|path| format!("source:{path}")),
        );
    }
    for edge in launch_edges {
        if edge.wrapper == entrypoint.id || edge.launch_entrypoint == entrypoint.id {
            keys.push(format!("source:{}", edge.launched));
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

fn composition_dependencies(
    manifest: &DependencyManifest,
    output: &str,
    composition: &Composition,
    entrypoints: &[AnalyzedEntrypoint],
    launch_edges: &[LaunchEdge],
    derived: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut keys = dependency_keys(
        manifest,
        &[
            DependencyKind::Analyzer,
            DependencyKind::ModelSet,
            DependencyKind::Limit,
            DependencyKind::ResolverConfig,
        ],
    );
    match output.strip_prefix("launch-composition:") {
        Some(file) => {
            keys.push(format!("source:{file}"));
            for edge in launch_edges.iter().filter(|edge| edge.launched == file) {
                if let Some(entrypoint_keys) =
                    derived.get(&format!("entrypoint:{}", edge.launch_entrypoint))
                {
                    keys.extend(entrypoint_keys.iter().cloned());
                }
            }
        }
        None => {
            let id = output.strip_prefix("composition:").unwrap_or(output);
            if let Some(entrypoint_keys) = derived.get(&format!("entrypoint:{id}")) {
                keys.extend(entrypoint_keys.iter().cloned());
            }
        }
    }
    for dependency in &composition.deps {
        if manifest.source_digest(dependency).is_some() {
            keys.push(format!("source:{dependency}"));
        }
    }
    for analyzed in entrypoints {
        if output == format!("launch-composition:{}", analyzed.entrypoint.source_file)
            && let Some(entrypoint_keys) =
                derived.get(&format!("entrypoint:{}", analyzed.entrypoint.id))
        {
            keys.extend(entrypoint_keys.iter().cloned());
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

pub(crate) fn derived_dependencies(
    manifest: &DependencyManifest,
    entrypoints: &[AnalyzedEntrypoint],
    module_paths: &[String],
    composed: &BTreeMap<String, Arc<Composition>>,
    launch_edges: &[LaunchEdge],
) -> BTreeMap<String, Vec<String>> {
    let mut derived = BTreeMap::new();
    for path in module_paths {
        derived.insert(
            format!("module:{path}"),
            module_dependencies(manifest, path),
        );
    }
    for analyzed in entrypoints {
        derived.insert(
            format!("entrypoint:{}", analyzed.entrypoint.id),
            entrypoint_dependencies(
                manifest,
                &analyzed.entrypoint,
                analyzed.plan(),
                launch_edges,
            ),
        );
    }
    for (id, composition) in composed {
        let output = match id.strip_prefix(LAUNCH_COMPOSITION_PREFIX) {
            Some(file) => format!("launch-composition:{file}"),
            None => format!("composition:{id}"),
        };
        let keys = composition_dependencies(
            manifest,
            &output,
            composition,
            entrypoints,
            launch_edges,
            &derived,
        );
        derived.insert(output, keys);
    }
    derived.insert(
        "query-snapshot".to_string(),
        manifest.keys().map(str::to_string).collect(),
    );
    derived
}

fn skipped_dependencies(
    manifest: &DependencyManifest,
    registry: &Registry,
    entrypoints: &[AnalyzedEntrypoint],
    composed: &BTreeMap<String, Arc<Composition>>,
    launch_edges: &[LaunchEdge],
    discovered: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Vec<String>> {
    let skipped: BTreeSet<String> = manifest
        .skipped_source_paths()
        .map(str::to_string)
        .collect();
    let augmented = registry.with_source_candidates(skipped.iter().map(String::as_str));
    let mut dependencies: BTreeMap<String, BTreeSet<String>> = skipped
        .iter()
        .map(|path| (path.clone(), BTreeSet::new()))
        .collect();
    for (path, ids) in discovered {
        if let Some(dependents) = dependencies.get_mut(path) {
            dependents.extend(ids.iter().cloned());
        }
    }

    for analyzed in entrypoints {
        let id = &analyzed.entrypoint.id;
        if let Some(plan) = analyzed.plan() {
            for path in plan.boundaries.iter().filter_map(|boundary| {
                (boundary.reason.as_str() == "unresolved_source")
                    .then_some(boundary.detail.as_deref())
                    .flatten()
                    .and_then(|detail| detail.strip_prefix("sourced file "))
                    .map(|path| match path.rsplit_once(": ") {
                        Some((
                            path,
                            "missing" | "escapes" | "not_a_file" | "dependency_denied"
                            | "namespace_denied",
                        )) => path,
                        _ => path,
                    })
            }) {
                if let Some(dependents) = dependencies.get_mut(path) {
                    dependents.insert(id.clone());
                }
            }
        }
        let mut pending = vec![analyzed.entrypoint.source_file.clone()];
        if let Some(composition) = composed.get(id) {
            pending.extend(composition.deps.iter().cloned());
        }
        pending.extend(
            launch_edges
                .iter()
                .filter(|edge| edge.wrapper == *id)
                .map(|edge| edge.launched.clone()),
        );
        let mut visited = BTreeSet::new();
        while let Some(path) = pending.pop() {
            if !visited.insert(path.clone()) {
                continue;
            }
            let Some(importer) = augmented.files.get(&path) else {
                continue;
            };
            let targets: Vec<String> = importer
                .summary
                .imports
                .iter()
                .chain(&importer.summary.scoped_imports)
                .chain(&importer.summary.exports)
                .filter_map(|binding| augmented.resolve_import(importer, binding))
                .map(|target| target.path.clone())
                .collect();
            for target in targets {
                if let Some(dependents) = dependencies.get_mut(&target) {
                    dependents.insert(id.clone());
                } else {
                    pending.push(target);
                }
            }
        }
    }

    dependencies
        .into_iter()
        .map(|(path, entrypoints)| (path, entrypoints.into_iter().collect()))
        .collect()
}

/// Analyze one entrypoint's subject, mapping embedded package-script spans
/// back to host-file byte offsets.
fn analyze_entrypoint(
    engine: &Engine,
    entrypoint: &Entrypoint,
) -> (EntrypointOutcome, AnalysisStats) {
    match contain_analysis(|| {
        if let Some(registration) = &entrypoint.registration {
            return engine.analyze_registration_initialization(
                &entrypoint.subject,
                entrypoint.source_cwd.as_deref(),
                registration,
            );
        }
        engine.analyze_file_cwds_with_stats(
            &entrypoint.subject,
            entrypoint.source_cwd.as_deref(),
            subject_cwd(&entrypoint.subject),
            matches!(
                entrypoint.evidence.kind,
                crate::discover::EntrypointKind::ShellFile
                    | crate::discover::EntrypointKind::ShebangFile
            )
            .then_some(entrypoint.source_file.as_str()),
        )
    }) {
        Ok((mut plan, stats)) => {
            if let Some(map) = &entrypoint.span_map {
                crate::discover::remap_spans(&mut plan, map);
            }
            (
                EntrypointOutcome::Analyzed {
                    plan: Box::new(plan),
                },
                stats,
            )
        }
        Err(error) => (
            EntrypointOutcome::Failed { error },
            AnalysisStats::default(),
        ),
    }
}

/// Run one entrypoint analysis so that neither a typed engine failure nor a
/// panic escapes: both become that entrypoint's failure text.
fn contain_analysis<T>(analyze: impl FnOnce() -> Result<T, EngineError>) -> Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(analyze)) {
        Ok(Ok(plan)) => Ok(plan),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(ANALYSIS_PANIC_ERROR.to_string()),
    }
}

/// Discover and analyze every entrypoint under `root`, and build the source
/// registry for cross-file composition.
pub fn build_index(root: &Path, limits: IndexLimits) -> RepoIndex {
    let mut budget = IndexBudget::new(limits.repository);
    let mut discovery = discover(root, &limits.crawl, &mut budget, &limits.engine);
    discovery
        .entrypoints
        .sort_by(|left, right| left.id.cmp(&right.id));

    let admitted = discovery
        .manifest
        .iter()
        .map(|input| input.path.clone())
        .collect();
    let roots = registry_roots(
        discovery.entrypoints.iter().flat_map(|entrypoint| {
            std::iter::once(entrypoint.source_file.clone())
                .chain(entrypoint.package_inits.iter().cloned())
        }),
        &discovery.launch_edges,
    );
    let script_roots = discovery
        .entrypoints
        .iter()
        .filter(|entry| matches!(&entry.subject, Subject::Source { language, .. } if language == "python"))
        .map(|entry| entry.source_file.clone())
        .collect();
    let (mut registry, extraction_skips, _) = Registry::build_reachable(
        root,
        &limits.crawl,
        &roots,
        &script_roots,
        &mut budget,
        &limits.engine,
        Some(&admitted),
    );
    let remaining = limits
        .crawl
        .max_skips
        .saturating_sub(discovery.skipped.len());
    discovery.skips_truncated |= extraction_skips.len() > remaining;
    discovery
        .skipped
        .extend(extraction_skips.into_iter().take(remaining));
    registry.retain_admitted(&admitted);
    registry.reindex_ruby_inputs(
        root,
        &discovery.manifest,
        &discovery.launch_edges,
        &mut budget,
    );
    let inputs = discovery.manifest.clone();

    let engine = repo_engine(root, &limits.crawl, &inputs, limits.engine.clone());
    let (analyzer, model_set) = engine_identity(&engine);
    let engine = engine;
    let mut entrypoints = Vec::new();
    let mut composed = BTreeMap::new();
    let mut saturated = budget.saturated;
    for entrypoint in discovery.entrypoints {
        let outcome = if let Some(limit) = saturated {
            EntrypointOutcome::LimitReached {
                limit: limit.to_string(),
            }
        } else {
            let (outcome, stats) = analyze_entrypoint(&engine, &entrypoint);
            let plan_bytes = match &outcome {
                EntrypointOutcome::Analyzed { plan } => {
                    effinterp_proto::canonical_json(plan).len() as u64
                }
                EntrypointOutcome::Failed { .. } | EntrypointOutcome::LimitReached { .. } => 0,
            };
            match budget.charge(stats.steps, plan_bytes) {
                Ok(()) => outcome,
                Err(limit) => {
                    saturated = Some(limit);
                    EntrypointOutcome::LimitReached {
                        limit: limit.to_string(),
                    }
                }
            }
        };
        let mut analyzed = AnalyzedEntrypoint {
            entrypoint,
            outcome,
        };
        if analyzed.plan().is_some() {
            composed.extend(compose_all(
                std::slice::from_mut(&mut analyzed),
                &registry,
                limits.repository,
                &mut budget,
            ));
            saturated = budget.saturated;
        }
        entrypoints.push(analyzed);
    }

    let selected_sources: BTreeSet<&str> = discovery
        .launch_edges
        .iter()
        .map(|edge| edge.launched.as_str())
        .collect();
    for file in selected_sources {
        if let Err(limit) = budget.charge(0, 0) {
            limit_launched_entrypoints(
                &mut entrypoints,
                &discovery.launch_edges,
                &mut composed,
                file,
                limit,
            );
            continue;
        }
        if let Some(module) = registry.files.get(file) {
            let composition = compose_callable(&registry, module, limits.repository);
            let retain = !composition.effects.is_empty()
                || !composition.boundaries.is_empty()
                || !composition.resolved_calls.is_empty();
            let retained_bytes = if retain {
                composition.retained_bytes()
            } else {
                0
            };
            match budget.charge(composition.budget.steps, retained_bytes) {
                Ok(()) => {
                    if retain {
                        composed.insert(launch_composition_key(file), Arc::new(composition));
                    }
                }
                Err(limit) => {
                    limit_launched_entrypoints(
                        &mut entrypoints,
                        &discovery.launch_edges,
                        &mut composed,
                        file,
                        limit,
                    );
                }
            }
        }
    }
    let go_root = go_root_effects_all(&mut entrypoints, &registry, &mut composed, &mut budget);
    let dependency_manifest = dependency_manifest(
        &inputs,
        &discovery.skipped_sources,
        analyzer_build_digest(),
        &model_set,
        &limits,
    );
    let module_paths = registry.files.keys().cloned().collect::<Vec<_>>();
    let derived_dependencies = derived_dependencies(
        &dependency_manifest,
        &entrypoints,
        &module_paths,
        &composed,
        &discovery.launch_edges,
    );
    let skipped_dependencies = skipped_dependencies(
        &dependency_manifest,
        &registry,
        &entrypoints,
        &composed,
        &discovery.launch_edges,
        &discovery.skipped_dependencies,
    );
    let snapshot_state = snapshot_state(
        &entrypoints,
        &discovery.skipped,
        discovery.skips_truncated,
        &composed,
        &discovery.launch_edges,
    );

    // Discovery owns the single bounded crawl. The resolver and registry use
    // exactly that manifest so no second scan can admit an over-cap source.
    let fingerprint = snapshot_id(&dependency_manifest);
    RepoIndex {
        root: root.to_string_lossy().replace('\\', "/"),
        fingerprint,
        analyzer,
        model_set,
        limits,
        dependency_manifest,
        module_paths,
        derived_dependencies,
        skipped_dependencies,
        skipped_roots: discovery.skipped_roots,
        snapshot_state,
        entrypoints,
        skipped: discovery.skipped,
        skips_truncated: discovery.skips_truncated,
        launch_edges: discovery.launch_edges,
        go_root_effects: go_root,
        registry,
        composed,
    }
}

/// A repository change to apply incrementally. Rename is expressed as a
/// `Deleted` of the old path plus an `Added` of the new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoChange {
    Added(String),
    Modified(String),
    Deleted(String),
    /// A tool/config identity changed outside the working-tree event stream.
    IdentityChanged {
        kind: DependencyKind,
        key: String,
    },
    /// A change kind not understood by this index implementation.
    Unknown(String),
}

impl RepoChange {
    fn path(&self) -> Option<&str> {
        match self {
            RepoChange::Added(p) | RepoChange::Modified(p) | RepoChange::Deleted(p) => Some(p),
            RepoChange::IdentityChanged { .. } | RepoChange::Unknown(_) => None,
        }
    }
}

/// The strongest work invalidated by a change. Ordering is deliberate so a
/// set of events deterministically selects the safest required action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidationAction {
    Reextract,
    Reanalyze,
    Recompose,
    Rediscover,
    Rebuild,
}

/// Classify one event through the discovery, frontend, and linker-owned
/// policies. Identity and unknown events always fail closed to a rebuild.
pub fn invalidation_action(change: &RepoChange) -> InvalidationAction {
    match change {
        RepoChange::IdentityChanged { .. } | RepoChange::Unknown(_) => InvalidationAction::Rebuild,
        RepoChange::Added(path) | RepoChange::Modified(path) | RepoChange::Deleted(path) => [
            crate::module::invalidation_for_path(path),
            crate::discover::invalidation_for_path(path),
            crate::linker::invalidation_for_path(path),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(InvalidationAction::Rediscover),
    }
}

fn concrete_repo_path(expr: &ResourceExpr, cwd: Option<&str>) -> Option<String> {
    match expr {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } if !path.starts_with('/') => Some(path.clone()),
        ResourceExpr::Parameter { name } if name == "cwd" => Some(cwd.unwrap_or("").to_string()),
        ResourceExpr::Join { parts } => {
            let mut path = String::new();
            for part in parts {
                let value = concrete_repo_path(part, cwd)?;
                if !path.is_empty() && !value.is_empty() {
                    path.push('/');
                }
                path.push_str(&value);
            }
            Some(effinterp_proto::normalize_path(&path, PathPlatform::Posix))
        }
        _ => None,
    }
}

fn resource_repo_paths(expr: &ResourceExpr, cwd: Option<&str>) -> Vec<String> {
    match expr {
        ResourceExpr::Union { alternatives } => alternatives
            .iter()
            .flat_map(|alternative| resource_repo_paths(alternative, cwd))
            .collect(),
        _ => concrete_repo_path(expr, cwd).into_iter().collect(),
    }
}

/// What an incremental update recomputed. Old and new fingerprint let a caller
/// confirm the index moved (or did not) as expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    pub outcome: UpdateOutcome,
    pub invalidation: InvalidationAction,
    /// Source files re-extracted or newly extracted.
    pub reextracted: Vec<String>,
    /// Entrypoint ids reanalyzed (their direct plan recomputed).
    pub reanalyzed: Vec<String>,
    /// Entrypoint ids whose composition was recomputed.
    pub recomposed: Vec<String>,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    Published,
    Unchanged,
    Failed { failure: UpdateFailure },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateFailure {
    Read { path: String },
    Parse { entrypoint: String, reason: String },
    Analysis { entrypoint: String, reason: String },
}

fn failed_update(
    index: &RepoIndex,
    invalidation: InvalidationAction,
    failure: UpdateFailure,
) -> UpdateReport {
    UpdateReport {
        outcome: UpdateOutcome::Failed { failure },
        invalidation,
        reextracted: Vec::new(),
        reanalyzed: Vec::new(),
        recomposed: Vec::new(),
        old_fingerprint: index.fingerprint.clone(),
        new_fingerprint: index.fingerprint.clone(),
    }
}

fn persisted_snapshot_unchanged(previous: &RepoIndex, candidate: &RepoIndex) -> bool {
    candidate.fingerprint == previous.fingerprint
        && crate::store::save_index(candidate) == crate::store::save_index(previous)
}

fn dependencies_changed(dependencies: Option<&Vec<String>>, changed: &BTreeSet<String>) -> bool {
    dependencies.is_none_or(|dependencies| {
        dependencies
            .iter()
            .any(|dependency| changed.contains(dependency))
    })
}

fn candidate_failure(
    previous: Option<&RepoIndex>,
    candidate: &RepoIndex,
    affected_paths: &BTreeSet<String>,
    reanalyzed: &BTreeSet<String>,
    full_rebuild: bool,
) -> Option<UpdateFailure> {
    if let Some(skip) = candidate.skipped.iter().find(|skip| {
        skip.category == SkipCategory::Failure
            && (affected_paths.contains(&skip.path)
                || !previous.is_some_and(|previous| {
                    previous.skipped.iter().any(|old| {
                        old.path == skip.path
                            && old.category == skip.category
                            && old.reason == skip.reason
                    })
                }))
    }) {
        return Some(if skip.reason.starts_with("parse_error:") {
            UpdateFailure::Parse {
                entrypoint: skip.path.clone(),
                reason: "parse_error".into(),
            }
        } else {
            UpdateFailure::Read {
                path: skip.path.clone(),
            }
        });
    }
    for analyzed in &candidate.entrypoints {
        let affected = full_rebuild || reanalyzed.contains(&analyzed.entrypoint.id);
        let directly_affected = affected_paths.contains(&analyzed.entrypoint.source_file)
            || affected_paths.contains(&analyzed.entrypoint.evidence.file);
        match &analyzed.outcome {
            EntrypointOutcome::Failed { error } if affected => {
                let previously_accepted = !directly_affected
                    && previous.is_some_and(|previous| {
                        previous.find(&analyzed.entrypoint.id).is_some_and(|old| {
                            matches!(&old.outcome, EntrypointOutcome::Failed { error: old } if old == error)
                        })
                    });
                if !previously_accepted {
                    return Some(UpdateFailure::Analysis {
                        entrypoint: analyzed.entrypoint.id.clone(),
                        reason: error.clone(),
                    });
                }
            }
            EntrypointOutcome::Analyzed { plan } if affected => {
                if let Some(boundary) = plan
                    .boundaries
                    .iter()
                    .filter(|boundary| {
                        boundary.reason == effinterp_proto::BoundaryReason::PARSE_ERROR
                    })
                    .find(|boundary| {
                        directly_affected
                            || !previous.is_some_and(|previous| {
                                previous.find(&analyzed.entrypoint.id).is_some_and(|old| {
                                    old.plan().is_some_and(|plan| {
                                        plan.boundaries.iter().any(|old| old == *boundary)
                                    })
                                })
                            })
                    })
                {
                    return Some(UpdateFailure::Parse {
                        entrypoint: analyzed.entrypoint.id.clone(),
                        reason: boundary.reason.to_string(),
                    });
                }
            }
            EntrypointOutcome::Failed { .. }
            | EntrypointOutcome::Analyzed { .. }
            | EntrypointOutcome::LimitReached { .. } => {}
        }
    }
    None
}

/// Apply repository change events incrementally. The result is byte-equivalent
/// to a clean [`build_index`] of the final repository state (the correctness
/// oracle), while reusing cached module extractions for unchanged files and
/// cached entrypoint plans for entrypoints whose source did not change.
///
/// `root` must already reflect the changes on disk (added/modified files
/// readable, deleted files gone); the events only say which paths changed so
/// unchanged inputs are not re-read or re-analyzed.
fn apply_changes_in_place(
    index: &mut RepoIndex,
    root: &Path,
    limits: &IndexLimits,
    requested_invalidation: InvalidationAction,
) -> UpdateReport {
    let old_fingerprint = index.fingerprint.clone();
    let old_ruby_resolution = index.registry.ruby_resolution_digest();
    let old_derived_dependencies = index.derived_dependencies.clone();
    let old_entrypoints = index
        .entrypoints
        .iter()
        .map(|analyzed| effinterp_proto::canonical_json(&analyzed.entrypoint))
        .collect::<Vec<_>>();
    let old_launch_edges = index.launch_edges.clone();
    let old_state_evidence = effinterp_proto::canonical_json(&(
        &index.skipped,
        &index.skipped_dependencies,
        &index.skipped_roots,
        index.skips_truncated,
        &index.snapshot_state,
    ));

    let mut budget = IndexBudget::new(limits.repository);
    let mut discovery = discover(root, &limits.crawl, &mut budget, &limits.engine);
    discovery
        .entrypoints
        .sort_by(|left, right| left.id.cmp(&right.id));
    let admitted: BTreeSet<String> = discovery
        .manifest
        .iter()
        .map(|input| input.path.clone())
        .collect();
    let old_admitted: BTreeSet<String> = index
        .dependency_manifest
        .source_paths()
        .map(str::to_string)
        .collect();
    let manifest = discovery.manifest.clone();
    let current_manifest = dependency_manifest(
        &manifest,
        &discovery.skipped_sources,
        analyzer_build_digest(),
        &index.model_set,
        limits,
    );
    let changed_dependencies = index
        .dependency_manifest
        .changed_keys(&current_manifest)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let source_membership_changed = old_admitted != admitted;

    // 1. Re-extract exactly the module summaries whose recorded dependency
    //    keys changed, plus newly admitted source modules.
    let mut reextracted = Vec::new();
    index.registry.bind_source_root(root, limits);
    index.registry.retain_admitted(&admitted);
    for file in index.registry.files.values() {
        let _ = budget.charge(0, file.summary.retained_bytes());
    }
    for input in &discovery.manifest {
        let output = format!("module:{}", input.path);
        if index.registry.files.contains_key(&input.path)
            && !dependencies_changed(old_derived_dependencies.get(&output), &changed_dependencies)
        {
            continue;
        }
        if input.path.ends_with(".py") && !index.registry.files.contains_key(&input.path) {
            if changed_dependencies.contains(&format!("source:{}", input.path)) {
                reextracted.push(input.path.clone());
            }
            continue;
        }
        if let Err(limit) = budget.charge(1, 0) {
            index.registry.files.remove(&input.path);
            if discovery.skipped.len() < limits.crawl.max_skips {
                discovery.skipped.push(Skip {
                    path: input.path.clone(),
                    category: SkipCategory::Limit,
                    reason: limit.into(),
                });
            } else {
                discovery.skips_truncated = true;
            }
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(root.join(&input.path))
            && index
                .registry
                .apply_source_change(&input.path, Some(&content))
        {
            reextracted.push(input.path.clone());
            let bytes = index
                .registry
                .files
                .get(&input.path)
                .map_or(0, |file| file.summary.retained_bytes());
            if let Err(limit) = budget.charge(0, bytes) {
                index.registry.files.remove(&input.path);
                if discovery.skipped.len() < limits.crawl.max_skips {
                    discovery.skipped.push(Skip {
                        path: input.path.clone(),
                        category: SkipCategory::Limit,
                        reason: limit.into(),
                    });
                } else {
                    discovery.skips_truncated = true;
                }
            }
        }
    }

    // 2. Re-discover entrypoints (handles new/removed entrypoints and changed
    //    discovery inputs such as package scripts). Reuse a cached plan only
    //    when its recorded dependencies and current dependency shape agree.
    let engine = repo_engine(root, &limits.crawl, &manifest, limits.engine.clone());
    let mut old_plans = BTreeMap::new();
    for analyzed in index.entrypoints.drain(..) {
        old_plans.insert(analyzed.entrypoint.id.clone(), analyzed);
    }

    let mut reanalyzed = Vec::new();
    let entrypoints: Vec<AnalyzedEntrypoint> = discovery
        .entrypoints
        .into_iter()
        .map(|entrypoint| {
            let output = format!("entrypoint:{}", entrypoint.id);
            let old = old_plans.remove(&entrypoint.id);
            let reuse = old.as_ref().is_some_and(|old| {
                let Some(plan) = old.plan() else {
                    return false;
                };
                old.entrypoint.subject == entrypoint.subject
                    && old.entrypoint.source_cwd == entrypoint.source_cwd
                    && old_derived_dependencies.get(&output)
                        == Some(&entrypoint_dependencies(
                            &current_manifest,
                            &entrypoint,
                            Some(plan),
                            &discovery.launch_edges,
                        ))
                    && !dependencies_changed(
                        old_derived_dependencies.get(&output),
                        &changed_dependencies,
                    )
            });
            let outcome = if let Err(limit) = budget.charge(0, 0) {
                EntrypointOutcome::LimitReached {
                    limit: limit.into(),
                }
            } else if reuse {
                old.unwrap().outcome
            } else {
                reanalyzed.push(entrypoint.id.clone());
                let (outcome, stats) = analyze_entrypoint(&engine, &entrypoint);
                match budget.charge(stats.steps, 0) {
                    Ok(()) => outcome,
                    Err(limit) => EntrypointOutcome::LimitReached {
                        limit: limit.into(),
                    },
                }
            };
            let outcome = match &outcome {
                EntrypointOutcome::Analyzed { plan } => {
                    match budget.charge(0, effinterp_proto::canonical_json(plan).len() as u64) {
                        Ok(()) => outcome,
                        Err(limit) => EntrypointOutcome::LimitReached {
                            limit: limit.into(),
                        },
                    }
                }
                _ => outcome,
            };
            AnalyzedEntrypoint {
                entrypoint,
                outcome,
            }
        })
        .collect();

    let roots = registry_roots(
        entrypoints.iter().flat_map(|entrypoint| {
            std::iter::once(entrypoint.entrypoint.source_file.clone())
                .chain(entrypoint.entrypoint.package_inits.iter().cloned())
        }),
        &discovery.launch_edges,
    );
    let (materialized, materialization_skips) = index.registry.refresh_python_closure(
        root,
        &manifest,
        &roots,
        &mut budget,
        limits.crawl.max_skips,
    );
    reextracted.extend(materialized);
    let remaining_skips = limits
        .crawl
        .max_skips
        .saturating_sub(discovery.skipped.len());
    if materialization_skips.len() > remaining_skips {
        discovery.skips_truncated = true;
    }
    discovery
        .skipped
        .extend(materialization_skips.into_iter().take(remaining_skips));
    reextracted.sort();
    reextracted.dedup();

    index.registry.reindex_ruby_inputs(
        root,
        &discovery.manifest,
        &discovery.launch_edges,
        &mut budget,
    );
    let ruby_load_paths_changed = old_ruby_resolution != index.registry.ruby_resolution_digest();

    // 3. Recompose outputs invalidated by their recorded keys. Source-set
    //    changes recompose every output because package/module resolution can
    //    change even when an existing source file did not.
    index.entrypoints = entrypoints;
    let mut previous_composed = std::mem::take(&mut index.composed);
    let reanalyzed_set: BTreeSet<&str> = reanalyzed.iter().map(String::as_str).collect();
    let mut recomposed = Vec::new();
    for analyzed in &mut index.entrypoints {
        if let Err(limit) = budget.charge(0, 0) {
            analyzed.outcome = EntrypointOutcome::LimitReached {
                limit: limit.into(),
            };
            continue;
        }
        let id = &analyzed.entrypoint.id;
        let output = format!("composition:{id}");
        let invalidated = ruby_load_paths_changed
            || source_membership_changed
            || reanalyzed_set.contains(id.as_str())
            || dependencies_changed(old_derived_dependencies.get(&output), &changed_dependencies);
        if invalidated {
            let had_composition = previous_composed.remove(id).is_some();
            let file = &analyzed.entrypoint.source_file;
            if let Some(module) = index.registry.files.get(file) {
                let composition = compose_with_package_init(
                    &index.registry,
                    module,
                    analyzed.entrypoint.entry_function.as_deref(),
                    analyzed.entrypoint.registration.as_ref(),
                    &analyzed.entrypoint.package_inits,
                    limits.repository,
                );
                if !composition.effects.is_empty()
                    || !composition.boundaries.is_empty()
                    || !composition.resolved_calls.is_empty()
                {
                    recomposed.push(id.clone());
                    if let Err(limit) =
                        budget.charge(composition.budget.steps, composition.retained_bytes())
                    {
                        analyzed.outcome = EntrypointOutcome::LimitReached {
                            limit: limit.into(),
                        };
                    } else {
                        index.composed.insert(id.clone(), Arc::new(composition));
                    }
                } else if had_composition {
                    recomposed.push(id.clone());
                }
            } else if had_composition {
                recomposed.push(id.clone());
            }
        } else if let Some(composition) = previous_composed.remove(id) {
            if let Err(limit) = budget.charge(0, composition.retained_bytes()) {
                analyzed.outcome = EntrypointOutcome::LimitReached {
                    limit: limit.into(),
                };
            } else {
                index.composed.insert(id.clone(), composition);
            }
        }
    }
    let launched_sources: BTreeSet<&str> = discovery
        .launch_edges
        .iter()
        .map(|edge| edge.launched.as_str())
        .collect();
    for file in launched_sources {
        if let Err(limit) = budget.charge(0, 0) {
            limit_launched_entrypoints(
                &mut index.entrypoints,
                &discovery.launch_edges,
                &mut index.composed,
                file,
                limit,
            );
            continue;
        }
        let key = launch_composition_key(file);
        let output = format!("launch-composition:{file}");
        let invalidated = ruby_load_paths_changed
            || source_membership_changed
            || dependencies_changed(old_derived_dependencies.get(&output), &changed_dependencies);
        if invalidated {
            let had_composition = previous_composed.remove(&key).is_some();
            if let Some(module) = index.registry.files.get(file) {
                let composition = compose_callable(&index.registry, module, limits.repository);
                if !composition.effects.is_empty()
                    || !composition.boundaries.is_empty()
                    || !composition.resolved_calls.is_empty()
                {
                    recomposed.push(file.to_string());
                    if budget
                        .charge(composition.budget.steps, composition.retained_bytes())
                        .is_ok()
                    {
                        index.composed.insert(key, Arc::new(composition));
                    }
                } else if had_composition {
                    recomposed.push(file.to_string());
                }
            } else if had_composition {
                recomposed.push(file.to_string());
            }
        } else if let Some(composition) = previous_composed.remove(&key)
            && budget.charge(0, composition.retained_bytes()).is_ok()
        {
            index.composed.insert(key, composition);
        }
        if let Some(limit) = budget.saturated {
            limit_launched_entrypoints(
                &mut index.entrypoints,
                &discovery.launch_edges,
                &mut index.composed,
                file,
                limit,
            );
        }
    }
    index.go_root_effects = go_root_effects_all(
        &mut index.entrypoints,
        &index.registry,
        &mut index.composed,
        &mut budget,
    );
    recomposed.sort();
    recomposed.dedup();

    // 4. Rebuild dependency/state evidence from the current inputs.
    index.limits = limits.clone();
    index.dependency_manifest = current_manifest;
    index.skipped = discovery.skipped;
    index.skips_truncated = discovery.skips_truncated;
    index.launch_edges = discovery.launch_edges;
    index.snapshot_state = snapshot_state(
        &index.entrypoints,
        &index.skipped,
        index.skips_truncated,
        &index.composed,
        &index.launch_edges,
    );
    index.module_paths = index.registry.files.keys().cloned().collect();
    index.skipped_dependencies = skipped_dependencies(
        &index.dependency_manifest,
        &index.registry,
        &index.entrypoints,
        &index.composed,
        &index.launch_edges,
        &discovery.skipped_dependencies,
    );
    index.skipped_roots = discovery.skipped_roots;
    index.derived_dependencies = derived_dependencies(
        &index.dependency_manifest,
        &index.entrypoints,
        &index.module_paths,
        &index.composed,
        &index.launch_edges,
    );
    index.fingerprint = snapshot_id(&index.dependency_manifest);
    let entrypoints = index
        .entrypoints
        .iter()
        .map(|analyzed| effinterp_proto::canonical_json(&analyzed.entrypoint))
        .collect::<Vec<_>>();
    let state_evidence = effinterp_proto::canonical_json(&(
        &index.skipped,
        &index.skipped_dependencies,
        &index.skipped_roots,
        index.skips_truncated,
        &index.snapshot_state,
    ));
    let invalidation = if old_entrypoints != entrypoints
        || old_launch_edges != index.launch_edges
        || old_state_evidence != state_evidence
    {
        InvalidationAction::Rediscover
    } else if !recomposed.is_empty() {
        InvalidationAction::Recompose
    } else if !reanalyzed.is_empty() {
        InvalidationAction::Reanalyze
    } else if !reextracted.is_empty() {
        InvalidationAction::Reextract
    } else {
        requested_invalidation
    };

    UpdateReport {
        outcome: UpdateOutcome::Published,
        invalidation,
        reextracted,
        reanalyzed,
        recomposed,
        old_fingerprint,
        new_fingerprint: index.fingerprint.clone(),
    }
}

/// Apply changes through an isolated candidate and publish only after all work
/// succeeds. A failed update leaves every byte of the prior snapshot intact.
pub fn apply_changes(
    index: &mut RepoIndex,
    root: &Path,
    limits: &IndexLimits,
    changes: &[RepoChange],
) -> UpdateReport {
    apply_changes_controlled(index, root, limits, changes)
}

fn apply_changes_controlled(
    index: &mut RepoIndex,
    root: &Path,
    limits: &IndexLimits,
    changes: &[RepoChange],
) -> UpdateReport {
    let invalidation = if &index.limits != limits
        || limits.repository != RepositoryLimits::default()
        || index
            .entrypoints
            .iter()
            .any(|entrypoint| matches!(entrypoint.outcome, EntrypointOutcome::LimitReached { .. }))
    {
        InvalidationAction::Rebuild
    } else {
        changes
            .iter()
            .map(invalidation_action)
            .max()
            .unwrap_or(InvalidationAction::Rediscover)
    };

    let mut candidate;
    let mut report;
    if invalidation == InvalidationAction::Rebuild {
        candidate = build_index(root, limits.clone());
        report = UpdateReport {
            outcome: UpdateOutcome::Published,
            invalidation,
            reextracted: candidate.registry.files.keys().cloned().collect(),
            reanalyzed: candidate
                .entrypoints
                .iter()
                .map(|entrypoint| entrypoint.entrypoint.id.clone())
                .collect(),
            recomposed: candidate
                .composed
                .keys()
                .map(|key| {
                    key.strip_prefix(LAUNCH_COMPOSITION_PREFIX)
                        .unwrap_or(key)
                        .to_string()
                })
                .collect(),
            old_fingerprint: index.fingerprint.clone(),
            new_fingerprint: candidate.fingerprint.clone(),
        };
    } else {
        candidate = index.clone();
        report = apply_changes_in_place(&mut candidate, root, limits, invalidation);
    }

    let affected_paths: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| change.path().map(str::to_string))
        .collect();
    let reanalyzed: BTreeSet<String> = report.reanalyzed.iter().cloned().collect();
    if let Some(failure) = candidate_failure(
        Some(index),
        &candidate,
        &affected_paths,
        &reanalyzed,
        invalidation == InvalidationAction::Rebuild,
    ) {
        return failed_update(index, invalidation, failure);
    }
    if persisted_snapshot_unchanged(index, &candidate) {
        report.outcome = UpdateOutcome::Unchanged;
        report.new_fingerprint = index.fingerprint.clone();
        return report;
    }

    *index = candidate;
    report.outcome = UpdateOutcome::Published;
    report.new_fingerprint = index.fingerprint.clone();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_panics_are_contained() {
        assert_eq!(
            contain_analysis::<()>(|| panic!("boom")),
            Err(ANALYSIS_PANIC_ERROR.to_string())
        );
    }

    #[test]
    fn engine_errors_are_contained() {
        let error = EngineError::EmptyArgv;
        assert_eq!(
            contain_analysis::<()>(|| Err(error.clone())),
            Err(error.to_string())
        );
    }

    #[test]
    fn repository_resolver_refuses_host_namespace() {
        let resolver = RepoResolver {
            root: Default::default(),
            max_file_bytes: 1,
            admitted: Default::default(),
        };
        assert_eq!(
            effinterp_engine::SourceResolver::resolve(
                &resolver,
                effinterp_engine::SourceRequest {
                    path: "/work/script.py",
                    namespace: effinterp_engine::SourceNamespace::Host,
                    purpose: effinterp_engine::SourcePurpose::InvocationInput,
                    requester_language: None,
                },
            ),
            effinterp_engine::SourceResponse::Refused(
                effinterp_engine::SourceRefusal::Unavailable(
                    effinterp_engine::UnavailableReason::NamespaceDenied,
                ),
            )
        );
        for language in ["js", "ts", "ruby"] {
            for path in ["cli", "cli.js", "cli.ts", "cli.rb"] {
                assert_eq!(
                    resolver.resolve(effinterp_engine::SourceRequest {
                        path,
                        namespace: effinterp_engine::SourceNamespace::Repository,
                        purpose: effinterp_engine::SourcePurpose::DependencySource,
                        requester_language: Some(language),
                    }),
                    effinterp_engine::SourceResponse::Refused(
                        effinterp_engine::SourceRefusal::Unavailable(
                            effinterp_engine::UnavailableReason::DependencyDenied,
                        ),
                    )
                );
            }
        }
        assert_eq!(
            effinterp_engine::SourceResolver::python_extension_suffixes(
                &resolver,
                "python3.12",
                Some("/work"),
            ),
            None,
        );
    }
}
