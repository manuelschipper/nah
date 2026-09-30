//! A registry of the repository's source modules and their callable surfaces.
//!
//! Every Python/JS/TS file is extracted to a [`ModuleSummary`] (each function's
//! parameterized effects, its outgoing call edges, and its imports) and keyed by
//! a module path so an import can be resolved to a file and a call to a callee's
//! summary. This is the substrate cross-file composition ([`crate::compose`])
//! walks; it reads source, never executes it.
//!
//! This file owns building, caching and incrementally updating module records,
//! import resolution and source admission. Language layout lives in the child
//! modules: `js_packages` (package.json exports), `php_psr4` (Composer PSR-4
//! roots), `rust_crates` (Cargo crate roots), `go_modules` and `go_build`
//! (go.mod and build constraints), `python_layout` (source-layout keys) and
//! `ruby`.

mod go_build;
mod go_modules;
pub(crate) mod js_packages;
mod php_psr4;
mod python_layout;
mod ruby;
mod rust_crates;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;

use effinterp_engine::{
    CallEdge, CallResult, FunctionEntry, ImportBinding, Lang, ModuleLoadKind, ModuleSummary,
    ObjectIdentity, ScopeKey, SemanticValue, SemanticValueKind, TypeRef, ValueOrigin,
    module_summaries,
};
use effinterp_proto::SourceDialect;

use crate::index::{CrawlLimits, IndexBudget, RepositoryLimits, Skip, SkipCategory};
use crate::linker::{
    GO_LINKER, JAVA_LINKER, JS_LINKER, Linker, MAX_EXPORT_CHASE, PHP_LINKER, PYTHON_LINKER,
    RUBY_LINKER, RUST_LINKER,
};
use crate::snapshot::InputRecord;
use effinterp_proto::content_digest;

use go_build::go_source_selected;
use go_modules::{collect_go_modules, go_module_for_dir, go_module_source, go_package_name};
use js_packages::{
    JS_BUILD_DIRS, JsPackage, js_package_artifact_for, named_js_packages, split_npm_spec,
};
use php_psr4::{collect_php_psr4, php_class_paths};
use python_layout::python_module_key;
use rust_crates::{RustCrate, collect_rust_crates, rust_scope};

const SKIP_DIRS: [&str; 5] = ["node_modules", ".git", "target", "vendor", ".claude"];
// Ordinary package re-exports execute exactly; only registry-sized import hubs
// widen instead of materializing every provider.
const MAX_EAGER_PYTHON_REGISTRATIONS: usize = 128;
type GoTypeKey = (String, String, String);

pub(crate) fn invalidation_for_path(path: &str) -> Option<crate::index::InvalidationAction> {
    lang_of(Path::new(path))
        .is_some()
        .then_some(crate::index::InvalidationAction::Reextract)
}

/// One analyzed source file: its module key, language, extracted surface, and
/// content digest (for incremental invalidation).
#[derive(Debug, Clone)]
pub struct ModuleFile {
    /// Repo-relative path, e.g. `pkg/util.py`.
    pub path: String,
    /// Directory of the file, for resolving relative imports.
    pub dir: String,
    pub lang: Lang,
    pub summary: ModuleSummary,
    pub digest: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PythonSource {
    dir: String,
    digest: String,
    #[serde(skip)]
    content: Option<Arc<str>>,
}

impl ModuleFile {
    pub fn function(&self, name: &str) -> Option<&FunctionEntry> {
        self.summary.functions.iter().find(|f| f.name == name)
    }
}

// Keep unchanged summaries shared when package reindexing visits every file.
fn update_summary(file: &mut Arc<ModuleFile>, update: impl FnOnce(&mut ModuleSummary)) {
    if let Some(file) = Arc::get_mut(file) {
        update(&mut file.summary);
        return;
    }
    let mut summary = file.summary.clone();
    update(&mut summary);
    if summary != file.summary {
        *file = Arc::new(ModuleFile {
            path: file.path.clone(),
            dir: file.dir.clone(),
            lang: file.lang,
            digest: file.digest.clone(),
            summary,
        });
    }
}

/// The repository's modules, indexed for import resolution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Registry {
    #[serde(skip)]
    engine_limits: effinterp_proto::Limits,
    #[serde(skip)]
    source_root: std::path::PathBuf,
    #[serde(skip)]
    source_limit: u64,
    #[serde(skip)]
    pending_changes: Arc<std::sync::Mutex<BTreeSet<String>>>,
    /// Re-export nodes the linker's export chases have entered, shared with
    /// clones. Counted, not a limit.
    #[serde(skip)]
    export_visits: Arc<std::sync::atomic::AtomicU64>,
    /// Keyed by repo-relative path.
    #[serde(skip)]
    pub files: BTreeMap<String, Arc<ModuleFile>>,
    /// Python dotted module path (e.g. `pkg.util`) -> file path.
    python_modules: BTreeMap<String, String>,
    /// Python execution roots eligible for script-directory absolute imports.
    script_roots: BTreeSet<String>,
    /// Admitted Python digests; source text is released after reachable extraction.
    python_sources: BTreeMap<String, PythonSource>,
    /// Large pure re-export roots whose provider expansion is represented by
    /// an explicit composition boundary.
    deferred_python_registrations: BTreeSet<String>,
    /// Go module directory -> declared module path. The empty directory is a
    /// repository-root `go.mod`; nested entries represent multi-module repos.
    go_modules: BTreeMap<String, String>,
    /// Evidence-backed Ruby roots; file/closure roots outrank this repository-wide set.
    pub(crate) ruby_load_paths: BTreeSet<String>,
    ruby_metadata_load_paths: BTreeSet<String>,
    ruby_conventional_load_paths: BTreeSet<String>,
    ruby_launch_load_paths: BTreeMap<String, BTreeSet<String>>,
    ruby_file_load_paths: BTreeMap<String, BTreeSet<String>>,
    ruby_closure_load_paths: BTreeMap<String, BTreeSet<String>>,
    /// Final import candidates, including ambiguity and misses, shared by composition walks.
    ruby_import_candidates: BTreeMap<String, BTreeMap<String, Vec<(String, String)>>>,
    ruby_loader_incomplete: bool,
    /// Gem identities, with lockfile versions preferred over dependency declarations.
    pub(crate) ruby_gems: BTreeMap<String, String>,
    ruby_gem_sources: BTreeMap<String, String>,
    /// Repo-relative Go file -> declared package name.
    pub(crate) go_packages: BTreeMap<String, String>,
    /// Rust package names from the repo's `Cargo.toml`s (hyphens mapped to
    /// underscores, as `use` paths spell them) -> the crate's source layout,
    /// so a binary's `use bat::...` / `use git_cliff_core::...` resolves into
    /// the sibling workspace crate's source tree. `[lib] path` is kept so a
    /// crate whose library is not `src/lib.rs` still resolves at the root.
    rust_crates: BTreeMap<String, RustCrate>,
    /// JS/TS workspace packages keyed by the `name` they declare in
    /// package.json. A bare specifier `@pkg/cli` resolves to that member's
    /// export entry (mapped back to source when the artifact is built output).
    js_packages: BTreeMap<String, JsPackage>,
    /// Composer PSR-4 namespace prefixes mapped to repository-relative roots.
    php_psr4: Vec<(String, String)>,
    /// Exact PHP class names whose declared file agrees with Composer or a
    /// conventional root/src/lib layout.
    php_classes: BTreeMap<String, String>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            engine_limits: effinterp_engine::default_limits(),
            source_root: Default::default(),
            source_limit: CrawlLimits::default().max_file_bytes,
            pending_changes: Default::default(),
            export_visits: Default::default(),
            files: Default::default(),
            python_modules: Default::default(),
            script_roots: Default::default(),
            python_sources: Default::default(),
            deferred_python_registrations: Default::default(),
            go_modules: Default::default(),
            ruby_load_paths: Default::default(),
            ruby_metadata_load_paths: Default::default(),
            ruby_conventional_load_paths: Default::default(),
            ruby_launch_load_paths: Default::default(),
            ruby_file_load_paths: Default::default(),
            ruby_closure_load_paths: Default::default(),
            ruby_import_candidates: Default::default(),
            ruby_loader_incomplete: false,
            ruby_gems: Default::default(),
            ruby_gem_sources: Default::default(),
            go_packages: Default::default(),
            rust_crates: Default::default(),
            js_packages: Default::default(),
            php_psr4: Default::default(),
            php_classes: Default::default(),
        }
    }
}

impl Registry {
    pub(crate) fn value_limits(&self) -> effinterp_engine::ValueLimits {
        effinterp_engine::AnalysisLimits::from_map(&self.engine_limits)
            .expect("validated registry limits")
            .value_limits()
    }

    /// Bind deferred source reads to the configured working tree and engine limits.
    pub fn bind_source_root(&mut self, root: &Path, limits: &crate::IndexLimits) {
        self.source_root = root.to_path_buf();
        self.source_limit = limits.crawl.max_file_bytes;
        self.engine_limits = limits.engine.clone();
    }

    pub(crate) fn note_export_visit(&self) {
        self.export_visits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Re-export nodes entered while resolving exported functions and classes.
    pub fn export_visits(&self) -> u64 {
        self.export_visits
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Digest mismatches discovered by demand materialization become update events.
    pub fn pending_changes(&self) -> Vec<crate::RepoChange> {
        self.pending_changes
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(crate::RepoChange::Modified)
            .collect()
    }

    fn drop_python_content(&mut self) {
        for source in self.python_sources.values_mut() {
            source.content = None;
        }
    }

    fn python_content(&self, path: &str, source: &PythonSource) -> Option<Arc<str>> {
        if let Some(content) = &source.content {
            return Some(content.clone());
        }
        let resolver = crate::index::RepoResolver {
            root: self.source_root.clone(),
            max_file_bytes: self.source_limit,
            admitted: BTreeSet::from([path.to_string()]),
        };
        use effinterp_engine::SourceResolver;
        let effinterp_engine::SourceResponse::Source(bytes) =
            resolver.resolve(effinterp_engine::SourceRequest {
                path,
                namespace: effinterp_engine::SourceNamespace::Repository,
                purpose: effinterp_engine::SourcePurpose::InvocationInput,
                requester_language: None,
            })
        else {
            self.pending_changes
                .lock()
                .unwrap()
                .insert(path.to_string());
            return None;
        };
        if content_digest(&bytes) != source.digest {
            self.pending_changes
                .lock()
                .unwrap()
                .insert(path.to_string());
            return None;
        }
        String::from_utf8(bytes).ok().map(Arc::from)
    }

    pub(crate) fn linker(&self, lang: Lang) -> &'static dyn Linker {
        match lang {
            Lang::Python => &PYTHON_LINKER,
            Lang::Js(_) => &JS_LINKER,
            Lang::Ruby => &RUBY_LINKER,
            Lang::Rust => &RUST_LINKER,
            Lang::Go => &GO_LINKER,
            Lang::Java => &JAVA_LINKER,
            Lang::Php => &PHP_LINKER,
        }
    }

    /// Build the registry by scanning source files under `root`.
    pub fn build(root: &Path, limits: &CrawlLimits) -> (Registry, Vec<Skip>, Vec<InputRecord>) {
        Self::build_inner(
            root,
            limits,
            None,
            &BTreeSet::new(),
            &mut IndexBudget::new(RepositoryLimits::default()),
            &effinterp_engine::default_limits(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_reachable(
        root: &Path,
        limits: &CrawlLimits,
        roots: &BTreeSet<String>,
        script_roots: &BTreeSet<String>,
        budget: &mut IndexBudget,
        engine_limits: &effinterp_proto::Limits,
        admitted: Option<&BTreeSet<String>>,
    ) -> (Registry, Vec<Skip>, Vec<InputRecord>) {
        Self::build_inner(
            root,
            limits,
            Some(roots),
            script_roots,
            budget,
            engine_limits,
            admitted,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_inner(
        root: &Path,
        limits: &CrawlLimits,
        python_roots: Option<&BTreeSet<String>>,
        script_roots: &BTreeSet<String>,
        budget: &mut IndexBudget,
        engine_limits: &effinterp_proto::Limits,
        admitted: Option<&BTreeSet<String>>,
    ) -> (Registry, Vec<Skip>, Vec<InputRecord>) {
        let mut skips = Vec::new();
        let mut admit_metadata = |path: &Path| {
            let relative = rel(root, path);
            if admitted.is_some_and(|admitted| !admitted.contains(&relative)) {
                return false;
            }
            let Ok(metadata) = std::fs::symlink_metadata(path) else {
                return false;
            };
            if !metadata.is_file() || metadata.len() > limits.max_file_bytes {
                return false;
            }
            if let Err(limit) = budget.charge(1, metadata.len()) {
                if skips.len() < limits.max_skips {
                    skips.push(Skip {
                        path: relative,
                        category: SkipCategory::Limit,
                        reason: limit.into(),
                    });
                }
                return false;
            }
            true
        };
        // Full indexing supplies the admitted manifest and launch edges after extraction.
        let ruby_inputs = if python_roots.is_none() {
            ruby::collect_ruby_metadata(root, admitted, limits, &mut admit_metadata)
        } else {
            Vec::new()
        };
        let mut reg = Registry {
            engine_limits: engine_limits.clone(),
            source_root: root.to_path_buf(),
            source_limit: limits.max_file_bytes,
            script_roots: script_roots.clone(),
            go_modules: collect_go_modules(root, &mut admit_metadata),
            rust_crates: collect_rust_crates(root, &mut admit_metadata),
            js_packages: named_js_packages(root, &mut admit_metadata),
            php_psr4: collect_php_psr4(root, &mut admit_metadata),
            ..Registry::default()
        };
        let mut manifest = Vec::new();
        let mut seen: u64 = 0;
        scan(
            root,
            root,
            0,
            limits,
            &mut seen,
            &mut reg,
            &mut skips,
            &mut manifest,
            python_roots.is_none(),
            budget,
            admitted,
        );
        manifest.extend(ruby_inputs);
        if python_roots.is_none() {
            reg.reindex_ruby_inputs(root, &manifest, &[], budget);
        }
        reg.reindex_python_modules();
        if let Some(roots) = python_roots {
            reg.retain_python_closure(roots, budget, &mut skips, limits.max_skips);
        }
        reg.reindex_go_package_vars();
        reg.reindex_php_classes();
        reg.drop_python_content();
        (reg, skips, manifest)
    }

    fn insert(&mut self, file: ModuleFile) {
        self.files.insert(file.path.clone(), Arc::new(file));
    }

    pub(crate) fn retain_admitted(&mut self, admitted: &BTreeSet<String>) {
        self.files.retain(|path, _| admitted.contains(path));
        self.python_sources
            .retain(|path, _| admitted.contains(path));
        self.go_packages.retain(|path, _| admitted.contains(path));
        self.go_modules.retain(|dir, _| {
            let path = if dir.is_empty() {
                "go.mod".to_string()
            } else {
                format!("{dir}/go.mod")
            };
            admitted.contains(&path)
        });
        self.reindex_python_modules();
        self.reindex_go_scopes();
        self.reindex_go_package_vars();
        self.reindex_php_classes();
    }

    pub(crate) fn with_source_candidates<'a>(&self, paths: impl Iterator<Item = &'a str>) -> Self {
        let mut registry = self.clone();
        let mut changed = false;
        let mut ruby_changed = false;
        for path in paths {
            let source = "";
            let Some(lang) = lang_of(Path::new(path)) else {
                continue;
            };
            let dir = path
                .rsplit_once('/')
                .map(|(dir, _)| dir.to_string())
                .unwrap_or_default();
            registry.insert(ModuleFile {
                path: path.to_string(),
                dir: dir.clone(),
                lang,
                summary: module_summaries(
                    source,
                    lang,
                    path,
                    scope_for_file(
                        lang,
                        path,
                        &dir,
                        &registry.go_modules,
                        &registry.rust_crates,
                    ),
                    &effinterp_engine::SummaryBudget::for_lang(&self.engine_limits, lang),
                ),
                digest: content_digest(source.as_bytes()),
            });
            changed = true;
            ruby_changed |= lang == Lang::Ruby;
        }
        if ruby_changed && !registry.ruby_loader_incomplete {
            registry
                .reindex_ruby_import_candidates(&mut IndexBudget::new(RepositoryLimits::default()));
        }
        if changed {
            registry.reindex_python_modules();
            registry.reindex_go_package_vars();
        }
        registry
    }

    /// Recompute the Python dotted-module map from the full file set. A Python
    /// file's module name is its path relative to its SOURCE ROOT — a
    /// conventional `src/` layout root, or else the first ancestor directory
    /// that is not a package. Packages are directories with `__init__.py` and
    /// PEP 420 implicit namespace packages (a directory that contains `.py`
    /// files). This depends on the whole file set, so it is recomputed after
    /// any change; being a pure function of `self.files` keeps an incremental
    /// update byte-equivalent to a clean rebuild.
    fn reindex_python_modules(&mut self) {
        let previous: BTreeMap<String, String> = self
            .python_modules
            .iter()
            .map(|(key, path)| (path.clone(), key.clone()))
            .collect();
        self.python_modules.clear();
        let python_paths: BTreeSet<&str> = self
            .python_sources
            .keys()
            .map(String::as_str)
            .chain(
                self.files
                    .values()
                    .filter(|file| file.lang == Lang::Python)
                    .map(|file| file.path.as_str()),
            )
            .collect();
        let explicit_packages: BTreeSet<String> = python_paths
            .iter()
            .filter_map(|p| {
                if *p == "__init__.py" {
                    Some(String::new())
                } else {
                    p.strip_suffix("/__init__.py").map(str::to_string)
                }
            })
            .collect();
        // Implicit namespace packages: a directory that holds a `.py` file is
        // itself a package even without `__init__.py`. A `src/` layout root is
        // not — it is on sys.path, not imported as a package.
        let mut package_dirs = explicit_packages.clone();
        for path in &python_paths {
            if path.ends_with(".py")
                && let Some(dir) = path.rsplit_once('/').map(|(d, _)| d)
                && !dir.is_empty()
                && dir != "src"
                && !dir.ends_with("/src")
            {
                package_dirs.insert(dir.to_string());
            }
        }
        let entries: Vec<(String, String)> = python_paths
            .iter()
            .map(|path| {
                (
                    python_module_key(path, &package_dirs, &explicit_packages),
                    (*path).to_string(),
                )
            })
            .collect();
        let mut rekeys: BTreeMap<String, String> = entries
            .iter()
            .map(|(key, path)| (provisional_python_key(path), key.clone()))
            .collect();
        for (key, path) in &entries {
            if let Some(old) = previous.get(path) {
                rekeys.insert(old.clone(), key.clone());
            }
        }
        if rekeys.iter().any(|(old, new)| old != new) {
            for file in self.files.values_mut().filter(|f| f.lang == Lang::Python) {
                update_summary(file, |summary| rewrite_summary_scopes(summary, &rekeys));
            }
        }
        for (key, path) in entries {
            match self.python_modules.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(path);
                }
                std::collections::btree_map::Entry::Occupied(mut entry)
                    if python_import_priority(&path) < python_import_priority(entry.get()) =>
                {
                    entry.insert(path);
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
    }

    fn retain_python_closure(
        &mut self,
        roots: &BTreeSet<String>,
        budget: &mut IndexBudget,
        skips: &mut Vec<Skip>,
        max_skips: usize,
    ) -> Vec<String> {
        let mut pending: Vec<String> = roots.iter().cloned().collect();
        pending.sort();
        pending.reverse();
        let mut reachable = BTreeSet::new();
        let mut materialized = Vec::new();

        while let Some(path) = pending.pop() {
            if !self.python_sources.contains_key(&path) || !reachable.insert(path.clone()) {
                continue;
            }
            if !self.files.contains_key(&path) {
                let Some(source) = self.python_sources.get(&path).cloned() else {
                    continue;
                };
                if let Err(limit) = budget.charge(1, 0) {
                    if skips.len() < max_skips {
                        skips.push(Skip {
                            path,
                            category: SkipCategory::Limit,
                            reason: limit.into(),
                        });
                    }
                    continue;
                }
                let Some(content) = self.python_content(&path, &source) else {
                    continue;
                };
                let PythonSource { dir, digest, .. } = source;
                let file = ModuleFile {
                    path: path.clone(),
                    dir,
                    lang: Lang::Python,
                    summary: module_summaries(
                        &content,
                        Lang::Python,
                        &path,
                        ScopeKey::Module {
                            key: self
                                .python_modules
                                .iter()
                                .find_map(|(key, candidate)| {
                                    (candidate == &path).then(|| key.clone())
                                })
                                .unwrap_or_else(|| provisional_python_key(&path)),
                        },
                        &effinterp_engine::SummaryBudget::for_lang(
                            &self.engine_limits,
                            Lang::Python,
                        ),
                    ),
                    digest,
                };
                if let Err(limit) = budget.charge(0, file.summary.retained_bytes()) {
                    if skips.len() < max_skips {
                        skips.push(Skip {
                            path,
                            category: SkipCategory::Limit,
                            reason: limit.into(),
                        });
                    }
                    continue;
                }
                self.insert(file);
                materialized.push(path.clone());
            }

            let Some(file) = self.files.get(&path) else {
                continue;
            };
            let registration_modules = file
                .summary
                .imports
                .iter()
                .map(|import| import.module.as_str())
                .collect::<BTreeSet<_>>();
            let defer_registrations = registration_modules.len() > MAX_EAGER_PYTHON_REGISTRATIONS
                && file.summary.functions.is_empty()
                && file.summary.classes.is_empty()
                && file.summary.module_calls.is_empty()
                && file.summary.module_effects.is_empty()
                && file.summary.main_calls.is_empty();
            if defer_registrations {
                self.deferred_python_registrations.insert(path);
                continue;
            }
            self.deferred_python_registrations.remove(&path);
            let dir = file.dir.clone();
            let imports = file
                .summary
                .imports
                .iter()
                .chain(&file.summary.scoped_imports)
                .cloned()
                .collect::<Vec<_>>();
            let callees = file
                .summary
                .module_calls
                .iter()
                .chain(&file.summary.main_calls)
                .chain(
                    file.summary
                        .functions
                        .iter()
                        .flat_map(|function| &function.calls),
                )
                .map(|edge| edge.callee.clone())
                .collect::<Vec<_>>();
            let mut discovered = Vec::new();
            for import in &imports {
                self.push_python_import_paths(&path, &dir, import, &mut discovered);
            }
            for callee in callees {
                let Some((head, members)) = callee.split_once('.') else {
                    continue;
                };
                let Some(import) = imports
                    .iter()
                    .find(|import| import.local == head && import.imported.is_none())
                else {
                    continue;
                };
                let mut module = import.module.clone();
                let parts = members.split('.').collect::<Vec<_>>();
                for member in parts.iter().take(parts.len().saturating_sub(1)) {
                    module.push('.');
                    module.push_str(member);
                    if let Some(path) = self.resolve_python(&path, &dir, &module) {
                        self.push_python_package_initializers(&path, &mut discovered);
                        discovered.push(path);
                    }
                }
            }
            discovered.sort();
            discovered.dedup();
            for dependency in discovered.into_iter().rev() {
                if !reachable.contains(&dependency) {
                    pending.push(dependency);
                }
            }
        }

        self.files
            .retain(|path, file| file.lang != Lang::Python || reachable.contains(path));
        self.deferred_python_registrations
            .retain(|path| reachable.contains(path));
        self.reindex_python_modules();
        materialized
    }

    pub(crate) fn defers_python_registrations(&self, path: &str) -> bool {
        self.deferred_python_registrations.contains(path)
    }

    fn push_python_import_paths(
        &self,
        importer_path: &str,
        importer_dir: &str,
        import: &ImportBinding,
        out: &mut Vec<String>,
    ) {
        if let Some(path) = self.resolve_python(importer_path, importer_dir, &import.module) {
            self.push_python_package_initializers(&path, out);
            out.push(path);
        }
        if let Some(imported) = import.imported.as_deref().filter(|name| *name != "*") {
            let module = if import.module.chars().all(|c| c == '.') {
                format!("{}{imported}", import.module)
            } else {
                format!("{}.{imported}", import.module)
            };
            if let Some(path) = self.resolve_python(importer_path, importer_dir, &module) {
                self.push_python_package_initializers(&path, out);
                out.push(path);
            }
        }
    }

    fn push_python_package_initializers(&self, path: &str, out: &mut Vec<String>) {
        let mut dir = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
        let mut initializers = Vec::new();
        while !dir.is_empty() {
            let init = format!("{dir}/__init__.py");
            if self.python_sources.contains_key(&init) {
                initializers.push(init);
            }
            dir = dir.rsplit_once('/').map(|(parent, _)| parent).unwrap_or("");
        }
        initializers.reverse();
        out.extend(initializers);
    }

    pub(crate) fn refresh_python_closure(
        &mut self,
        root: &Path,
        manifest: &[InputRecord],
        roots: &BTreeSet<String>,
        budget: &mut IndexBudget,
        max_skips: usize,
    ) -> (Vec<String>, Vec<Skip>) {
        let mut skipped = Vec::new();
        for input in manifest {
            if lang_of(Path::new(&input.path)) == Some(Lang::Python) {
                if self
                    .python_sources
                    .get(&input.path)
                    .is_some_and(|source| source.digest == input.digest)
                {
                    continue;
                }
                let dir = input
                    .path
                    .rsplit_once('/')
                    .map(|(dir, _)| dir.to_string())
                    .unwrap_or_default();
                let source_bytes =
                    std::fs::metadata(root.join(&input.path)).map_or(0, |metadata| metadata.len());
                if let Err(limit) = budget.charge(0, source_bytes) {
                    self.python_sources.remove(&input.path);
                    self.files.remove(&input.path);
                    if skipped.len() < max_skips {
                        skipped.push(Skip {
                            path: input.path.clone(),
                            category: SkipCategory::Limit,
                            reason: limit.into(),
                        });
                    }
                    continue;
                }
                let content = match std::fs::read_to_string(root.join(&input.path)) {
                    Ok(content) if content_digest(content.as_bytes()) == input.digest => content,
                    Ok(_) => {
                        self.python_sources.remove(&input.path);
                        self.files.remove(&input.path);
                        skipped.push(Skip {
                            path: input.path.clone(),
                            category: SkipCategory::Failure,
                            reason: "changed during Python materialization".to_string(),
                        });
                        continue;
                    }
                    Err(error) => {
                        self.python_sources.remove(&input.path);
                        self.files.remove(&input.path);
                        skipped.push(Skip {
                            path: input.path.clone(),
                            category: SkipCategory::Failure,
                            reason: format!("unreadable during Python materialization: {error}"),
                        });
                        continue;
                    }
                };
                self.python_sources.insert(
                    input.path.clone(),
                    PythonSource {
                        dir,
                        digest: input.digest.clone(),
                        content: Some(Arc::from(content)),
                    },
                );
            }
        }
        self.reindex_python_modules();
        {
            let materialized = self.retain_python_closure(roots, budget, &mut skipped, max_skips);
            self.drop_python_content();
            (materialized, skipped)
        }
    }

    /// Register a Python dotted module key -> file mapping. Used when building
    /// a registry by hand (tests); the normal path derives it in `insert`.
    pub fn register_python_module(&mut self, key: &str, path: &str) {
        self.python_modules
            .insert(key.to_string(), path.to_string());
    }

    /// Add or replace a source file from its content (extracting its surface),
    /// or remove it when `content` is None. A non-source file is ignored on
    /// add and simply absent on remove. Returns whether the registry changed.
    pub fn apply_change(&mut self, relpath: &str, content: Option<&str>) -> bool {
        let changed = self.apply_source_change(relpath, content);
        if changed {
            self.reindex_ruby_sources(&mut IndexBudget::new(RepositoryLimits::default()));
        }
        changed
    }

    // Index updates refresh Ruby loader evidence once, after all source changes.
    pub(crate) fn apply_source_change(&mut self, relpath: &str, content: Option<&str>) -> bool {
        if Path::new(relpath)
            .file_name()
            .is_some_and(|name| name == "go.mod")
        {
            let dir = relpath
                .rsplit_once('/')
                .map(|(dir, _)| dir.to_string())
                .unwrap_or_default();
            let module = content.and_then(go_module_source);
            let changed = self.go_modules.get(&dir) != module.as_ref();
            match module {
                Some(module) => {
                    self.go_modules.insert(dir, module);
                }
                None => {
                    self.go_modules.remove(&dir);
                }
            }
            if changed {
                self.reindex_go_scopes();
            }
            return changed;
        }
        let changed = match content {
            None => {
                let source_removed = self.python_sources.remove(relpath).is_some();
                self.files.remove(relpath).is_some() || source_removed
            }
            Some(source) => {
                let path = Path::new(relpath);
                let sniffed = (path.extension().is_none())
                    .then(|| {
                        ruby_shebang(source)
                            .then_some(Lang::Ruby)
                            .or_else(|| php_shebang(source).then_some(Lang::Php))
                    })
                    .flatten();
                let Some(lang) = lang_of(path).or(sniffed) else {
                    return self.apply_source_change(relpath, None);
                };
                if lang == Lang::Go && !go_source_selected(relpath, source) {
                    self.go_packages.remove(relpath);
                    let changed = self.files.remove(relpath).is_some();
                    self.reindex_go_package_vars();
                    return changed;
                }
                let digest = effinterp_proto::content_digest(source.as_bytes());
                let dir = relpath
                    .rsplit_once('/')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_default();
                if lang == Lang::Python {
                    self.python_sources.insert(
                        relpath.to_string(),
                        PythonSource {
                            dir: dir.clone(),
                            digest: digest.clone(),
                            content: Some(Arc::from(source)),
                        },
                    );
                }
                if lang == Lang::Go {
                    if let Some(package) = go_package_name(source) {
                        self.go_packages.insert(relpath.to_string(), package);
                    } else {
                        self.go_packages.remove(relpath);
                    }
                }
                self.insert(ModuleFile {
                    path: relpath.to_string(),
                    dir,
                    lang,
                    summary: module_summaries(
                        source,
                        lang,
                        relpath,
                        scope_for_file(
                            lang,
                            relpath,
                            relpath.rsplit_once('/').map(|(d, _)| d).unwrap_or(""),
                            &self.go_modules,
                            &self.rust_crates,
                        ),
                        &effinterp_engine::SummaryBudget::for_lang(&self.engine_limits, lang),
                    ),
                    digest,
                });
                true
            }
        };
        if content.is_none() {
            self.go_packages.remove(relpath);
        }
        // Adding or removing a file (an `__init__.py` in particular) can change
        // which directories are packages, so re-derive the Python module keys
        // from the whole file set — the same keying `build` uses.
        self.reindex_python_modules();
        self.reindex_go_package_vars();
        self.reindex_php_classes();
        changed
    }

    fn reindex_php_classes(&mut self) {
        let mut candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for file in self.files.values().filter(|file| file.lang == Lang::Php) {
            for class in &file.summary.classes {
                if php_class_paths(&class.name, &self.php_psr4)
                    .iter()
                    .any(|candidate| candidate == &file.path)
                {
                    candidates
                        .entry(class.name.clone())
                        .or_default()
                        .push(file.path.clone());
                }
            }
        }
        self.php_classes = candidates
            .into_iter()
            .filter_map(|(name, mut files)| {
                files.sort();
                files.dedup();
                (files.len() == 1).then(|| (name, files.remove(0)))
            })
            .collect();
    }

    pub(crate) fn php_class_file(&self, class: &str) -> Option<&ModuleFile> {
        self.php_classes
            .get(class)
            .and_then(|path| self.files.get(path))
            .map(Arc::as_ref)
    }

    fn reindex_go_package_vars(&mut self) {
        // Frontend extraction sees one file at a time. Resolve package-scoped
        // type names after every file in the package has been indexed.
        let mut declared: BTreeMap<GoTypeKey, String> = BTreeMap::new();
        let mut declared_identities: BTreeMap<String, (String, String)> = BTreeMap::new();
        for file in self
            .files
            .values()
            .filter(|file| file.lang == Lang::Go && !file.path.ends_with("_test.go"))
        {
            let Some(package) = self.go_packages.get(&file.path) else {
                continue;
            };
            for class in &file.summary.classes {
                declared.insert(
                    (file.dir.clone(), package.clone(), class.name.clone()),
                    file.path.clone(),
                );
                if let ScopeKey::GoPackage { key } = scope_for_file(
                    Lang::Go,
                    &file.path,
                    &file.dir,
                    &self.go_modules,
                    &self.rust_crates,
                ) {
                    declared_identities.insert(
                        format!("{key}.{}", class.name),
                        (file.path.clone(), class.name.clone()),
                    );
                }
            }
        }
        for file in self.files.values_mut().filter(|file| file.lang == Lang::Go) {
            let dir = file.dir.clone();
            let Some(package) = self.go_packages.get(&file.path) else {
                continue;
            };
            update_summary(file, |summary| {
                for edge in summary
                    .module_calls
                    .iter_mut()
                    .chain(&mut summary.main_calls)
                    .chain(summary.functions.iter_mut().flat_map(|f| &mut f.calls))
                {
                    fill_go_edge_type(edge, &dir, package, &declared);
                }
                for function in &mut summary.functions {
                    for ty in &mut function.return_types {
                        resolve_go_type_ref(ty, &dir, package, &declared);
                        if let Some(TypeRef::External { path }) = ty
                            && let Some((target, name)) = declared_identities.get(path)
                        {
                            *ty = Some(TypeRef::Repo {
                                file: target.clone(),
                                name: name.clone(),
                            });
                        }
                    }
                }
            });
        }

        let mut types: BTreeMap<GoTypeKey, TypeRef> = BTreeMap::new();
        for file in self
            .files
            .values()
            .filter(|file| file.lang == Lang::Go && !file.path.ends_with("_test.go"))
        {
            let Some(package) = self.go_packages.get(&file.path) else {
                continue;
            };
            for edge in &file.summary.module_calls {
                if !matches!(
                    edge.origin_for_result(0),
                    Some(ValueOrigin::Site { ref function, .. }) if function.is_empty()
                ) {
                    continue;
                }
                let Some(ty) = edge.result_type() else {
                    continue;
                };
                for (_, name) in edge.result_bindings() {
                    types.insert(
                        (file.dir.clone(), package.clone(), name.to_string()),
                        ty.clone(),
                    );
                }
            }
        }
        for file in self.files.values_mut().filter(|file| file.lang == Lang::Go) {
            let dir = file.dir.clone();
            let Some(package) = self.go_packages.get(&file.path) else {
                continue;
            };
            update_summary(file, |summary| {
                for edge in summary
                    .module_calls
                    .iter_mut()
                    .chain(&mut summary.main_calls)
                    .chain(summary.functions.iter_mut().flat_map(|f| &mut f.calls))
                {
                    fill_go_instance_type(edge.receiver.as_mut(), &dir, package, &types, &declared);
                    for argument in &mut edge.arguments {
                        fill_go_instance_type(
                            Some(&mut argument.value),
                            &dir,
                            package,
                            &types,
                            &declared,
                        );
                    }
                }
            });
        }
    }

    fn reindex_go_scopes(&mut self) {
        let scopes: Vec<_> = self
            .files
            .values()
            .filter(|file| file.lang == Lang::Go)
            .map(|file| {
                (
                    file.path.clone(),
                    scope_for_file(
                        Lang::Go,
                        &file.path,
                        &file.dir,
                        &self.go_modules,
                        &self.rust_crates,
                    ),
                )
            })
            .collect();
        for (path, scope) in scopes {
            update_summary(self.files.get_mut(&path).unwrap(), |summary| {
                set_summary_scope(summary, &scope)
            });
        }
    }

    /// Resolve an import binding used in `importer` (a [`ModuleFile`]) to the
    /// target file. Returns None (an external/unresolvable import) rather than
    /// guessing.
    pub fn resolve_import(
        &self,
        importer: &ModuleFile,
        import: &ImportBinding,
    ) -> Option<&ModuleFile> {
        let file_path = match importer.lang {
            Lang::Python => self.resolve_python(&importer.path, &importer.dir, &import.module),
            Lang::Js(_) => {
                let commonjs = importer.summary.module_loads.iter().any(|load| {
                    load.local == import.local
                        && load.module == import.module
                        && load.kind == ModuleLoadKind::CommonJs
                });
                self.resolve_js(&importer.dir, &import.module, commonjs)
            }
            Lang::Ruby => self.resolve_ruby(importer, &import.module),
            Lang::Rust => self.resolve_rust(importer, import),
            Lang::Go => self.resolve_go(&importer.dir, &import.module),
            Lang::Java => self.resolve_java(&import.module),
            Lang::Php => self.resolve_php(&importer.dir, &import.module),
        };
        file_path.and_then(|p| self.files.get(&p)).map(Arc::as_ref)
    }

    /// Python import resolution: relative (`.util`, `..pkg.util`) against the
    /// importer's directory, otherwise the dotted module map.
    fn resolve_python(
        &self,
        importer_path: &str,
        importer_dir: &str,
        module: &str,
    ) -> Option<String> {
        if let Some(stripped) = module.strip_prefix('.') {
            let mut ups = 1;
            let mut rest = stripped;
            while let Some(r) = rest.strip_prefix('.') {
                ups += 1;
                rest = r;
            }
            let mut base: Vec<&str> = if importer_dir.is_empty() {
                Vec::new()
            } else {
                importer_dir.split('/').collect()
            };
            for _ in 1..ups {
                base.pop();
            }
            let tail = rest.replace('.', "/");
            let joined = if tail.is_empty() {
                base.join("/")
            } else if base.is_empty() {
                tail
            } else {
                format!("{}/{}", base.join("/"), tail)
            };
            return self.python_file_for_relpath(&joined);
        }
        let rel = module.replace('.', "/");
        // Absolute imports are tried against the repo root, then the
        // conventional `src/` layout root — the same root discovery uses for
        // console-script specs — then another discovered source root and the
        // script's directory.
        self.python_file_for_relpath(&rel)
            .or_else(|| self.python_file_for_relpath(&format!("src/{rel}")))
            .or_else(|| self.python_modules.get(module).cloned())
            .or_else(|| {
                if !self.script_roots.contains(importer_path) {
                    return None;
                }
                let candidate = if importer_dir.is_empty() {
                    rel.clone()
                } else {
                    format!("{importer_dir}/{rel}")
                };
                self.python_file_for_relpath(&candidate)
            })
    }

    fn python_file_for_relpath(&self, relpath: &str) -> Option<String> {
        let init = format!("{relpath}/__init__.py");
        if self.python_sources.contains_key(&init) || self.files.contains_key(&init) {
            return Some(init);
        }
        let direct = format!("{relpath}.py");
        if self.python_sources.contains_key(&direct) || self.files.contains_key(&direct) {
            return Some(direct);
        }
        None
    }

    /// JS import resolution: a relative specifier (`./util`) maps to a sibling
    /// file; a bare specifier that a workspace package owns maps through that
    /// package's `exports`/`main` to source. External packages stay unresolved.
    fn resolve_js(&self, importer_dir: &str, module: &str, commonjs: bool) -> Option<String> {
        if !module.starts_with('.') {
            return self.resolve_js_package(module, commonjs);
        }
        let base = join_rel(importer_dir, module);
        // An explicit extension in the specifier (`./util.js`) resolves directly.
        if self.files.contains_key(&base) {
            return Some(base);
        }
        for ext in ["js", "ts", "mjs", "cjs", "jsx", "tsx"] {
            let cand = format!("{base}.{ext}");
            if self.files.contains_key(&cand) {
                return Some(cand);
            }
        }
        for idx in ["index.js", "index.ts"] {
            let cand = format!("{base}/{idx}");
            if self.files.contains_key(&cand) {
                return Some(cand);
            }
        }
        None
    }

    /// A workspace package specifier (`@pkg/cli`, `@pkg/cli/changelog`)
    /// resolves through that member's declared export to a repo source file.
    fn resolve_js_package(&self, spec: &str, commonjs: bool) -> Option<String> {
        let (name, sub) = split_npm_spec(spec);
        let pkg = self.js_packages.get(name)?;
        let artifact = js_package_artifact_for(pkg, &sub, commonjs)?;
        self.map_js_artifact(&pkg.dir, &artifact)
    }

    /// Map a package-relative artifact (`dist/index.mjs`) to a registry file:
    /// the artifact itself when present, otherwise the unique source that
    /// produces it. Ambiguous stems stay unresolved.
    fn map_js_artifact(&self, pkg_dir: &str, artifact: &str) -> Option<String> {
        let artifact = artifact.trim_start_matches("./");
        let joined = if pkg_dir.is_empty() {
            artifact.to_string()
        } else {
            format!("{pkg_dir}/{artifact}")
        };
        if self.files.contains_key(&joined) {
            return Some(joined);
        }
        let (dir, name) = artifact.rsplit_once('/').unwrap_or(("", artifact));
        let (stem, ext) = name.rsplit_once('.')?;
        let source_exts: &[&str] = match ext {
            "js" => &["ts", "tsx", "js", "jsx"],
            "mjs" => &["mts", "ts", "mjs"],
            "cjs" => &["cts", "ts", "cjs"],
            _ => return None,
        };
        let rest = match dir.split_once('/') {
            Some((head, rest)) if JS_BUILD_DIRS.contains(&head) => Some(rest),
            None if JS_BUILD_DIRS.contains(&dir) => Some(""),
            _ => None,
        };
        if let Some(rest) = rest {
            for src_root in ["src", ""] {
                let base = [pkg_dir, src_root, rest]
                    .iter()
                    .copied()
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
                    .join("/");
                let prefix = if base.is_empty() {
                    stem.to_string()
                } else {
                    format!("{base}/{stem}")
                };
                for e in source_exts {
                    let cand = format!("{prefix}.{e}");
                    if self.files.contains_key(&cand) {
                        return Some(cand);
                    }
                }
            }
        }
        let src_prefix = if pkg_dir.is_empty() {
            "src/".to_string()
        } else {
            format!("{pkg_dir}/src/")
        };
        let mut found: Vec<String> = self
            .files
            .keys()
            .filter(|p| p.starts_with(&src_prefix))
            .filter(|p| {
                let fname = p.rsplit('/').next().unwrap_or("");
                source_exts.iter().any(|e| fname == format!("{stem}.{e}"))
            })
            .cloned()
            .collect();
        found.sort();
        found.dedup();
        match found.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        }
    }

    /// Rust: cross-file call edges come from `use crate::path::item; item()`,
    /// so `import.module` is the full `use` path and `import.imported` is the
    /// item name. Strip the item to get the module path, then map it to a file
    /// (`crate::a::b` -> `a/b.rs` or `a/b/mod.rs`; `self::`/`super::` relative
    /// to the importer). A head that is neither a path root nor `std` may name
    /// a workspace crate by package name (`use bat::output::...` from a binary)
    /// or a sibling module of the importer's directory; both are tried.
    fn resolve_rust(&self, importer: &ModuleFile, import: &ImportBinding) -> Option<String> {
        self.resolve_rust_inner(importer, import, &mut HashSet::new())
    }

    fn resolve_rust_inner(
        &self,
        importer: &ModuleFile,
        import: &ImportBinding,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<String> {
        let mut segs: Vec<&str> = import.module.split("::").collect();
        // Drop the trailing item name (the imported symbol) to get the module.
        if let Some(item) = &import.imported
            && segs.last() == Some(&item.as_str())
        {
            segs.pop();
        }
        if segs.is_empty() {
            return None;
        }
        match segs[0] {
            "crate" => {
                let base = self.rust_crate_root(&importer.dir);
                if let Some(krate) = self
                    .rust_crates
                    .values()
                    .find(|krate| krate.src_dir == base)
                {
                    return self.rust_crate_file(
                        krate,
                        &segs[1..],
                        import.imported.as_deref(),
                        visited,
                    );
                }
                self.rust_mod_file(&base, &segs[1..]).or_else(|| {
                    self.rust_follow_module_alias(
                        &base,
                        None,
                        &segs[1..],
                        import.imported.as_deref(),
                        visited,
                    )
                })
            }
            "self" => self.rust_mod_file(&importer.dir, &segs[1..]),
            "super" => {
                // For `x/y.rs` the parent module lives in `x` itself; only a
                // module-root file (`lib.rs`/`main.rs`/`mod.rs`) has its parent
                // module in the directory above.
                let file_name = importer.path.rsplit('/').next().unwrap_or("");
                let dir = if matches!(file_name, "lib.rs" | "main.rs" | "mod.rs") {
                    importer.dir.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
                } else {
                    importer.dir.as_str()
                };
                self.rust_mod_file(dir, &segs[1..])
            }
            // A std path: not a repo file.
            "std" | "core" | "alloc" => None,
            head => {
                // A workspace crate named by its package name, including a
                // `[lib] path` override so `uu_cat::uumain` lands in `cat.rs`.
                if let Some(krate) = self.rust_crates.get(head)
                    && let Some(p) =
                        self.rust_crate_file(krate, &segs[1..], import.imported.as_deref(), visited)
                {
                    return Some(p);
                }
                // A sibling module of the importer's directory (`mod assets;`
                // then `use assets::...` / a bare `util::wipe(...)` call).
                self.rust_mod_file(&importer.dir, &segs)
            }
        }
    }

    /// Resolve a path under a workspace crate: an empty remainder is the
    /// library root (`[lib] path` when declared, else `lib.rs`/`main.rs`/
    /// `mod.rs`); further segments are ordinary module files under `src/`.
    /// A missing first segment may be a crate-root module alias
    /// (`pub extern crate grep_cli as cli` / `pub use grep_cli as cli`).
    fn rust_crate_file(
        &self,
        krate: &RustCrate,
        rest: &[&str],
        imported: Option<&str>,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<String> {
        let src_dir = krate.src_dir.clone();
        let lib_path = krate.lib_path.clone();
        if rest.is_empty() {
            if let Some(lib) = &lib_path
                && self.files.contains_key(lib)
            {
                return Some(lib.clone());
            }
            return self.rust_mod_file(&src_dir, &[]);
        }
        self.rust_mod_file(&src_dir, rest).or_else(|| {
            self.rust_follow_module_alias(&src_dir, lib_path.as_deref(), rest, imported, visited)
        })
    }

    /// When `rest[0]` is not a file under `base_dir`, follow a crate-root export
    /// of that name and restart resolution from the aliased path.
    fn rust_follow_module_alias(
        &self,
        base_dir: &str,
        lib_path: Option<&str>,
        rest: &[&str],
        imported: Option<&str>,
        visited: &mut HashSet<(String, String)>,
    ) -> Option<String> {
        let segment = rest.first().copied()?;
        if self.rust_mod_file(base_dir, &[segment]).is_some() {
            return None;
        }
        let root_path = self.rust_base_root_path(base_dir, lib_path)?;
        if visited.len() >= MAX_EXPORT_CHASE
            || !visited.insert((root_path.clone(), segment.to_string()))
        {
            return None;
        }
        let root = self.files.get(&root_path)?;
        let bindings: Vec<ImportBinding> = root
            .summary
            .exports
            .iter()
            .filter(|binding| binding.local == segment)
            .cloned()
            .collect();
        for binding in bindings {
            let mut module = binding.module;
            if rest.len() > 1 {
                module.push_str("::");
                module.push_str(&rest[1..].join("::"));
            }
            if let Some(item) = imported {
                let suffix = format!("::{item}");
                if module != item && !module.ends_with(&suffix) {
                    module.push_str(&suffix);
                }
            }
            let import = ImportBinding {
                local: imported.unwrap_or(segment).to_string(),
                module,
                imported: imported.map(str::to_string),
            };
            if let Some(path) = self.resolve_rust_inner(root, &import, visited) {
                return Some(path);
            }
        }
        None
    }

    fn rust_base_root_path(&self, base_dir: &str, lib_path: Option<&str>) -> Option<String> {
        if let Some(lib) = lib_path
            && self.files.contains_key(lib)
        {
            return Some(lib.to_string());
        }
        self.rust_mod_file(base_dir, &[])
    }

    /// Map module-path segments under a base directory to a repo file:
    /// `a/b.rs`, then `a/b/mod.rs`; an empty path is the module root itself
    /// (`lib.rs`/`main.rs`/`mod.rs` of the base directory).
    fn rust_mod_file(&self, base_dir: &str, rest: &[&str]) -> Option<String> {
        let join = |tail: &str| {
            if base_dir.is_empty() {
                tail.to_string()
            } else {
                format!("{base_dir}/{tail}")
            }
        };
        if rest.is_empty() {
            return ["lib.rs", "main.rs", "mod.rs"]
                .into_iter()
                .map(join)
                .find(|c| self.files.contains_key(c));
        }
        let joined = join(&rest.join("/"));
        let direct = format!("{joined}.rs");
        if self.files.contains_key(&direct) {
            return Some(direct);
        }
        let modrs = format!("{joined}/mod.rs");
        self.files.contains_key(&modrs).then_some(modrs)
    }

    /// The crate-root directory a Rust `crate::` path is relative to: the nearest
    /// ancestor of the importer (itself included) that holds a crate entry file
    /// (`main.rs`/`lib.rs`). In a workspace this is NOT the repo root — ripgrep's
    /// binary crate lives at `crates/core`, so `crate::flags` is
    /// `crates/core/flags`, not `flags`. Falls back to the repo root when no
    /// entry file is found.
    fn rust_crate_root(&self, importer_dir: &str) -> String {
        let mut dir = importer_dir.to_string();
        loop {
            let main = if dir.is_empty() {
                "main.rs".to_string()
            } else {
                format!("{dir}/main.rs")
            };
            let lib = if dir.is_empty() {
                "lib.rs".to_string()
            } else {
                format!("{dir}/lib.rs")
            };
            if self.files.contains_key(&main) || self.files.contains_key(&lib) {
                return dir;
            }
            if dir.is_empty() {
                return String::new();
            }
            dir = dir
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_default();
        }
    }

    /// Go: an import path like `example.com/app/pkg/util` maps to the repo
    /// directory `pkg/util` when it is prefixed by a discovered module path.
    /// A Go package spans every `.go` file in that
    /// directory; the first such file (sorted) resolves the call. Standard
    /// library and external imports (no module-prefix match) stay unresolved.
    fn resolve_go(&self, importer_dir: &str, import_path: &str) -> Option<String> {
        let sub = self.go_dir_for_import(importer_dir, import_path)?;
        // Files in the package directory `sub` (BTreeMap keeps them sorted).
        self.files
            .keys()
            .find(|p| p.ends_with(".go") && p.rsplit_once('/').map(|(d, _)| d).unwrap_or("") == sub)
            .cloned()
    }

    fn go_dir_for_import(&self, importer_dir: &str, import_path: &str) -> Option<String> {
        let importer_module =
            go_module_for_dir(importer_dir, &self.go_modules).filter(|(_, module)| {
                import_path == module.as_str()
                    || import_path
                        .strip_prefix(module.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            });
        let fallback = || {
            let mut matches: Vec<_> = self
                .go_modules
                .iter()
                .filter(|(_, module)| {
                    import_path == module.as_str()
                        || import_path
                            .strip_prefix(module.as_str())
                            .is_some_and(|rest| rest.starts_with('/'))
                })
                .collect();
            matches.sort_by(|(left_dir, left_module), (right_dir, right_module)| {
                right_module
                    .len()
                    .cmp(&left_module.len())
                    .then_with(|| left_dir.len().cmp(&right_dir.len()))
            });
            matches.into_iter().next()
        };
        let (module_dir, module) = importer_module.or_else(fallback)?;
        let sub = import_path
            .strip_prefix(module)
            .unwrap_or_default()
            .trim_start_matches('/');
        Some(match (module_dir.is_empty(), sub.is_empty()) {
            (true, _) => sub.to_string(),
            (_, true) => module_dir.clone(),
            _ => format!("{module_dir}/{sub}"),
        })
    }

    /// Java: an import FQN like `com.example.util.Helper` maps to the source
    /// file `com/example/util/Helper.java`. Source roots vary
    /// (`src/main/java/...`), so a file whose path ends with that package path
    /// resolves the call. Standard-library and external types (no matching
    /// file) stay unresolved.
    fn resolve_java(&self, fqn: &str) -> Option<String> {
        let rel = format!("{}.java", fqn.replace('.', "/"));
        if self.files.contains_key(&rel) {
            return Some(rel);
        }
        let suffix = format!("/{rel}");
        self.files.keys().find(|p| p.ends_with(&suffix)).cloned()
    }

    /// PHP: `require`/`include` names a filesystem path (`./util.php`,
    /// `lib/helper.php`), resolved relative to the requiring file's directory,
    /// with a repo-root sibling as fallback. Dynamic or absolute paths that
    /// match no known file stay unresolved.
    fn resolve_php(&self, importer_dir: &str, module: &str) -> Option<String> {
        let stem = module.strip_suffix(".php").unwrap_or(module);
        let rel = join_rel(importer_dir, stem);
        let cand = format!("{rel}.php");
        if self.files.contains_key(&cand) {
            return Some(cand);
        }
        // `__DIR__ . '/php/wp-cli.php'` yields a leading-slash spec; treat it
        // as repo-relative after stripping the slash.
        let trimmed = stem.trim_start_matches('/').trim_start_matches("./");
        let root_rel = format!("{trimmed}.php");
        if self.files.contains_key(&root_rel) {
            return Some(root_rel);
        }
        if let Some(base) = trimmed.rsplit('/').next() {
            let sibling = if importer_dir.is_empty() {
                format!("{base}.php")
            } else {
                format!("{importer_dir}/{base}.php")
            };
            if self.files.contains_key(&sibling) {
                return Some(sibling);
            }
        }
        None
    }
}

fn python_import_priority(path: &str) -> (u8, u8) {
    let source_root = (path.starts_with("src/") || path.contains("/src/")) as u8;
    let module_file = (!path.ends_with("/__init__.py") && path != "__init__.py") as u8;
    (source_root, module_file)
}

/// Normalize a `./x`/`../x` specifier against a base directory into a
/// repo-relative path (no extension).
fn join_rel(base_dir: &str, spec: &str) -> String {
    let mut parts: Vec<&str> = if base_dir.is_empty() {
        Vec::new()
    } else {
        base_dir.split('/').collect()
    };
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

pub(crate) fn lang_of(path: &Path) -> Option<Lang> {
    match path.extension()?.to_str()? {
        "py" => Some(Lang::Python),
        "js" | "mjs" | "cjs" | "jsx" => Some(Lang::Js(SourceDialect::Js)),
        "ts" | "tsx" => Some(Lang::Js(SourceDialect::Ts)),
        "go" => Some(Lang::Go),
        "rb" => Some(Lang::Ruby),
        "rs" => Some(Lang::Rust),
        "java" => Some(Lang::Java),
        "php" => Some(Lang::Php),
        _ => None,
    }
}

/// An extensionless Ruby executable (a gem's `exe/`/`bin/` script): identified
/// by its shebang, so the entrypoint file itself is a registry module and
/// cross-file composition can start from it.
fn ruby_shebang(content: &str) -> bool {
    content.starts_with("#!")
        && content
            .lines()
            .next()
            .is_some_and(|line| line.contains("ruby"))
}

fn php_shebang(content: &str) -> bool {
    content.starts_with("#!")
        && content
            .lines()
            .next()
            .is_some_and(|line| line.split_whitespace().any(|word| word.ends_with("php")))
}

#[allow(clippy::too_many_arguments)]
fn scan(
    root: &Path,
    dir: &Path,
    depth: u32,
    limits: &CrawlLimits,
    seen: &mut u64,
    reg: &mut Registry,
    skips: &mut Vec<Skip>,
    manifest: &mut Vec<InputRecord>,
    eager_python: bool,
    budget: &mut IndexBudget,
    admitted: Option<&BTreeSet<String>>,
) {
    if depth > limits.max_depth {
        return;
    }
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(Result::ok).collect(),
        Err(_) => return,
    };
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        if crate::canonical_repo_path(root, &path).is_none() {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if SKIP_DIRS.contains(&name.as_str()) || name == ".claude" {
                continue;
            }
            scan(
                root,
                &path,
                depth + 1,
                limits,
                seen,
                reg,
                skips,
                manifest,
                eager_python,
                budget,
                admitted,
            );
        } else if ft.is_file() {
            // Extensionless Ruby and PHP executables are sniffed by shebang
            // after reading. Other files without a recognized extension are
            // not source modules.
            let ext_lang = lang_of(&path);
            if ext_lang.is_none() && path.extension().is_some() {
                continue;
            }
            if *seen >= limits.max_files {
                return;
            }
            *seen += 1;
            let relpath = rel(root, &path);
            if admitted.is_some_and(|admitted| !admitted.contains(&relpath)) {
                continue;
            }
            if let Ok(m) = std::fs::metadata(&path)
                && m.len() > limits.max_file_bytes
            {
                if ext_lang.is_some() && skips.len() < limits.max_skips {
                    skips.push(Skip {
                        path: relpath,
                        category: SkipCategory::Limit,
                        reason: format!("file exceeds max_file_bytes ({} bytes)", m.len()),
                    });
                }
                continue;
            }
            if let Err(limit) = budget.charge(0, 0) {
                if skips.len() < limits.max_skips {
                    skips.push(Skip {
                        path: relpath,
                        category: SkipCategory::Limit,
                        reason: limit.into(),
                    });
                }
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    if ext_lang.is_some() && skips.len() < limits.max_skips {
                        skips.push(Skip {
                            path: relpath,
                            category: SkipCategory::Failure,
                            reason: format!("unreadable or non-utf8: {e}"),
                        });
                    }
                    continue;
                }
            };
            let Some(lang) = ext_lang.or_else(|| {
                ruby_shebang(&content)
                    .then_some(Lang::Ruby)
                    .or_else(|| php_shebang(&content).then_some(Lang::Php))
            }) else {
                continue;
            };
            let digest = content_digest(content.as_bytes());
            manifest.push(InputRecord {
                path: relpath.clone(),
                digest: digest.clone(),
            });
            if lang == Lang::Go && !go_source_selected(&relpath, &content) {
                continue;
            }
            if let Err(limit) = budget.charge(
                u64::from(eager_python || lang != Lang::Python),
                content.len() as u64,
            ) {
                if skips.len() < limits.max_skips {
                    skips.push(Skip {
                        path: relpath,
                        category: SkipCategory::Limit,
                        reason: limit.into(),
                    });
                }
                continue;
            }
            let file_dir = path.parent().map(|p| rel(root, p)).unwrap_or_default();
            if lang == Lang::Python {
                reg.python_sources.insert(
                    relpath.clone(),
                    PythonSource {
                        dir: file_dir.clone(),
                        digest: digest.clone(),
                        content: Some(Arc::from(content.as_str())),
                    },
                );
                if !eager_python {
                    continue;
                }
            }
            let scope =
                scope_for_file(lang, &relpath, &file_dir, &reg.go_modules, &reg.rust_crates);
            let summary = module_summaries(
                &content,
                lang,
                &relpath,
                scope,
                &effinterp_engine::SummaryBudget::for_lang(&reg.engine_limits, lang),
            );
            if let Err(limit) = budget.charge(0, summary.retained_bytes()) {
                if skips.len() < limits.max_skips {
                    skips.push(Skip {
                        path: relpath,
                        category: SkipCategory::Limit,
                        reason: limit.into(),
                    });
                }
                continue;
            }
            if lang == Lang::Go
                && let Some(package) = go_package_name(&content)
            {
                reg.go_packages.insert(relpath.clone(), package);
            }
            reg.insert(ModuleFile {
                path: relpath,
                dir: file_dir,
                lang,
                summary,
                digest,
            });
        }
    }
}

fn scope_for_file(
    lang: Lang,
    path: &str,
    dir: &str,
    go_modules: &BTreeMap<String, String>,
    rust_crates: &BTreeMap<String, RustCrate>,
) -> ScopeKey {
    match lang {
        Lang::Go => {
            let key = match go_module_for_dir(dir, go_modules) {
                Some((module_dir, module)) => {
                    let package_dir = dir
                        .strip_prefix(module_dir)
                        .unwrap_or(dir)
                        .trim_start_matches('/');
                    if package_dir.is_empty() {
                        module.clone()
                    } else {
                        format!("{module}/{package_dir}")
                    }
                }
                None => dir.to_string(),
            };
            ScopeKey::GoPackage { key }
        }
        Lang::Rust => ScopeKey::RustModule {
            key: rust_scope(path, rust_crates),
        },
        Lang::Python => ScopeKey::Module {
            key: provisional_python_key(path),
        },
        _ => ScopeKey::Module {
            key: path.to_string(),
        },
    }
}

fn provisional_python_key(path: &str) -> String {
    let path = path.strip_suffix(".py").unwrap_or(path);
    path.strip_suffix("/__init__")
        .unwrap_or(path)
        .replace('/', ".")
}

fn rewrite_summary_scopes(summary: &mut ModuleSummary, rekeys: &BTreeMap<String, String>) {
    if let Some(scope) = &mut summary.linkage.scope {
        rewrite_scope(scope, rekeys);
    }
    for edge in summary
        .module_calls
        .iter_mut()
        .chain(&mut summary.main_calls)
        .chain(summary.functions.iter_mut().flat_map(|f| &mut f.calls))
    {
        rewrite_edge_scopes(edge, rekeys);
    }
    for value in summary.module_values.values_mut() {
        rewrite_value_scope(value, rekeys);
    }
}

fn rewrite_edge_scopes(edge: &mut CallEdge, rekeys: &BTreeMap<String, String>) {
    for result in &mut edge.results {
        if let Some(origin) = &mut result.value.evidence.origin {
            rewrite_origin_scope(origin, rekeys);
        }
    }
    if let Some(receiver) = &mut edge.receiver {
        rewrite_value_scope(receiver, rekeys);
    }
    for argument in &mut edge.arguments {
        rewrite_value_scope(&mut argument.value, rekeys);
    }
}

fn rewrite_value_scope(value: &mut SemanticValue, rekeys: &BTreeMap<String, String>) {
    if let Some(origin) = &mut value.evidence.origin {
        rewrite_origin_scope(origin, rekeys);
    }
    if let SemanticValueKind::Object(object) = &mut value.kind {
        match &mut object.identity {
            ObjectIdentity::ModuleBinding { scope, .. } => rewrite_scope(scope, rekeys),
            ObjectIdentity::Class { constructor, .. } => {
                for argument in constructor {
                    rewrite_value_scope(&mut argument.value, rekeys);
                }
            }
            _ => {}
        }
        for property in object.properties.values_mut() {
            rewrite_value_scope(property, rekeys);
        }
    }
}

fn rewrite_origin_scope(origin: &mut ValueOrigin, rekeys: &BTreeMap<String, String>) {
    if let ValueOrigin::Module { scope, .. } = origin {
        rewrite_scope(scope, rekeys);
    }
}

fn rewrite_scope(scope: &mut ScopeKey, rekeys: &BTreeMap<String, String>) {
    if let ScopeKey::Module { key } = scope
        && let Some(final_key) = rekeys.get(key)
    {
        *key = final_key.clone();
    }
}

fn set_summary_scope(summary: &mut ModuleSummary, scope: &ScopeKey) {
    summary.linkage.scope = Some(scope.clone());
    for value in summary.module_values.values_mut() {
        set_value_scope(Some(value), scope);
    }
    for edge in summary
        .module_calls
        .iter_mut()
        .chain(&mut summary.main_calls)
        .chain(
            summary
                .functions
                .iter_mut()
                .flat_map(|function| &mut function.calls),
        )
    {
        for result in &mut edge.results {
            if let Some(ValueOrigin::Module {
                scope: origin_scope,
                ..
            }) = &mut result.value.evidence.origin
            {
                *origin_scope = scope.clone();
            }
        }
        set_value_scope(edge.receiver.as_mut(), scope);
        for argument in &mut edge.arguments {
            set_value_scope(Some(&mut argument.value), scope);
        }
    }
}

fn set_value_scope(value: Option<&mut SemanticValue>, scope: &ScopeKey) {
    let Some(value) = value else { return };
    if let Some(ValueOrigin::Module {
        scope: origin_scope,
        ..
    }) = &mut value.evidence.origin
    {
        *origin_scope = scope.clone();
    }
    if let SemanticValueKind::Object(object) = &mut value.kind {
        match &mut object.identity {
            ObjectIdentity::ModuleBinding {
                scope: instance_scope,
                ..
            } => *instance_scope = scope.clone(),
            ObjectIdentity::Class { constructor, .. } => {
                for argument in constructor {
                    set_value_scope(Some(&mut argument.value), scope);
                }
            }
            _ => {}
        }
        for property in object.properties.values_mut() {
            set_value_scope(Some(property), scope);
        }
    }
}

fn fill_go_edge_type(
    edge: &mut CallEdge,
    dir: &str,
    package: &str,
    declared: &BTreeMap<GoTypeKey, String>,
) {
    if edge.results.is_empty() {
        edge.results.push(CallResult::new(0, None, None, None));
    }
    let ty = &mut edge.results[0].value.evidence.ty;
    if ty.is_none()
        && let Some(file) =
            declared.get(&(dir.to_string(), package.to_string(), edge.callee.clone()))
    {
        *ty = Some(TypeRef::Repo {
            file: file.clone(),
            name: edge.callee.clone(),
        });
    }
    resolve_go_type_ref(ty, dir, package, declared);
}

fn resolve_go_type_ref(
    ty: &mut Option<TypeRef>,
    dir: &str,
    package: &str,
    declared: &BTreeMap<GoTypeKey, String>,
) {
    let Some(TypeRef::Repo { file, name }) = ty else {
        return;
    };
    if file.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("") == dir {
        *ty = declared
            .get(&(dir.to_string(), package.to_string(), name.clone()))
            .map(|file| TypeRef::Repo {
                file: file.clone(),
                name: name.clone(),
            });
    }
}

fn fill_go_instance_type(
    value: Option<&mut SemanticValue>,
    dir: &str,
    package: &str,
    types: &BTreeMap<GoTypeKey, TypeRef>,
    declared: &BTreeMap<GoTypeKey, String>,
) {
    let Some(value) = value else { return };
    let SemanticValueKind::Object(object) = &mut value.kind else {
        return;
    };
    match &mut object.identity {
        ObjectIdentity::ModuleBinding { name, .. } => {
            value.evidence.ty = types
                .get(&(dir.to_string(), package.to_string(), name.clone()))
                .cloned();
        }
        ObjectIdentity::Class { constructor, .. } => {
            resolve_go_type_ref(&mut value.evidence.ty, dir, package, declared);
            for argument in constructor {
                fill_go_instance_type(Some(&mut argument.value), dir, package, types, declared);
            }
        }
        _ => {}
    }
}

fn rel(root: &Path, path: &Path) -> String {
    crate::canonical_repo_path(root, path).expect("walked repository path is canonical")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_rel_normalizes() {
        assert_eq!(join_rel("app/sub", "./util"), "app/sub/util");
        assert_eq!(join_rel("app/sub", "../util"), "app/util");
        assert_eq!(join_rel("", "./util"), "util");
    }
}
