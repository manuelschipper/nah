//! Entrypoint discovery. Walks a repository (bounded, skipping vendored and
//! build directories) and recognizes entrypoints with retained evidence: a
//! package.json script, a shell/shebang file, a Makefile target, or a
//! compiled-language source file with a program entry (`fn main`/`func main`).
//! Discovery
//! evidence is kept because an entrypoint inferred from a file convention is
//! not the same claim as an explicit process target.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use effinterp_proto::{ExecutionRealm, ProvenanceRef, ResourceExpr, Subject};
use serde::{Deserialize, Serialize};

use crate::index::{CrawlLimits, SkipCategory, SkippedPath};
use crate::snapshot::InputRecord;
use crate::{CRAWL_SKIP_DIRS, walked_repo_path};
use effinterp_proto::content_digest;

mod language;
mod launch_sources;
mod noncode_mask;
mod package;
mod shebang;
mod workflow;

use language::{main_language, php_entrypoint, read_composer_bins, script_subject};
use launch_sources::{launch_local_sources, sort_launch_edges, source_language};
use noncode_mask::mask_noncode;
use package::{
    makefile_targets, package_bin_entrypoints, package_scripts, python_entry_point_scripts,
};
use shebang::{could_have_shebang, push_shell_file, shebang_file};
use workflow::github_workflow_steps;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointKind {
    /// A declared FastAPI route, without a claim about its deployment or mount.
    Route,
    /// A declared Cobra command, without a parent-command hierarchy.
    Command,
    PackageScript,
    ShellFile,
    ShebangFile,
    MakefileTarget,
    CiStep,
    /// A compiled-language source file with a program entry (`fn main` /
    /// `func main`), analyzed from that entry.
    MainFile,
    /// A Python console script declared in packaging metadata
    /// (`[project.scripts]` etc. — `name = "pkg.mod:func"`): the module file,
    /// with the named function as the execution root after import.
    ConsoleScript,
    /// A package.json `bin` program, mapped back to its source file when the
    /// declared target is built output absent from the source repo.
    PackageBin,
}

/// Why a subject is treated as an entrypoint, and where it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrypointEvidence {
    pub kind: EntrypointKind,
    /// Repo-relative path containing the discovery evidence.
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoint {
    /// Stable identifier, e.g. `scripts/deploy.sh` or `package.json:scripts.build`.
    pub id: String,
    pub subject: Subject,
    /// Repo-relative source file analyzed for this entrypoint.
    pub source_file: String,
    /// Repository-relative namespace used only to resolve source-relative
    /// imports and includes. The empty string is repository root.
    pub source_cwd: Option<String>,
    pub evidence: EntrypointEvidence,
    /// For a console-script entrypoint (`pkg.mod:func`): the function the
    /// script runner calls after importing the module, an execution root the
    /// file's own top level never names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_function: Option<String>,
    /// Declaration-local labels, roots, locations, and unresolved context.
    pub registration: Option<effinterp_engine::Registration>,
    /// Package initializers executed first, outermost to innermost, when this
    /// source was selected by `python -m package`.
    pub(crate) package_inits: Vec<String>,
    /// For a package-script subject embedded in its manifest: the mapping from
    /// subject-source byte offsets to evidence-file byte offsets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_map: Option<Vec<SpanSegment>>,
}

/// One `span_map` segment: a run of an embedded script mapped into its host
/// file. Subject-source bytes `[src, src+len)` came from evidence-file bytes
/// starting at `host` (verbatim runs are 1:1; a JSON escape maps its decoded
/// bytes to the escape's start).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanSegment {
    pub src: u32,
    pub host: u32,
    pub len: u32,
}

/// Rewrite the plan's top-level source spans through `map` so they index the
/// evidence file instead of the embedded subject source. Spans reached through
/// a nested invocation are relative to the nested subject's own source and are
/// left alone; antecedents always reference earlier nodes, so one forward pass
/// finds them.
pub(crate) fn remap_spans(plan: &mut effinterp_proto::Plan, map: &[SpanSegment]) {
    if map.is_empty() {
        return;
    }
    let mut crossed = vec![false; plan.provenance.len()];
    for i in 0..plan.provenance.len() {
        let node = &plan.provenance[i];
        crossed[i] = matches!(node.kind, effinterp_proto::ProvenanceKind::Execution { .. })
            || node
                .antecedents
                .iter()
                .any(|a| crossed.get(a.0 as usize).copied().unwrap_or(false));
    }
    for (i, node) in plan.provenance.iter_mut().enumerate() {
        if crossed[i] {
            continue;
        }
        if let effinterp_proto::ProvenanceKind::SourceSpan { start, end } = &mut node.kind {
            let host_end = if *end == 0 {
                map_offset(map, 0)
            } else {
                map_offset(map, *end - 1) + 1
            };
            *start = map_offset(map, *start);
            *end = host_end.max(*start);
        }
    }
}

/// The evidence-file offset for one subject-source offset: locate the segment
/// containing (or last starting before) the offset and translate within it,
/// clamped to the segment so separator bytes between runs land on its edge.
fn map_offset(map: &[SpanSegment], pos: u32) -> u32 {
    let idx = map.partition_point(|s| s.src <= pos).saturating_sub(1);
    let seg = &map[idx];
    seg.host + pos.saturating_sub(seg.src).min(seg.len)
}

/// A wrapper entrypoint launching another entrypoint's program: a shell script
/// that names a `.php` file it execs. The wrapper's effective surface unions
/// the launched program's surface through this edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchEdge {
    /// Entrypoint id of the wrapper.
    pub wrapper: String,
    /// Repository-relative source file of the launched program.
    pub launched: String,
    /// Entrypoint analyzed with this launch's cwd.
    pub launch_entrypoint: String,
    /// 1-based line in the wrapper file naming the launched program.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Typed process identity and evidence when this edge came from an
    /// analyzed invocation rather than package metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessLaunchEvidence>,
    /// This edge is one of several bounded alternatives for one invocation.
    pub alternative: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLaunchEvidence {
    pub resource: ResourceExpr,
    pub realm: ExecutionRealm,
    pub provenance: Vec<ProvenanceRef>,
}

pub(crate) struct Discovery {
    pub entrypoints: Vec<Entrypoint>,
    pub skipped: Vec<SkippedPath>,
    pub skipped_sources: Vec<SkippedPath>,
    pub skipped_dependencies: BTreeMap<String, Vec<String>>,
    pub skipped_roots: BTreeSet<String>,
    pub skips_truncated: bool,
    pub manifest: Vec<InputRecord>,
    pub launch_edges: Vec<LaunchEdge>,
}

pub(crate) fn invalidation_for_path(
    path: &str,
) -> Option<crate::index::incremental_update::InvalidationAction> {
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    (path.ends_with(".gemspec")
        || path.ends_with(".tf")
        || path.ends_with(".tf.json")
        || path.starts_with(".github/workflows/")
        || matches!(
            name,
            "Cargo.toml"
                | "Gemfile"
                | "Gemfile.lock"
                | "Justfile"
                | "Makefile"
                | "Taskfile.yaml"
                | "Taskfile.yml"
                | "build.gradle"
                | "build.gradle.kts"
                | "justfile"
                | "makefile"
                | "composer.json"
                | "go.mod"
                | "go.work"
                | "package.json"
                | "pom.xml"
                | "pyproject.toml"
                | "setup.cfg"
                | "taskfile.yaml"
                | "taskfile.yml"
                | "tsconfig.json"
        ))
    .then_some(crate::index::incremental_update::InvalidationAction::Rediscover)
}

/// Discover entrypoints under `root`, bounded by `limits`. Repository source is
/// untrusted input: only in-repo regular file symlinks are followed;
/// directory depth and file count are bounded, and the
/// crawl stops globally when `max_files` is reached with one truncation record
/// rather than a skip per remaining file.
pub(crate) fn discover(
    root: &Path,
    limits: &CrawlLimits,
    budget: &mut crate::index::IndexBudget,
    engine_limits: &effinterp_proto::Limits,
) -> Discovery {
    let composer_bins = read_composer_bins(root, limits, budget);
    let mut ctx = EntrypointCrawl {
        limits,
        budget,
        engine_limits,
        composer_bins,
        entrypoints: Vec::new(),
        skipped: Vec::new(),
        skipped_sources: Vec::new(),
        skipped_dependencies: BTreeMap::new(),
        skipped_roots: BTreeSet::new(),
        manifest: Vec::new(),
        files_seen: 0,
        total_source_bytes: 0,
        truncated: false,
        skips_truncated: false,
    };
    walk(&mut ctx, root, root, 0);
    // File-based IDs can spell a declaration ID. Keep the file root and report
    // the ambiguous declaration rather than silently dropping it or aliasing it.
    let file_ids: BTreeSet<_> = ctx
        .entrypoints
        .iter()
        .filter(|entry| entry.registration.is_none())
        .map(|entry| entry.id.clone())
        .collect();
    let mut collisions = Vec::new();
    ctx.entrypoints.retain(|entry| {
        if entry.registration.is_some() && file_ids.contains(&entry.id) {
            collisions.push(entry.source_file.clone());
            false
        } else {
            true
        }
    });
    for file in collisions {
        ctx.skip_source(file, SkipCategory::Failure, "registration_id_collision");
    }
    let admitted: BTreeSet<&str> = ctx
        .manifest
        .iter()
        .map(|input| input.path.as_str())
        .collect();
    for entry in &mut ctx.entrypoints {
        if entry.evidence.kind == EntrypointKind::Route {
            entry.package_inits = Path::new(&entry.source_file)
                .ancestors()
                .skip(1)
                .take_while(|parent| !parent.as_os_str().is_empty())
                .map(|parent| parent.join("__init__.py").to_string_lossy().into_owned())
                .filter(|path| path != &entry.source_file && admitted.contains(path.as_str()))
                .collect();
            entry.package_inits.reverse();
        }
    }
    // Typed process identities from shell and package-script plans identify
    // literal local source launches. Register those source files as programs
    // and retain the launch evidence for surface composition.
    let mut launch_edges = launch_local_sources(&mut ctx, root);
    // package.json `bin` programs whose declared target (or whose wrapper's
    // import) is built output absent from the source repo are mapped back to
    // their source files and registered as entrypoints.
    launch_edges.extend(package_bin_entrypoints(&mut ctx, root));
    sort_launch_edges(&mut launch_edges);
    launch_edges.dedup();
    // Console scripts declared in Python packaging metadata root at their
    // module file with the named function as the execution root.
    python_entry_point_scripts(&mut ctx, root);
    ctx.entrypoints.sort_by(|a, b| a.id.cmp(&b.id));
    ctx.skipped
        .sort_by(|a, b| (&a.path, &a.reason).cmp(&(&b.path, &b.reason)));
    ctx.manifest.sort_by(|a, b| a.path.cmp(&b.path));
    ctx.manifest.dedup_by(|a, b| a.path == b.path);
    for entrypoints in ctx.skipped_dependencies.values_mut() {
        entrypoints.sort();
        entrypoints.dedup();
    }
    Discovery {
        entrypoints: ctx.entrypoints,
        skipped: ctx.skipped,
        skipped_sources: ctx.skipped_sources,
        skipped_dependencies: ctx.skipped_dependencies,
        skipped_roots: ctx.skipped_roots,
        skips_truncated: ctx.skips_truncated,
        manifest: ctx.manifest,
        launch_edges,
    }
}

/// State of one entrypoint crawl: the budgets it charges and the entrypoints,
/// skipped paths and input manifest it has collected so far.
struct EntrypointCrawl<'a> {
    limits: &'a CrawlLimits,
    budget: &'a mut crate::index::IndexBudget,
    engine_limits: &'a effinterp_proto::Limits,
    /// Repo-relative paths declared as `bin` in the root `composer.json`; the
    /// only PHP files that count as entrypoints without a shebang or `bin/` dir.
    composer_bins: Vec<String>,
    entrypoints: Vec<Entrypoint>,
    skipped: Vec<SkippedPath>,
    skipped_sources: Vec<SkippedPath>,
    skipped_dependencies: BTreeMap<String, Vec<String>>,
    skipped_roots: BTreeSet<String>,
    manifest: Vec<InputRecord>,
    files_seen: u64,
    total_source_bytes: u64,
    truncated: bool,
    skips_truncated: bool,
}

impl EntrypointCrawl<'_> {
    /// Record a skip and remember when relevant evidence exceeds the cap.
    fn skip(&mut self, path: String, category: SkipCategory, reason: impl Into<String>) {
        if self.skipped.len() >= self.limits.max_skips {
            if category != SkipCategory::Ignored {
                self.skips_truncated = true;
            }
            return;
        }
        self.skipped.push(SkippedPath {
            path,
            category,
            reason: reason.into(),
        });
    }

    fn skip_source(&mut self, path: String, category: SkipCategory, reason: impl Into<String>) {
        if self.skipped.len() >= self.limits.max_skips {
            self.skips_truncated = true;
            return;
        }
        let skip = SkippedPath {
            path,
            category,
            reason: reason.into(),
        };
        self.skipped.push(skip.clone());
        self.skipped_sources.push(skip);
    }

    fn skipped_source_path(&self, from_dir: &str, spec: &str) -> Option<String> {
        let path = join_rel_path(from_dir, spec)?;
        self.skipped_sources
            .iter()
            .any(|skip| skip.path == path)
            .then_some(path)
    }

    fn depend_on_skipped_source(&mut self, path: String, entrypoint: &str) {
        self.skipped_dependencies
            .entry(path)
            .or_default()
            .push(entrypoint.to_string());
    }

    fn mark_skipped_root(&mut self, path: &str) {
        if self.skipped_sources.iter().any(|skip| skip.path == path) {
            self.skipped_roots.insert(path.to_string());
        }
    }
}

fn invalid_path_marker(root: &Path, path: &Path) -> String {
    let encoded = path
        .strip_prefix(root)
        .unwrap_or(path)
        .as_os_str()
        .as_encoded_bytes();
    format!(
        ".effinterp-invalid-path/{}",
        content_digest(encoded).trim_start_matches("blake3:")
    )
}

fn walk(ctx: &mut EntrypointCrawl, root: &Path, dir: &Path, depth: u32) {
    if ctx.truncated {
        return;
    }
    if depth > ctx.limits.max_depth {
        ctx.skip(
            walked_repo_path(root, dir),
            SkipCategory::Limit,
            "max_depth reached",
        );
        return;
    }
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(Result::ok).collect(),
        Err(e) => {
            let path = walked_repo_path(root, dir);
            ctx.skip(
                if path.is_empty() {
                    ".effinterp-root".to_string()
                } else {
                    path
                },
                SkipCategory::Failure,
                format!("unreadable directory: {e}"),
            );
            return;
        }
    };
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        if ctx.truncated {
            return;
        }
        let path = entry.path();
        let Some(relpath) = crate::canonical_repo_path(root, &path) else {
            ctx.skip(
                invalid_path_marker(root, &path),
                SkipCategory::Failure,
                "repository path is not valid UTF-8 or contains a literal backslash",
            );
            continue;
        };
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                ctx.skip(
                    relpath,
                    SkipCategory::Failure,
                    format!("unreadable entry: {e}"),
                );
                continue;
            }
        };
        // Only regular file targets inside the canonical repository are safe to visit.
        if file_type.is_symlink() {
            if let (Ok(canonical_root), Ok(target)) =
                (std::fs::canonicalize(root), std::fs::canonicalize(&path))
                && target.is_file()
                && target.starts_with(&canonical_root)
                && let Some(source_file) = crate::canonical_repo_path(&canonical_root, &target)
            {
                visit_file(ctx, &canonical_root, &target, relpath, source_file);
                continue;
            }
            ctx.skip(relpath, SkipCategory::Ignored, "symlink not followed");
            continue;
        }
        if file_type.is_dir() {
            let name = entry
                .file_name()
                .into_string()
                .expect("canonical path component");
            if CRAWL_SKIP_DIRS.contains(&name.as_str()) {
                ctx.skip(
                    relpath,
                    SkipCategory::Ignored,
                    "vendored or build directory",
                );
                continue;
            }
            walk(ctx, root, &path, depth + 1);
        } else if file_type.is_file() {
            visit_file(ctx, root, &path, relpath.clone(), relpath);
        }
    }
}

fn visit_file(
    ctx: &mut EntrypointCrawl,
    root: &Path,
    path: &Path,
    relpath: String,
    source_file: String,
) {
    if ctx.files_seen >= ctx.limits.max_files {
        // Stop the whole crawl with a single truncation record.
        ctx.truncated = true;
        ctx.skip(
            relpath,
            SkipCategory::Limit,
            "crawl truncated: max_files reached",
        );
        return;
    }
    ctx.files_seen += 1;
    if let Err(limit) = ctx.budget.charge(1, 0) {
        ctx.skip_source(relpath, SkipCategory::Limit, limit);
        return;
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_default();

    // Only files that can define entrypoints or launched source are read;
    // unrelated files are ignored without adding skip noise.
    let ext = path.extension().and_then(|e| e.to_str());
    let is_ci_workflow =
        relpath.starts_with(".github/workflows/") && matches!(ext, Some("yml" | "yaml"));
    let is_infrastructure_input = matches!(ext, Some("tf" | "tfvars" | "json" | "yaml" | "yml"));
    let is_resolver_input = ext == Some("gemspec")
        || is_infrastructure_input
        || matches!(
            name.as_str(),
            "Cargo.toml"
                | "Gemfile"
                | "Gemfile.lock"
                | "Justfile"
                | "Taskfile.yaml"
                | "Taskfile.yml"
                | "build.gradle"
                | "build.gradle.kts"
                | "composer.json"
                | "go.mod"
                | "go.work"
                | "justfile"
                | "package.json"
                | "pom.xml"
                | "pyproject.toml"
                | "setup.cfg"
                | "taskfile.yaml"
                | "taskfile.yml"
                | "tsconfig.json"
        );
    let is_entrypoint_candidate = is_ci_workflow
        || name == "package.json"
        || name == "composer.json"
        || name == "Makefile"
        || name == "makefile"
        || ext == Some("sh")
        || matches!(ext, Some("rs" | "go" | "java" | "php" | "rb"))
        || could_have_shebang(&name, path);
    let is_source_candidate = source_language(&source_file).is_some();
    if !is_resolver_input && !is_entrypoint_candidate && !is_source_candidate {
        return;
    }

    let meta = std::fs::metadata(path);
    if let Ok(m) = &meta
        && m.len() > ctx.limits.max_file_bytes
    {
        let reason = format!("file exceeds max_file_bytes ({} bytes)", m.len());
        if is_source_candidate {
            ctx.skip_source(relpath, SkipCategory::Limit, reason);
        } else {
            ctx.skip(relpath, SkipCategory::Limit, reason);
        }
        return;
    }
    if (is_source_candidate || is_infrastructure_input)
        && let Ok(m) = &meta
        && ctx.total_source_bytes.saturating_add(m.len()) > ctx.limits.max_total_source_bytes
    {
        ctx.skip_source(relpath, SkipCategory::Limit, "crawl.max_total_source_bytes");
        return;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            let reason = format!("unreadable or non-utf8: {e}");
            if is_source_candidate {
                ctx.skip_source(relpath, SkipCategory::Failure, reason);
            } else {
                ctx.skip(relpath, SkipCategory::Failure, reason);
            }
            return;
        }
    };
    if let Err(limit) = ctx.budget.charge(0, content.len() as u64) {
        ctx.skip_source(relpath, SkipCategory::Limit, limit);
        return;
    }
    if is_source_candidate || is_infrastructure_input {
        ctx.total_source_bytes = ctx.total_source_bytes.saturating_add(content.len() as u64);
    }
    ctx.manifest.push(InputRecord {
        path: source_file.clone(),
        digest: content_digest(content.as_bytes()),
    });

    if is_resolver_input && !is_entrypoint_candidate {
        return;
    }

    // Non-root files stay in the manifest so imports and explicit launches
    // can still reach them.
    if is_non_root_path(&relpath, &name) {
        return;
    }
    if !is_entrypoint_candidate {
        return;
    }

    let dir = path
        .parent()
        .map(|p| walked_repo_path(root, p))
        .unwrap_or_default();
    let cwd = (!dir.is_empty()).then_some(dir.clone());

    if let Some(lang) = match ext {
        Some("py") => Some(effinterp_engine::Lang::Python),
        Some("go") => Some(effinterp_engine::Lang::Go),
        _ => None,
    } {
        language::registration_entrypoints(ctx, &source_file, &content, &dir, lang);
    }
    let before = ctx.entrypoints.len();
    let mut classification_failure = None;
    if is_ci_workflow {
        github_workflow_steps(ctx, &relpath, &content);
    } else if name == "package.json" {
        package_scripts(ctx, &relpath, &content, cwd.as_deref());
    } else if name.eq_ignore_ascii_case("makefile") {
        makefile_targets(ctx, &relpath, &content, cwd.as_deref());
    } else if ext == Some("sh") {
        push_shell_file(
            ctx,
            &relpath,
            content.clone(),
            dir.clone(),
            EntrypointKind::ShellFile,
        );
    } else if ext == Some("php") {
        // PHP has no `main`; a class file is not a program. Only a shebang
        // script, a `bin/` file, or a declared composer bin is an entrypoint.
        // Its own directory is preserved separately so the include graph can
        // resolve relative and `__DIR__`-based requires.
        php_entrypoint(ctx, &relpath, &content, dir.clone());
    } else {
        // Program-entry detection runs against code only: string literals and
        // comments are masked out first so `fn main` inside a fixture string or
        // an f-string mentioning `__name__` cannot be mistaken for a program.
        let masked = mask_noncode(&content, ext);
        if let Some(language) = main_language(ext, &masked) {
            // A compiled-language file with a program entry is analyzed from it.
            ctx.entrypoints.push(Entrypoint {
                id: relpath.clone(),
                subject: Subject::Source {
                    dialect: None,
                    language: language.to_string(),
                    source: content.clone(),
                    cwd: None,
                    context: Default::default(),
                },
                source_file: relpath.clone(),
                source_cwd: Some(dir.clone()),
                evidence: EntrypointEvidence {
                    kind: EntrypointKind::MainFile,
                    file: relpath.clone(),
                    line: None,
                },
                entry_function: None,
                registration: None,
                package_inits: Vec::new(),
                span_map: None,
            });
        } else if let Some(subject) = script_subject(ext, &content, &masked, ctx.engine_limits)
            .unwrap_or_else(|reason| {
                classification_failure = Some(reason);
                None
            })
        {
            // A non-shebang Python/JS script (a __main__ guard, or a JS file that
            // runs at module scope rather than only exporting).
            ctx.entrypoints.push(Entrypoint {
                id: relpath.clone(),
                subject,
                source_file: relpath.clone(),
                source_cwd: Some(dir.clone()),
                evidence: EntrypointEvidence {
                    kind: EntrypointKind::MainFile,
                    file: relpath.clone(),
                    line: None,
                },
                entry_function: None,
                registration: None,
                package_inits: Vec::new(),
                span_map: None,
            });
        }
    }
    // A shebang classifies any remaining candidate (including .sh with an
    // unusual interpreter) only if nothing else claimed it.
    if ctx.entrypoints.len() == before {
        shebang_file(ctx, &relpath, &content, dir);
    }
    if ctx.entrypoints.len() == before
        && let Some(reason) = classification_failure
    {
        ctx.skip_source(relpath, SkipCategory::Failure, reason);
    }
    for entry in &mut ctx.entrypoints[before..] {
        entry.source_file = source_file.clone();
    }
}

/// Paths excluded from implicit execution roots, while remaining analyzable.
/// Match whole segments so names such as `src/latest` remain eligible.
fn is_non_root_path(relpath: &str, name: &str) -> bool {
    const SEGMENTS: [&str; 12] = [
        "test",
        "tests",
        "__tests__",
        "testdata",
        "fixtures",
        "spec",
        "_vendor",
        "third_party",
        "examples",
        "docs",
        "demo",
        "demos",
    ];
    if relpath.split('/').any(|seg| SEGMENTS.contains(&seg)) {
        return true;
    }
    (name.ends_with(".py") && (name.starts_with("test_") || name.ends_with("_test.py")))
        || name.ends_with("_test.go")
        || name.contains(".test.")
        || name.ends_with(".min.js")
        || name.ends_with(".bundle.js")
        || name.contains(".spec.")
}

pub(crate) fn subject_cwd(subject: &Subject) -> Option<&str> {
    match subject {
        Subject::Exec { cwd, .. }
        | Subject::Shell { cwd, .. }
        | Subject::Source { cwd, .. }
        | Subject::ToolCall { cwd, .. } => cwd.as_deref(),
        Subject::Sql { .. } => None,
    }
}

/// Normalize a `./x`/`../x` specifier against a base directory into a
/// repo-relative path.
fn join_rel_path(base_dir: &str, spec: &str) -> Option<String> {
    if spec.starts_with('/') {
        return None;
    }
    let mut parts = Vec::new();
    for seg in base_dir.split('/').chain(spec.split('/')) {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}
