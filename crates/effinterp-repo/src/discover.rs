//! Entrypoint discovery. Walks a repository (bounded, skipping vendored and
//! build directories) and recognizes entrypoints with retained evidence: a
//! package.json script, a shell/shebang file, a Makefile target, or a
//! compiled-language source file with a program entry (`fn main`/`func main`).
//! Discovery
//! evidence is kept because an entrypoint inferred from a file convention is
//! not the same claim as an explicit process target.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use effinterp_engine::{Engine, GITHUB_ACTIONS_DRIVER, rust_is_entry_macro_line};
use effinterp_proto::{
    ExecutionRealm, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity, SourceDialect,
    Subject,
};
use serde::{Deserialize, Serialize};

use crate::index::{CrawlLimits, Skip, SkipCategory};
use crate::snapshot::InputRecord;
use effinterp_proto::content_digest;

mod language;
mod package;
mod shebang;
mod workflow;

use language::{main_language, php_entrypoint, read_composer_bins, script_subject};
use package::{
    makefile_targets, package_bin_entrypoints, package_scripts, python_entry_point_scripts,
    python_module_program,
};
use shebang::{could_have_shebang, interpreter, push_shell_file, shebang_file};
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
    pub span_map: Option<Vec<SpanSeg>>,
}

/// One `span_map` segment: a run of an embedded script mapped into its host
/// file. Subject-source bytes `[src, src+len)` came from evidence-file bytes
/// starting at `host` (verbatim runs are 1:1; a JSON escape maps its decoded
/// bytes to the escape's start).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanSeg {
    pub src: u32,
    pub host: u32,
    pub len: u32,
}

/// Rewrite the plan's top-level source spans through `map` so they index the
/// evidence file instead of the embedded subject source. Spans reached through
/// a nested invocation are relative to the nested subject's own source and are
/// left alone; antecedents always reference earlier nodes, so one forward pass
/// finds them.
pub(crate) fn remap_spans(plan: &mut effinterp_proto::Plan, map: &[SpanSeg]) {
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
fn map_offset(map: &[SpanSeg], pos: u32) -> u32 {
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
    pub skipped: Vec<Skip>,
    pub skipped_sources: Vec<Skip>,
    pub skipped_dependencies: BTreeMap<String, Vec<String>>,
    pub skipped_roots: BTreeSet<String>,
    pub skips_truncated: bool,
    pub manifest: Vec<InputRecord>,
    pub launch_edges: Vec<LaunchEdge>,
}

const SKIP_DIRS: [&str; 5] = ["node_modules", ".git", "target", "vendor", ".claude"];

pub(crate) fn invalidation_for_path(path: &str) -> Option<crate::index::InvalidationAction> {
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
    .then_some(crate::index::InvalidationAction::Rediscover)
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
    let mut ctx = Ctx {
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

struct Ctx<'a> {
    limits: &'a CrawlLimits,
    budget: &'a mut crate::index::IndexBudget,
    engine_limits: &'a effinterp_proto::Limits,
    /// Repo-relative paths declared as `bin` in the root `composer.json`; the
    /// only PHP files that count as entrypoints without a shebang or `bin/` dir.
    composer_bins: Vec<String>,
    entrypoints: Vec<Entrypoint>,
    skipped: Vec<Skip>,
    skipped_sources: Vec<Skip>,
    skipped_dependencies: BTreeMap<String, Vec<String>>,
    skipped_roots: BTreeSet<String>,
    manifest: Vec<InputRecord>,
    files_seen: u64,
    total_source_bytes: u64,
    truncated: bool,
    skips_truncated: bool,
}

impl Ctx<'_> {
    /// Record a skip and remember when relevant evidence exceeds the cap.
    fn skip(&mut self, path: String, category: SkipCategory, reason: impl Into<String>) {
        if self.skipped.len() >= self.limits.max_skips {
            if category != SkipCategory::Ignored {
                self.skips_truncated = true;
            }
            return;
        }
        self.skipped.push(Skip {
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
        let skip = Skip {
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

fn rel(root: &Path, path: &Path) -> String {
    crate::canonical_repo_path(root, path).expect("walked repository path is canonical")
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

fn walk(ctx: &mut Ctx, root: &Path, dir: &Path, depth: u32) {
    if ctx.truncated {
        return;
    }
    if depth > ctx.limits.max_depth {
        ctx.skip(rel(root, dir), SkipCategory::Limit, "max_depth reached");
        return;
    }
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(Result::ok).collect(),
        Err(e) => {
            let path = rel(root, dir);
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
            if SKIP_DIRS.contains(&name.as_str()) {
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

fn visit_file(ctx: &mut Ctx, root: &Path, path: &Path, relpath: String, source_file: String) {
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

    let dir = path.parent().map(|p| rel(root, p)).unwrap_or_default();
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

/// Register repository source files named by typed process effects in shell
/// and package-script entrypoints. The engine bounds argv alternatives before
/// this adapter sees them, so symbolic and over-wide commands stay unresolved.
fn launch_local_sources(ctx: &mut Ctx, root: &Path) -> Vec<LaunchEdge> {
    let wrappers: Vec<Entrypoint> = ctx
        .entrypoints
        .iter()
        .filter(|entry| matches!(entry.subject, Subject::Shell { .. }))
        .cloned()
        .collect();
    let engine = Engine::new();
    let mut edges = Vec::new();
    for wrapper in wrappers {
        let Ok(plan) = engine.analyze_with_cwds(
            &wrapper.subject,
            wrapper.source_cwd.as_deref(),
            subject_cwd(&wrapper.subject),
        ) else {
            continue;
        };
        let source = match &wrapper.subject {
            Subject::Shell { source, .. } => source.as_str(),
            _ => unreachable!(),
        };
        for effect in &plan.effects {
            let ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::Process {
                        executable,
                        path,
                        argv,
                        cwd,
                    },
            } = &effect.resource
            else {
                continue;
            };
            if !effect.realm.is_host() {
                continue;
            }
            let invocation_executable = invocation_executable(&plan, &effect.provenance);
            let cwd = repository_cwd(cwd.as_deref());
            let mut specs = Vec::new();
            for launched in
                launched_sources(executable, path.as_deref(), argv, invocation_executable)
            {
                match launched {
                    LaunchedSource::Resolved(spec) => {
                        specs.push((spec.to_string(), true, false, false, true, true, Vec::new()));
                    }
                    LaunchedSource::Literal(spec) => {
                        let direct = !engine_nests_source(executable);
                        specs.push((
                            spec.to_string(),
                            false,
                            false,
                            false,
                            direct,
                            direct,
                            Vec::new(),
                        ));
                    }
                    LaunchedSource::Dynamic { argument } => {
                        let recovered = static_source_specs(
                            &plan,
                            &effect.provenance,
                            source,
                            executable,
                            argument + 1,
                        );
                        let alternative = recovered.len() > 1;
                        specs.extend(recovered.into_iter().map(|spec| {
                            (
                                spec.path,
                                false,
                                alternative,
                                spec.wrapper_relative,
                                true,
                                false,
                                Vec::new(),
                            )
                        }));
                    }
                    LaunchedSource::PythonModule(module) => {
                        let Some(from_dir) = cwd.as_deref() else {
                            continue;
                        };
                        let Some((file, package_inits)) =
                            python_module_program(ctx, root, from_dir, module)
                        else {
                            continue;
                        };
                        specs.push((file, true, false, false, true, false, package_inits));
                    }
                }
            }
            let wrapper_dir = wrapper
                .evidence
                .file
                .rsplit_once('/')
                .map_or("", |(dir, _)| dir);
            for (
                spec,
                resolved,
                alternative,
                wrapper_relative,
                contextual,
                require_shebang,
                package_inits,
            ) in specs
            {
                let from_dir = if resolved {
                    Some("")
                } else if wrapper_relative {
                    Some(wrapper_dir)
                } else {
                    cwd.as_deref()
                };
                let Some(from_dir) = from_dir else {
                    continue;
                };
                let relpath = match resolve_repo_source(ctx, root, from_dir, &spec, require_shebang)
                {
                    Some(relpath) => relpath,
                    None => {
                        if let Some(path) = ctx.skipped_source_path(from_dir, &spec) {
                            ctx.depend_on_skipped_source(path, &wrapper.id);
                        }
                        continue;
                    }
                };
                let Some(launch_entrypoint) = add_local_source_program(
                    ctx,
                    root,
                    &relpath,
                    cwd.clone(),
                    contextual,
                    package_inits,
                ) else {
                    continue;
                };
                edges.push(LaunchEdge {
                    wrapper: wrapper.id.clone(),
                    launched: relpath,
                    launch_entrypoint,
                    line: source_line(&plan, &effect.provenance, source),
                    process: Some(ProcessLaunchEvidence {
                        resource: effect.resource.clone(),
                        realm: effect.realm.clone(),
                        provenance: effect.provenance.clone(),
                    }),
                    alternative,
                });
            }
        }
    }
    sort_launch_edges(&mut edges);
    edges.dedup();
    edges
}

fn sort_launch_edges(edges: &mut [LaunchEdge]) {
    edges.sort_by_cached_key(|edge| {
        (
            edge.wrapper.clone(),
            edge.launched.clone(),
            edge.launch_entrypoint.clone(),
            edge.line,
            format!("{:?}", edge.process),
        )
    });
}

enum LaunchedSource<'a> {
    Resolved(&'a str),
    Literal(&'a str),
    Dynamic { argument: usize },
    PythonModule(&'a str),
}

fn launched_sources<'a>(
    executable: &str,
    path: Option<&'a str>,
    argv: &'a [ResourceExpr],
    invocation_executable: Option<&'a str>,
) -> Vec<LaunchedSource<'a>> {
    if let Some(path) = path {
        return vec![LaunchedSource::Resolved(path)];
    }
    if let Some(spec) = invocation_executable
        && spec.contains('/')
    {
        return vec![LaunchedSource::Literal(spec)];
    }
    if matches!(executable, "python" | "python2" | "python3")
        && let Some(module) = python_module_operand(argv)
    {
        return vec![LaunchedSource::PythonModule(module)];
    }
    let (operand, expected) = match executable {
        "python" | "python2" | "python3" => (
            program_operand(
                argv,
                &["-W", "-X", "--check-hash-based-pycs"],
                &["-c", "-m", "-"],
            ),
            &["py"][..],
        ),
        "node" | "nodejs" | "iojs" => (
            program_operand(
                argv,
                &[
                    "--require",
                    "-r",
                    "--import",
                    "--loader",
                    "--experimental-loader",
                    "--conditions",
                    "-C",
                ],
                &["-e", "--eval", "-p", "--print", "-"],
            ),
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..],
        ),
        "tsx" | "ts-node" | "bun" => (
            program_operand(argv, &[], &[]),
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..],
        ),
        "deno" if argv.first().and_then(literal) == Some("run") => (
            program_operand(
                &argv[1..],
                &[
                    "--cert",
                    "--config",
                    "-c",
                    "--env-file",
                    "--ext",
                    "--import-map",
                    "--location",
                    "--lock",
                    "--seed",
                    "--v8-flags",
                ],
                &[],
            )
            .map(|(index, value)| (index + 1, value)),
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..],
        ),
        "php" | "php7" | "php8" => {
            if argv.first().and_then(literal) == Some("-f") {
                (argv.get(1).map(|value| (1, literal(value))), &["php"][..])
            } else {
                (
                    program_operand(
                        argv,
                        &["-c", "-d", "-F", "-B", "-R", "-E", "-S", "-t", "-z"],
                        &["-r", "--run", "-"],
                    ),
                    &["php"][..],
                )
            }
        }
        "ruby" | "irb" => (
            program_operand(
                argv,
                &["-I", "-r", "-E", "--encoding"],
                &["-e", "--eval", "-C", "--directory", "-"],
            ),
            &["rb"][..],
        ),
        "go" if argv.first().and_then(literal) == Some("run") => {
            let Some((argument, value)) = program_operand(
                &argv[1..],
                &[
                    "-asmflags",
                    "-buildmode",
                    "-compiler",
                    "-covermode",
                    "-coverpkg",
                    "-exec",
                    "-gccgoflags",
                    "-gcflags",
                    "-installsuffix",
                    "-ldflags",
                    "-mod",
                    "-modfile",
                    "-overlay",
                    "-p",
                    "-pgo",
                    "-pkgdir",
                    "-tags",
                    "-toolexec",
                ],
                &["-C"],
            )
            .map(|(index, value)| (index + 1, value)) else {
                return Vec::new();
            };
            return match value {
                Some(value) if value.ends_with(".go") => argv[argument..]
                    .iter()
                    .map_while(literal)
                    .take_while(|value| value.ends_with(".go"))
                    .map(LaunchedSource::Literal)
                    .collect(),
                Some(_) => Vec::new(),
                None => vec![LaunchedSource::Dynamic { argument }],
            };
        }
        "java" => (
            program_operand(
                argv,
                &[
                    "--class-path",
                    "-classpath",
                    "-cp",
                    "--module-path",
                    "-p",
                    "--source",
                ],
                &[],
            ),
            &["java"][..],
        ),
        "rust-script" => (program_operand(argv, &[], &[]), &["rs"][..]),
        _ => return Vec::new(),
    };
    let Some((argument, value)) = operand else {
        return Vec::new();
    };
    match value {
        Some(value) => {
            let Some((_, ext)) = value.rsplit_once('.') else {
                return Vec::new();
            };
            if expected.contains(&ext) {
                vec![LaunchedSource::Literal(value)]
            } else {
                Vec::new()
            }
        }
        None => vec![LaunchedSource::Dynamic { argument }],
    }
}

fn python_module_operand(argv: &[ResourceExpr]) -> Option<&str> {
    let mut index = 0;
    while index < argv.len() {
        let argument = literal(&argv[index])?;
        if argument == "-m" {
            return argv.get(index + 1).and_then(literal);
        }
        if let Some(module) = argument
            .strip_prefix("-m")
            .filter(|module| !module.is_empty())
        {
            return Some(module);
        }
        if matches!(argument, "-W" | "-X" | "--check-hash-based-pycs") {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return None;
        }
    }
    None
}

fn engine_nests_source(executable: &str) -> bool {
    matches!(
        executable,
        "python"
            | "python2"
            | "python3"
            | "node"
            | "nodejs"
            | "iojs"
            | "tsx"
            | "ts-node"
            | "bun"
            | "deno"
            | "php"
            | "php7"
            | "php8"
            | "ruby"
            | "irb"
            | "go"
            | "java"
            | "rust-script"
    )
}

fn program_operand<'a>(
    argv: &'a [ResourceExpr],
    value_flags: &[&str],
    blocked: &[&str],
) -> Option<(usize, Option<&'a str>)> {
    let mut index = 0;
    while index < argv.len() {
        // Shell wrappers commonly splice an unset `*_ARGS` environment word
        // before the program. It contributes no source candidate of its own;
        // the next operand still has to carry bounded program evidence.
        if matches!(&argv[index], ResourceExpr::Environment { name } if name.ends_with("_ARGS")) {
            index += 1;
            continue;
        }
        match literal(&argv[index]) {
            Some("--") => return argv.get(index + 1).map(|value| (index + 1, literal(value))),
            Some(value) if blocked.contains(&value) => return None,
            Some(value) if blocked.iter().any(|flag| has_attached_value(value, flag)) => {
                return None;
            }
            Some(flag) if value_flags.contains(&flag) => index += 2,
            Some(flag) if flag.starts_with('-') => index += 1,
            Some(value) => return Some((index, Some(value))),
            None => return Some((index, None)),
        }
    }
    None
}

fn has_attached_value(argument: &str, flag: &str) -> bool {
    if flag == "-" {
        return false;
    }
    argument
        .strip_prefix(flag)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !flag.starts_with("--") || value.starts_with('='))
}

fn literal(expr: &ResourceExpr) -> Option<&str> {
    match expr {
        ResourceExpr::Literal { value } => Some(value),
        _ => None,
    }
}

fn invocation_executable<'a>(
    plan: &'a effinterp_proto::Plan,
    roots: &[ProvenanceRef],
) -> Option<&'a str> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let node = plan.provenance.get(reference.0 as usize)?;
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(execution) = plan.execution_graph.nodes.get(execution as usize)
            && let Subject::Exec { argv, .. } = &execution.subject
        {
            return argv.first().map(String::as_str);
        }
        pending.extend(node.antecedents.iter().copied());
    }
    None
}

/// Literal source paths retained in shell assignments before a bounded value
/// becomes symbolic (for example a path built from `dirname "$0"`). More than
/// four candidates is intentionally not a bounded alternative.
fn static_source_specs(
    plan: &effinterp_proto::Plan,
    roots: &[ProvenanceRef],
    source: &str,
    executable: &str,
    argument: usize,
) -> Vec<StaticSourceSpec> {
    let expected = match executable {
        "python" | "python2" | "python3" => &["py"][..],
        "node" | "nodejs" | "iojs" | "tsx" | "ts-node" | "bun" | "deno" => {
            &["js", "mjs", "cjs", "ts", "mts", "cts", "tsx", "jsx"][..]
        }
        "php" | "php7" | "php8" => &["php"][..],
        "ruby" | "irb" => &["rb"][..],
        "go" => &["go"][..],
        "java" => &["java"][..],
        "rust-script" => &["rs"][..],
        _ => return Vec::new(),
    };
    let roots = program_assignment_roots(plan, roots, source, argument);
    if roots.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let spans = source_spans(plan, &roots, source.len());
    let wrapper_relative = source_spans_reference_wrapper(source, &spans);
    for extension in expected {
        let suffix = format!(".{extension}");
        for (span_start, span_end) in &spans {
            let Some(span) = source.get(*span_start..*span_end) else {
                continue;
            };
            let mut offset = 0;
            while let Some(found) = span[offset..].find(&suffix) {
                let end = offset + found + suffix.len();
                if inside_shell_substitution(span, offset + found) {
                    offset = end;
                    continue;
                }
                let mut start = end - suffix.len();
                while start > 0 {
                    let byte = span.as_bytes()[start - 1];
                    if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
                        start -= 1;
                    } else {
                        break;
                    }
                }
                if start < end - suffix.len() {
                    let raw = &span[start..end];
                    if source_token_is_substitution_suffix(span, start) {
                        offset = end;
                        continue;
                    }
                    let candidate = raw
                        .strip_prefix('/')
                        .filter(|rest| rest.starts_with("../"))
                        .unwrap_or(raw)
                        .to_string();
                    let candidate = StaticSourceSpec {
                        path: candidate,
                        wrapper_relative,
                    };
                    if !out.contains(&candidate) {
                        out.push(candidate);
                    }
                }
                if out.len() > 4 {
                    return Vec::new();
                }
                offset = end;
            }
        }
    }
    out.sort_by(|left, right| left.path.cmp(&right.path));
    out.dedup();
    out
}

#[derive(Clone, PartialEq, Eq)]
struct StaticSourceSpec {
    path: String,
    wrapper_relative: bool,
}

fn source_spans_reference_wrapper(source: &str, spans: &[(usize, usize)]) -> bool {
    for (start, end) in spans {
        let Some(span) = source.get(*start..*end) else {
            continue;
        };
        if !span.contains("dirname") {
            continue;
        }
        if span.contains("$0") || span.contains("${0}") {
            return true;
        }
        if shell_variables(span)
            .into_iter()
            .any(|name| shell_assignment_references_script(source, name))
        {
            return true;
        }
    }
    false
}

fn shell_variables(source: &str) -> Vec<&str> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(found) = source[index..].find('$') {
        let start = index + found + 1;
        let braced = bytes.get(start) == Some(&b'{');
        let name_start = start + usize::from(braced);
        let mut end = name_start;
        while bytes
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            end += 1;
        }
        if end > name_start && (!braced || bytes.get(end) == Some(&b'}')) {
            out.push(&source[name_start..end]);
        }
        index = end.max(start);
    }
    out
}

fn shell_assignment_references_script(source: &str, name: &str) -> bool {
    source.lines().any(|line| {
        line.trim_start()
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .is_some_and(|value| value.contains("$0") || value.contains("${0}"))
    })
}

fn source_token_is_substitution_suffix(source: &str, position: usize) -> bool {
    position > 0
        && matches!(source.as_bytes()[position - 1], b')' | b'`')
        && !source[position..].starts_with('/')
}

fn inside_shell_substitution(source: &str, position: usize) -> bool {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut depth = 0;
    let mut backtick = false;
    while index < position.min(bytes.len()) {
        if bytes[index] == b'`' && (index == 0 || bytes[index - 1] != b'\\') {
            backtick = !backtick;
        } else if !backtick && bytes[index..].starts_with(b"$(") {
            depth += 1;
            index += 1;
        } else if !backtick && depth > 0 && bytes[index] == b')' {
            depth -= 1;
        }
        index += 1;
    }
    backtick || depth > 0
}

fn program_assignment_roots(
    plan: &effinterp_proto::Plan,
    roots: &[ProvenanceRef],
    source: &str,
    argument: usize,
) -> Vec<ProvenanceRef> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(execution) = plan.execution_graph.nodes.get(execution as usize)
            && let Subject::Exec { argv, .. } = &execution.subject
            && let Some(name) = argv.get(argument).and_then(|raw| shell_parameter(raw))
        {
            return node
                .antecedents
                .iter()
                .copied()
                .filter(|reference| assignment_name(plan, *reference, source) == Some(name))
                .collect();
        }
        pending.extend(node.antecedents.iter().copied());
    }
    Vec::new()
}

fn shell_parameter(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix('"')
        .and_then(|raw| raw.strip_suffix('"'))
        .unwrap_or(raw);
    let name = raw
        .strip_prefix("${")
        .and_then(|raw| raw.strip_suffix('}'))
        .or_else(|| raw.strip_prefix('$'))?;
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()))
    .then_some(name)
}

fn assignment_name<'a>(
    plan: &effinterp_proto::Plan,
    reference: ProvenanceRef,
    source: &'a str,
) -> Option<&'a str> {
    let node = plan.provenance.get(reference.0 as usize)?;
    let ProvenanceKind::SourceSpan { start, end } = node.kind else {
        return None;
    };
    let span = source.get(start as usize..end as usize)?;
    let (name, _) = span.split_once('=')?;
    let name = name.trim();
    let name = name.strip_suffix('+').unwrap_or(name);
    (!name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()))
    .then_some(name)
}

fn source_spans(
    plan: &effinterp_proto::Plan,
    roots: &[ProvenanceRef],
    source_len: usize,
) -> Vec<(usize, usize)> {
    let mut invocation_spans = std::collections::HashSet::new();
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if let ProvenanceKind::Execution { node: execution } = node.kind
            && let Some(execution) = plan.execution_graph.nodes.get(execution as usize)
        {
            invocation_spans.extend(execution.evidence.iter().copied());
        }
        pending.extend(node.antecedents.iter().copied());
    }
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    let mut spans = Vec::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let Some(node) = plan.provenance.get(reference.0 as usize) else {
            continue;
        };
        if !invocation_spans.contains(&reference)
            && let ProvenanceKind::SourceSpan { start, end } = node.kind
        {
            spans.push((
                (start as usize).min(source_len),
                (end as usize).min(source_len),
            ));
        }
        pending.extend(node.antecedents.iter().copied());
    }
    spans.sort();
    spans.dedup();
    spans
}

fn repository_cwd(expr: Option<&ResourceExpr>) -> Option<String> {
    match expr {
        Some(ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        }) if !path.starts_with('/') => join_rel_path("", path),
        _ => None,
    }
}

fn resolve_repo_source(
    ctx: &Ctx,
    root: &Path,
    from_dir: &str,
    spec: &str,
    require_shebang: bool,
) -> Option<String> {
    if from_dir.starts_with('/') || spec.starts_with('/') {
        return None;
    }
    let joined = join_rel_path(from_dir, spec)?;
    if !ctx.manifest.iter().any(|input| input.path == joined) {
        return None;
    }
    let source = std::fs::read_to_string(root.join(&joined)).ok()?;
    if require_shebang && !source.starts_with("#!") {
        return None;
    }
    source_language_evidence(&joined, &source).map(|_| joined)
}

fn source_language(path: &str) -> Option<&'static str> {
    match path.rsplit_once('.')?.1 {
        "py" => Some("python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("js"),
        "ts" | "mts" | "cts" | "tsx" => Some("ts"),
        "php" => Some("php"),
        "rb" => Some("ruby"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "java" => Some("java"),
        "sh" => Some("shell"),
        _ => None,
    }
}

fn source_language_evidence(path: &str, source: &str) -> Option<&'static str> {
    source_language(path).or_else(|| {
        let shebang = source.lines().next()?.strip_prefix("#!")?;
        match interpreter(shebang)?.as_str() {
            "sh" | "bash" | "dash" | "zsh" => Some("shell"),
            "python" | "python2" | "python3" => Some("python"),
            "node" | "nodejs" => Some("js"),
            "tsx" | "ts-node" | "bun" | "deno" => Some("ts"),
            "php" => Some("php"),
            "ruby" => Some("ruby"),
            _ => None,
        }
    })
}

fn source_line(plan: &effinterp_proto::Plan, roots: &[ProvenanceRef], source: &str) -> Option<u32> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        let node = plan.provenance.get(reference.0 as usize)?;
        if !seen.insert(reference) {
            continue;
        }
        if let ProvenanceKind::SourceSpan { start, .. } = node.kind {
            let start = (start as usize).min(source.len());
            return Some(
                source.as_bytes()[..start]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count() as u32
                    + 1,
            );
        }
        pending.extend(node.antecedents.iter().copied());
    }
    None
}

fn add_local_source_program(
    ctx: &mut Ctx,
    root: &Path,
    relpath: &str,
    runtime_cwd: Option<String>,
    contextual: bool,
    package_inits: Vec<String>,
) -> Option<String> {
    if !contextual
        && package_inits.is_empty()
        && let Some(entrypoint) = ctx.entrypoints.iter().find(|entry| {
            entry.source_file == relpath
                && entry.registration.is_none()
                && entry.package_inits.is_empty()
        })
    {
        return Some(entrypoint.id.clone());
    }
    if let Some(entrypoint) = ctx.entrypoints.iter().find(|entry| {
        entry.source_file == relpath
            && entry.registration.is_none()
            && entry.entry_function.is_none()
            && subject_cwd(&entry.subject) == runtime_cwd.as_deref()
            && entry.package_inits == package_inits
    }) {
        return Some(entrypoint.id.clone());
    }
    let Ok(source) = std::fs::read_to_string(root.join(relpath)) else {
        return None;
    };
    let source_cwd = relpath
        .rsplit_once('/')
        .map_or_else(String::new, |(dir, _)| dir.to_string());
    let language = source_language_evidence(relpath, &source)?;
    let subject = match language {
        "shell" => Subject::Shell {
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        "python" => Subject::Source {
            dialect: None,
            language: "python".into(),
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        "js" | "ts" => Subject::Source {
            language: "js".into(),
            source,
            dialect: Some(if language == "ts" {
                SourceDialect::Ts
            } else {
                SourceDialect::Js
            }),
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        "php" => Subject::Source {
            dialect: None,
            language: language.to_string(),
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
        language => Subject::Source {
            dialect: None,
            language: language.to_string(),
            source,
            cwd: runtime_cwd.clone(),
            context: Default::default(),
        },
    };
    let context = match runtime_cwd.as_deref() {
        Some("") => "root",
        Some(cwd) => cwd,
        None => "unknown",
    };
    let id = if !package_inits.is_empty() {
        format!("{relpath}:launch@{context}:python-m")
    } else {
        format!("{relpath}:launch@{context}")
    };
    ctx.entrypoints.push(Entrypoint {
        id: id.clone(),
        subject,
        source_file: relpath.to_string(),
        source_cwd: Some(source_cwd),
        evidence: EntrypointEvidence {
            kind: EntrypointKind::MainFile,
            file: relpath.to_string(),
            line: None,
        },
        entry_function: None,
        registration: None,
        package_inits,
        span_map: None,
    });
    Some(id)
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

/// Per-language lexical shape used to mask string literals and comments.
struct Syntax {
    /// Line-comment starters (`//` or `#`).
    line: &'static [&'static str],
    /// Whether `/* ... */` block comments apply.
    block: bool,
    /// Double-quoted, backslash-escapable strings.
    dquote: bool,
    /// Single-quoted, backslash-escapable strings (JS/Python).
    squote_string: bool,
    /// Single-quoted char/rune literals, bounded (Rust/Go/Java).
    squote_char: bool,
    /// Backtick raw strings/templates (Go/JS).
    backtick: bool,
    /// Rust raw strings `r#"..."#`.
    rust_raw: bool,
    /// Python triple-quoted strings.
    triple: bool,
}

fn syntax_for(ext: Option<&str>) -> Option<Syntax> {
    Some(match ext? {
        "rs" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: false,
            squote_char: true,
            backtick: false,
            rust_raw: true,
            triple: false,
        },
        "go" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: false,
            squote_char: true,
            backtick: true,
            rust_raw: false,
            triple: false,
        },
        "java" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: false,
            squote_char: true,
            backtick: false,
            rust_raw: false,
            triple: false,
        },
        "js" | "mjs" | "cjs" => Syntax {
            line: &["//"],
            block: true,
            dquote: true,
            squote_string: true,
            squote_char: false,
            backtick: true,
            rust_raw: false,
            triple: false,
        },
        "rb" => Syntax {
            line: &["#"],
            block: false,
            dquote: true,
            squote_string: true,
            squote_char: false,
            backtick: false,
            rust_raw: false,
            triple: false,
        },
        "py" => Syntax {
            line: &["#"],
            block: false,
            dquote: true,
            squote_string: true,
            squote_char: false,
            backtick: false,
            rust_raw: false,
            triple: true,
        },
        _ => return None,
    })
}

/// Replace string-literal and comment content with spaces (newlines preserved,
/// so line/column structure survives) for the source languages we scan. A file
/// whose extension has no syntax entry is returned unchanged. This is a
/// lightweight lexer, not a parser: enough to keep code-only text for the
/// substring/line checks that detect a program entry.
fn mask_noncode(content: &str, ext: Option<&str>) -> String {
    let Some(syn) = syntax_for(ext) else {
        return content.to_string();
    };
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < chars.len() {
        if syn.line.iter().any(|lc| starts_with_str(&chars, i, lc)) {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if syn.block && starts_with_str(&chars, i, "/*") {
            out.push_str("  ");
            i += 2;
            while i < chars.len() && !starts_with_str(&chars, i, "*/") {
                out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            if i < chars.len() {
                out.push_str("  ");
                i += 2;
            }
            continue;
        }
        if syn.rust_raw
            && chars[i] == 'r'
            && let Some(next) = mask_rust_raw(&chars, i, &mut out)
        {
            i = next;
            continue;
        }
        if syn.triple
            && let Some(q) = triple_quote_at(&chars, i)
        {
            i = mask_triple(&chars, i, q, &mut out);
            continue;
        }
        if syn.backtick && chars[i] == '`' {
            i = mask_raw_until(&chars, i, '`', &mut out);
            continue;
        }
        if syn.dquote && chars[i] == '"' {
            i = mask_escapable(&chars, i, '"', &mut out);
            continue;
        }
        if syn.squote_string && chars[i] == '\'' {
            i = mask_escapable(&chars, i, '\'', &mut out);
            continue;
        }
        if syn.squote_char
            && chars[i] == '\''
            && let Some(len) = char_lit_len(&chars, i)
        {
            for _ in 0..len {
                out.push(' ');
            }
            i += len;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn starts_with_str(chars: &[char], i: usize, pat: &str) -> bool {
    pat.chars()
        .enumerate()
        .all(|(k, c)| chars.get(i + k) == Some(&c))
}

/// Mask a backslash-escapable string starting at the opening `quote`. Returns
/// the index just past the closing quote (or end of input).
fn mask_escapable(chars: &[char], i: usize, quote: char, out: &mut String) -> usize {
    out.push(' ');
    let mut j = i + 1;
    while j < chars.len() {
        let c = chars[j];
        if c == '\\' {
            out.push(' ');
            j += 1;
            if j < chars.len() {
                out.push(if chars[j] == '\n' { '\n' } else { ' ' });
                j += 1;
            }
            continue;
        }
        out.push(if c == '\n' { '\n' } else { ' ' });
        j += 1;
        if c == quote {
            break;
        }
    }
    j
}

/// Mask a raw (no-escape) string/template delimited by `quote` (a backtick).
fn mask_raw_until(chars: &[char], i: usize, quote: char, out: &mut String) -> usize {
    out.push(' ');
    let mut j = i + 1;
    while j < chars.len() {
        let c = chars[j];
        out.push(if c == '\n' { '\n' } else { ' ' });
        j += 1;
        if c == quote {
            break;
        }
    }
    j
}

fn triple_quote_at(chars: &[char], i: usize) -> Option<char> {
    ['"', '\''].into_iter().find(|&q| {
        chars.get(i) == Some(&q) && chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q)
    })
}

fn mask_triple(chars: &[char], i: usize, q: char, out: &mut String) -> usize {
    out.push_str("   ");
    let mut j = i + 3;
    while j < chars.len() {
        if chars[j] == '\\' {
            out.push(' ');
            j += 1;
            if j < chars.len() {
                out.push(if chars[j] == '\n' { '\n' } else { ' ' });
                j += 1;
            }
            continue;
        }
        if chars[j] == q && chars.get(j + 1) == Some(&q) && chars.get(j + 2) == Some(&q) {
            out.push_str("   ");
            return j + 3;
        }
        out.push(if chars[j] == '\n' { '\n' } else { ' ' });
        j += 1;
    }
    j
}

/// Mask a Rust raw string `r#*"..."#*` starting at `r`. Returns the index past
/// the close, or None if `r` does not begin a raw string (an ordinary
/// identifier such as `return`).
fn mask_rust_raw(chars: &[char], i: usize, out: &mut String) -> Option<usize> {
    let mut j = i + 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    if chars.get(j) != Some(&'"') {
        return None;
    }
    // Blank `r`, the hashes, and the opening quote.
    for _ in i..=j {
        out.push(' ');
    }
    j += 1;
    while j < chars.len() {
        if chars[j] == '"' {
            let mut k = j + 1;
            let mut h = 0;
            while h < hashes && chars.get(k) == Some(&'#') {
                h += 1;
                k += 1;
            }
            if h == hashes {
                for _ in j..k {
                    out.push(' ');
                }
                return Some(k);
            }
        }
        out.push(if chars[j] == '\n' { '\n' } else { ' ' });
        j += 1;
    }
    Some(j)
}

/// Length of a well-formed char/rune literal starting at `'`, or None. Bounded
/// so a Rust lifetime (`'a`) is left as code rather than swallowing the line.
fn char_lit_len(chars: &[char], i: usize) -> Option<usize> {
    if chars.get(i + 1) == Some(&'\\') {
        ((i + 2)..(i + 6).min(chars.len()))
            .find(|&j| chars[j] == '\'')
            .map(|j| j - i + 1)
    } else if chars.get(i + 2) == Some(&'\'')
        && chars.get(i + 1).is_some_and(|&c| c != '\'' && c != '\n')
    {
        Some(3)
    } else {
        None
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
