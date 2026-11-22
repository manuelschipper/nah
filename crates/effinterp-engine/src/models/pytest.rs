//! Read the Python sources in pytest's broad collection scope. Runtime
//! options, config features and registrations that can change that scope
//! retain coverage gaps.

use std::collections::{BTreeSet, VecDeque};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionInputRole, ExecutionPhase, ExecutionSelector, ObservationOutcome, ObservationQuery,
    ObservationRefusal, PathKind, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::common::{RuntimeSourceLanguage, runtime_searched_source};
use crate::models::{CommandModel, InvocationCtx, ModelCausalBinding};
use crate::nest::SourceSearchObservation;
use crate::python::{PytestMode, PythonImportSearch};
use crate::word::{Word, WordPart};
use crate::{SourceNamespace, SourcePurpose};

pub(super) fn with_collection(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(Pytest { owner })
}

struct Pytest {
    owner: Box<dyn CommandModel>,
}

/// Options of the declarative model that consume a separate argument.
const VALUE_OPTIONS: &[&str] = &["-k", "-m", "--maxfail", "--tb"];

/// How far the ancestor and package walks may climb. This is the listing depth
/// the host itself will answer; a walk that stops on the bound is partial.
const MAX_WALK: usize = effinterp_proto::MAX_LISTING_DEPTH;

const CONFIG_NAMES: [&str; 7] = [
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
];

impl CommandModel for Pytest {
    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn requires_established_identity(&self, ctx: &InvocationCtx) -> bool {
        self.owner.requires_established_identity(ctx)
    }

    fn applies_under_unresolved_identity(&self, ctx: &InvocationCtx) -> bool {
        self.owner.applies_under_unresolved_identity(ctx)
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.stdout_value_bindings(argv)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let ignore_startup_environment = ctx.nest.python_ignores_startup_environment.take();
        let options = invocation_options(builder, ctx, model_node);
        let owner_ctx = InvocationCtx {
            argv: &options.argv,
            argv_provenance: options.provenance.as_deref(),
            stdin: ctx.stdin,
            cwd: ctx.cwd,
            cwd_resource: ctx.cwd_resource.clone(),
            runtime_cwd: ctx.runtime_cwd,
            scope: ctx.scope,
            cwd_node: ctx.cwd_node,
            nest: ctx.nest,
            depth: ctx.depth,
            model_stack: ctx.model_stack.clone(),
        };
        // The collector owns the gaps for advanced options. Delay the gaps
        // until after reading sources so they do not stale those observations.
        // An unreviewed flag is the declarative surface's refusal: it
        // withholds that surface's effects and does not run collection under
        // a flag-free command, which would claim the plain pytest effects.
        if options.unrecognized.is_empty() {
            self.owner.apply(builder, &owner_ctx, model_node);
            if builder.is_host_realm()
                && let Some(cwd) = ctx.runtime_cwd
            {
                collect(
                    builder,
                    ctx,
                    model_node,
                    cwd,
                    options,
                    ignore_startup_environment,
                );
            } else {
                feature_gap(
                    builder,
                    model_node,
                    "pytest collection directory is unavailable".into(),
                    None,
                );
            }
        } else {
            unrecognized_arguments(builder, model_node, &options.unrecognized);
        }
    }
}

#[derive(Default)]
struct InvocationOptions {
    argv: Vec<Word>,
    provenance: Option<Vec<Vec<ProvenanceRef>>>,
    targets: Vec<String>,
    mode: PytestMode,
    gaps: Vec<Deferred>,
    features: BTreeSet<String>,
    /// Flags outside the declarative pytest surface. Collection does not run
    /// for them: that surface reports unrecognized arguments and withholds
    /// the effects it would emit for a plain pytest command.
    unrecognized: Vec<String>,
    autoload_disabled: bool,
}

/// Recognize option spelling and arity without interpreting its value.
fn advanced_option(word: &str) -> Option<(&str, bool, Option<&str>)> {
    let (name, attached) = word
        .split_once('=')
        .map_or((word, None), |(name, value)| (name, Some(value)));
    let takes_value = match name {
        "-p" | "-c" | "-o" | "-W" | "--inifile" | "--rootdir" | "--confcutdir"
        | "--import-mode" | "--override-ini" => true,
        "--pyargs" | "--noconftest" | "--collect-in-virtualenv" => false,
        _ => {
            return ["-p", "-c", "-o", "-W"].into_iter().find_map(|prefix| {
                word.strip_prefix(prefix)
                    .map(|value| (prefix, false, Some(value)))
            });
        }
    };
    Some((name, takes_value && attached.is_none(), attached))
}

fn invocation_options(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) -> InvocationOptions {
    let mut parsed = InvocationOptions {
        provenance: ctx.argv_provenance.map(|_| Vec::new()),
        ..InvocationOptions::default()
    };
    let mut args = ctx.argv.iter().enumerate();
    let mut positionals = false;
    let mut value = false;
    while let Some((index, word)) = args.next() {
        if index != 0
            && !value
            && !positionals
            && let Some((feature, takes_value, attached)) =
                word.as_literal().and_then(advanced_option)
        {
            let argument = if takes_value {
                args.next().and_then(|(_, argument)| argument.as_literal())
            } else {
                attached
            };
            if feature == "-W" {
                if argument.is_none_or(warning_filter_references_import) {
                    parsed.features.insert("-W (filterwarnings)".into());
                }
            } else if matches!(feature, "-o" | "--override-ini")
                && let Some((key, value)) = argument.and_then(|arg| arg.split_once('='))
            {
                let key = key.trim();
                if setting_references_import(key, value) {
                    parsed.features.insert(format!("{feature} ({key})"));
                } else if key != "filterwarnings" {
                    parsed.features.insert(feature.to_string());
                }
            } else {
                parsed.features.insert(feature.to_string());
            }
            continue;
        }
        let mut retained = word.clone();
        if index != 0 && !value {
            match word.as_literal() {
                Some("--") if !positionals => positionals = true,
                Some("--disable-plugin-autoload") if !positionals => {
                    parsed.autoload_disabled = true;
                    continue;
                }
                Some("-h" | "--help") if !positionals => {
                    if parsed.mode != PytestMode::Version {
                        parsed.mode = PytestMode::Help;
                    }
                    retained = Word::literal("--help");
                }
                Some("-V" | "--version") if !positionals => {
                    parsed.mode = PytestMode::Version;
                    retained = Word::literal("--version");
                }
                Some("--collect-only" | "--collectonly" | "--co") if !positionals => {
                    if !parsed.mode.startup_only() {
                        parsed.mode = PytestMode::Collect;
                    }
                    retained = Word::literal("--collect-only");
                }
                Some(flag) if !positionals && VALUE_OPTIONS.contains(&flag) => {
                    value = true;
                }
                Some(flag) if !positionals && flag.starts_with('-') => {
                    // Keep flags the declarative model understands. An unknown
                    // flag is not a collection feature: the reviewed surface
                    // refuses the command instead of analyzing a flag-free one.
                    if !matches!(
                        flag.split('=').next().unwrap_or(flag),
                        "-x" | "-q"
                            | "-v"
                            | "-s"
                            | "--disable-warnings"
                            | "--maxfail"
                            | "--tb"
                            | "-k"
                            | "-m"
                    ) {
                        parsed.unrecognized.push(flag.to_string());
                        continue;
                    }
                }
                Some(path) => parsed.targets.push(path.to_string()),
                None => {
                    if let [WordPart::Glob(pattern)] = word.parts.as_slice()
                        && builder.is_host_realm()
                        && let Some(cwd) = ctx.runtime_cwd
                        && let Some(paths) = glob_targets(
                            builder,
                            model_node,
                            cwd,
                            pattern,
                            positionals,
                            &mut parsed.gaps,
                        )
                    {
                        if let (Some(kept), Some(items)) =
                            (&mut parsed.provenance, ctx.argv_provenance)
                        {
                            kept.extend(std::iter::repeat_n(
                                items.get(index).cloned().unwrap_or_default(),
                                paths.len(),
                            ));
                        }
                        parsed.argv.extend(paths.iter().cloned().map(Word::literal));
                        parsed.targets.extend(paths);
                        continue;
                    }
                    parsed.features.insert("unresolved argument".into());
                }
            }
        } else {
            value = false;
        }
        parsed.argv.push(retained);
        if let (Some(kept), Some(items)) = (&mut parsed.provenance, ctx.argv_provenance) {
            kept.push(items.get(index).cloned().unwrap_or_default());
        }
    }
    parsed
}

enum Deferred {
    Listing {
        path: String,
        refusal: ObservationRefusal,
    },
    UnresolvedLink {
        path: String,
    },
    UnreadConfig {
        path: String,
    },
    WalkCapped {
        path: String,
    },
    ConfigFeature {
        path: String,
        key: String,
    },
}

/// Pytest names a source by the path used for collection. A symlink can
/// supply the bytes elsewhere without changing the parent package.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct CollectionPath {
    logical: String,
    source: String,
}

impl CollectionPath {
    fn direct(path: String) -> Self {
        Self {
            source: path.clone(),
            logical: path,
        }
    }
}

type SelectedItems = (Vec<CollectionPath>, Vec<CollectionPath>, Vec<String>);

struct ImportContext {
    base: String,
    package: Option<String>,
    inits: Vec<CollectionPath>,
    capped: bool,
}

fn collect(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    cwd: &str,
    options: InvocationOptions,
    ignore_startup_environment: bool,
) {
    let cwd = normalized(cwd);
    let mut gaps = options.gaps;
    let (mut scans, modules, item_dirs) =
        selected_items(builder, model_node, cwd, &options.targets, &mut gaps);
    let mut starts = item_dirs.clone();
    starts.push(cwd.to_string());
    let fallback = common_ancestor(&starts);
    // Config can be found from each argument separately. Walk all those
    // ancestry paths for feature detection, choosing the common path first.
    let mut anchors = vec![if item_dirs.is_empty() {
        cwd.to_string()
    } else {
        common_ancestor(&item_dirs)
    }];
    anchors.extend(starts);
    let root = discover_root(builder, ctx, model_node, &dedup(anchors), &mut gaps)
        .unwrap_or_else(|| fallback.clone());
    // Scanning the root must not erase a separately selected directory.
    if !scans.iter().any(|dir| dir.logical == root) {
        scans.push(CollectionPath::direct(root));
    }
    let mut files = CollectedFiles {
        modules,
        conftests: Vec::new(),
        item_dirs,
        gaps,
    };
    collect_directories(builder, model_node, scans, &mut files);
    // Git markers and pytest's recursive exclusions never cut off the
    // ancestry of a conftest, including one above a linked selection.
    for dir in ancestor_dirs("/", &dedup(files.item_dirs), &mut files.gaps) {
        let logical = join_under(&dir, "conftest.py");
        match observe_node(builder, model_node, &logical) {
            Observed::File(source) => files.conftests.push(CollectionPath { logical, source }),
            Observed::Unresolved => files.gaps.push(Deferred::UnresolvedLink { path: logical }),
            Observed::Dir(_) | Observed::Absent => {}
        }
    }

    let roots = import_roots(cwd, ctx);
    let executable = ctx.argv[0].as_literal().map(str::to_string);
    let mut seen = BTreeSet::new();
    let mut prepared = Vec::new();
    let autoload_disabled = options.autoload_disabled || plugin_autoload_disabled(ctx);
    let startup_warning_imports = !ignore_startup_environment
        && ctx
            .environment_value("PYTHONWARNINGS")
            .is_some_and(|value| match value {
                ResourceExpr::Literal { value } => warning_environment_references_import(&value),
                _ => true,
            });
    // Help and version still import conftests. Keep the broader module
    // walk if options, configuration or the environment may load plugins.
    if options.mode.startup_only()
        && autoload_disabled
        && !startup_warning_imports
        && options.features.is_empty()
        && !files.gaps.iter().any(|gap| {
            matches!(
                gap,
                Deferred::ConfigFeature { .. } | Deferred::UnreadConfig { .. }
            )
        })
        && ["PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"]
            .iter()
            .all(|&name| {
                (name == "PYTHONPATH" && ignore_startup_environment)
                    || match ctx.environment_value(name) {
                        None => true,
                        Some(ResourceExpr::Literal { value }) => value.is_empty(),
                        Some(_) => false,
                    }
            })
    {
        files.modules.clear();
    }
    for path in files.conftests.into_iter().chain(files.modules) {
        if !seen.insert(path.clone()) {
            continue;
        }
        let mut context = import_context(builder, model_node, &path.logical);
        if context.capped {
            files.gaps.push(Deferred::WalkCapped {
                path: path.logical.clone(),
            });
        }
        for init in std::mem::take(&mut context.inits) {
            if seen.insert(init.clone()) {
                let context = import_context(builder, model_node, &init.logical);
                prepared.push(prepare_source(
                    init,
                    context,
                    &roots,
                    &executable,
                    options.mode,
                ));
            }
        }
        prepared.push(prepare_source(
            path,
            context,
            &roots,
            &executable,
            options.mode,
        ));
    }
    for (path, search) in &prepared {
        run(builder, ctx, model_node, search, path);
    }
    emit_deferred(builder, model_node, files.gaps);
    for feature in options.features {
        feature_gap(
            builder,
            model_node,
            format!("pytest option {feature} is outside plain collection"),
            None,
        );
    }
    environment_gaps(builder, ctx, model_node, startup_warning_imports);
    if !autoload_disabled {
        emit_entry_point_boundary(builder, model_node);
    }
}

/// Directories to scan, test files named by a positional path, and the
/// directories whose ancestor `conftest.py` files are in scope.
fn selected_items(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    cwd: &str,
    targets: &[String],
    gaps: &mut Vec<Deferred>,
) -> SelectedItems {
    let mut scan_dirs = Vec::new();
    let mut file_modules = Vec::new();
    let mut item_dirs = Vec::new();
    if targets.is_empty() {
        item_dirs.push(cwd.to_string());
        scan_dirs.push(CollectionPath::direct(cwd.to_string()));
        return (scan_dirs, file_modules, item_dirs);
    }
    for target in targets {
        let spec = target.split("::").next().unwrap_or(target);
        let Some((_, abs)) = crate::paths::join_source_path(Some(cwd), spec) else {
            continue;
        };
        // An argument that is a link is the file or directory it names.
        // `observe_kind` stops at the link, so a selected test or a selected
        // directory would be dropped while pytest runs the target.
        match observe_node(builder, model_node, &abs) {
            Observed::Dir(source) => {
                item_dirs.push(abs.clone());
                scan_dirs.push(CollectionPath {
                    logical: abs,
                    source,
                });
            }
            Observed::File(source) => {
                item_dirs.push(crate::paths::parent_dir(&abs));
                if abs.ends_with(".py") {
                    file_modules.push(CollectionPath {
                        logical: abs,
                        source,
                    });
                }
            }
            Observed::Unresolved => gaps.push(Deferred::UnresolvedLink { path: abs }),
            Observed::Absent => {}
        }
    }
    (scan_dirs, file_modules, item_dirs)
}

/// Expand the pathname patterns the shell already spelled, including its
/// dotglob readings. Each wildcard component searches one directory.
fn glob_targets(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    cwd: &str,
    pattern: &str,
    positionals: bool,
    gaps: &mut Vec<Deferred>,
) -> Option<Vec<String>> {
    if pattern.contains("::")
        || ["?(", "*(", "+(", "@(", "!("]
            .iter()
            .any(|group| pattern.contains(group))
        || pattern
            .split('/')
            .any(|part| part == ".." || part.contains("**"))
    {
        return None;
    }
    let first = pattern.find(['*', '?', '[', '\\'])?;
    let (prefix, suffix) = pattern[..first]
        .rfind('/')
        .map_or((".", pattern), |slash| pattern.split_at(slash + 1));
    let (_, prefix) = crate::paths::join_source_path(Some(cwd), prefix)?;
    let mut dirs = vec![prefix];
    let mut components = suffix.split('/').peekable();
    while let Some(component) = components.next() {
        let mut paths = Vec::new();
        for dir in dirs {
            if component.contains(['*', '?', '[', '\\']) {
                let source = match observe_node(builder, model_node, &dir) {
                    Observed::Dir(source) => source,
                    Observed::Absent | Observed::File(_) => continue,
                    Observed::Unresolved => {
                        gaps.push(Deferred::UnresolvedLink { path: dir });
                        continue;
                    }
                };
                match listing(builder, model_node, &source, Some(1)) {
                    Ok(entries) => {
                        for (entry, kind) in entries {
                            if !builder.budget().try_charge_steps(1) {
                                builder.note_saturated("max_analysis_steps");
                                return None;
                            }
                            if (components.peek().is_none()
                                || matches!(kind, PathKind::Directory | PathKind::Symlink))
                                && effinterp_proto::glob_match(component, &entry).ok()?
                            {
                                paths.push(join_under(&dir, &entry));
                            }
                        }
                    }
                    Err(refusal) => gaps.push(Deferred::Listing { path: dir, refusal }),
                }
            } else {
                paths.push(join_under(&dir, component));
            }
        }
        dirs = paths;
    }
    if dirs.is_empty()
        && let Some((_, literal)) = crate::paths::join_source_path(Some(cwd), pattern)
    {
        // Bash can leave an unmatched pattern in argv as literal text.
        dirs.push(literal);
    }
    if !positionals
        && !pattern.starts_with(['/', '.'])
        && dirs.iter().any(|path| {
            path.strip_prefix(cwd.trim_end_matches('/'))
                .and_then(|path| path.strip_prefix('/'))
                .is_some_and(|relative| relative.starts_with('-'))
        })
    {
        // A relative expansion that begins with a dash could select options.
        return None;
    }
    Some(dirs)
}

/// Observe config presence and settings that need coverage gaps. Config
/// values do not drive the source walk. An ordinary pyproject.toml and
/// setup.py can mark the root even when there is no pytest section.
fn discover_root(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    anchors: &[String],
    gaps: &mut Vec<Deferred>,
) -> Option<String> {
    let mut seen = BTreeSet::new();
    let mut root = None;
    let mut pyproject = None;
    let mut setup = None;
    for start in anchors {
        let (dirs, capped) = ancestry("/", start);
        if capped {
            gaps.push(Deferred::WalkCapped {
                path: start.clone(),
            });
        }
        for dir in dirs.into_iter().rev() {
            if !seen.insert(dir.clone()) {
                break;
            }
            let inventory = listing(builder, model_node, &dir, Some(1));
            let mut saw_marker = false;
            let candidates = CONFIG_NAMES.into_iter().chain(["setup.py"]);
            for name in candidates {
                let path = join_under(&dir, name);
                let observed = match &inventory {
                    Ok(entries) => match entries.iter().find(|(entry, _)| entry == name) {
                        Some((_, PathKind::File)) => Observed::File(path.clone()),
                        Some((_, PathKind::Symlink)) => observe_node(builder, model_node, &path),
                        _ => continue,
                    },
                    Err(_) => observe_node(builder, model_node, &path),
                };
                match observed {
                    Observed::File(source) => {
                        saw_marker = true;
                        match name {
                            "pyproject.toml" => {
                                pyproject.get_or_insert_with(|| dir.clone());
                            }
                            "setup.py" => {
                                setup.get_or_insert_with(|| dir.clone());
                            }
                            _ => {}
                        }
                        if name != "setup.py" {
                            match read_text(builder, ctx, &source)
                                .and_then(|text| config_features(name, &text).ok())
                            {
                                Some(Some(keys)) => {
                                    root.get_or_insert_with(|| dir.clone());
                                    for key in keys {
                                        gaps.push(Deferred::ConfigFeature {
                                            path: path.clone(),
                                            key,
                                        });
                                    }
                                }
                                Some(None) => {}
                                None => {
                                    root.get_or_insert_with(|| dir.clone());
                                    gaps.push(Deferred::UnreadConfig { path });
                                }
                            }
                        }
                    }
                    Observed::Unresolved => {
                        saw_marker = true;
                        gaps.push(Deferred::UnreadConfig { path });
                    }
                    Observed::Dir(_) | Observed::Absent => {}
                }
            }
            if let Err(refusal) = inventory {
                let exists = saw_marker
                    || matches!(observe_node(builder, model_node, &dir), Observed::Dir(_))
                    || matches!(
                        observe_node(builder, model_node, &join_under(&dir, "conftest.py")),
                        Observed::File(_)
                    );
                if exists || refusal != ObservationRefusal::Unobserved {
                    gaps.push(Deferred::Listing { path: dir, refusal });
                } else {
                    break;
                }
            }
        }
    }
    root.or(pyproject).or(setup)
}

fn read_text(builder: &PlanBuilder, ctx: &InvocationCtx, path: &str) -> Option<String> {
    match ctx.nest.observe_source_search(
        builder,
        &[(SourceNamespace::Host, path.to_string())],
        SourcePurpose::InvocationInput,
    ) {
        SourceSearchObservation::Found { bytes, .. } => String::from_utf8(bytes).ok(),
        _ => None,
    }
}

fn advanced_config_key(key: &str) -> bool {
    key.starts_with("python_")
        || matches!(
            key,
            "addopts"
                | "plugins"
                | "pytest_plugins"
                | "required_plugins"
                | "pythonpath"
                | "testpaths"
                | "norecursedirs"
                | "consider_namespace_packages"
        )
}

fn warning_filter_references_import(filter: &str) -> bool {
    // Pytest imports from the category field. The message and module
    // fields are patterns and may contain dotted text too.
    let category = filter.split(':').nth(2).unwrap_or_default().trim();
    !matches!(
        category.strip_prefix("builtins.").unwrap_or(category),
        "" | "Warning"
            | "UserWarning"
            | "DeprecationWarning"
            | "PendingDeprecationWarning"
            | "SyntaxWarning"
            | "RuntimeWarning"
            | "FutureWarning"
            | "ImportWarning"
            | "UnicodeWarning"
            | "BytesWarning"
            | "ResourceWarning"
            | "EncodingWarning"
    )
}

fn setting_references_import(key: &str, value: &str) -> bool {
    if key == "filterwarnings" {
        return value.lines().any(warning_filter_references_import);
    }
    // Other pytest settings can belong to plugins. Treat qualified object
    // names as possible imports even when the setting is unfamiliar.
    value
        .split(|ch: char| ch.is_whitespace() || ",;\"'[](){}=".contains(ch))
        .any(|word| {
            word.contains(['.', ':'])
                && word.split(['.', ':']).all(|part| {
                    !part.is_empty()
                        && !part.starts_with(|ch: char| ch.is_ascii_digit())
                        && part
                            .chars()
                            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric() || !ch.is_ascii())
                })
        })
}

fn config_features(name: &str, text: &str) -> Result<Option<Vec<String>>, ()> {
    // The parsers here use LF and CRLF. Refuse other Python line separators
    // before they can merge two settings or warning filters into one line.
    if text.lines().any(|line| {
        line.contains([
            '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
        ])
    }) {
        return Err(());
    }
    if name == "pyproject.toml" {
        return pyproject_pytest_features(text);
    }
    if name == "pytest.toml" || name == ".pytest.toml" {
        return toml_pytest_features(text);
    }
    let section = if name == "setup.cfg" {
        "tool:pytest"
    } else {
        "pytest"
    };
    let keys = ini_features(text, section)?;
    Ok(if matches!(name, "pytest.ini" | ".pytest.ini") {
        Some(keys.unwrap_or_default())
    } else {
        keys
    })
}

/// Native `[tool.pytest]` keys and the legacy `ini_options` table are both
/// settings. An empty legacy table does not hide a native key beside it.
fn pyproject_pytest_features(text: &str) -> Result<Option<Vec<String>>, ()> {
    let doc = text.parse::<toml::Table>().map_err(|_| ())?;
    let Some(pytest) = doc.get("tool").and_then(|tool| tool.get("pytest")) else {
        return Ok(None);
    };
    let table = pytest.as_table().ok_or(())?;
    let mut keys = Vec::new();
    if let Some(ini) = table.get("ini_options") {
        keys.extend(toml_setting_features(ini.as_table().ok_or(())?));
    }
    keys.extend(toml_setting_features(table).filter(|key| key != "ini_options"));
    Ok(Some(keys))
}

/// Pytest 9 reads `[pytest]` from `pytest.toml` and `.pytest.toml`. The file
/// is config even when that table is absent.
fn toml_pytest_features(text: &str) -> Result<Option<Vec<String>>, ()> {
    let doc = text.parse::<toml::Table>().map_err(|_| ())?;
    let Some(table) = doc.get("pytest") else {
        return Ok(Some(Vec::new()));
    };
    Ok(Some(
        toml_setting_features(table.as_table().ok_or(())?).collect(),
    ))
}

fn toml_setting_features(table: &toml::Table) -> impl Iterator<Item = String> + '_ {
    table
        .iter()
        .filter(|(key, value)| {
            advanced_config_key(key)
                || value
                    .as_str()
                    .is_some_and(|value| setting_references_import(key, value))
                || value.as_array().is_some_and(|values| {
                    values.iter().filter_map(toml::Value::as_str).any(|value| {
                        if key.as_str() == "filterwarnings" {
                            warning_filter_references_import(value)
                        } else {
                            setting_references_import(key, value)
                        }
                    })
                })
        })
        .map(|(key, _)| key.clone())
}

fn ini_features(text: &str, section: &str) -> Result<Option<Vec<String>>, ()> {
    let mut active = false;
    let mut found = false;
    let mut keys = Vec::new();
    let mut previous = None;
    for raw in text.trim_start_matches('\u{feff}').lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let indentation = raw.len() - raw.trim_start().len();
        if let Some((prior, key)) = previous
            && indentation > prior
        {
            if active
                && setting_references_import(key, line)
                && keys.last().is_none_or(|last| last != key)
            {
                keys.push(key.to_string());
            }
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let (header, tail) = header.split_once(']').ok_or(())?;
            if !tail.trim().is_empty() && !tail.trim_start().starts_with(['#', ';']) {
                return Err(());
            }
            active = header.trim() == section;
            found |= active;
            previous = None;
            continue;
        }
        let separator = line.find(['=', ':']).ok_or(())?;
        let (key, value) = line.split_at(separator);
        let key = key.trim();
        if key.is_empty() {
            return Err(());
        }
        if active && (advanced_config_key(key) || setting_references_import(key, &value[1..])) {
            keys.push(key.to_string());
        }
        previous = Some((indentation, key));
    }
    Ok(found.then_some(keys))
}

fn ancestor_dirs(top: &str, items: &[String], gaps: &mut Vec<Deferred>) -> Vec<String> {
    let mut dirs = Vec::new();
    for item in items {
        let (found, capped) = ancestry(if is_ancestor(top, item) { top } else { "/" }, item);
        if capped {
            gaps.push(Deferred::WalkCapped { path: item.clone() });
        }
        dirs.extend(found);
    }
    dedup(dirs)
}

struct CollectedFiles {
    modules: Vec<CollectionPath>,
    conftests: Vec<CollectionPath>,
    item_dirs: Vec<String>,
    gaps: Vec<Deferred>,
}

fn collect_directories(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    scans: Vec<CollectionPath>,
    files: &mut CollectedFiles,
) {
    let mut pending: VecDeque<_> = scans
        .into_iter()
        .map(|dir| (dir, Vec::<String>::new(), false))
        .collect();
    let mut seen = BTreeSet::new();
    while let Some((dir, mut ancestors, in_excluded_tree)) = pending.pop_front() {
        if !seen.insert((dir.clone(), in_excluded_tree)) {
            continue;
        }
        files
            .item_dirs
            .extend([dir.logical.clone(), dir.source.clone()]);
        if ancestors.len() == MAX_WALK || ancestors.contains(&dir.source) {
            files.gaps.push(Deferred::WalkCapped { path: dir.logical });
            continue;
        }
        ancestors.push(dir.source.clone());
        let entries = match listing(builder, model_node, &dir.source, None) {
            Ok(entries) => entries,
            Err(refusal) => {
                files.gaps.push(Deferred::Listing {
                    path: dir.source,
                    refusal,
                });
                continue;
            }
        };
        if !builder.budget().try_charge_steps(1 + entries.len() as u64) {
            builder.note_saturated("max_analysis_steps");
            return;
        }
        let venvs = venv_roots(&entries);
        for (rel, kind) in entries {
            let base = rel.rsplit('/').next().unwrap_or(&rel);
            let conftest = base == "conftest.py";
            let excluded = rel
                .rsplit_once('/')
                .is_some_and(|(dirs, _)| dirs.split('/').any(excluded_component))
                || under_venv(&rel, &venvs);
            let candidate = conftest || base.ends_with(".py") && !excluded && !in_excluded_tree;
            let logical = join_under(&dir.logical, &rel);
            let source = join_under(&dir.source, &rel);
            match kind {
                PathKind::File if candidate => {
                    let bucket = if conftest {
                        &mut files.conftests
                    } else {
                        &mut files.modules
                    };
                    bucket.push(CollectionPath { logical, source });
                }
                PathKind::Symlink => match observe_node(builder, model_node, &source) {
                    Observed::File(source) if candidate => {
                        let bucket = if conftest {
                            &mut files.conftests
                        } else {
                            &mut files.modules
                        };
                        bucket.push(CollectionPath { logical, source });
                    }
                    Observed::Dir(source) => {
                        pending.push_back((
                            CollectionPath { logical, source },
                            ancestors.clone(),
                            in_excluded_tree || excluded || excluded_component(base),
                        ));
                    }
                    Observed::Unresolved => {
                        files.gaps.push(Deferred::UnresolvedLink { path: logical })
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
}

fn prepare_source(
    path: CollectionPath,
    context: ImportContext,
    roots: &[String],
    executable: &Option<String>,
    mode: PytestMode,
) -> (CollectionPath, PythonImportSearch) {
    let mut roots = roots.to_vec();
    roots.insert(0, context.base);
    let mut search = PythonImportSearch::new(dedup(roots), executable.clone(), context.package);
    search.pytest_mode = Some(mode);
    if path.logical != path.source {
        search.pytest_path = Some(path.logical.clone());
    }
    (path, search)
}

/// The deepest directory that is an ancestor of, or equal to, every path.
fn common_ancestor(dirs: &[String]) -> String {
    let mut common: Option<Vec<&str>> = None;
    for dir in dirs {
        let comps: Vec<&str> = normalized(dir).split('/').collect();
        common = Some(match common {
            None => comps,
            Some(prev) => {
                let shared = prev.iter().zip(&comps).take_while(|(a, b)| a == b).count();
                comps[..shared].to_vec()
            }
        });
    }
    common.map(|c| c.join("/")).unwrap_or_default()
}

/// Virtual-environment roots in a recursive listing: a directory holding
/// `pyvenv.cfg` or `conda-meta/history`. The scanned directory itself is never
/// a root, so an explicitly selected environment is still collected.
fn venv_roots(entries: &[(String, PathKind)]) -> Vec<String> {
    entries
        .iter()
        .filter(|(_, kind)| *kind == PathKind::File)
        .filter_map(|(rel, _)| {
            if let Some(dir) = rel.strip_suffix("/pyvenv.cfg") {
                Some(dir.to_string())
            } else {
                rel.strip_suffix("/conda-meta/history").map(str::to_string)
            }
        })
        .filter(|root| !root.is_empty())
        .collect()
}

fn under_venv(rel: &str, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|root| rel.starts_with(&format!("{root}/")))
}

fn import_context(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    file: &str,
) -> ImportContext {
    let parent = crate::paths::parent_dir(file);
    let mut dir = parent.clone();
    let mut package = None;
    let mut inits = Vec::new();
    let mut capped = true;
    for level in 0..MAX_WALK {
        let init = join_under(&dir, "__init__.py");
        // A package `__init__.py` that is a link is the file it points at.
        // The link path itself has no source bytes.
        let Observed::File(source) = observe_node(builder, model_node, &init) else {
            capped = false;
            break;
        };
        inits.push(CollectionPath {
            logical: init,
            source,
        });
        if level == 0 {
            package = Some(parent.clone());
        }
        let next = crate::paths::parent_dir(&dir);
        if normalized(&next) == normalized(&dir) {
            capped = false;
            break;
        }
        dir = next;
    }
    inits.reverse();
    ImportContext {
        base: dir,
        package,
        inits,
        capped,
    }
}

/// pytest's default `norecursedirs`: a leading `.` matches hidden directories,
/// and `*.egg` matches an egg directory.
fn excluded_component(name: &str) -> bool {
    name.starts_with('.')
        || name.ends_with(".egg")
        || matches!(
            name,
            "_darcs" | "build" | "CVS" | "dist" | "node_modules" | "venv" | "{arch}"
        )
}

/// Directories from `top` down to `bottom`, and whether the walk hit the bound
/// before `top`.
fn ancestry(top: &str, bottom: &str) -> (Vec<String>, bool) {
    if !is_ancestor(top, bottom) {
        return (Vec::new(), false);
    }
    let top = normalized(top);
    let mut dirs = Vec::new();
    let mut dir = normalized(bottom).to_string();
    for _ in 0..MAX_WALK {
        dirs.push(dir.clone());
        if normalized(&dir) == top
            || normalized(&crate::paths::parent_dir(&dir)) == normalized(&dir)
        {
            dirs.reverse();
            return (dirs, false);
        }
        dir = crate::paths::parent_dir(&dir);
    }
    dirs.reverse();
    (dirs, true)
}

/// Whether `descendant` is `ancestor` or lies beneath it. The filesystem root
/// is an ancestor of every absolute path; trimming it and then joining `"/"`
/// would look for a `//` prefix and match nothing.
fn is_ancestor(ancestor: &str, descendant: &str) -> bool {
    let ancestor = normalized(ancestor);
    let descendant = normalized(descendant);
    ancestor == "/" || descendant == ancestor || descendant.starts_with(&format!("{ancestor}/"))
}

fn normalized(path: &str) -> &str {
    let path = path.trim_end_matches('/');
    if path.is_empty() { "/" } else { path }
}

fn join_under(dir: &str, rel: &str) -> String {
    let dir = if normalized(dir) == "/" {
        ""
    } else {
        normalized(dir)
    };
    format!("{dir}/{rel}")
}

fn dedup(paths: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn run(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    search: &PythonImportSearch,
    path: &CollectionPath,
) {
    if ctx
        .nest
        .python_imports
        .pytest_source_recorded(builder, &path.logical)
    {
        return;
    }
    *ctx.nest.python_import_search.borrow_mut() = Some(search.clone());
    runtime_searched_source(
        builder,
        ctx,
        model_node,
        &path.logical,
        vec![path.source.clone()],
        ExecutionInputRole::DependencyRequest,
        ExecutionPhase::Import,
        ExecutionSelector::Dependency {
            specifier: path.logical.clone(),
        },
        RuntimeSourceLanguage::Python,
        true,
    );
    ctx.nest.python_import_search.borrow_mut().take();
}

/// What a path observation resolved to. A symlink to a regular file is that
/// file; a symlink whose target is not known is not the same as a missing path.
enum Observed {
    File(String),
    Dir(String),
    Unresolved,
    Absent,
}

fn observe_node(builder: &mut PlanBuilder, model_node: ProvenanceRef, path: &str) -> Observed {
    let query = ObservationQuery::Path {
        path: path.to_string(),
    };
    if !effinterp_proto::valid_observation_query(&query) {
        return Observed::Absent;
    }
    let outcome = builder.budget().observe_path(path);
    if outcome == ObservationOutcome::Refused(ObservationRefusal::Unobserved) {
        return Observed::Absent;
    }
    builder.node(
        ProvenanceKind::HostObservation {
            query,
            outcome: outcome.clone(),
        },
        &[model_node],
    );
    match outcome {
        ObservationOutcome::Path(fact) => match fact.kind {
            PathKind::File => Observed::File(path.to_string()),
            PathKind::Directory => Observed::Dir(path.to_string()),
            PathKind::Missing => Observed::Absent,
            PathKind::Symlink => match fact.followed {
                effinterp_proto::Fact::Known(target) => match target.kind {
                    effinterp_proto::Fact::Known(PathKind::File) => Observed::File(target.path),
                    effinterp_proto::Fact::Known(PathKind::Directory) => Observed::Dir(target.path),
                    effinterp_proto::Fact::Known(_) => Observed::Absent,
                    effinterp_proto::Fact::Unavailable(_) => Observed::Unresolved,
                },
                effinterp_proto::Fact::Unavailable(_) => Observed::Unresolved,
            },
            PathKind::Fifo | PathKind::Other => Observed::Absent,
        },
        ObservationOutcome::Refused(_) => Observed::Unresolved,
        ObservationOutcome::Listing(_) => Observed::Absent,
    }
}

fn import_roots(cwd: &str, ctx: &InvocationCtx) -> Vec<String> {
    let mut roots = vec![cwd.to_string()];
    if let Some(ResourceExpr::Literal { value }) = ctx.environment_value("PYTHONPATH") {
        roots.extend(crate::models::pyexec::python_path_entries(
            &value,
            Some(cwd),
        ));
    }
    dedup(roots)
}

fn listing(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    directory: &str,
    depth: Option<u32>,
) -> Result<Vec<(String, PathKind)>, ObservationRefusal> {
    let query = ObservationQuery::Listing {
        path: directory.to_string(),
        depth,
    };
    if !effinterp_proto::valid_observation_query(&query) {
        return Err(ObservationRefusal::Invalid);
    }
    let budget = builder.budget();
    let outcome = budget.observe_listing(directory, depth, budget.unmodeled_steps());
    if let ObservationOutcome::Refused(refusal) = &outcome
        && *refusal == ObservationRefusal::Unobserved
    {
        return Err(ObservationRefusal::Unobserved);
    }
    builder.node(
        ProvenanceKind::HostObservation {
            query,
            outcome: outcome.clone(),
        },
        &[model_node],
    );
    match outcome {
        ObservationOutcome::Listing(listing) => Ok(listing
            .entries
            .into_iter()
            .map(|entry| (entry.path, entry.kind))
            .collect()),
        ObservationOutcome::Refused(refusal) => Err(refusal),
        _ => Err(ObservationRefusal::Invalid),
    }
}

const ENVIRONMENT_NAMES: &[&str] = &[
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTEST_PLUGINS",
    "PYTEST_ADDOPTS",
    "PYTHONPATH",
    "PYTHONWARNINGS",
];

fn warning_environment_references_import(value: &str) -> bool {
    value.split(',').any(|filter| {
        filter.split(':').nth(2).is_some_and(|category| {
            category
                .trim()
                .rsplit_once('.')
                .is_some_and(|(module, _)| module != "builtins")
        })
    })
}

fn environment_gaps(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    startup_warning_imports: bool,
) {
    if startup_warning_imports {
        feature_gap(
            builder,
            model_node,
            "Python startup warning filters may import a category from PYTHONWARNINGS".into(),
            None,
        );
    }
    if !ctx.nest.tracks_host_context_environment() {
        environment_boundary(
            builder,
            model_node,
            ENVIRONMENT_NAMES,
            "pytest collection depends on its environment",
        );
        return;
    }
    for &name in ENVIRONMENT_NAMES
        .iter()
        .filter(|&&name| name != "PYTHONWARNINGS")
    {
        let Some(value) = ctx.environment_value(name) else {
            continue;
        };
        match value {
            ResourceExpr::Literal { value } if name == "PYTHONPATH" || value.is_empty() => {}
            _ => environment_boundary(
                builder,
                model_node,
                &[name],
                &format!("pytest environment variable {name} is outside plain collection"),
            ),
        }
    }
}

fn unrecognized_arguments(builder: &mut PlanBuilder, model_node: ProvenanceRef, flags: &[String]) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new("filesystem"), Domain::new("process")],
            affected_resource: None,
            callee: None,
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!(
                "pytest option {} is outside the reviewed command surface",
                flags.join(" ")
            )),
        },
        CoverageLevel::Partial,
    );
}

fn feature_gap(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    detail: String,
    path: Option<&str>,
) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::FRONTEND_PARTIAL,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new("filesystem")],
            affected_resource: path.map(crate::value::fs_path_resource),
            callee: None,
            provenance: vec![model_node],
            limit: None,
            detail: Some(detail),
        },
        CoverageLevel::Partial,
    );
}

fn environment_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    names: &[&str],
    detail: &str,
) {
    let alternatives = names
        .iter()
        .map(|name| ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable {
                name: (*name).to_string(),
            },
        })
        .collect();
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(ResourceExpr::Union { alternatives }),
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(detail.to_string()),
        },
        CoverageLevel::Partial,
    );
}

fn plugin_autoload_disabled(ctx: &InvocationCtx) -> bool {
    match ctx.environment_value("PYTEST_DISABLE_PLUGIN_AUTOLOAD") {
        // Any non-empty literal is truthy to Python, including `"0"`.
        Some(ResourceExpr::Literal { value }) => !value.is_empty(),
        _ => false,
    }
}

fn emit_deferred(builder: &mut PlanBuilder, model_node: ProvenanceRef, gaps: Vec<Deferred>) {
    let mut seen = BTreeSet::new();
    for gap in gaps {
        let key = match &gap {
            Deferred::Listing { path, refusal } => format!("list:{path}:{}", refusal.code()),
            Deferred::UnresolvedLink { path } => format!("link:{path}"),
            Deferred::UnreadConfig { path } => format!("cfg:{path}"),
            Deferred::WalkCapped { path } => format!("cap:{path}"),
            Deferred::ConfigFeature { path, key } => format!("option:{path}:{key}"),
        };
        if !seen.insert(key) {
            continue;
        }
        match gap {
            Deferred::Listing { path, refusal } => {
                let (class, limit) = match &refusal {
                    ObservationRefusal::Limit { limit } => {
                        (BoundaryClass::Limit, Some(limit.clone()))
                    }
                    _ => (BoundaryClass::Unresolved, None),
                };
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                        class,
                        scope: BoundaryScope::Invocation,
                        domains: vec![Domain::new("filesystem")],
                        affected_resource: Some(crate::value::fs_path_resource(&path)),
                        callee: None,
                        provenance: vec![model_node],
                        limit,
                        detail: Some(format!("path identity unobserved: {}", refusal.code())),
                    },
                    CoverageLevel::Partial,
                );
            }
            Deferred::UnresolvedLink { path } => {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        domains: vec![Domain::new("filesystem")],
                        affected_resource: Some(crate::value::fs_path_resource(&path)),
                        callee: None,
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some("pytest symlink target is unobserved".to_string()),
                    },
                    CoverageLevel::Partial,
                );
            }
            Deferred::UnreadConfig { path } => {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::UNREAD_CONFIG,
                        class: BoundaryClass::Unresolved,
                        scope: BoundaryScope::Invocation,
                        domains: vec![Domain::new("filesystem")],
                        affected_resource: Some(crate::value::fs_path_resource(&path)),
                        callee: None,
                        provenance: vec![model_node],
                        limit: None,
                        detail: Some("pytest config could not be read or parsed".to_string()),
                    },
                    CoverageLevel::Partial,
                );
            }
            Deferred::ConfigFeature { path, key } => feature_gap(
                builder,
                model_node,
                format!("pytest config option {key} is outside plain collection"),
                Some(&path),
            ),
            Deferred::WalkCapped { path } => {
                builder.boundary_with_coverage(
                    Boundary {
                        reason: BoundaryReason::OBSERVATION_UNAVAILABLE,
                        class: BoundaryClass::Limit,
                        scope: BoundaryScope::Invocation,
                        domains: vec![Domain::new("filesystem")],
                        affected_resource: Some(crate::value::fs_path_resource(&path)),
                        callee: None,
                        provenance: vec![model_node],
                        limit: Some("max_listing_depth".to_string()),
                        detail: Some(
                            "pytest collection walk reached a depth bound or a directory link cycle".to_string(),
                        ),
                    },
                    CoverageLevel::Partial,
                );
            }
        }
    }
}

fn emit_entry_point_boundary(builder: &mut PlanBuilder, model_node: ProvenanceRef) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::UNRESOLVED_SOURCE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            domains: vec![Domain::new("filesystem")],
            affected_resource: None,
            callee: None,
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "pytest11 entry-point autoload depends on installed distribution metadata"
                    .to_string(),
            ),
        },
        CoverageLevel::Partial,
    );
}

#[cfg(test)]
mod tests {
    use super::{advanced_option, config_features, is_ancestor};

    #[test]
    fn filesystem_root_is_an_ancestor_of_every_absolute_path() {
        assert!(is_ancestor("/", "/workspace/project"));
        assert!(is_ancestor("/", "/"));
        assert!(is_ancestor("/workspace", "/workspace/project"));
        assert!(!is_ancestor("/workspace", "/workspace2"));
        assert!(!is_ancestor("/workspace/project", "/workspace"));
    }

    #[test]
    fn detects_advanced_config_features() {
        let ini = config_features(
            "pytest.ini",
            "[pytest]\ntestpaths:\n    tests\naddopts: --pyargs project",
        )
        .unwrap()
        .unwrap();
        let toml = config_features(
            "pyproject.toml",
            "  [tool.pytest.ini_options] # config\npython_files = [\"*.py\"]",
        )
        .unwrap()
        .unwrap();
        assert_eq!(ini, ["testpaths", "addopts"]);
        assert_eq!(toml, ["python_files"]);
        let mixed = config_features(
            "pyproject.toml",
            "[tool.pytest]\ntestpaths = [\"sibling\"]\n[tool.pytest.ini_options]\n",
        )
        .unwrap()
        .unwrap();
        assert!(mixed.iter().any(|key| key == "testpaths"));
        let native = config_features("pytest.toml", "[pytest]\ntestpaths = [\"sibling\"]\n")
            .unwrap()
            .unwrap();
        let hidden = config_features(".pytest.toml", "[pytest]\npythonpath = [\"lib\"]\n")
            .unwrap()
            .unwrap();
        assert_eq!(native, ["testpaths"]);
        assert_eq!(hidden, ["pythonpath"]);
        assert!(
            config_features("pytest.toml", "")
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert!(config_features("tox.ini", "[tox]\n").unwrap().is_none());
        assert!(config_features("pyproject.toml", "[tool.pytest.ini_options").is_err());
        assert!(config_features("pytest.toml", "[pytest").is_err());

        for (name, section) in [
            ("pytest.ini", "pytest"),
            (".pytest.ini", "pytest"),
            ("tox.ini", "pytest"),
            ("setup.cfg", "tool:pytest"),
        ] {
            let config = format!(
                "[{section}]\nfilterwarnings =\n    error::mypkg.MyWarning\ncustom = mypkg.handler\n"
            );
            assert_eq!(
                config_features(name, &config).unwrap().unwrap(),
                ["filterwarnings", "custom"],
                "{name}"
            );
        }
        for name in ["pytest.toml", ".pytest.toml"] {
            let config = "[pytest]\nfilterwarnings = [\"error::mypkg.MyWarning\"]\n";
            assert_eq!(
                config_features(name, config).unwrap().unwrap(),
                ["filterwarnings"]
            );
        }
        let plain = "[pytest]\nminversion = 8.4.1\nfilterwarnings = ignore:message.regex:builtins.DeprecationWarning:module.regex\n";
        assert!(
            config_features("pytest.ini", plain)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        let crlf = plain.replace('\n', "\r\n");
        assert_eq!(config_features("pytest.ini", &crlf), Ok(Some(Vec::new())));
        for separator in [
            '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
        ] {
            let mixed = format!(
                "[pytest]\nfilterwarnings = ignore::DeprecationWarning::{separator}    error::mypkg.MyWarning\n"
            );
            assert!(
                config_features("pytest.ini", &mixed).is_err(),
                "{separator:?}"
            );
        }
    }

    #[test]
    fn advanced_options_distinguish_values_and_positionals() {
        for (input, expected) in [
            ("-pplugin", ("-p", false, Some("plugin"))),
            ("-p", ("-p", true, None)),
            ("-c=settings.toml", ("-c", false, Some("settings.toml"))),
            ("--rootdir=.", ("--rootdir", false, Some("."))),
            ("--confcutdir", ("--confcutdir", true, None)),
            ("--pyargs", ("--pyargs", false, None)),
            ("--import-mode", ("--import-mode", true, None)),
            ("-W", ("-W", true, None)),
            (
                "-Werror::mypkg.MyWarning",
                ("-W", false, Some("error::mypkg.MyWarning")),
            ),
            (
                "-ofilterwarnings=error",
                ("-o", false, Some("filterwarnings=error")),
            ),
            (
                "--override-ini=filterwarnings=error",
                ("--override-ini", false, Some("filterwarnings=error")),
            ),
        ] {
            assert_eq!(advanced_option(input), Some(expected), "{input}");
        }
    }
}
