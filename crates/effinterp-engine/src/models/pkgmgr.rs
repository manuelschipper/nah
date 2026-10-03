//! Package managers: `apt`/`apt-get`/`dnf`/`yum`/`pip`/`npm`. Installs fetch
//! over the network, write to system/library paths we cannot enumerate, and
//! run maintainer/setup scripts that are arbitrary code — so an install is a
//! network effect plus an explicit boundary, never a fabricated file list.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    Effect, ExecutionContent, ExecutionEdgeKind, ExecutionInputReason, ExecutionInputRole,
    ExecutionNodeRef, ExecutionPhase, ExecutionRealm, ExecutionSelection, ExecutionSelector,
    Modality, Operation, ProvenanceKind, ProvenanceRef, ResourceExpr, ResourceIdentity, Subject,
};

use super::artifact::NpmSetting;
use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::common::{
    Attrs, RuntimeSourceLanguage, arg_effect, arg_node, program_input_attrs, program_output_attrs,
    runtime_selected_source,
};
use crate::models::{CommandModel, InvocationCtx, source_refusal_detail};
use crate::nest::{SourceResolution, Transition};
use crate::value::unresolved_resource;
use crate::word::Word;

pub(crate) fn pkgmgr_models() -> Vec<Box<dyn CommandModel>> {
    vec![Box::new(PkgMgr)]
}

struct PkgMgr;

/// The models that run a package's binary: npx's for `npx` and the explicit
/// `--package` command of `npm exec`, `pnpm dlx` and `yarn dlx`; bunx's for
/// `bunx` and `bun x`. The execution edge to the launched child cites one,
/// but its child's argv[0] is a package operand only under
/// [`PACKAGE_BINARY_INFERENCE_MODEL`].
pub const PACKAGE_LAUNCH_MODELS: &[&str] = &[
    "p18b/package-build-vcs/npx@v1",
    "p18b/package-build-vcs/bunx@v1",
];

/// The certificate on a package-launch child edge that the launcher inferred
/// the binary, the child's argv[0], from its package operand: the operand
/// itself, or its name without a version spec. It is absent when `--package`
/// makes that word an explicit command.
pub const PACKAGE_BINARY_INFERENCE_MODEL: &str = "package/binary-inference@v0";

// Built-in commands take precedence over shorthand package scripts. These lists are
// pinned to npm 11.17.0, pnpm 12.3.4, Yarn Classic 1.22.22, and Bun 1.4.2 `--help`.
const NPM_BUILTIN_SUBCOMMANDS: &[&str] = &[
    "access",
    "adduser",
    "approve-scripts",
    "audit",
    "bugs",
    "cache",
    "ci",
    "completion",
    "config",
    "dedupe",
    "deny-scripts",
    "deprecate",
    "diff",
    "dist-tag",
    "docs",
    "doctor",
    "edit",
    "exec",
    "explain",
    "explore",
    "find-dupes",
    "fund",
    "get",
    "help",
    "help-search",
    "init",
    "install",
    "install-ci-test",
    "install-scripts",
    "install-test",
    "link",
    "ll",
    "login",
    "logout",
    "ls",
    "org",
    "outdated",
    "owner",
    "pack",
    "ping",
    "pkg",
    "prefix",
    "profile",
    "prune",
    "publish",
    "query",
    "rebuild",
    "repo",
    "restart",
    "root",
    "run",
    "sbom",
    "search",
    "set",
    "shrinkwrap",
    "stage",
    "star",
    "stars",
    "start",
    "stop",
    "team",
    "test",
    "token",
    "trust",
    "undeprecate",
    "uninstall",
    "unpublish",
    "unstar",
    "update",
    "version",
    "view",
    "whoami",
];

const PNPM_BUILTIN_SUBCOMMANDS: &[&str] = &[
    "access",
    "adduser",
    "add",
    "approve-builds",
    "audit",
    "bin",
    "bugs",
    "cache",
    "cat-file",
    "cat-index",
    "c",
    "change",
    "ci",
    "clean",
    "clean-install",
    "completion",
    "config",
    "create",
    "dedupe",
    "deploy",
    "deprecate",
    "dislink",
    "dist-tag",
    "dist-tags",
    "dlx",
    "docs",
    "doctor",
    "edit",
    "env",
    "exec",
    "fetch",
    "find",
    "find-hash",
    "get",
    "help",
    "home",
    "i",
    "ic",
    "ignored-builds",
    "import",
    "info",
    "init",
    "install",
    "install-clean",
    "install-test",
    "issues",
    "it",
    "la",
    "lane",
    "licences",
    "licenses",
    "link",
    "list",
    "ll",
    "ln",
    "login",
    "logout",
    "ls",
    "m",
    "multi",
    "outdated",
    "owner",
    "owners",
    "pack",
    "pack-app",
    "patch",
    "patch-commit",
    "patch-remove",
    "peers",
    "ping",
    "pkg",
    "prefix",
    "profile",
    "prune",
    "publish",
    "purge",
    "rb",
    "rebuild",
    "recursive",
    "remove",
    "repo",
    "restart",
    "root",
    "run",
    "rm",
    "rt",
    "runtime",
    "s",
    "sbom",
    "se",
    "search",
    "self-update",
    "set",
    "set-script",
    "show",
    "setup",
    "shim",
    "stage",
    "ss",
    "star",
    "stars",
    "start",
    "stop",
    "store",
    "team",
    "test",
    "token",
    "un",
    "undeprecate",
    "uni",
    "unlink",
    "uninstall",
    "unpublish",
    "unstar",
    "up",
    "update",
    "upgrade",
    "v",
    "version",
    "view",
    "whoami",
    "why",
    "with",
    "xmas",
];

const YARN_BUILTIN_SUBCOMMANDS: &[&str] = &[
    "access",
    "add",
    "audit",
    "autoclean",
    "bin",
    "cache",
    "check",
    "config",
    "create",
    "exec",
    "generate-lock-entry",
    "generateLockEntry",
    "global",
    "help",
    "import",
    "info",
    "init",
    "install",
    "licenses",
    "link",
    "list",
    "login",
    "logout",
    "node",
    "outdated",
    "owner",
    "pack",
    "policies",
    "publish",
    "remove",
    "run",
    "tag",
    "team",
    "unlink",
    "unplug",
    "upgrade",
    "upgrade-interactive",
    "upgradeInteractive",
    "version",
    "versions",
    "why",
    "workspace",
    "workspaces",
];

const BUN_BUILTIN_SUBCOMMANDS: &[&str] = &[
    "a", "add", "audit", "build", "c", "create", "dedupe", "exec", "i", "info", "init", "install",
    "link", "outdated", "patch", "pm", "prune", "publish", "remove", "repl", "rm", "run", "test",
    "unlink", "update", "upgrade", "why", "x",
];

fn is_package_manager_builtin(manager: &str, command: &str) -> bool {
    let commands = match manager {
        "npm" => NPM_BUILTIN_SUBCOMMANDS,
        "pnpm" => PNPM_BUILTIN_SUBCOMMANDS,
        "yarn" => YARN_BUILTIN_SUBCOMMANDS,
        "bun" => BUN_BUILTIN_SUBCOMMANDS,
        _ => return false,
    };
    commands.contains(&command)
}

fn is_package_install_family(command: &str) -> bool {
    matches!(
        command,
        "install"
            | "i"
            | "add"
            | "remove"
            | "rm"
            | "uninstall"
            | "upgrade"
            | "update"
            | "up"
            | "link"
            | "unlink"
            | "publish"
            | "init"
            | "create"
            | "exec"
            | "dlx"
            | "x"
            | ""
    )
}

fn has_unsupported_package_selection(
    ctx: &InvocationCtx<'_>,
    manager: &str,
    script_index: Option<usize>,
) -> bool {
    let separator = ctx
        .argv
        .iter()
        .position(|word| word.as_literal() == Some("--"))
        .unwrap_or(ctx.argv.len());
    let option_end = if manager == "npm" {
        separator
    } else {
        script_index.unwrap_or(separator).min(separator)
    };
    let selection_words: Vec<_> = ctx.argv[1..option_end]
        .iter()
        .filter_map(|word| word.as_literal())
        .collect();
    // npm and pnpm read `--if-present` as a run option; other managers'
    // readings of it are not modeled.
    let lifecycle_selection = selection_words.contains(&"--ignore-scripts")
        || (!matches!(manager, "npm" | "pnpm") && selection_words.contains(&"--if-present"));
    let workspace_selection = selection_words.into_iter().any(|word| match manager {
        "npm" => {
            matches!(word, "-w" | "--workspace" | "--workspaces")
                || word.starts_with("-w=")
                || word.starts_with("--workspace=")
                || word.starts_with("--workspaces=")
        }
        "pnpm" => {
            matches!(
                word,
                "-r" | "--recursive" | "-F" | "--filter" | "-w" | "--workspace-root"
            ) || word.starts_with("--filter=")
        }
        "yarn" => matches!(word, "workspace" | "workspaces"),
        "bun" => {
            matches!(word, "-F" | "--filter" | "--workspaces") || word.starts_with("--filter=")
        }
        _ => false,
    });
    lifecycle_selection || workspace_selection
}

/// Options that change how npm or pnpm reports a script run, not which
/// script runs or its arguments: npm's `-s` and `--silent` are `--loglevel
/// silent`, `-q` and `--quiet` `--loglevel warn`, and `-d` to `-ddd` raise it.
/// `--if-present` only turns a missing script into a no-op.
fn is_neutral_run_option(manager: &str, word: &str) -> bool {
    match manager {
        "npm" => {
            matches!(
                word,
                "-s" | "--silent"
                    | "-q"
                    | "--quiet"
                    | "-d"
                    | "-dd"
                    | "-ddd"
                    | "--verbose"
                    | "--timing"
                    | "--if-present"
            ) || word.starts_with("--loglevel=")
        }
        "pnpm" => matches!(word, "-s" | "--silent" | "--if-present"),
        _ => false,
    }
}

/// Whether `npm install` or `npm ci` may install the project itself. npm 11
/// runs the root package's install lifecycle only then: when no package is
/// named and the install is not global. It first drops an operand that
/// resolves to its own prefix, so `npm install .` is bare. An operand that
/// may be an unresolved option's value may leave the install bare.
fn npm_installs_project(ctx: &InvocationCtx<'_>, sub_index: usize) -> bool {
    let parsed = super::artifact::npm_options(ctx, 1);
    !parsed.relocated(ctx)
        && parsed
            .operands
            .iter()
            .filter(|index| **index > sub_index)
            .all(|&index| {
                parsed.maybe_value(index)
                    || ctx.argv[index]
                        .as_literal()
                        .is_some_and(|operand| super::artifact::npm_prefix_is_cwd(ctx, operand))
            })
}

/// Whether `npm version` may bump the root package, which runs its version
/// lifecycle: one new-version operand and no workspace selection.
fn npm_versions_project(ctx: &InvocationCtx<'_>, sub_index: usize) -> bool {
    let parsed = super::artifact::npm_options(ctx, 1);
    let operands: Vec<usize> = parsed
        .operands
        .iter()
        .copied()
        .filter(|index| *index > sub_index)
        .collect();
    !parsed.selects_workspaces()
        && !parsed.relocated(ctx)
        && !operands.is_empty()
        && operands
            .iter()
            .filter(|index| !parsed.maybe_value(**index))
            .count()
            <= 1
}

/// Whether a Bun option relocates the package it acts on: another
/// directory, a global install or a workspace filter.
fn bun_relocates(word: &str) -> bool {
    matches!(word, "-g" | "--global" | "--cwd" | "-F" | "--filter")
        || word.starts_with("--cwd=")
        || word.starts_with("--filter=")
}

/// Whether `bun install` installs the project itself: it names no package,
/// counting option values as values, and no option relocates it.
fn bun_installs_project(ctx: &InvocationCtx<'_>, sub_index: usize) -> bool {
    bun_package_operand_index(ctx, sub_index) == 0
        && !ctx.argv[sub_index + 1..]
            .iter()
            .filter_map(Word::as_literal)
            .any(bun_relocates)
}

/// `bun pm pack` packs the project and runs its `prepack`, `prepare` and
/// `postpack` scripts, during `--dry-run` too, unless `--ignore-scripts`.
/// Its output options (`--destination`, `--filename`, `--gzip-level`) choose
/// where the tarball goes, not which package is packed.
fn bun_pack(builder: &mut PlanBuilder, ctx: &InvocationCtx<'_>, model_node: ProvenanceRef) {
    let words = &ctx.argv[3..];
    let project = !words.iter().filter_map(Word::as_literal).any(bun_relocates);
    npm_lifecycle_inputs(
        builder,
        ctx,
        model_node,
        "bun",
        &["prepack", "prepare", "postpack"],
        "pack",
        project,
    );
    arg_effect(
        builder,
        ctx,
        model_node,
        2,
        "filesystem.read",
        ctx.resolve_fs_word(&Word::literal("package.json")),
        program_input_attrs(),
    );
    if !words
        .iter()
        .any(|word| word.as_literal() == Some("--dry-run"))
    {
        arg_effect(
            builder,
            ctx,
            model_node,
            2,
            "filesystem.write",
            unresolved_resource("filesystem"),
            program_output_attrs(),
        );
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::MODEL_COVERAGE,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("filesystem")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("bun pm pack file inventory and archive name are unmodeled".into()),
    });
}

/// `npm rebuild` runs the install scripts of the packages it rebuilds, all
/// of them when none is named, and relinks their binaries. The project root
/// is among them unless a workspace is selected or packages are named, so
/// only then are its install hooks followed; npm 11's Arborist runs `prepare`
/// for linked packages only, not for the root. Dependencies' scripts stay a
/// boundary.
fn npm_rebuild(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    sub_index: usize,
) {
    let parsed = super::artifact::npm_options(ctx, 1);
    let project = !parsed.selects_workspaces()
        && !parsed.relocated(ctx)
        && parsed
            .operands
            .iter()
            .filter(|index| **index > sub_index)
            .all(|index| parsed.maybe_value(*index));
    if project {
        npm_lifecycle_inputs(
            builder,
            ctx,
            model_node,
            "npm",
            &["preinstall", "install", "postinstall"],
            "rebuild",
            true,
        );
    }
    arg_effect(
        builder,
        ctx,
        model_node,
        sub_index as u32,
        "filesystem.write",
        unresolved_resource("filesystem"),
        program_output_attrs(),
    );
    builder.boundary(Boundary {
        reason: BoundaryReason::PACKAGE_SCRIPTS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Environment,
        affected_resource: None,
        callee: None,
        domains: ["filesystem", "process", "environment", "network"]
            .iter()
            .map(|domain| Domain::new(*domain))
            .collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(
            "npm rebuild runs dependency install scripts (arbitrary code) and writes unenumerated paths"
                .into(),
        ),
    });
    for domain in ["filesystem", "network", "process"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
}

/// pip install's long options that take a value, from pip 25.1's install
/// parser (its own options and pip's general options).
const PIP_INSTALL_VALUE_OPTIONS: &[&str] = &[
    "--abi",
    "--cache-dir",
    "--cert",
    "--client-cert",
    "--config-settings",
    "--constraint",
    "--default-timeout",
    "--editable",
    "--exists-action",
    "--extra-index-url",
    "--find-links",
    "--global-option",
    "--group",
    "--implementation",
    "--index-url",
    "--keyring-provider",
    "--local-log",
    "--log",
    "--log-file",
    "--no-binary",
    "--only-binary",
    "--platform",
    "--prefix",
    "--progress-bar",
    "--proxy",
    "--pypi-url",
    "--python",
    "--python-version",
    "--report",
    "--requirement",
    "--resume-retries",
    "--retries",
    "--root",
    "--root-user-action",
    "--source",
    "--source-dir",
    "--source-directory",
    "--src",
    "--target",
    "--timeout",
    "--trusted-host",
    "--upgrade-strategy",
    "--use-deprecated",
    "--use-feature",
];

/// pip install's long options that take no value. optparse accepts any
/// unique prefix of a long option, so a prefix is resolved against both lists.
const PIP_INSTALL_FLAG_OPTIONS: &[&str] = &[
    "--break-system-packages",
    "--check-build-dependencies",
    "--compile",
    "--debug",
    "--disable-pip-version-check",
    "--dry-run",
    "--force-reinstall",
    "--help",
    "--ignore-installed",
    "--ignore-requires-python",
    "--isolated",
    "--no-build-isolation",
    "--no-cache-dir",
    "--no-clean",
    "--no-color",
    "--no-compile",
    "--no-dependencies",
    "--no-deps",
    "--no-index",
    "--no-input",
    "--no-python-version-warning",
    "--no-use-pep517",
    "--no-user",
    "--no-warn-conflicts",
    "--no-warn-script-location",
    "--pre",
    "--prefer-binary",
    "--quiet",
    "--require-hashes",
    "--require-venv",
    "--require-virtualenv",
    "--upgrade",
    "--use-pep517",
    "--user",
    "--verbose",
    "--version",
];

/// pip install's short options that take a value; its other short options
/// (`-I`, `-U`, `-V`, `-h`, `-q`, `-v`) take none.
const PIP_INSTALL_SHORT_VALUE_OPTIONS: &str = "Ccefirt";

/// The requirements a `pip install` whose subcommand is at `sub_index` installs,
/// each with the argv index that spells it, or `None` when help, before or
/// after the subcommand, ends pip before it installs anything.
fn pip_install_requirements<'a>(
    ctx: &'a InvocationCtx<'_>,
    sub_index: usize,
) -> Option<Vec<(usize, &'a str)>> {
    // pip parses its global options up to the subcommand, then the install
    // options after it; either phase's help exits.
    pip_arguments(ctx, 1..sub_index)?;
    pip_arguments(ctx, sub_index + 1..ctx.argv.len())
}

/// The requirement operands and `-e`/`--editable` values among `range` of the
/// argv, each with its index, read the way pip's optparse parser assigns
/// arguments to options; `None` when the range asks for help. Other options'
/// values, such as `--target` or `-r`, are never requirements, and a value
/// spelled `--help` is not help.
fn pip_arguments<'a>(
    ctx: &'a InvocationCtx<'_>,
    range: std::ops::Range<usize>,
) -> Option<Vec<(usize, &'a str)>> {
    let mut requirements = Vec::new();
    let mut words = ctx
        .argv
        .iter()
        .enumerate()
        .take(range.end)
        .skip(range.start);
    while let Some((index, word)) = words.next() {
        let Some(word) = word.as_literal() else {
            continue;
        };
        if word == "--" {
            requirements
                .extend(words.filter_map(|(index, word)| Some((index, word.as_literal()?))));
            break;
        }
        // A long option, or a unique prefix of one, with its value attached
        // after `=` or in the next argument.
        if let Some(long) = word.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let name = format!("--{name}");
            let known = PIP_INSTALL_VALUE_OPTIONS
                .iter()
                .chain(PIP_INSTALL_FLAG_OPTIONS)
                .copied();
            let option = known.clone().find(|option| *option == name).or_else(|| {
                let mut matches = known.filter(|option| option.starts_with(&name));
                matches.next().filter(|_| matches.next().is_none())
            });
            if option == Some("--help") {
                return None;
            }
            if option.is_some_and(|option| PIP_INSTALL_VALUE_OPTIONS.contains(&option)) {
                let value = match attached {
                    Some(value) => Some((index, value)),
                    None => words
                        .next()
                        .and_then(|(index, word)| Some((index, word.as_literal()?))),
                };
                if option == Some("--editable") {
                    requirements.extend(value);
                }
            }
            continue;
        }
        // A cluster of short options; a value-taking one takes the rest of the
        // word, or the next argument.
        if let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) {
            for (offset, short) in cluster.char_indices() {
                if short == 'h' {
                    return None;
                }
                if PIP_INSTALL_SHORT_VALUE_OPTIONS.contains(short) {
                    let rest = &cluster[offset + short.len_utf8()..];
                    let value = if rest.is_empty() {
                        words
                            .next()
                            .and_then(|(index, word)| Some((index, word.as_literal()?)))
                    } else {
                        Some((index, rest))
                    };
                    if short == 'e' {
                        requirements.extend(value);
                    }
                    break;
                }
            }
            continue;
        }
        requirements.push((index, word));
    }
    Some(requirements)
}

/// The repository a pip VCS requirement clones: a `git+http://`,
/// `git+https://` or `git+ssh://` URL, alone or as the direct reference of a
/// named requirement (`name @ git+…`, PEP 508). The endpoint is read from the
/// URL; its `@rev` and `#egg=` suffixes stay in the endpoint's path.
fn pip_vcs_endpoint(requirement: &str) -> Option<ResourceIdentity> {
    let url = match requirement.split_once('@') {
        Some((name, reference)) if !requirement.starts_with("git+") => {
            let name = name.trim();
            let name = name.split_once('[').map_or(name, |(name, _)| name);
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return None;
            }
            // A marker follows the URL after whitespace.
            reference.split_whitespace().next()?
        }
        _ => requirement,
    };
    let url = url.strip_prefix("git+")?;
    ["http://", "https://", "ssh://"]
        .iter()
        .any(|scheme| url.to_ascii_lowercase().starts_with(scheme))
        .then(|| crate::value::parse_url_endpoint(url))
        .flatten()
}

fn bun_package_operand_index(ctx: &InvocationCtx<'_>, sub_index: usize) -> u32 {
    // Value-taking options from Bun 1.4.2 add/install/remove --help.
    let mut words = ctx.argv.iter().enumerate().skip(sub_index + 1);
    while let Some((index, word)) = words.next() {
        let Some(word) = word.as_literal() else {
            return 0;
        };
        if word == "--" {
            return words.next().map_or(0, |(index, _)| index as u32);
        }
        if matches!(
            word,
            "-c" | "--config"
                | "--ca"
                | "--cafile"
                | "--cache-dir"
                | "--cwd"
                | "--backend"
                | "--registry"
                | "--concurrent-scripts"
                | "--network-concurrency"
                | "--omit"
                | "--linker"
                | "--minimum-release-age"
                | "--cpu"
                | "--os"
                | "-F"
                | "--filter"
        ) {
            words.next();
        } else if !word.starts_with('-') {
            return index as u32;
        }
    }
    0
}

/// npm's subcommand: the first operand of its configuration reading, or a
/// later subcommand modeled here when the operands before it may be an
/// unresolved option's values.
fn npm_subcommand<'a>(ctx: &'a InvocationCtx<'_>) -> Option<(usize, &'a str)> {
    let parsed = super::artifact::npm_options(ctx, 1);
    parsed
        .select(
            ctx,
            1,
            &[
                "publish",
                "unpublish",
                "owner",
                "author",
                "deprecate",
                "pack",
                "install",
                "i",
                "ci",
                "clean-install",
                "ic",
                "install-clean",
                "version",
            ],
        )
        .or_else(|| {
            let index = *parsed.operands.first()?;
            Some((index, ctx.argv[index].as_literal()?))
        })
}

fn npm_configuration_read(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    index: usize,
) {
    arg_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        "filesystem.read",
        ctx.resolve_fs_word(&Word::literal(".npmrc")),
        program_input_attrs(),
    );
}

fn npm_special_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) -> bool {
    let Some((sub_index, subcommand)) = npm_subcommand(ctx) else {
        return false;
    };
    let parsed = super::artifact::npm_options(ctx, 1);
    if matches!(subcommand, "publish" | "unpublish" | "pack") && parsed.prints_only() {
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        return true;
    }
    if matches!(subcommand, "owner" | "author") {
        let Some(action) = ctx.argv.get(sub_index + 1).and_then(Word::as_literal) else {
            return false;
        };
        if action != "ls" {
            return false;
        }
        let mut package = None;
        let mut words = ctx.argv.iter().enumerate().skip(sub_index + 2);
        while let Some((_, word)) = words.next() {
            let Some(word) = word.as_literal() else {
                return false;
            };
            if matches!(word, "--registry" | "--otp") {
                if words
                    .next()
                    .and_then(|(_, word)| word.as_literal())
                    .is_none()
                {
                    return false;
                }
            } else if word.starts_with("--registry=") || word.starts_with("--otp=") {
            } else if word.starts_with('-') || package.replace(word).is_some() {
                return false;
            }
        }
        npm_configuration_read(builder, ctx, model_node, sub_index);
        let mut attributes = Attrs::from([
            ("action".into(), AttrValue::String("list".into())),
            ("package_manager".into(), AttrValue::String("npm".into())),
        ]);
        if let Some(package) = package {
            attributes.insert("package".into(), AttrValue::String(package.into()));
        }
        arg_effect(
            builder,
            ctx,
            model_node,
            sub_index as u32,
            "network.request",
            unresolved_resource("network"),
            attributes,
        );
        for domain in ["filesystem", "network", "process"] {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        return true;
    }
    if subcommand == "deprecate" {
        let mut operands = Vec::new();
        let mut words = ctx.argv.iter().skip(sub_index + 1);
        while let Some(word) = words.next() {
            let Some(word) = word.as_literal() else {
                return false;
            };
            if matches!(word, "--registry" | "--otp") {
                if words.next().and_then(Word::as_literal).is_none() {
                    return false;
                }
            } else if word.starts_with("--registry=") || word.starts_with("--otp=") {
            } else if word.starts_with('-') {
                return false;
            } else {
                operands.push(word);
            }
        }
        if operands.len() != 2 {
            return false;
        }
        npm_configuration_read(builder, ctx, model_node, sub_index);
        let attributes = Attrs::from([
            ("action".into(), AttrValue::String("deprecate".into())),
            ("package".into(), AttrValue::String(operands[0].into())),
            ("package_manager".into(), AttrValue::String("npm".into())),
        ]);
        arg_effect(
            builder,
            ctx,
            model_node,
            sub_index as u32,
            "network.upload",
            unresolved_resource("network"),
            attributes,
        );
        for domain in ["filesystem", "network", "process"] {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Full);
        }
        return true;
    }
    if subcommand != "pack" {
        return false;
    }
    // `npm pack <spec>` packs that package, and a workspace selection packs
    // the workspaces, instead of the project.
    if parsed.selects_workspaces()
        || parsed
            .operands
            .iter()
            .any(|index| *index > sub_index && !parsed.maybe_value(*index))
    {
        return false;
    }
    let dry_run = parsed.setting("dry-run") == NpmSetting::Proven;
    npm_configuration_read(builder, ctx, model_node, sub_index);
    npm_lifecycle_inputs(
        builder,
        ctx,
        model_node,
        "npm",
        &["prepack", "prepare", "postpack"],
        "pack",
        true,
    );
    for path in ["package.json", "."] {
        arg_effect(
            builder,
            ctx,
            model_node,
            sub_index as u32,
            "filesystem.read",
            ctx.resolve_fs_word(&Word::literal(path)),
            program_input_attrs(),
        );
    }
    if !dry_run {
        arg_effect(
            builder,
            ctx,
            model_node,
            sub_index as u32,
            "filesystem.write",
            unresolved_resource("filesystem"),
            program_output_attrs(),
        );
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::PACKAGE_SCRIPTS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Environment,
        affected_resource: None,
        callee: None,
        domains: ["filesystem", "network", "process"]
            .into_iter()
            .map(Domain::new)
            .collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some("npm pack lifecycle hooks may execute arbitrary code".into()),
    });
    builder.boundary(Boundary {
        reason: BoundaryReason::MODEL_COVERAGE,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("filesystem")],
        provenance: vec![model_node],
        limit: None,
        detail: Some("npm pack file inventory and archive name are unmodeled".into()),
    });
    true
}

fn mark_package_publication_access(builder: &mut PlanBuilder, first_effect: usize) {
    let publishes = (first_effect..builder.effects_len())
        .any(|index| builder.effect_operation(index) == Some("artifact.publish"));
    for index in first_effect..builder.effects_len() {
        let operation = builder.effect_operation(index);
        let input_read = operation == Some("filesystem.read");
        let upload = operation == Some("network.upload");
        let tarball_read = input_read
            && matches!(builder.effect_resource(index), Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path }
            }) if path.ends_with(".tgz") || path.ends_with(".tar.gz"));
        if input_read {
            builder.set_effect_string_attribute(index, "access_purpose", "program_input");
        }
        if tarball_read || (publishes && upload) {
            builder.set_effect_string_attribute(index, "disclosure", "contents");
        }
    }
}

/// The child a package runner's exec mode starts.
enum RunnerChild {
    /// A package's binary. Without `packages` the command's first word is the
    /// package the binary is selected from; with them it is an explicit
    /// command, lowered through npx's model.
    Launch { packages: Vec<String> },
    /// A command run by name, with the project's `node_modules/.bin` ahead of
    /// PATH.
    Exec,
    /// A shell body: the command words joined by spaces, as Node's
    /// `spawn(..., { shell: true })` joins them. With `package`, the argv
    /// index of the first package option, the runner installs packages
    /// before it runs the body.
    Shell { package: Option<usize> },
}

struct RunnerLowering {
    child: RunnerChild,
    /// Indices in the runner's argv of the words the child receives.
    words: Vec<usize>,
    /// A workspace selector runs the child in workspace directories Nah
    /// cannot name, possibly more than once.
    workspace: bool,
    /// The argv index of a directory the runner starts the child in.
    cwd: Option<usize>,
}

/// `npm exec`, `yarn dlx`, `yarn exec` and `pnpm exec` start a child process
/// that inherits the runner's environment. A form outside the literal option
/// surface parsed here keeps the manager's unmodeled boundary.
fn package_runner_dispatch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    mgr: &str,
) -> bool {
    let subcommand = ctx.argv.get(1).and_then(Word::as_literal);
    // Only Yarn Berry has `dlx`; Classic runs it as the project script `dlx`.
    // A pin names the intended generation but not the yarn that runs, so it
    // adds its generation's reading and never removes the package launch.
    let generation = (mgr == "yarn" && subcommand == Some("dlx"))
        .then(|| yarn_generation(builder, ctx))
        .flatten();
    if generation == Some(YarnGeneration::Classic) {
        yarn_run_script(builder, ctx, model_node);
    }
    let lowering = match (mgr, subcommand) {
        ("npm", Some("exec" | "x")) => npm_exec(ctx),
        ("yarn", Some("dlx")) => yarn_dlx(ctx),
        ("yarn", Some("exec")) => yarn_exec(ctx),
        ("pnpm", _) => pnpm_exec(ctx),
        _ => None,
    };
    let Some(lowering) = lowering else {
        return false;
    };
    let unknown_cwd;
    let moved_cwd;
    let moved_ctx;
    let ctx = if lowering.workspace {
        unresolved_script(
            builder,
            model_node,
            "workspace/lifecycle selection is not modeled".to_string(),
        );
        unknown_cwd = InvocationCtx {
            argv: ctx.argv,
            stdin: ctx.stdin,
            argv_provenance: ctx.argv_provenance,
            cwd: None,
            cwd_resource: Some(unresolved_resource("filesystem")),
            runtime_cwd: None,
            scope: ctx.scope,
            cwd_node: None,
            nest: ctx.nest,
            depth: ctx.depth,
            model_stack: ctx.model_stack.clone(),
        };
        &unknown_cwd
    } else if let Some(index) = lowering.cwd {
        moved_cwd = ctx.command_cwd(builder, Some((index as u32, &ctx.argv[index])));
        let (cwd, cwd_resource, runtime_cwd, cwd_node) = &moved_cwd;
        moved_ctx = InvocationCtx {
            argv: ctx.argv,
            stdin: ctx.stdin,
            argv_provenance: ctx.argv_provenance,
            cwd: cwd.as_deref(),
            cwd_resource: cwd_resource.clone(),
            runtime_cwd: runtime_cwd.as_deref(),
            scope: ctx.scope,
            cwd_node: *cwd_node,
            nest: ctx.nest,
            depth: ctx.depth,
            model_stack: ctx.model_stack.clone(),
        };
        &moved_ctx
    } else {
        ctx
    };
    let command = lowering
        .words
        .iter()
        .map(|&index| ctx.argv[index].clone())
        .collect::<Vec<_>>();
    if let RunnerChild::Shell {
        package: Some(index),
    } = lowering.child
    {
        package_install(builder, ctx, model_node, index as u32);
    }
    if !matches!(lowering.child, RunnerChild::Launch { .. }) {
        let detail = if matches!(lowering.child, RunnerChild::Shell { package: Some(_) }) {
            format!(
                "{mgr} puts the installed packages' binaries, which are not observed, ahead of PATH"
            )
        } else {
            format!("{mgr} exec searches node_modules/.bin, which is not observed, before PATH")
        };
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
        builder.boundary(Boundary {
            reason: BoundaryReason::MODEL_COVERAGE,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("process")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(detail),
        });
    }
    // npm runs a call with its `script-shell` setting, which a `.npmrc` can
    // set to any program.
    if mgr == "npm" && matches!(lowering.child, RunnerChild::Shell { .. }) {
        builder.boundary(Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("process")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "npm exec runs the call with npm's script-shell setting, which npm configuration can change and is not observed"
                    .to_string(),
            ),
        });
    }
    match lowering.child {
        RunnerChild::Launch { packages } if packages.is_empty() => {
            let establish = mgr != "yarn" || generation == Some(YarnGeneration::Berry);
            package_binary_launch(
                builder,
                ctx,
                model_node,
                &lowering.words,
                &command,
                establish,
            );
        }
        RunnerChild::Launch { packages } => {
            let mut argv = vec![Word::literal("npx")];
            argv.extend(
                packages
                    .iter()
                    .map(|package| Word::literal(format!("--package={package}"))),
            );
            argv.push(Word::literal("--"));
            argv.extend(command);
            ctx.delegate_command_model(builder, &argv, None, &[model_node]);
        }
        RunnerChild::Exec => {
            let provenance = lowering
                .words
                .iter()
                .map(|&index| ctx.argv_provenance_at(builder, index))
                .collect::<Vec<_>>();
            ctx.nest_exec(
                builder,
                &command,
                ctx.runtime_cwd,
                Some(&provenance),
                &[model_node],
            );
        }
        RunnerChild::Shell { .. } => {
            let arg = arg_node(builder, ctx, lowering.words[0] as u32);
            let source = command
                .iter()
                .map(|word| word.as_literal().unwrap())
                .collect::<Vec<_>>()
                .join(" ");
            // The selected context's cwd, which a workspace leaves unresolved.
            ctx.nest.nest(
                builder,
                Transition::file(Subject::Shell {
                    source,
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                })
                .source_cwd(ctx.runtime_cwd)
                .runtime_cwd(ctx.runtime_cwd)
                .cwd(ctx.cwd_resource.clone(), ctx.cwd_node),
                &[model_node, arg],
                ctx.depth,
            );
        }
    }
    true
}

/// Runs `argv[index..]` as the command `pnpm exec` or `yarn run` falls back
/// to: a binary from the project's `node_modules/.bin`, then PATH.
fn local_binary(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    mgr: &str,
    index: usize,
) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    builder.boundary(Boundary {
        reason: BoundaryReason::MODEL_COVERAGE,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("process")],
        provenance: vec![model_node],
        limit: None,
        detail: Some(format!(
            "{mgr} searches node_modules/.bin, which is not observed, before PATH"
        )),
    });
    let provenance = (index..ctx.argv.len())
        .map(|index| ctx.argv_provenance_at(builder, index))
        .collect::<Vec<_>>();
    ctx.nest_exec(
        builder,
        &ctx.argv[index..],
        ctx.runtime_cwd,
        Some(&provenance),
        &[model_node],
    );
}

/// `npm exec -- <package>`, `pnpm dlx <package>` and Yarn Berry's
/// `yarn dlx <package>` install the package and run the binary its manifest
/// selects, which Nah does not observe. Only a reviewed package's binary is
/// established, and only when `establish` confirms the runner selects it that
/// way; the child then runs under that binary's model, still certified as
/// inferred from the operand.
fn package_binary_launch(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    indices: &[usize],
    command: &[Word],
    establish: bool,
) {
    package_install(builder, ctx, model_node, indices[0] as u32);
    if let Some(spec) = command[0]
        .as_literal()
        .filter(|spec| remote_package_spec(spec))
    {
        remote_package_execution(builder, model_node, spec);
    }
    let certificate = builder.node(
        ProvenanceKind::ModelApplication {
            model: PACKAGE_BINARY_INFERENCE_MODEL.to_string(),
        },
        &[model_node],
    );
    let argv_provenance = indices
        .iter()
        .map(|&index| ctx.argv_provenance_at(builder, index))
        .collect::<Vec<_>>();
    if let Some(binary) = command[0]
        .as_literal()
        .and_then(reviewed_package_binary)
        .filter(|_| establish)
    {
        let mut command = command.to_vec();
        command[0] = Word::literal(binary);
        ctx.nest_exec(
            builder,
            &command,
            ctx.runtime_cwd,
            Some(&argv_provenance),
            &[model_node, certificate],
        );
        return;
    }
    unestablished_package_child(
        builder,
        ctx,
        command,
        &argv_provenance,
        &[model_node, certificate],
    );
}

/// The binary a package launcher runs for its package operand.
pub(crate) enum PackageBinary {
    /// The operand is itself the command name, as a bare package name is.
    AsSpelled,
    /// A registry `name@<version|range|latest>` of a package whose binary is
    /// reviewed in [`REVIEWED_PACKAGE_BINARIES`], selecting no release older
    /// than the first that declares it.
    Named(&'static str),
    /// Any other spec runs the binary its manifest selects, which Nah does
    /// not observe: a scoped package, an alias or protocol spec (`npm:`,
    /// `github:`, `file:`), a Git shorthand, local path or tarball after
    /// `name@`, and a registry spec of an unreviewed package, whose binary
    /// name need not be the package name (`typescript` runs `tsc`).
    Unestablished,
}

/// Reviewed packages: (package, binary, first release with that binary),
/// from the registry manifests. Every rimraf release from 2.2.0 through
/// 6.1.3 declares the single binary `rimraf`; 1.0.0 through 2.1.4 declare
/// none, so npm cannot select a binary for them. Every npm release, 1.1.25
/// through 12.1.0, declares `npm` as its first binary (later ones beside
/// `npx`): npm, pnpm and Yarn Berry select the binary named after the
/// package, and Bun the first. `latest` pointed at 6.1.3 and 12.1.0 when
/// reviewed, and a release published later is assumed to keep the binary, as
/// for an open range such as `>=5`.
const REVIEWED_PACKAGE_BINARIES: &[(&str, &str, Version)] =
    &[("rimraf", "rimraf", (2, 2, 0)), ("npm", "npm", (1, 1, 25))];

/// How npx, bunx and pnpm dlx select the binary for a package operand. A bare
/// operand keeps being read as the command name. After `name@`, only a
/// reviewed package establishes its binary, and only for a selector that
/// cannot pick a release without it: the `latest` tag, or a valid version or
/// range whose lowest candidate is at or above the first release with the
/// binary. Other tags, invalid selectors and older releases stay
/// unestablished.
pub(crate) fn package_operand_binary(operand: &str) -> PackageBinary {
    if operand.starts_with(['.', '/', '~']) {
        return PackageBinary::AsSpelled;
    }
    if operand.starts_with('@') || operand.contains(':') {
        return PackageBinary::Unestablished;
    }
    if !operand.contains('@') {
        return PackageBinary::AsSpelled;
    }
    match reviewed_package_binary(operand) {
        Some(binary) => PackageBinary::Named(binary),
        None => PackageBinary::Unestablished,
    }
}

/// A package spec fetched from outside the registry: a tarball or Git URL, a
/// hosted-Git shorthand (`github:`, `gitlab:`, `bitbucket:`, `gist:`), or the
/// bare `owner/repo` npm reads as a GitHub repository. Registry names, `npm:`
/// aliases, and `file:` or path specs are not.
pub(crate) fn remote_package_spec(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    if [
        "http://",
        "https://",
        "git://",
        "git+http://",
        "git+https://",
        "git+ssh://",
        "ssh://",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    !spec.starts_with(['@', '.', '/', '~'])
        && !spec.contains(':')
        && spec.split_once('/').is_some_and(|(owner, repo)| {
            !owner.is_empty() && !repo.is_empty() && !repo.contains('/')
        })
}

/// A package launcher installs a remotely fetched package and runs code from
/// it: the binary it selects, or the lifecycle scripts the install runs. A
/// tarball or Git-over-HTTP URL names the endpoint fetched; hosted-Git
/// shorthands and SSH remotes resolve through Git and npm configuration.
pub(crate) fn remote_package_execution(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    spec: &str,
) {
    let effect = |operation: &str, resource, attributes| Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: None,
        execution: ExecutionNodeRef(0),
        provenance: vec![model_node],
    };
    let url = spec.strip_prefix("git+").unwrap_or(spec);
    let endpoint = ["http://", "https://"]
        .iter()
        .any(|scheme| url.to_ascii_lowercase().starts_with(scheme))
        .then(|| crate::value::parse_url_endpoint(url))
        .flatten();
    let download = builder.effect(effect(
        "network.download",
        endpoint.map_or(unresolved_resource("network"), |identity| {
            ResourceExpr::Concrete { identity }
        }),
        Default::default(),
    ));
    let execution = builder.effect(effect(
        "process.code_execution",
        unresolved_resource("process"),
        [("source".to_string(), AttrValue::String("file".to_string()))]
            .into_iter()
            .collect(),
    ));
    if let (Some(download), Some(execution)) = (download, execution) {
        builder.flow_stage(crate::flow::FlowStage {
            execution: Some(builder.current_execution()),
            effects: vec![download, execution],
            bindings: vec![crate::flow::PortBinding {
                assurance: effinterp_proto::CausalAssurance::Conservative,
                from: crate::flow::BindEnd::Effect(download),
                to: crate::flow::BindEnd::Effect(execution),
            }],
            provenance: vec![model_node],
        });
    }
}

/// The binary a reviewed package's operand runs: a bare name, which npm and
/// Yarn resolve to the `latest` tag unless a local binary of that name
/// exists, or `name@<selector>` under the rules of [`package_operand_binary`].
/// Any other operand is not a reviewed package.
fn reviewed_package_binary(operand: &str) -> Option<&'static str> {
    let (name, spec) = operand.split_once('@').unwrap_or((operand, "latest"));
    let (_, binary, first) = REVIEWED_PACKAGE_BINARIES
        .iter()
        .find(|(package, ..)| *package == name)?;
    (spec == "latest" || semver_range_lower_bound(spec).is_some_and(|lower| lower >= *first))
        .then_some(*binary)
}

/// A release version without prerelease or build metadata.
type Version = (u64, u64, u64);

/// node-semver's bound on a version's major, minor and patch numbers.
const SEMVER_MAX_COMPONENT: u64 = 9_007_199_254_740_991;

/// node-semver's bound on the length of a version string.
const SEMVER_MAX_LENGTH: usize = 256;

/// The lowest version a node-semver range (npm-package-arg's registry
/// version or range, parsed loosely) can select, or `None` when the spec is
/// not such a range, a comparator set can match nothing, or the range
/// carries prerelease or build metadata, whose ordering is not reviewed here.
/// Git shorthand, local paths, tarballs and tags are therefore `None`.
fn semver_range_lower_bound(spec: &str) -> Option<Version> {
    spec.split("||")
        .map(comparator_set_lower_bound)
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .min()
}

/// One version bound: the version and whether it is itself included.
type VersionBound = (Version, bool);

/// A space-separated comparator set, or a hyphen range `A - B`.
fn comparator_set_lower_bound(set: &str) -> Option<Version> {
    // node-semver allows whitespace between an operator and its version.
    let mut words = Vec::<String>::new();
    let mut operator = None;
    for word in set.split_whitespace() {
        if matches!(word, "<" | ">" | "<=" | ">=" | "=" | "~" | "~>" | "^") {
            if operator.replace(word).is_some() {
                return None;
            }
        } else {
            words.push(format!("{}{word}", operator.take().unwrap_or("")));
        }
    }
    if operator.is_some() {
        return None;
    }
    let words = words.iter().map(String::as_str).collect::<Vec<_>>();
    let mut lower: VersionBound = ((0, 0, 0), true);
    let mut upper: Option<VersionBound> = None;
    let mut raise = |bound: VersionBound| {
        if bound.0 > lower.0 || bound.0 == lower.0 && !bound.1 {
            lower = bound;
        }
    };
    let cap = |bound: VersionBound, upper: &mut Option<VersionBound>| {
        if upper.is_none_or(|upper| bound.0 < upper.0 || bound.0 == upper.0 && !bound.1) {
            *upper = Some(bound);
        }
    };
    match words.as_slice() {
        [] => return None,
        [from, "-", to] => {
            let from = partial(from)?;
            raise((fill(&from), true));
            if let Some(bound) = partial_upper(&partial(to)?) {
                cap(bound, &mut upper);
            }
        }
        comparators => {
            for comparator in comparators {
                let (operator, version) = split_operator(comparator);
                let version = partial(version)?;
                match operator {
                    "" | "=" => {
                        if version[0].is_some() {
                            raise((fill(&version), true));
                        }
                        if let Some(bound) = partial_upper(&version) {
                            cap(bound, &mut upper);
                        }
                    }
                    ">=" => raise((fill(&version), true)),
                    ">" => match version {
                        [None, ..] => return None,
                        [Some(major), None, _] => raise(((major + 1, 0, 0), true)),
                        [Some(major), Some(minor), None] => raise(((major, minor + 1, 0), true)),
                        _ => raise((fill(&version), false)),
                    },
                    "<" => cap((fill(&version), false), &mut upper),
                    "<=" => {
                        if let Some(bound) = partial_upper(&version) {
                            cap(bound, &mut upper);
                        }
                    }
                    "~" | "~>" => {
                        raise((fill(&version), true));
                        let bound = match version {
                            [None, ..] => None,
                            [Some(major), None, _] => Some((major + 1, 0, 0)),
                            [Some(major), Some(minor), _] => Some((major, minor + 1, 0)),
                        };
                        if let Some(bound) = bound {
                            cap((bound, false), &mut upper);
                        }
                    }
                    "^" => {
                        raise((fill(&version), true));
                        let bound = match version {
                            [None, ..] => None,
                            [Some(0), Some(0), Some(patch)] => Some((0, 0, patch + 1)),
                            [Some(0), Some(minor), _] => Some((0, minor + 1, 0)),
                            [Some(major), ..] => Some((major + 1, 0, 0)),
                        };
                        if let Some(bound) = bound {
                            cap((bound, false), &mut upper);
                        }
                    }
                    _ => return None,
                }
            }
        }
    }
    // A set whose bounds cross selects no release.
    match upper {
        Some((version, inclusive))
            if version < lower.0 || version == lower.0 && !(inclusive && lower.1) =>
        {
            None
        }
        _ => Some(lower.0),
    }
}

fn split_operator(comparator: &str) -> (&str, &str) {
    let operator = ["~>", ">=", "<=", ">", "<", "=", "~", "^"]
        .into_iter()
        .find(|operator| comparator.starts_with(operator))
        .unwrap_or("");
    (operator, &comparator[operator.len()..])
}

/// A partial version `X[.Y[.Z]]`, each part a number or `x`, `X` or `*`; a
/// missing or wildcard part is `None`. Loose parsing accepts a leading `v` or
/// `=`. Anything else, including prerelease or build metadata or a component
/// above node-semver's MAX_SAFE_INTEGER, is rejected.
fn partial(text: &str) -> Option<[Option<u64>; 3]> {
    let text = text.trim_start_matches(['v', '=']);
    let mut parts = [None; 3];
    let mut wildcard = false;
    for (index, part) in text.split('.').enumerate() {
        let slot = parts.get_mut(index)?;
        match part {
            "x" | "X" | "*" => wildcard = true,
            _ if wildcard => return None,
            _ if !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0')) =>
            {
                // node-semver refuses a component above MAX_SAFE_INTEGER;
                // the bound also keeps every successor (`+ 1`) below u64::MAX.
                *slot = Some(
                    part.parse::<u64>()
                        .ok()
                        .filter(|value| *value <= SEMVER_MAX_COMPONENT)?,
                );
            }
            _ => return None,
        }
    }
    Some(parts)
}

fn fill(version: &[Option<u64>; 3]) -> Version {
    (
        version[0].unwrap_or(0),
        version[1].unwrap_or(0),
        version[2].unwrap_or(0),
    )
}

/// The upper bound a bare partial (`X`, `X.Y`, `X.Y.Z`) sets as `=` or `<=`.
fn partial_upper(version: &[Option<u64>; 3]) -> Option<VersionBound> {
    match *version {
        [None, ..] => None,
        [Some(major), None, _] => Some(((major + 1, 0, 0), false)),
        [Some(major), Some(minor), None] => Some(((major, minor + 1, 0), false)),
        [Some(major), Some(minor), Some(patch)] => Some(((major, minor, patch), true)),
    }
}

/// Records a package launch whose binary is not established. The child is
/// recorded with the package operand as argv[0], but that operand is never
/// modeled as an executable or a path: its effects stay behind an explicit
/// boundary. `provenance` carries the binary-inference certificate.
pub(crate) fn unestablished_package_child(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    command: &[Word],
    argv_provenance: &[Vec<ProvenanceRef>],
    provenance: &[ProvenanceRef],
) {
    let transition = Transition::exec(
        command.iter().map(crate::nest::word_resource).collect(),
        command.to_vec(),
    )
    .exec_cwd(ctx.runtime_cwd)
    .cwd(ctx.cwd_resource.clone(), ctx.cwd_node)
    .stdin(ctx.stdin)
    .argv_provenance(Some(argv_provenance))
    .kind(ExecutionEdgeKind::ToolModel);
    let Some(frame) = ctx.nest.begin(builder, transition, provenance, ctx.depth) else {
        return;
    };
    let mut antecedents = vec![frame.scope];
    antecedents.extend(argv_provenance.first().into_iter().flatten().copied());
    let arg0 = builder.node(ProvenanceKind::Argument { index: 0 }, &antecedents);
    let package = command[0].as_literal().unwrap_or_default().to_string();
    builder.effect(Effect {
        request_assurance: effinterp_proto::RequestAssurance::Conservative,
        id: Default::default(),
        operation: Operation::new("process.exec"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::Process {
                executable: package.clone(),
                path: None,
                argv: command[1..]
                    .iter()
                    .map(crate::nest::word_resource)
                    .collect(),
                cwd: ctx.cwd_resource.clone().map(Box::new),
            },
        },
        attributes: Default::default(),
        modality: Modality::May,
        realm: ExecutionRealm::Host,
        condition: None,
        execution: ExecutionNodeRef(0),
        provenance: vec![arg0],
    });
    crate::exec::unmodeled(
        builder,
        arg0,
        &format!(
            "no model for command {package:?}: the binary its package selects is not established"
        ),
    );
    frame.end(builder);
}

/// Installing packages downloads them into a cache Nah does not observe and
/// runs their lifecycle scripts.
fn package_install(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    operand: u32,
) {
    for (operation, family, attributes) in [
        ("network.download", "network", Attrs::default()),
        ("filesystem.write", "filesystem", program_output_attrs()),
    ] {
        arg_effect(
            builder,
            ctx,
            model_node,
            operand,
            operation,
            unresolved_resource(family),
            attributes,
        );
    }
    builder.boundary(Boundary {
        reason: BoundaryReason::PACKAGE_SCRIPTS,
        class: BoundaryClass::Unmodeled,
        scope: BoundaryScope::Environment,
        affected_resource: None,
        callee: None,
        domains: ["filesystem", "network", "process"]
            .into_iter()
            .map(Domain::new)
            .collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some("installing the package runs its lifecycle scripts".to_string()),
    });
    for domain in ["filesystem", "network", "process"] {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
}

/// `npm exec [options] [--] <package|command> [args...]`, npm 11. Without
/// `--`, npm reads an option-shaped word after the command as its own.
fn npm_exec(ctx: &InvocationCtx<'_>) -> Option<RunnerLowering> {
    let mut packages = Vec::new();
    let mut package = None;
    let mut call = None;
    let mut workspace = false;
    let mut separated = false;
    let mut index = 2;
    while let Some(word) = ctx.argv.get(index) {
        let word = word.as_literal()?;
        let value = ctx.argv.get(index + 1).and_then(Word::as_literal);
        match word {
            "--" => {
                separated = true;
                index += 1;
                break;
            }
            "--package" => {
                packages.push(value?.to_string());
                package.get_or_insert(index);
                index += 1;
            }
            "-c" | "--call" => {
                value?;
                call = Some(index + 1);
                index += 1;
            }
            "-w" | "--workspace" => {
                value?;
                workspace = true;
                index += 1;
            }
            "-ws" | "--workspaces" => workspace = true,
            // These only answer npm's install prompt.
            "-y" | "--yes" | "--no" => {}
            _ if word.starts_with("--package=") => {
                packages.push(word["--package=".len()..].to_string());
                package.get_or_insert(index);
            }
            _ if word.starts_with("--workspace=") || word.starts_with("-w=") => workspace = true,
            _ if word.starts_with('-') => return None,
            _ => break,
        }
        index += 1;
    }
    if let Some(call) = call {
        // The call body replaces the command, and npm refuses operands beside
        // it. With `--package` npm installs the packages first.
        return (call + 1 == ctx.argv.len()).then_some(RunnerLowering {
            child: RunnerChild::Shell { package },
            words: vec![call],
            workspace,
            cwd: None,
        });
    }
    let command = ctx
        .argv
        .get(index..)
        .filter(|command| !command.is_empty())?;
    if command.iter().any(|word| {
        word.as_literal()
            .is_none_or(|word| !separated && word.starts_with('-'))
    }) {
        return None;
    }
    Some(RunnerLowering {
        child: RunnerChild::Launch { packages },
        words: (index..ctx.argv.len()).collect(),
        workspace,
        cwd: None,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum YarnGeneration {
    Classic,
    Berry,
}

/// The Yarn generation the project's `package.json` pins in `packageManager`,
/// a Corepack spec `yarn@<version>[+<algorithm>.<hex>]`. Corepack runs the
/// pinned release, but a yarn run directly may be either generation: Berry
/// does not enforce the pin, and both generations hand off to an rc file's
/// `yarnPath`. The pin therefore only adds its generation's reading: a
/// Classic pin the project script `dlx`, a Berry pin the named package
/// binary. An invalid pin, or none, establishes neither.
fn yarn_generation(builder: &mut PlanBuilder, ctx: &InvocationCtx<'_>) -> Option<YarnGeneration> {
    let SourceResolution::Source {
        source: manifest, ..
    } = ctx.resolve_source_operand(builder, "package.json", SourcePurpose::InvocationInput)
    else {
        return None;
    };
    let manifest = serde_json::from_str::<serde_json::Value>(&manifest).ok()?;
    let pin = manifest
        .get("packageManager")?
        .as_str()?
        .strip_prefix("yarn@")?;
    let major = corepack_pin_major(pin)?;
    Some(if major < 2 {
        YarnGeneration::Classic
    } else {
        YarnGeneration::Berry
    })
}

/// The major version of a Corepack pin's exact semver version, with an
/// optional prerelease and an optional `+<algorithm>.<hex>` hash. Corepack
/// rejects anything else, including what node-semver refuses: a pin longer
/// than 256 characters or a core number above MAX_SAFE_INTEGER.
fn corepack_pin_major(pin: &str) -> Option<u64> {
    if pin.len() > SEMVER_MAX_LENGTH {
        return None;
    }
    let (version, hash) = pin
        .split_once('+')
        .map_or((pin, None), |(v, h)| (v, Some(h)));
    if let Some(hash) = hash {
        let (algorithm, hex) = hash.split_once('.')?;
        if algorithm.is_empty()
            || !algorithm.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || hex.is_empty()
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
    }
    let digits = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    };
    let numeric = |part: &str| {
        digits(part)
            .then(|| part.parse::<u64>().ok())
            .flatten()
            .filter(|value| *value <= SEMVER_MAX_COMPONENT)
    };
    let (core, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(c, p)| (c, Some(p)));
    if let Some(prerelease) = prerelease
        && !prerelease.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!identifier.bytes().all(|byte| byte.is_ascii_digit()) || digits(identifier))
        })
    {
        return None;
    }
    let parts = core.split('.').collect::<Vec<_>>();
    let [major, minor, patch] = parts.as_slice() else {
        return None;
    };
    numeric(minor)?;
    numeric(patch)?;
    numeric(major)
}

/// Runs `yarn <command> ...` as `yarn run <command> ...`, as a generation
/// without that command does: Yarn Classic 1.22 has no `dlx`, so `yarn dlx
/// ...` runs the project script `dlx`, and Yarn Berry has no `owner`.
fn yarn_run_script(builder: &mut PlanBuilder, ctx: &InvocationCtx<'_>, model_node: ProvenanceRef) {
    let argv = [ctx.argv[0].clone(), Word::literal("run")]
        .into_iter()
        .chain(ctx.argv[1..].iter().cloned())
        .collect::<Vec<_>>();
    let provenance = [0, 1]
        .into_iter()
        .chain(1..ctx.argv.len())
        .map(|index| ctx.argv_provenance_at(builder, index))
        .collect::<Vec<_>>();
    let ctx = InvocationCtx {
        argv: &argv,
        stdin: ctx.stdin,
        argv_provenance: Some(&provenance),
        cwd: ctx.cwd,
        cwd_resource: ctx.cwd_resource.clone(),
        runtime_cwd: ctx.runtime_cwd,
        scope: ctx.scope,
        cwd_node: ctx.cwd_node,
        nest: ctx.nest,
        depth: ctx.depth,
        model_stack: ctx.model_stack.clone(),
    };
    PkgMgr.apply(builder, &ctx, model_node);
}

/// `yarn dlx [-p <package>]... [-q] <command> [args...]`, Yarn Berry: options
/// end at the first operand.
fn yarn_dlx(ctx: &InvocationCtx<'_>) -> Option<RunnerLowering> {
    let mut packages = Vec::new();
    let mut index = 2;
    loop {
        let word = ctx.argv.get(index)?.as_literal()?;
        match word {
            "-p" | "--package" => {
                packages.push(ctx.argv.get(index + 1)?.as_literal()?.to_string());
                index += 1;
            }
            "-q" | "--quiet" => {}
            _ if word.starts_with("--package=") => {
                packages.push(word["--package=".len()..].to_string());
            }
            _ if word.starts_with('-') => return None,
            _ => break,
        }
        index += 1;
    }
    if ctx.argv[index..]
        .iter()
        .any(|word| word.as_literal().is_none())
    {
        return None;
    }
    Some(RunnerLowering {
        child: RunnerChild::Launch { packages },
        words: (index..ctx.argv.len()).collect(),
        workspace: false,
        cwd: None,
    })
}

/// `yarn exec <command> [args...]`, Yarn Classic 1.22. Classic's CLI parser
/// reads every option-shaped word before the first `--` as its own, and an
/// unknown option takes the word after it as its value; the words after
/// `--` reach the command verbatim. Only a tail with no option before `--`
/// has a known child argv: its words before and after the separator.
fn yarn_exec(ctx: &InvocationCtx<'_>) -> Option<RunnerLowering> {
    let separator = (2..ctx.argv.len()).find(|&index| ctx.argv[index].as_literal() == Some("--"));
    let before = 2..separator.unwrap_or(ctx.argv.len());
    if ctx.argv[before.clone()]
        .iter()
        .any(|word| word.as_literal().is_none_or(|word| word.starts_with('-')))
    {
        return None;
    }
    let words = before
        .chain(separator.map_or(0..0, |separator| separator + 1..ctx.argv.len()))
        .collect::<Vec<_>>();
    words.first()?;
    Some(RunnerLowering {
        child: RunnerChild::Exec,
        words,
        workspace: false,
        cwd: None,
    })
}

/// `pnpm [-c | -r | --filter <selector> | -C <dir>]... exec [--] <command>
/// [args...]`, pnpm 9 and 10. Runner options precede `exec`; everything after
/// it, less one leading `--`, is the command. A recursive or filtered exec
/// runs in each selected workspace; `-C`/`--dir` runs it in `<dir>`.
///
/// `pnpm --package <package>... -c dlx <command> [args...]` installs the
/// packages and runs the command words as a shell body. Without `-c` or
/// `--package`, `dlx` keeps the package-launch lowering.
fn pnpm_exec(ctx: &InvocationCtx<'_>) -> Option<RunnerLowering> {
    let mut workspace = false;
    let mut shell = false;
    let mut package = None;
    let mut cwd = None;
    let mut index = 1;
    let dlx = loop {
        let word = ctx.argv.get(index)?.as_literal()?;
        match word {
            "exec" => break false,
            "dlx" => break true,
            "-c" | "--shell-mode" => shell = true,
            "-r" | "--recursive" => workspace = true,
            "-F" | "--filter" => {
                ctx.argv.get(index + 1)?;
                workspace = true;
                index += 1;
            }
            "-C" | "--dir" => {
                ctx.argv.get(index + 1)?;
                cwd = Some(index + 1);
                index += 1;
            }
            "--package" => {
                ctx.argv.get(index + 1)?;
                package.get_or_insert(index);
                index += 1;
            }
            _ if word.starts_with("--filter=") => workspace = true,
            _ if word.starts_with("--package=") => {
                package.get_or_insert(index);
            }
            _ => return None,
        }
        index += 1;
    };
    if dlx != package.is_some() || dlx && (!shell || workspace || cwd.is_some()) {
        return None;
    }
    index += 1;
    if !dlx && ctx.argv.get(index).and_then(Word::as_literal) == Some("--") {
        index += 1;
    }
    let command = ctx
        .argv
        .get(index..)
        .filter(|command| !command.is_empty())?;
    if command.iter().any(|word| word.as_literal().is_none())
        || dlx && command[0].as_literal()?.starts_with('-')
    {
        return None;
    }
    Some(RunnerLowering {
        child: if shell {
            RunnerChild::Shell { package }
        } else {
            RunnerChild::Exec
        },
        words: (index..ctx.argv.len()).collect(),
        workspace,
        cwd,
    })
}

/// Bun 1.4 runs a script or file shorthand (`bun --cwd <dir> <script|file>`)
/// from `<dir>` with either `--cwd` spelling. Only the joined `--cwd=<dir>`
/// applies to `run`; the separated one leaves `run` without its script and
/// makes `x` a script name. `bun --cwd=<dir> x ...` still launches the package
/// from the original cwd. Other built-in subcommands keep the manager's
/// option boundary.
fn bun_cwd_dispatch(
    model: &PkgMgr,
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) -> bool {
    let word = |index: usize| ctx.argv.get(index).and_then(Word::as_literal);
    let mut index = 1;
    while matches!(word(index), Some("--bun" | "--silent")) {
        index += 1;
    }
    let (directory, next) = match word(index) {
        Some("--cwd") if ctx.argv.len() > index + 1 => (ctx.argv[index + 1].clone(), index + 2),
        Some(option) if option.starts_with("--cwd=") => {
            (Word::literal(&option["--cwd=".len()..]), index + 1)
        }
        _ => return false,
    };
    let joined = next == index + 1;
    let moves = match word(next) {
        Some("run") if joined => true,
        Some("x") if joined => false,
        Some(shorthand)
            if !shorthand.starts_with('-') && !is_package_manager_builtin("bun", shorthand) =>
        {
            true
        }
        _ => return false,
    };
    let kept = (0..index).chain(next..ctx.argv.len());
    let argv = kept
        .clone()
        .map(|index| ctx.argv[index].clone())
        .collect::<Vec<_>>();
    let provenance = kept
        .map(|index| ctx.argv_provenance_at(builder, index))
        .collect::<Vec<_>>();
    let (cwd, cwd_resource, runtime_cwd, cwd_node) = if moves {
        ctx.command_cwd(builder, Some(((next - 1) as u32, &directory)))
    } else {
        (
            ctx.cwd.map(str::to_string),
            ctx.cwd_resource.clone(),
            ctx.runtime_cwd.map(str::to_string),
            ctx.cwd_node,
        )
    };
    let ctx = InvocationCtx {
        argv: &argv,
        stdin: ctx.stdin,
        argv_provenance: Some(&provenance),
        cwd: cwd.as_deref(),
        cwd_resource,
        runtime_cwd: runtime_cwd.as_deref(),
        scope: ctx.scope,
        cwd_node,
        nest: ctx.nest,
        depth: ctx.depth,
        model_stack: ctx.model_stack.clone(),
    };
    model.apply(builder, &ctx, model_node);
    true
}

impl CommandModel for PkgMgr {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        "pkg/manager@v1"
    }

    fn command_names(&self) -> &'static [&'static str] {
        &[
            "apt", "apt-get", "dnf", "yum", "pip", "pip3", "npm", "pnpm", "pnpx", "yarn", "bun",
        ]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let mgr = crate::exec::dispatch_program_name(&ctx.argv[0]).unwrap_or("");
        // A case-folded or `.exe` spelling (`BUN`, `bun.exe`) reads the manifest
        // and keeps the script effects the same as `bun`; only a recognized
        // manager name folds, the launcher identity stays the original argv.
        let folded = crate::models::folded_program(mgr);
        let mgr = folded
            .as_deref()
            .filter(|folded| self.command_names().contains(folded))
            .unwrap_or(mgr);
        // pnpm's `pnpx` shim inserts `dlx` before its arguments and runs pnpm.
        if mgr == "pnpx" {
            let argv = [Word::literal("pnpm"), Word::literal("dlx")]
                .into_iter()
                .chain(ctx.argv[1..].iter().cloned())
                .collect::<Vec<_>>();
            let provenance = [0, 0]
                .into_iter()
                .chain(1..ctx.argv.len())
                .map(|index| ctx.argv_provenance_at(builder, index))
                .collect::<Vec<_>>();
            let ctx = InvocationCtx {
                argv: &argv,
                stdin: ctx.stdin,
                argv_provenance: Some(&provenance),
                cwd: ctx.cwd,
                cwd_resource: ctx.cwd_resource.clone(),
                runtime_cwd: ctx.runtime_cwd,
                scope: ctx.scope,
                cwd_node: ctx.cwd_node,
                nest: ctx.nest,
                depth: ctx.depth,
                model_stack: ctx.model_stack.clone(),
            };
            self.apply(builder, &ctx, model_node);
            return;
        }
        // Bun's runtime inputs analyze `bun -e CODE` and `bun run -`; neither
        // names a package script.
        if mgr == "bun"
            && (super::nodeexec::bun_eval_source(ctx).is_some()
                || super::nodeexec::bun_stdin_program(ctx))
        {
            return;
        }
        if mgr == "bun" && bun_cwd_dispatch(self, builder, ctx, model_node) {
            return;
        }
        if package_runner_dispatch(builder, ctx, model_node, mgr) {
            return;
        }
        if mgr == "pnpm" {
            // `--package` before `dlx` selects the installed packages, and the
            // command is explicit, lowered through npx's model. pnpm stops
            // parsing its options at `dlx`, so every word after it is the
            // command; without `--package` that word is the package whose
            // binary runs. Other runner options need their own parser.
            let mut packages = Vec::new();
            let mut index = 1;
            let mut dlx = false;
            while let Some(word) = ctx.argv.get(index).and_then(Word::as_literal) {
                if word == "dlx" {
                    dlx = true;
                    index += 1;
                    break;
                } else if word == "--package" && ctx.argv.get(index + 1).is_some() {
                    packages.extend_from_slice(&ctx.argv[index..index + 2]);
                    index += 1;
                } else if word.starts_with("--package=") {
                    packages.push(ctx.argv[index].clone());
                } else {
                    break;
                }
                index += 1;
            }
            if dlx
                && ctx
                    .argv
                    .get(index)
                    .and_then(Word::as_literal)
                    .is_some_and(|word| !word.starts_with('-'))
            {
                if packages.is_empty() {
                    let words = (index..ctx.argv.len()).collect::<Vec<_>>();
                    package_binary_launch(
                        builder,
                        ctx,
                        model_node,
                        &words,
                        &ctx.argv[index..],
                        true,
                    );
                    return;
                }
                let mut argv = vec![Word::literal("npx")];
                argv.extend(packages);
                argv.extend_from_slice(&ctx.argv[index..]);
                ctx.delegate_command_model(builder, &argv, None, &[model_node]);
                return;
            }
        }
        // `bun x` is Bun's documented alias of `bunx`. Only leading flags known
        // to take no value are skipped, so an option's value is never read as
        // `x`; `--bun` also selects the runtime for `bunx`.
        if mgr == "bun" {
            let mut argv = vec![Word::literal("bunx")];
            let mut index = 1;
            while let Some(word @ ("--bun" | "--silent")) =
                ctx.argv.get(index).and_then(Word::as_literal)
            {
                if word == "--bun" {
                    argv.push(ctx.argv[index].clone());
                }
                index += 1;
            }
            if ctx.argv.get(index).and_then(Word::as_literal) == Some("x") {
                argv.extend_from_slice(&ctx.argv[index + 1..]);
                ctx.delegate_command_model(builder, &argv, None, &[model_node]);
                return;
            }
        }
        if mgr == "npm" && npm_special_dispatch(builder, ctx, model_node) {
            return;
        }
        if mgr == "npm" {
            let first_effect = builder.effects_len();
            if super::artifact::npm_dispatch(builder, ctx, model_node) {
                mark_package_publication_access(builder, first_effect);
                return;
            }
        }
        // `yarn owner` changes owners only in Yarn Classic. A Berry pin reads it
        // as the project script `owner`; unpinned, the Classic reading stays.
        if mgr == "yarn"
            && ctx.argv.get(1).and_then(Word::as_literal) == Some("owner")
            && yarn_generation(builder, ctx) == Some(YarnGeneration::Berry)
        {
            yarn_run_script(builder, ctx, model_node);
            return;
        }
        if mgr != "npm" {
            let first_effect = builder.effects_len();
            if super::artifact::literal_package_dispatch(builder, ctx, model_node) {
                mark_package_publication_access(builder, first_effect);
                return;
            }
        }
        // First non-flag operand is the subcommand.
        let mut sub_index = 1;
        let mut sub = "";
        for (index, operand) in ctx.argv.iter().enumerate().skip(1) {
            let Some(operand) = operand.as_literal() else {
                crate::models::common::runtime_unobserved_input(
                    builder,
                    ctx,
                    "$SUBCOMMAND",
                    ExecutionInputRole::UnexpectedSelected,
                    ExecutionPhase::PackageHook,
                    ExecutionSelector::RuntimeOption {
                        option: "subcommand".into(),
                    },
                    ExecutionInputReason::Ambiguous,
                );
                continue;
            };
            if !operand.starts_with('-') {
                sub_index = index;
                sub = operand;
                break;
            }
        }
        // npm's option reading selects its subcommand; a symbolic one keeps
        // the first literal operand found above.
        if mgr == "npm" {
            if let Some(found) = npm_subcommand(ctx) {
                (sub_index, sub) = found;
            } else if super::artifact::npm_options(ctx, 1).operands.is_empty() {
                (sub_index, sub) = (1, "");
            }
        }

        if mgr != "npm" && matches!(sub, "publish" | "unpublish") {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNMODELED_SUBCOMMAND,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: ["artifact", "filesystem", "network", "process"]
                    .iter()
                    .map(|domain| Domain::new(*domain))
                    .collect(),
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!("{mgr} publication is unmodeled")),
            });
            return;
        }
        let npm_ci = mgr == "npm" && matches!(sub, "ci" | "clean-install" | "ic" | "install-clean");
        if matches!(mgr, "npm" | "pnpm" | "yarn") && matches!(sub, "" | "install" | "i") || npm_ci {
            let project = mgr == "npm" && !sub.is_empty() && npm_installs_project(ctx, sub_index);
            npm_lifecycle_inputs(
                builder,
                ctx,
                model_node,
                mgr,
                &[
                    "preinstall",
                    "install",
                    "postinstall",
                    "prepublish",
                    "preprepare",
                    "prepare",
                    "postprepare",
                ],
                "install",
                project,
            );
        } else if mgr == "npm" && sub == "version" && npm_versions_project(ctx, sub_index) {
            npm_lifecycle_inputs(
                builder,
                ctx,
                model_node,
                mgr,
                &["preversion", "version", "postversion"],
                "version",
                true,
            );
        } else if mgr == "bun"
            && sub_index == 1
            && matches!(sub, "install" | "i")
            && bun_installs_project(ctx, sub_index)
        {
            // Bun runs the project's own install and prepare scripts; a
            // dependency's only when `trustedDependencies` admits it, which
            // the install boundary below keeps. Whether an add or a named
            // install runs the root's is not established, so it stays under
            // that boundary too.
            npm_lifecycle_inputs(
                builder,
                ctx,
                model_node,
                mgr,
                &[
                    "preinstall",
                    "install",
                    "postinstall",
                    "preprepare",
                    "prepare",
                    "postprepare",
                ],
                "install",
                true,
            );
        } else if mgr == "bun"
            && sub_index == 1
            && sub == "pm"
            && ctx.argv.get(2).and_then(Word::as_literal) == Some("pack")
        {
            bun_pack(builder, ctx, model_node);
            return;
        } else if mgr == "npm" && matches!(sub, "rebuild" | "rb") {
            npm_rebuild(builder, ctx, model_node, sub_index);
            return;
        }
        let script_manager = matches!(mgr, "npm" | "pnpm" | "yarn" | "bun");
        let builtin = is_package_manager_builtin(mgr, sub);
        // npm 11 aliases `run` as `run-script`, `rum` and `urn`.
        let run =
            matches!(sub, "run" | "run-script") || (mgr == "npm" && matches!(sub, "rum" | "urn"));
        let script = if script_manager {
            if run {
                // Options before the script name belong to the manager. Never
                // interpret an option (or its value) as a manifest script.
                let index = ctx
                    .argv
                    .iter()
                    .enumerate()
                    .skip(sub_index + 1)
                    .find(|(_, word)| !word.as_literal().is_some_and(|word| word.starts_with('-')))
                    .map_or(ctx.argv.len(), |(index, _)| index);
                Some((
                    index,
                    ctx.argv
                        .get(index)
                        .and_then(|word| word.as_literal())
                        .unwrap_or(""),
                ))
            } else if matches!(mgr, "npm" | "pnpm") && matches!(sub, "t" | "tst") {
                // npm and pnpm alias `test` as `t` and `tst`.
                Some((sub_index, "test"))
            } else if (mgr == "npm" && matches!(sub, "test" | "start" | "stop" | "restart"))
                || (mgr == "pnpm" && sub == "test")
                || (mgr != "npm" && !builtin && !is_package_install_family(sub))
            {
                Some((sub_index, sub))
            } else {
                None
            }
        } else {
            None
        };
        // Workspace and lifecycle selectors belong to the lifecycle model.
        let unsupported_selection = script_manager
            && has_unsupported_package_selection(ctx, mgr, script.map(|(index, _)| index));
        if unsupported_selection
            && !matches!(
                sub,
                "install" | "i" | "add" | "remove" | "rm" | "uninstall" | "update" | "upgrade"
            )
        {
            unresolved_script(
                builder,
                model_node,
                "workspace/lifecycle selection is not modeled".to_string(),
            );
            return;
        }
        // Manager options can change the manifest or consume the apparent subcommand.
        // npm also accepts options after the script name, up to the -- separator.
        let unsupported_npm_options = mgr == "npm"
            && script.is_some()
            && ctx
                .argv
                .iter()
                .skip(sub_index + 1)
                .take_while(|word| word.as_literal() != Some("--"))
                .any(|word| {
                    word.as_literal().is_none_or(|word| {
                        word.starts_with('-') && !is_neutral_run_option(mgr, word)
                    })
                });
        // Only npm's reporting options may precede the subcommand of a script run.
        let leading = &ctx.argv[1..if sub.is_empty() {
            ctx.argv.len()
        } else {
            sub_index
        }];
        let leading_options = leading.iter().any(|word| {
            word.as_literal().is_none_or(|word| {
                word.starts_with('-')
                    && !(mgr == "npm" && script.is_some() && is_neutral_run_option(mgr, word))
            })
        });
        if unsupported_npm_options || (script_manager && leading_options) {
            builder.boundary(Boundary {
                reason: BoundaryReason::UNRESOLVED_PACKAGE_SCRIPT,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: vec![
                    Domain::new("filesystem"),
                    Domain::new("network"),
                    Domain::new("process"),
                ],
                provenance: vec![model_node],
                limit: None,
                detail: Some("package manager options are not modeled".to_string()),
            });
            return;
        }
        if let Some((index, name)) = script {
            if run
                && ctx.argv[sub_index + 1..index.min(ctx.argv.len())]
                    .iter()
                    .any(|word| {
                        word.as_literal()
                            .is_none_or(|word| !is_neutral_run_option(mgr, word))
                    })
            {
                unresolved_script(
                    builder,
                    model_node,
                    "package run options are not modeled".to_string(),
                );
                return;
            }
            // `--if-present` makes a missing script a no-op. npm reads it
            // anywhere before `--`; pnpm only before the script name.
            let if_present = match mgr {
                "npm" => ctx.argv[1..]
                    .iter()
                    .take_while(|word| word.as_literal() != Some("--"))
                    .any(|word| word.as_literal() == Some("--if-present")),
                "pnpm" => {
                    run && ctx.argv[sub_index + 1..index.min(ctx.argv.len())]
                        .iter()
                        .any(|word| word.as_literal() == Some("--if-present"))
                }
                _ => false,
            };
            let arg = arg_node(builder, ctx, index.min(ctx.argv.len() - 1) as u32);
            // A run in a followed script's text reads the manifest that script
            // came from when its cwd resolves to it and nothing may have
            // written it since. Source resolution is off inside the script,
            // so any other manifest stays unresolved.
            let inherited = ctx
                .nest
                .package_manifest
                .borrow()
                .clone()
                .filter(|(origin, _)| {
                    crate::paths::join_source_path(ctx.runtime_cwd, "package.json")
                        .is_some_and(|(_, path)| path == *origin)
                        && matches!(
                            builder.written_source(origin, |resource, path| {
                                ctx.nest.source_mutation_may_alias(resource, path)
                            }),
                            crate::builder::WrittenSource::Host
                        )
                });
            let nested = inherited.is_some();
            let resolved = match inherited {
                Some((origin, source)) => SourceResolution::Source { origin, source },
                None => ctx.resolve_source_operand(
                    builder,
                    "package.json",
                    SourcePurpose::InvocationInput,
                ),
            };
            // Whether the observed manifest proves no script of this name.
            let mut script_absent = false;
            if let SourceResolution::Source {
                origin,
                source: manifest,
            } = &resolved
            {
                let read = builder.node(
                    ProvenanceKind::ToolArgument {
                        name: origin.clone(),
                    },
                    &[model_node, arg],
                );
                builder.effect(Effect {
                    request_assurance: effinterp_proto::RequestAssurance::Conservative,
                    id: Default::default(),
                    operation: Operation::new("filesystem.read"),
                    resource: ctx.resolve_fs_word(&Word::literal("package.json")),
                    attributes: Default::default(),
                    modality: Modality::May,
                    realm: ExecutionRealm::Host,
                    condition: None,
                    execution: ExecutionNodeRef(0),
                    provenance: vec![model_node, arg, read],
                });
                builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Full);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(manifest)
                    && json.is_object()
                {
                    let scripts = json.get("scripts").filter(|scripts| scripts.is_object());
                    let main = scripts.and_then(|scripts| scripts.get(name));
                    let default_start = mgr == "npm" && name == "start" && main.is_none();
                    script_absent =
                        main.is_none() && (scripts.is_some() || json.get("scripts").is_none());
                    if if_present
                        && main.is_none()
                        && !default_start
                        && (scripts.is_some() || json.get("scripts").is_none())
                    {
                        return;
                    }
                    if main.and_then(|value| value.as_str()).is_some() || default_start {
                        let tail = &ctx.argv[(index + 1).min(ctx.argv.len())..];
                        let tail = if mgr == "npm" {
                            tail.iter()
                                .position(|word| word.as_literal() == Some("--"))
                                .map_or(&tail[tail.len()..], |separator| &tail[separator + 1..])
                        } else {
                            tail
                        };
                        if tail.iter().any(|word| word.as_literal().is_none()) {
                            unresolved_script(
                                builder,
                                model_node,
                                format!("{mgr} script {name:?}: arguments are not literal"),
                            );
                            return;
                        }
                        // A nested run's own script text gets no manifest,
                        // so manifest execution follows one level.
                        let outer_manifest = ctx
                            .nest
                            .package_manifest
                            .replace((!nested).then(|| (origin.clone(), manifest.clone())));
                        for script_name in [
                            format!("pre{name}"),
                            name.to_string(),
                            format!("post{name}"),
                        ] {
                            let source = scripts
                                .and_then(|scripts| scripts.get(&script_name))
                                .and_then(|source| source.as_str());
                            if source.is_none() && !(default_start && script_name == name) {
                                continue;
                            }
                            let identity = builder.node(
                                ProvenanceKind::ToolArgument {
                                    name: format!("{origin}:scripts.{script_name}"),
                                },
                                &[read, arg],
                            );
                            let subject = if default_start && script_name == name {
                                Subject::Exec {
                                    argv: ["node".to_string(), "server.js".to_string()]
                                        .into_iter()
                                        .chain(
                                            tail.iter()
                                                .map(|word| word.as_literal().unwrap().to_string()),
                                        )
                                        .collect(),
                                    cwd: ctx.cwd.map(str::to_string),
                                    context: Default::default(),
                                }
                            } else {
                                let mut source = source.unwrap().to_string();
                                if script_name == name {
                                    for word in tail {
                                        source.push_str(" '");
                                        source.push_str(
                                            &word.as_literal().unwrap().replace('\'', "'\\''"),
                                        );
                                        source.push('\'');
                                    }
                                }
                                Subject::Shell {
                                    source,
                                    cwd: ctx.cwd.map(str::to_string),
                                    context: Default::default(),
                                }
                            };
                            // Only npm's default start exec may resolve server.js.
                            let previous = ctx.nest.source_resolution_disabled.get();
                            if matches!(subject, Subject::Shell { .. }) {
                                ctx.nest.source_resolution_disabled.set(true);
                            }
                            {
                                let origin = origin.clone();
                                let source_cwd = crate::models::source_parent(&origin).to_string();
                                ctx.nest.nest(
                                    builder,
                                    Transition::file(subject)
                                        .origin(origin)
                                        .kind(ExecutionEdgeKind::PackageScript)
                                        .source_cwd(Some(&source_cwd))
                                        .runtime_cwd(ctx.runtime_cwd)
                                        .cwd(ctx.cwd_resource.clone(), ctx.cwd_node),
                                    &[model_node, arg, read, identity],
                                    ctx.depth,
                                );
                            };
                            ctx.nest.source_resolution_disabled.set(previous);
                        }
                        ctx.nest.package_manifest.replace(outer_manifest);
                        return;
                    }
                }
            }
            // Without a script of that name, pnpm's shorthand runs the command
            // as `pnpm exec` does, and Yarn's `run` and shorthand run the
            // dependency binary of that name. Unless the manifest proves the
            // script absent, both readings stay.
            if !name.is_empty() && (mgr == "yarn" || (mgr == "pnpm" && !run)) {
                local_binary(builder, ctx, model_node, mgr, index);
                if script_absent {
                    return;
                }
            }
            let detail = format!("{mgr} script {name:?}");
            let detail = match resolved {
                SourceResolution::Refused(refusal) => {
                    match source_refusal_detail(builder, refusal, &detail) {
                        Some(detail) => detail,
                        None => return,
                    }
                }
                SourceResolution::UnsupportedEncoding => {
                    format!("{detail}: source is not valid UTF-8")
                }
                _ => detail,
            };
            unresolved_script(builder, model_node, detail);
            return;
        }

        let installs = matches!(
            sub,
            "install" | "add" | "i" | "reinstall" | "upgrade" | "dist-upgrade" | "update"
        ) || npm_ci
            || (mgr.starts_with("pip") && sub == "install")
            || (matches!(mgr, "npm" | "pnpm" | "yarn") && (sub.is_empty() || sub == "install"));
        let removes = matches!(
            sub,
            "remove" | "purge" | "uninstall" | "erase" | "autoremove"
        );

        if installs || removes {
            let effect_index = if mgr == "bun" {
                bun_package_operand_index(ctx, sub_index)
            } else {
                0
            };
            // Fetch from a repository (endpoint not statically known).
            arg_effect(
                builder,
                ctx,
                model_node,
                effect_index,
                "network.download",
                unresolved_resource("network"),
                Default::default(),
            );
            // A literal VCS requirement also names the repository pip clones;
            // its dependencies still come from the index above.
            if mgr.starts_with("pip") && sub == "install" {
                for (index, requirement) in
                    pip_install_requirements(ctx, sub_index).unwrap_or_default()
                {
                    if let Some(identity) = pip_vcs_endpoint(requirement) {
                        arg_effect(
                            builder,
                            ctx,
                            model_node,
                            index as u32,
                            "network.download",
                            ResourceExpr::Concrete { identity },
                            Default::default(),
                        );
                    }
                }
            }
            let op = if removes && mgr != "bun" {
                "filesystem.delete"
            } else {
                "filesystem.write"
            };
            // Writes/removes go to system or library paths we cannot enumerate.
            arg_effect(
                builder,
                ctx,
                model_node,
                effect_index,
                op,
                if mgr == "bun" {
                    crate::paths::filesystem_glob("dependency-tree", ctx.cwd_resource())
                } else {
                    unresolved_resource("filesystem")
                },
                if op == "filesystem.write" && matches!(mgr, "npm" | "pnpm" | "yarn") {
                    program_output_attrs()
                } else {
                    Default::default()
                },
            );
            builder.boundary(Boundary {
                reason: BoundaryReason::PACKAGE_SCRIPTS,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Environment,
                affected_resource: None,
                callee: None,
                domains: if mgr == "bun" { vec![Domain::new("filesystem"), Domain::new("network"), Domain::new("process")] } else { [
                    "filesystem", "process", "environment", "network",
                ].iter()
                .map(|d| Domain::new(*d))
                .collect() },
                provenance: vec![model_node],
                limit: None,
                detail: if mgr == "bun" { None } else { Some(format!(
                    "{mgr} {sub} runs maintainer/setup scripts (arbitrary code) and writes unenumerated paths"
                )) },
            });
            if mgr == "bun" {
                builder.boundary(Boundary {
                    reason: BoundaryReason::REVIEWED_COMMAND_SURFACE,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Environment,
                    affected_resource: None,
                    callee: None,
                    domains: vec![
                        Domain::new("filesystem"),
                        Domain::new("network"),
                        Domain::new("process"),
                    ],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some("model covers a reviewed command surface".to_string()),
                });
            }
            builder.declare_coverage(Domain::new("network"), CoverageLevel::Partial);
            builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Partial);
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
        } else {
            // Non-mutating subcommands (list, show, search, run, ...) — the
            // effect set is unknown; keep it honest rather than empty.
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
            if script_manager {
                builder.declare_coverage(Domain::new("filesystem"), CoverageLevel::Partial);
                builder.declare_coverage(Domain::new("network"), CoverageLevel::Partial);
            }
            builder.boundary(Boundary {
                reason: BoundaryReason::UNMODELED_SUBCOMMAND,
                class: BoundaryClass::Unmodeled,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: if script_manager {
                    vec![
                        Domain::new("filesystem"),
                        Domain::new("network"),
                        Domain::new("process"),
                    ]
                } else {
                    vec![Domain::new("process"), Domain::new("network")]
                },
                provenance: vec![model_node],
                limit: None,
                detail: Some(format!("{mgr} {sub}")),
            });
        }
    }
}

/// The `ignore-scripts` a project `.npmrc` in the runtime cwd sets, under a
/// strict reading rather than npm's ini decoder. Lines are trimmed of spaces,
/// tabs and carriage returns only; blank lines and lines starting with `;` or
/// `#` are skipped, a `[section]` header of plain characters ends the
/// top-level settings, a key without `=` is true, and the last plain
/// top-level assignment wins. A key that is not plain (anything outside
/// letters, digits, `_.:/@-` and internal spaces or tabs, or any non-ASCII
/// character) may decode to `ignore-scripts`, so it leaves the whole file
/// unproven. A quoted or escaped value, a case variant, or a value other
/// than `true` or `false` leaves the setting unproven until a later plain
/// assignment.
fn project_npmrc_ignore_scripts(builder: &mut PlanBuilder, ctx: &InvocationCtx<'_>) -> NpmSetting {
    let Some((_, bytes)) = super::artifact::observe_data_file(builder, ctx, ".npmrc") else {
        return NpmSetting::Unset;
    };
    let text = String::from_utf8_lossy(&bytes);
    let trim = |text: &str| text.trim_matches([' ', '\t', '\r']).to_string();
    let plain = |text: &str| {
        text.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/@- \t".contains(&byte))
    };
    let mut setting = NpmSetting::Unset;
    let mut section = false;
    for line in text.split('\n') {
        let line = trim(line);
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            && plain(header)
        {
            section = true;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .map_or((line.as_str(), None), |(key, value)| (key, Some(value)));
        if !plain(key) {
            return NpmSetting::Unproven;
        }
        let key = trim(key);
        if section || !key.eq_ignore_ascii_case("ignore-scripts") {
            continue;
        }
        setting = match value {
            _ if key != "ignore-scripts" => NpmSetting::Unproven,
            None => NpmSetting::Proven,
            Some(value) if value.contains(['"', '\'', '\\']) => NpmSetting::Unproven,
            Some(value) => {
                match trim(value.split([';', '#']).next().unwrap_or_default()).as_str() {
                    "true" => NpmSetting::Proven,
                    "false" => NpmSetting::False,
                    _ => NpmSetting::Unproven,
                }
            }
        };
    }
    setting
}

/// Whether a pnpm or Yarn command line sets `ignore-scripts`: only a bare
/// `--ignore-scripts` or `--ignore-scripts=true` proves it; any other word
/// naming it, or a symbolic word, leaves it unproven.
fn manager_ignore_scripts(ctx: &InvocationCtx<'_>) -> NpmSetting {
    let mut setting = NpmSetting::Unset;
    for (index, word) in ctx.argv.iter().enumerate().skip(1) {
        let Some(word) = word.as_literal() else {
            return NpmSetting::Unproven;
        };
        if word == "--" {
            break;
        }
        let next = ctx.argv.get(index + 1).and_then(Word::as_literal);
        setting = match word {
            "--ignore-scripts" if !matches!(next, Some("true" | "false")) => NpmSetting::Proven,
            "--ignore-scripts=true" => NpmSetting::Proven,
            "--ignore-scripts=false" | "--no-ignore-scripts" => NpmSetting::False,
            _ if word.contains("ignore-scripts") => return NpmSetting::Unproven,
            _ => continue,
        };
    }
    setting
}

/// Follows the root package's `hooks` that a `lifecycle` command runs from
/// `package.json`: an npm, pnpm, Yarn or Bun install, npm's ci, version,
/// pack or rebuild, or Bun's pack. npm skips them only under a proven
/// `ignore-scripts`, read from the command line, the environment and an
/// observed project `.npmrc` in that order; Bun reads it from configuration
/// files that are not observed. When none of them decides it, a user or
/// global npmrc that is not observed still may: that possibility stays
/// recorded as an ambiguous input, and the hooks npm runs by default are
/// still followed when `project` says the command may run the root
/// package's lifecycle.
fn npm_lifecycle_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    manager: &str,
    hooks: &[&str],
    lifecycle: &str,
    project: bool,
) {
    let parsed = (manager == "npm").then(|| super::artifact::npm_options(ctx, 1));
    // A literal prefix naming another directory moves the package, and its
    // project npmrc, away from the one observed here. A symbolic or missing
    // one leaves npm on the current package.
    let elsewhere = |prefix: Option<&str>| {
        prefix.is_some_and(|prefix| !super::artifact::npm_prefix_is_cwd(ctx, prefix))
    };
    let package_selector = match &parsed {
        Some(parsed) if parsed.names("prefix") => {
            elsewhere(parsed.value("prefix").and_then(Word::as_literal)).then(|| {
                ExecutionSelector::RuntimeOption {
                    option: "--prefix".to_string(),
                }
            })
        }
        Some(_) => {
            let prefix = match ctx.environment_value("npm_config_prefix") {
                Some(ResourceExpr::Literal { value }) => Some(value),
                _ => None,
            };
            elsewhere(prefix.as_deref()).then(|| ExecutionSelector::Environment {
                variable: "npm_config_prefix".to_string(),
            })
        }
        None => None,
    };
    if parsed.as_ref().is_some_and(|parsed| parsed.unresolved) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: ["filesystem", "network", "process"]
                .iter()
                .map(|domain| Domain::new(*domain))
                .collect(),
            provenance: vec![model_node],
            limit: None,
            detail: Some(format!(
                "npm options this reading does not understand may change the {lifecycle} lifecycle"
            )),
        });
    }
    // npm's layers, highest first: command line, environment, the project
    // npmrc, then user and global npmrc files, which are not observed.
    let setting = match &parsed {
        None => manager_ignore_scripts(ctx),
        Some(parsed) => match parsed.setting("ignore-scripts") {
            NpmSetting::Unset => {
                match super::artifact::npm_environment_setting(ctx, "ignore-scripts") {
                    // A prefix moves the project npmrc with the package, and
                    // a command that runs no root lifecycle by default needs
                    // none.
                    NpmSetting::Unset if package_selector.is_some() || !project => {
                        NpmSetting::Unset
                    }
                    NpmSetting::Unset => project_npmrc_ignore_scripts(builder, ctx),
                    setting => setting,
                }
            }
            setting => setting,
        },
    };
    let ignore_scripts = match setting {
        NpmSetting::Proven => Some(true),
        NpmSetting::False => Some(false),
        // Bun also reads `ignore-scripts` from bunfig.toml and .npmrc, which
        // are not observed.
        NpmSetting::Unset if !matches!(manager, "npm" | "bun") => Some(false),
        NpmSetting::Unset | NpmSetting::Unproven => None,
    };
    match ignore_scripts {
        Some(true) => return,
        Some(false) => {}
        None => {
            crate::models::common::runtime_unobserved_input(
                builder,
                ctx,
                "package.json",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::PackageHook,
                ExecutionSelector::RuntimeOption {
                    option: "ignore-scripts".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            if !project {
                return;
            }
        }
    }
    if let Some(selector) = package_selector {
        crate::models::common::runtime_unobserved_input(
            builder,
            ctx,
            "package.json",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::PackageHook,
            selector,
            ExecutionInputReason::Ambiguous,
        );
        return;
    }
    let path = "package.json";
    let Some((namespace, resolved_path)) = crate::paths::join_source_path(ctx.runtime_cwd, path)
    else {
        return;
    };
    let mut input = ctx.nest.source_input(
        builder,
        path,
        SourcePurpose::InvocationInput,
        ExecutionContent::Unobserved {
            reason: ExecutionInputReason::ResolverUnavailable,
        },
        manager,
    );
    input.role = ExecutionInputRole::UnexpectedSelected;
    input.phase = ExecutionPhase::PackageHook;
    input.selector = ExecutionSelector::Convention {
        name: format!("{manager}-{lifecycle}-lifecycle@1"),
    };
    input.selected = Some(ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath {
            path: resolved_path.clone(),
        },
    });
    input.selection = ExecutionSelection::Direct {
        request: path.to_string(),
    };
    let SourceResolution::Source {
        origin,
        source: manifest,
    } = ctx.nest.resolve_execution_input(
        builder,
        resolved_path,
        namespace,
        SourcePurpose::InvocationInput,
        input,
    )
    else {
        return;
    };
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        ctx.nest.record_unsupported_source(builder, &origin);
        return;
    };
    let Some(scripts) = manifest
        .get("scripts")
        .and_then(|scripts| scripts.as_object())
    else {
        return;
    };
    for name in hooks {
        let Some(source) = scripts.get(*name).and_then(|source| source.as_str()) else {
            continue;
        };
        {
            let origin = origin.clone();
            let source_cwd = crate::models::source_parent(&origin).to_string();
            ctx.nest.nest(
                builder,
                Transition::file(Subject::Shell {
                    source: source.to_string(),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                })
                .origin(origin)
                .kind(ExecutionEdgeKind::PackageHook)
                .source_cwd(Some(&source_cwd))
                .runtime_cwd(ctx.runtime_cwd)
                .cwd(ctx.cwd_resource.clone(), ctx.cwd_node),
                &[model_node],
                ctx.depth,
            );
        };
    }
}

pub(crate) fn composer_plugin_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    let SourceResolution::Source {
        source: root_manifest,
        ..
    } = ctx.resolve_source_operand(builder, "composer.json", SourcePurpose::InvocationInput)
    else {
        return;
    };
    let Ok(root) = serde_json::from_str::<serde_json::Value>(&root_manifest) else {
        return;
    };
    let Some(allowed) = root
        .pointer("/config/allow-plugins")
        .and_then(|allowed| allowed.as_object())
    else {
        return;
    };
    // Composer 2 loads the installed package list, not path-repository offers.
    let vendor_dir = ctx.environment_value("COMPOSER_VENDOR_DIR");
    let vendor_dir = match &vendor_dir {
        Some(ResourceExpr::Literal { value }) => value.as_str(),
        Some(_) => return,
        None => root
            .pointer("/config/vendor-dir")
            .and_then(|value| value.as_str())
            .unwrap_or("vendor"),
    };
    let installed_path = format!("{vendor_dir}/composer/installed.json");
    let SourceResolution::Source {
        source: installed, ..
    } = ctx.resolve_source_operand(builder, &installed_path, SourcePurpose::InvocationInput)
    else {
        return;
    };
    let Ok(installed) = serde_json::from_str::<serde_json::Value>(&installed) else {
        return;
    };
    let Some(packages) = installed.get("packages").and_then(|value| value.as_array()) else {
        return;
    };
    for plugin in packages {
        let Some(install_path) = plugin.get("install-path").and_then(|value| value.as_str()) else {
            continue;
        };
        let directory = crate::paths::join_cwd(&format!("{vendor_dir}/composer"), install_path);
        let Some(package) = plugin.get("name").and_then(|value| value.as_str()) else {
            continue;
        };
        if allowed.get(package).and_then(|value| value.as_bool()) != Some(true)
            || plugin.get("type").and_then(|value| value.as_str()) != Some("composer-plugin")
        {
            continue;
        }
        let Some(class) = plugin
            .pointer("/extra/class")
            .and_then(|value| value.as_str())
        else {
            continue;
        };
        let Some(prefixes) = plugin
            .pointer("/autoload/psr-4")
            .and_then(|value| value.as_object())
        else {
            continue;
        };
        let Some((prefix, source_dir)) = prefixes
            .iter()
            .find_map(|(prefix, directory)| class.strip_prefix(prefix).zip(directory.as_str()))
        else {
            continue;
        };
        let path = format!(
            "{}/{}/{}.php",
            directory.trim_end_matches('/'),
            source_dir.trim_matches('/'),
            prefix.replace('\\', "/")
        );
        runtime_selected_source(
            builder,
            ctx,
            model_node,
            &path,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Plugin,
            ExecutionSelector::Convention {
                name: "composer-installed-allow-plugins@2".to_string(),
            },
            RuntimeSourceLanguage::Source("php"),
        );
    }
}

fn unresolved_script(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: String) {
    builder.declare_coverage(Domain::new("process"), CoverageLevel::Partial);
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRESOLVED_PACKAGE_SCRIPT,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new("process")],
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail),
    });
}
