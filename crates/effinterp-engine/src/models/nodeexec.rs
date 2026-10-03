//! Node.js launcher models: `node -e "code"` runs inline JavaScript analyzed
//! as a nested Js subject; a script-path operand nests source supplied by a
//! repository resolver and otherwise remains an explicit boundary.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionInputReason, ExecutionInputRole, ExecutionPhase, ExecutionSelector, ProvenanceRef,
    ResourceExpr, SourceDialect, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::common::{
    RuntimeSourceLanguage, arg_node, code_execution, dynamic_source, operand_effect,
    runtime_searched_source, runtime_selected_source, runtime_unobserved_input,
    syntax_check_operand, unrecognized_arguments_boundary,
};
use crate::models::registry::launcher::{LauncherBoundary, LauncherInvocation};
use crate::models::{
    CommandModel, InvocationCtx, ModelBindingEnd, ModelCausalBinding, source_refusal_detail,
};
use crate::nest::SourceResolution;
use crate::value::unresolved_resource;
use crate::word::Word;

/// Node runtime options that consume the next argument.
const VALUE_FLAGS: &[&str] = &[
    "--allow-fs-read",
    "--allow-fs-write",
    "--require",
    "-r",
    "--import",
    "--loader",
    "--experimental-loader",
    "--experimental-default-type",
    "--conditions",
    "--cpu-prof-dir",
    "--cpu-prof-interval",
    "--cpu-prof-name",
    "--debug-port",
    "--diagnostic-dir",
    "--disable-proto",
    "--disable-warning",
    "--dns-result-order",
    "--env-file",
    "--env-file-if-exists",
    "--experimental-test-isolation",
    "--experimental-test-tag-filter",
    "--heap-prof-dir",
    "--heap-prof-interval",
    "--heap-prof-name",
    "--heapsnapshot-near-heap-limit",
    "--heapsnapshot-signal",
    "--input-type",
    "--icu-data-dir",
    "--inspect-port",
    "--inspect-publish-uid",
    "--localstorage-file",
    "--max-http-header-size",
    "--max-old-space-size-percentage",
    "--network-family-autoselection-attempt-timeout",
    "--openssl-config",
    "--redirect-warnings",
    "--report-dir",
    "--report-directory",
    "--report-filename",
    "--report-signal",
    "--secure-heap",
    "--secure-heap-min",
    "--snapshot-blob",
    "--test-concurrency",
    "--test-coverage-branches",
    "--test-coverage-exclude",
    "--test-coverage-functions",
    "--test-coverage-include",
    "--test-coverage-lines",
    "--test-global-setup",
    "--test-isolation",
    "--test-name-pattern",
    "--test-random-seed",
    "--test-reporter",
    "--test-reporter-destination",
    "--test-rerun-failures",
    "--test-shard",
    "--test-skip-pattern",
    "--test-timeout",
    "--tls-cipher-list",
    "--tls-keylog",
    "--title",
    "--trace-event-categories",
    "--trace-event-file-pattern",
    "--trace-require-module",
    "--unhandled-rejections",
    "--use-largepages",
    "--v8-pool-size",
    "--watch-kill-signal",
    "--watch-path",
    "-C",
];

// Narrow proof for the file selector whose request assurance is audited.
fn accepted_node_file(argv: &[Word]) -> Option<usize> {
    let node = argv
        .first()
        .and_then(Word::as_literal)
        .map(|name| name.rsplit('/').next().unwrap());
    if node != Some("node") || argv.iter().any(|word| word.as_literal().is_none()) {
        return None;
    }
    let (index, script) = match argv.get(1).and_then(Word::as_literal)? {
        "--" => (2, argv.get(2).and_then(Word::as_literal)?),
        script if !script.starts_with('-') => (1, script),
        _ => return None,
    };
    (!script.is_empty() && script != "-").then_some(index)
}

pub(crate) fn apply(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    node_preload_inputs(builder, ctx, model_node, invocation);
    let source_option = invocation.options.iter().find(|option| {
        option.class == effinterp_model_schema::LauncherOptionClassDeclaration::InlineSource
    });
    let source_index = source_option
        .map(|option| option.index)
        .or_else(|| invocation.script.as_ref().map(|script| script.index))
        .unwrap_or(u32::MAX);
    let preceding = invocation
        .options
        .iter()
        .filter(|option| option.index < source_index)
        .collect::<Vec<_>>();
    let mut stdin_is_code = true;
    let mut script_recovery_uncertain = false;
    for option in preceding {
        if matches!(
            option.name.as_str(),
            "-h" | "--help" | "-v" | "--version" | "--v8-options" | "--completion-bash"
        ) || matches!(
            option.name.as_str(),
            "--run" | "--prof-process" | "--experimental-sea-config" | "--build-snapshot-config"
        ) {
            return;
        }
        if matches!(option.name.as_str(), "--build-snapshot" | "--test") {
            stdin_is_code = false;
        }
        if matches!(
            option.class,
            effinterp_model_schema::LauncherOptionClassDeclaration::Value
                | effinterp_model_schema::LauncherOptionClassDeclaration::Preload
        ) && option.value.is_none()
        {
            return;
        }
        if option.class == effinterp_model_schema::LauncherOptionClassDeclaration::Unreviewed {
            let argument = invocation
                .boundaries
                .iter()
                .find_map(|boundary| match boundary {
                    LauncherBoundary::UnreviewedOption(argument)
                        if argument.index == option.index =>
                    {
                        Some(argument)
                    }
                    LauncherBoundary::UnreviewedOption(_)
                    | LauncherBoundary::UnexpectedOperand(_) => None,
                });
            if let Some(argument) = argument
                && !inert_node_option(argument.word.as_literal().unwrap_or_default())
            {
                unrecognized_arguments_boundary(
                    builder,
                    model_node,
                    &["filesystem", "process"],
                    &[(argument.index, argument.word.render_raw())],
                );
                script_recovery_uncertain = true;
            }
        }
    }

    if let Some(option) = source_option {
        if script_recovery_uncertain {
            return;
        }
        let Some(source) = option.value.as_ref() else {
            if matches!(option.name.as_str(), "-p" | "--print") && stdin_is_code {
                stdin_program(
                    builder,
                    ctx,
                    model_node,
                    None,
                    "node interactive interpreter",
                );
            }
            return;
        };
        if source.word.as_literal() == Some("")
            && matches!(option.name.as_str(), "--eval" | "--print")
        {
            return;
        }
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            Some(source.index),
            "argument",
            Default::default(),
        );
        if let Some(code) = source.word.as_literal() {
            let arg = arg_node(builder, ctx, source.index);
            // tsx evaluates TypeScript; node evaluates JavaScript.
            let tsx = ctx
                .argv
                .first()
                .and_then(Word::as_literal)
                .is_some_and(|command| command.rsplit('/').next() == Some("tsx"));
            ctx.nest_subject(
                builder,
                Subject::Source {
                    language: "js".into(),
                    source: code.to_string(),
                    dialect: Some(if tsx {
                        SourceDialect::Ts
                    } else {
                        SourceDialect::Js
                    }),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                &[model_node, arg],
            );
        } else {
            node_source_unavailable(builder, model_node, "node -e with non-literal source");
        }
        return;
    }

    if let Some(check) = invocation.options.iter().find(|option| {
        option.index < source_index && matches!(option.name.as_str(), "-c" | "--check")
    }) {
        if !script_recovery_uncertain {
            syntax_check_operand(builder, ctx, model_node, check.index as usize + 1);
        }
        return;
    }
    if let Some(script) = invocation.script.as_ref() {
        if script_recovery_uncertain {
            return;
        }
        if script.word.as_literal() == Some("-") && stdin_is_code {
            stdin_program(
                builder,
                ctx,
                model_node,
                Some(script.index),
                "node program is read from stdin",
            );
        } else {
            node_script(
                builder,
                ctx,
                model_node,
                script.index as usize,
                &script.word,
            );
        }
        return;
    }
    if stdin_is_code {
        stdin_program(
            builder,
            ctx,
            model_node,
            None,
            "node interactive interpreter",
        );
    }
}

fn inert_node_option(option: &str) -> bool {
    option.starts_with("-C=")
        || option.starts_with("-r=")
        || option.starts_with("--experimental-")
        || option.starts_with("--no-experimental-")
        || option.starts_with("--harmony-")
}

fn node_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    script: &Word,
) {
    code_execution(
        if accepted_node_file(ctx.argv) == Some(index) {
            effinterp_proto::RequestAssurance::Exact
        } else {
            effinterp_proto::RequestAssurance::Conservative
        },
        builder,
        ctx,
        model_node,
        Some(index as u32),
        "file",
        Default::default(),
    );
    operand_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        script,
        "filesystem.read",
        Default::default(),
    );
    let Some(path) = script.as_literal() else {
        node_source_unavailable(builder, model_node, "node script target is dynamic");
        return;
    };
    let resolved = ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput);
    match resolved {
        SourceResolution::Source {
            origin: path,
            source,
        } => {
            let dialect = js_dialect(&path);
            let arg = arg_node(builder, ctx, index as u32);
            ctx.nest_script_subject(
                builder,
                Subject::Source {
                    language: "js".into(),
                    source,
                    dialect: Some(dialect),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                &[model_node, arg],
                path,
                index,
            );
        }
        SourceResolution::Refused(refusal) => {
            if let Some(detail) =
                source_refusal_detail(builder, refusal, "node script source is unavailable")
            {
                node_source_unavailable(builder, model_node, &detail);
            }
        }
        SourceResolution::UnsupportedEncoding => {
            node_source_unavailable(builder, model_node, "node script source is not valid UTF-8")
        }
        SourceResolution::AlreadySelected => (),
        SourceResolution::Unavailable => {
            node_source_unavailable(builder, model_node, "node script source is unavailable")
        }
    }
}

/// The argv index of the code `bun -e CODE` (also `--eval`, `-p`, `--print`)
/// runs. Only the leading form is recognized; other runtime options before
/// it stay with the package-manager model.
pub(crate) fn bun_eval_source(ctx: &InvocationCtx<'_>) -> Option<usize> {
    matches!(
        ctx.argv.get(1)?.as_literal()?,
        "-e" | "--eval" | "-p" | "--print"
    )
    .then_some(2)
    .filter(|index| *index < ctx.argv.len())
}

/// `bun run` switches that take no value
/// (https://bun.sh/docs/cli/run).
const BUN_RUN_SWITCHES: &[&str] = &[
    "--silent",
    "--if-present",
    "--bun",
    "-b",
    "--smol",
    "--expose-gc",
    "--no-deprecation",
    "--throw-deprecation",
    "--zero-fill-buffers",
    "--no-addons",
    "--watch",
    "--hot",
    "--no-clear-screen",
    "--no-install",
    "-i",
    "--prefer-offline",
    "--prefer-latest",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--no-macros",
    "--use-system-ca",
    "--use-openssl-ca",
    "--use-bundled-ca",
];

/// Whether the invocation is `bun run [SWITCHES] -`, which "reads
/// JavaScript, TypeScript, TSX, or JSX from stdin and executes it"
/// (https://bun.sh/docs/cli/run). A bare `bun -` is not documented.
pub(crate) fn bun_stdin_program(ctx: &InvocationCtx<'_>) -> bool {
    ctx.argv.get(1).and_then(Word::as_literal) == Some("run")
        && ctx.argv[2..]
            .iter()
            .map(Word::as_literal)
            .find(|word| !word.is_some_and(|word| BUN_RUN_SWITCHES.contains(&word)))
            == Some(Some("-"))
}

pub(crate) fn bun_runtime_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    if bun_stdin_program(ctx) {
        stdin_program(
            builder,
            ctx,
            model_node,
            None,
            "bun program from stdin is unavailable",
        );
        return;
    }
    // Bun transpiles evaluated code as TypeScript, with Node's modules and
    // its own `Bun` global.
    if let Some(index) = bun_eval_source(ctx) {
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            Some(index as u32),
            "argument",
            Default::default(),
        );
        match ctx.argv[index].as_literal() {
            Some(code) => {
                let arg = arg_node(builder, ctx, index as u32);
                ctx.nest_subject(
                    builder,
                    Subject::Source {
                        language: "js".into(),
                        source: code.to_string(),
                        dialect: Some(SourceDialect::Ts),
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    },
                    &[model_node, arg],
                );
            }
            None => node_source_unavailable(builder, model_node, "bun -e with non-literal source"),
        }
        return;
    }
    if ctx
        .argv
        .get(1)
        .and_then(|word| word.as_literal())
        .is_some_and(|subcommand| {
            matches!(
                subcommand,
                "add" | "install" | "link" | "pm" | "remove" | "update"
            )
        })
    {
        return;
    }
    let mut index = 1;
    let mut selected_preload = false;
    while index < ctx.argv.len() {
        match ctx.argv[index].as_literal() {
            Some("--preload" | "-r") => {
                let Some(path) = ctx.argv.get(index + 1).and_then(|word| word.as_literal()) else {
                    if ctx.argv.get(index + 1).is_none() {
                        return;
                    }
                    runtime_unobserved_input(
                        builder,
                        ctx,
                        "$PRELOAD",
                        ExecutionInputRole::UnexpectedSelected,
                        ExecutionPhase::Preload,
                        ExecutionSelector::RuntimeOption {
                            option: "--preload".into(),
                        },
                        ExecutionInputReason::Ambiguous,
                    );
                    return;
                };
                node_selected_module(
                    builder,
                    ctx,
                    model_node,
                    path,
                    ExecutionSelector::RuntimeOption {
                        option: "--preload".to_string(),
                    },
                    true,
                );
                selected_preload = true;
                index += 2;
            }
            Some(option) if option.starts_with("--preload=") => {
                node_selected_module(
                    builder,
                    ctx,
                    model_node,
                    option.trim_start_matches("--preload="),
                    ExecutionSelector::RuntimeOption {
                        option: "--preload".to_string(),
                    },
                    true,
                );
                selected_preload = true;
                index += 1;
            }
            Some("run") => index += 1,
            Some("--") => {
                index += 1;
                break;
            }
            Some(option) if option.starts_with('-') => index += 1,
            _ => break,
        }
    }
    if !selected_preload {
        return;
    }
    let Some(path) = ctx.argv.get(index).and_then(|word| word.as_literal()) else {
        return;
    };
    runtime_selected_source(
        builder,
        ctx,
        model_node,
        path,
        ExecutionInputRole::ExplicitInvocation,
        ExecutionPhase::Main,
        ExecutionSelector::InvocationPath,
        RuntimeSourceLanguage::JavaScript(js_dialect(path)),
    );
}

pub(crate) fn deno_runtime_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    let mut index = 1;
    if ctx.argv.get(index).and_then(|word| word.as_literal()) == Some("eval") {
        deno_eval(builder, ctx, model_node);
        return;
    }
    if ctx.argv.get(index).and_then(|word| word.as_literal()) == Some("run") {
        index += 1;
    }
    let mut import_map = None;
    while index < ctx.argv.len() {
        match ctx.argv[index].as_literal() {
            Some("--import-map" | "--config") => {
                let Some(path) = ctx.argv.get(index + 1).and_then(|word| word.as_literal()) else {
                    if ctx.argv.get(index + 1).is_none() {
                        return;
                    }
                    runtime_unobserved_input(
                        builder,
                        ctx,
                        "$CONFIG",
                        ExecutionInputRole::UnexpectedSelected,
                        ExecutionPhase::Import,
                        ExecutionSelector::RuntimeOption {
                            option: "--import-map/--config".into(),
                        },
                        ExecutionInputReason::Ambiguous,
                    );
                    return;
                };
                import_map = Some((ctx.argv[index].as_literal().unwrap(), path));
                index += 2;
            }
            Some(option) if option.starts_with("--import-map=") => {
                import_map = Some(("--import-map", option.trim_start_matches("--import-map=")));
                index += 1;
            }
            Some(option) if option.starts_with("--config=") => {
                import_map = Some(("--config", option.trim_start_matches("--config=")));
                index += 1;
            }
            Some("--") => {
                index += 1;
                break;
            }
            Some(option) if option.starts_with('-') => index += 1,
            _ => break,
        }
    }
    let Some(path) = ctx.argv.get(index).and_then(|word| word.as_literal()) else {
        return;
    };
    let Some((option, map_path)) = import_map else {
        return;
    };
    let resolved = ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput);
    let SourceResolution::Source {
        origin,
        source: main_source,
    } = resolved
    else {
        node_source_unavailable(builder, model_node, "deno main source is unavailable");
        return;
    };
    if let SourceResolution::Source {
        origin: map_origin,
        source: map_source,
    } = ctx.resolve_source_operand(builder, map_path, SourcePurpose::InvocationInput)
        && let Ok(map) = serde_json::from_str::<serde_json::Value>(&map_source)
        && let Some(imports) = map.get("imports").and_then(|imports| imports.as_object())
    {
        for specifier in
            crate::js::runtime_imports(&main_source, js_dialect(path)).unwrap_or_default()
        {
            let Some(target) = imports.get(&specifier).and_then(|target| target.as_str()) else {
                continue;
            };
            let target = crate::paths::join_relative_file(
                Some(&crate::paths::parent_dir(&map_origin)),
                target,
            )
            .unwrap_or_else(|| target.to_string());
            runtime_selected_source(
                builder,
                ctx,
                model_node,
                &target,
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Import,
                ExecutionSelector::RuntimeOption {
                    option: option.to_string(),
                },
                RuntimeSourceLanguage::JavaScript(js_dialect(&target)),
            );
        }
    }
    let arg = arg_node(builder, ctx, index as u32);
    ctx.nest_script_subject(
        builder,
        Subject::Source {
            language: "js".into(),
            source: main_source,
            dialect: Some(js_dialect(path)),
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        &[model_node, arg],
        origin,
        index,
    );
}

/// `deno eval` options that take no value, as the deno model declares them.
const DENO_EVAL_SWITCHES: &[&str] = &[
    "-p",
    "--print",
    "-q",
    "--quiet",
    "--no-check",
    "--cached-only",
    "--no-remote",
    "--no-npm",
];

/// `deno eval [OPTIONS] CODE [ARGS...]` runs CODE as a module: JavaScript
/// unless `--ext` names a TypeScript extension. The deno model declares the
/// same options; any other option leaves CODE's position unknown, and the
/// model reports it as unrecognized.
fn deno_eval(builder: &mut PlanBuilder, ctx: &InvocationCtx<'_>, model_node: ProvenanceRef) {
    let mut dialect = SourceDialect::Js;
    let mut index = 2;
    while let Some(word) = ctx.argv.get(index) {
        let Some(word) = word.as_literal() else {
            return;
        };
        let extension = match word {
            "--ext" => {
                index += 1;
                Some(ctx.argv.get(index).and_then(Word::as_literal))
            }
            _ => word.strip_prefix("--ext=").map(Some),
        };
        match extension {
            Some(extension) => {
                dialect = match extension {
                    Some("js" | "jsx" | "mjs" | "cjs") => SourceDialect::Js,
                    Some("ts" | "tsx" | "mts" | "cts") => SourceDialect::Ts,
                    _ => return,
                };
            }
            None if DENO_EVAL_SWITCHES.contains(&word) => {}
            None if word.starts_with('-') => return,
            None => break,
        }
        index += 1;
    }
    let Some(code) = ctx.argv.get(index) else {
        return;
    };
    let Some(code) = code.as_literal() else {
        node_source_unavailable(builder, model_node, "deno eval with non-literal source");
        return;
    };
    let arg = arg_node(builder, ctx, index as u32);
    ctx.nest_subject(
        builder,
        Subject::Source {
            language: "js".into(),
            source: code.to_string(),
            dialect: Some(dialect),
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        &[model_node, arg],
    );
}

fn node_preload_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    if let Some(value) = ctx.environment_value("NODE_OPTIONS") {
        match value {
            ResourceExpr::Literal { value } => {
                let Some(words) = node_option_words(&value) else {
                    runtime_unobserved_input(
                        builder,
                        ctx,
                        "$NODE_OPTIONS",
                        ExecutionInputRole::UnexpectedSelected,
                        ExecutionPhase::Preload,
                        ExecutionSelector::Environment {
                            variable: "NODE_OPTIONS".to_string(),
                        },
                        ExecutionInputReason::Ambiguous,
                    );
                    return;
                };
                let mut index = 0;
                while index < words.len() {
                    let option = words[index].as_str();
                    let (name, attached) = option
                        .split_once('=')
                        .map_or((option, None), |(name, value)| (name, Some(value)));
                    if matches!(
                        name,
                        "--require" | "-r" | "--import" | "--loader" | "--experimental-loader"
                    ) {
                        let path = attached.or_else(|| words.get(index + 1).map(String::as_str));
                        let Some(path) = path else {
                            break;
                        };
                        node_preload_module(
                            builder,
                            ctx,
                            model_node,
                            path,
                            ExecutionSelector::Environment {
                                variable: "NODE_OPTIONS".to_string(),
                            },
                            name,
                        );
                        if attached.is_none() {
                            index += 1;
                        }
                    } else if attached.is_none() && VALUE_FLAGS.contains(&name) {
                        index += 1;
                    }
                    index += 1;
                }
            }
            _ => runtime_unobserved_input(
                builder,
                ctx,
                "$NODE_OPTIONS",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Preload,
                ExecutionSelector::Environment {
                    variable: "NODE_OPTIONS".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            ),
        }
    }
    for option in &invocation.options {
        let (name, path) =
            if option.class == effinterp_model_schema::LauncherOptionClassDeclaration::Preload {
                let Some(path) = option.value.as_ref() else {
                    return;
                };
                (option.name.as_str(), path.word.as_literal())
            } else {
                let Some(path) = option
                    .raw
                    .as_literal()
                    .and_then(|raw| raw.strip_prefix("-r="))
                else {
                    continue;
                };
                ("-r", Some(path))
            };
        let Some(path) = path else {
            runtime_unobserved_input(
                builder,
                ctx,
                "$PRELOAD",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Preload,
                ExecutionSelector::RuntimeOption {
                    option: name.to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            return;
        };
        node_preload_module(
            builder,
            ctx,
            model_node,
            path,
            ExecutionSelector::RuntimeOption {
                option: name.to_string(),
            },
            name,
        );
    }
    if invocation.options.iter().all(|option| {
        option.class != effinterp_model_schema::LauncherOptionClassDeclaration::EndOfOptions
    }) && invocation
        .script
        .as_ref()
        .is_some_and(|script| script.word.as_literal().is_none())
    {
        runtime_unobserved_input(
            builder,
            ctx,
            "$OPTION",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: "unresolved argument".into(),
            },
            ExecutionInputReason::Ambiguous,
        );
    }
}

fn node_preload_module(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    request: &str,
    selector: ExecutionSelector,
    option: &str,
) {
    if !matches!(option, "--require" | "-r") {
        runtime_unobserved_input(
            builder,
            ctx,
            request,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            selector,
            ExecutionInputReason::ResolverUnavailable,
        );
        return;
    }
    node_selected_module(builder, ctx, model_node, request, selector, false);
}

fn node_selected_module(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    request: &str,
    selector: ExecutionSelector,
    typescript: bool,
) {
    if crate::js::is_node_builtin_module(request) {
        return;
    }
    if !(request.starts_with('.') || request.starts_with('/')) {
        runtime_unobserved_input(
            builder,
            ctx,
            request,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            selector,
            ExecutionInputReason::ResolverUnavailable,
        );
        return;
    }
    let dialect = if typescript || matches!(js_dialect(request), SourceDialect::Ts) {
        SourceDialect::Ts
    } else {
        SourceDialect::Js
    };
    if std::path::Path::new(request).extension().is_some() {
        runtime_selected_source(
            builder,
            ctx,
            model_node,
            request,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            selector,
            if request.ends_with(".node") || request.ends_with(".json") {
                RuntimeSourceLanguage::Opaque
            } else {
                RuntimeSourceLanguage::JavaScript(dialect)
            },
        );
    } else {
        runtime_searched_source(
            builder,
            ctx,
            model_node,
            request,
            ["", ".js", ".json", ".node"]
                .into_iter()
                .map(|suffix| format!("{request}{suffix}"))
                .collect(),
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            selector,
            RuntimeSourceLanguage::JavaScript(dialect),
            true,
        );
    }
}

// NODE_OPTIONS uses double quotes and backslash escapes inside quoted strings,
// not shell tokenization (single quotes are ordinary characters).
fn node_option_words(value: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                quoted = !quoted;
            }
            '\\' if quoted => {
                word.push(chars.next()?);
                started = true;
            }
            ' ' if !quoted => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            _ => {
                word.push(ch);
                started = true;
            }
        }
    }
    if quoted {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

pub(crate) fn js_dialect(path: &str) -> SourceDialect {
    if path.ends_with(".ts")
        || path.ends_with(".mts")
        || path.ends_with(".cts")
        || path.ends_with(".tsx")
    {
        SourceDialect::Ts
    } else {
        SourceDialect::Js
    }
}

fn stdin_program(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    argument: Option<u32>,
    unavailable_detail: &str,
) {
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        argument,
        "stdin",
        Default::default(),
    );
    if let Some(code) = ctx.stdin_literal() {
        let mut provenance = vec![model_node];
        provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
        ctx.nest_subject(
            builder,
            Subject::Source {
                language: "js".into(),
                source: code.to_string(),
                dialect: Some(SourceDialect::Js),
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &provenance,
        );
    } else if ctx.stdin.is_some() {
        node_source_unavailable(
            builder,
            model_node,
            "stdin program is not statically recoverable",
        );
    } else {
        node_source_unavailable(builder, model_node, unavailable_detail);
    }
}

fn node_source_unavailable(builder: &mut PlanBuilder, model_node: ProvenanceRef, detail: &str) {
    const DOMAINS: [&str; 4] = ["environment", "filesystem", "network", "process"];
    for domain in DOMAINS {
        builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
    }
    dynamic_source(builder, model_node, detail);
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
        provenance: vec![model_node],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

/// `deno run` options that take no value; the permission and resolution
/// switches among them also accept an attached `=VALUE`
/// (https://docs.deno.com/runtime/reference/cli/run/).
const DENO_RUN_SWITCHES: &[&str] = &[
    "-A",
    "--allow-all",
    "--allow-read",
    "--allow-write",
    "--allow-net",
    "--allow-env",
    "--allow-sys",
    "--allow-run",
    "--allow-ffi",
    "--allow-import",
    "--deny-read",
    "--deny-write",
    "--deny-net",
    "--deny-env",
    "--deny-sys",
    "--deny-run",
    "--deny-ffi",
    "--deny-import",
    "-R",
    "-W",
    "-N",
    "-E",
    "-S",
    "-r",
    "--reload",
    "--watch",
    "--hmr",
    "--inspect",
    "--inspect-brk",
    "--inspect-wait",
    "--coverage",
    "--unsafely-ignore-certificate-errors",
    "--no-clear-screen",
    "--no-code-cache",
    "--frozen-lockfile",
    "--allow-scripts",
    "--use-env-proxy",
    "--no-prompt",
    "-q",
    "--quiet",
    "--check",
    "--no-check",
    "--cached-only",
    "--no-remote",
    "--no-npm",
    "--no-config",
    "--lock",
    "--no-lock",
    "--node-modules-dir",
    "--vendor",
    "--env-file",
];

/// `deno run` options whose value is the next argument.
const DENO_RUN_VALUE_FLAGS: &[&str] = &[
    "-c",
    "--config",
    "--import-map",
    "--cert",
    "--location",
    "--seed",
    "--ext",
    "-L",
    "--log-level",
    "--v8-flags",
    "--conditions",
    "--preload",
    "--require",
    "--watch-exclude",
    "--node-modules-linker",
    "--min-dep-age",
];

/// Letters of the no-value short switches deno accepts clustered, as in `-Ar`.
const DENO_RUN_SHORT_SWITCHES: &str = "ARWNESqr";

/// The code `deno run [OPTIONS] SCRIPT [ARGS...]` fetches or reads from its
/// input. Options end at SCRIPT; every later word is the script's own
/// argument. A registry specifier is left to the deno model.
enum DenoScript {
    /// An `http(s)` URL: deno fetches the module and runs it
    /// (https://docs.deno.com/runtime/getting_started/command_line_interface/).
    /// With no permission flags the module is sandboxed, but deno prompts to
    /// grant access when interactive, and `-A` turns the sandbox off
    /// (https://docs.deno.com/runtime/fundamentals/security/).
    Remote(usize),
    /// `-`: the program is read from stdin.
    Stdin,
    /// A local file path; only one this call wrote earlier is modeled here.
    Local(usize),
}

fn deno_run_script(argv: &[Word]) -> Option<DenoScript> {
    // Deno 2 runs a bare `deno SCRIPT` as `deno run SCRIPT`
    // (https://docs.deno.com/runtime/reference/cli/run/).
    let mut index = match argv.get(1).and_then(Word::as_literal) {
        Some("run") => 2,
        Some(script) if script.starts_with("http://") || script.starts_with("https://") => 1,
        // A module extension keeps a file apart from a subcommand name.
        Some(script)
            if [".ts", ".js", ".mts", ".mjs", ".cts", ".cjs", ".tsx", ".jsx"]
                .iter()
                .any(|extension| script.ends_with(extension)) =>
        {
            1
        }
        _ => return None,
    };
    while index > 1
        && let Some(word) = argv.get(index).and_then(Word::as_literal)
    {
        let name = word.split_once('=').map_or(word, |(name, _)| name);
        if word == "--" {
            index += 1;
            break;
        } else if DENO_RUN_VALUE_FLAGS.contains(&word) {
            index += 2;
        } else if DENO_RUN_SWITCHES.contains(&name)
            || (word.contains('=') && DENO_RUN_VALUE_FLAGS.contains(&name))
            || word.starts_with("--unstable")
            || word.strip_prefix('-').is_some_and(|letters| {
                letters.len() > 1 && letters.chars().all(|c| DENO_RUN_SHORT_SWITCHES.contains(c))
            })
        {
            index += 1;
        } else {
            break;
        }
    }
    match argv.get(index)?.as_literal()? {
        "-" => Some(DenoScript::Stdin),
        script if script.starts_with("http://") || script.starts_with("https://") => {
            Some(DenoScript::Remote(index))
        }
        // `jsr:`, `npm:` and other specifiers name a module, not a path.
        script if !script.contains(':') => Some(DenoScript::Local(index)),
        _ => None,
    }
}

pub(crate) fn with_deno_run(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    Box::new(DenoRun { owner })
}

/// The declarative deno model with `deno run`, whose script operand ends
/// option parsing, which the declarative grammar cannot express.
struct DenoRun {
    owner: Box<dyn CommandModel>,
}

impl CommandModel for DenoRun {
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

    fn records_process(&self) -> bool {
        self.owner.records_process()
    }

    fn stdout_value_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        self.owner.stdout_value_bindings(argv)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<ModelCausalBinding> {
        match deno_run_script(argv) {
            // The fetched module is the code deno runs.
            Some(DenoScript::Remote(_)) => vec![ModelCausalBinding {
                assurance: effinterp_proto::CausalAssurance::Exact,
                from: ModelBindingEnd::Effect {
                    operation: "network.download".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
                to: ModelBindingEnd::Effect {
                    operation: "process.code_execution".into(),
                    selection: effinterp_model_schema::EffectSelection::All,
                },
            }],
            Some(DenoScript::Stdin) => Vec::new(),
            Some(DenoScript::Local(_)) | None => self.owner.causal_bindings(argv),
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let Some(script) = deno_run_script(ctx.argv)
            .filter(|script| !matches!(script, DenoScript::Local(index) if !written_earlier(builder, ctx, *index)))
        else {
            self.owner.apply(builder, ctx, model_node);
            return;
        };
        let conservative = effinterp_proto::RequestAssurance::Conservative;
        match script {
            DenoScript::Remote(index) => {
                builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
                let arg = arg_node(builder, ctx, index as u32);
                let resource = ctx.argv[index]
                    .as_literal()
                    .and_then(crate::models::net::parse_endpoint)
                    .map_or(unresolved_resource("network"), |identity| {
                        ResourceExpr::Concrete { identity }
                    });
                builder.effect(effinterp_proto::Effect {
                    request_assurance: conservative,
                    id: Default::default(),
                    operation: effinterp_proto::Operation::new("network.download"),
                    resource,
                    attributes: Default::default(),
                    modality: effinterp_proto::Modality::May,
                    realm: effinterp_proto::ExecutionRealm::Host,
                    condition: None,
                    execution: effinterp_proto::ExecutionNodeRef(0),
                    provenance: vec![arg, model_node],
                });
                code_execution(
                    conservative,
                    builder,
                    ctx,
                    model_node,
                    Some(index as u32),
                    "file",
                    Default::default(),
                );
                node_source_unavailable(builder, model_node, "deno remote module is not analyzed");
            }
            DenoScript::Stdin => {
                code_execution(
                    conservative,
                    builder,
                    ctx,
                    model_node,
                    None,
                    "stdin",
                    Default::default(),
                );
                node_source_unavailable(
                    builder,
                    model_node,
                    "deno program from stdin is not analyzed",
                );
            }
            // Deno reads the file and runs it, as `node FILE` does; its bytes
            // are whatever the earlier write left, which the walk cannot name.
            DenoScript::Local(index) => {
                code_execution(
                    conservative,
                    builder,
                    ctx,
                    model_node,
                    Some(index as u32),
                    "file",
                    Default::default(),
                );
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    index as u32,
                    &ctx.argv[index],
                    "filesystem.read",
                    Default::default(),
                );
                node_source_unavailable(
                    builder,
                    model_node,
                    "deno script written earlier in the call is not analyzed",
                );
            }
        }
    }
}

/// Whether an earlier write in this call replaced the script at `index` with
/// bytes the walk cannot name. Any other local script stays with the deno
/// model, whose plans for files on disk are unchanged.
fn written_earlier(builder: &PlanBuilder, ctx: &InvocationCtx, index: usize) -> bool {
    let Some((_, path)) = ctx.argv[index]
        .as_literal()
        .and_then(|script| crate::paths::join_source_path(ctx.runtime_cwd, script))
    else {
        return false;
    };
    matches!(
        builder.written_source(&path, |resource, path| {
            ctx.nest.source_mutation_may_alias(resource, path)
        }),
        crate::builder::WrittenSource::Stale | crate::builder::WrittenSource::Ambiguous
    )
}
