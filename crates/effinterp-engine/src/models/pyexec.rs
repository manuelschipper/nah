//! The python/python3 command model: inline `-c` source is analyzed as a
//! nested Python subject; local `-m module` entrypoints and script paths nest
//! source supplied by a repository resolver. Reviewed `-m` entrypoints without
//! a local shadow delegate to their command models. The `py` launcher takes
//! the same arguments behind its own version selector. `ipython -c` source
//! is one IPython cell.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionAssurance, ExecutionContent, ExecutionInput, ExecutionInputReason, ExecutionInputRole,
    ExecutionPhase, ExecutionSelector, ProvenanceRef, ResourceExpr, ResourceIdentity, Subject,
};

use crate::builder::PlanBuilder;
use crate::models::common::{
    RuntimeSourceLanguage, RuntimeSourceOutcome, arg_node, code_execution, opaque_source,
    operand_effect, runtime_searched_source, runtime_selected_source, runtime_unobserved_input,
};
use crate::models::registry::launcher::LauncherInvocation;
use crate::models::{InvocationCtx, source_refusal_detail};
use crate::nest::{Nest, SourceResolution, SourceSearchObservation};
use crate::python::{PackageDirs, PythonImportSearch, package_dirs};
use crate::word::Word;
use crate::{SourcePurpose, SourceRefusal};

pub(crate) fn apply(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    if is_ipython(ctx) {
        ipython(builder, ctx, model_node, invocation);
        return;
    }
    let controls = python_controls(ctx);
    let (reviewed_runtime, runtime_issue) = python_reviewed_runtime(ctx);
    if let Some(reason) = runtime_issue {
        python_runtime_boundary(builder, ctx, reason);
    }
    if let Some(option) = controls.unknown_code_selector.as_deref() {
        runtime_unobserved_input(
            builder,
            ctx,
            option,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Startup,
            if option == "PYTHONSAFEPATH" {
                ExecutionSelector::Environment {
                    variable: option.to_string(),
                }
            } else {
                ExecutionSelector::RuntimeOption {
                    option: option.to_string(),
                }
            },
            ExecutionInputReason::Ambiguous,
        );
    } else if reviewed_runtime {
        python_startup_inputs(builder, ctx, model_node, &controls);
    }

    let source_option = invocation.options.iter().find(|option| {
        matches!(
            option.class,
            effinterp_model_schema::LauncherOptionClassDeclaration::InlineSource
                | effinterp_model_schema::LauncherOptionClassDeclaration::ModuleSelector
        )
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
    if preceding.iter().any(|option| {
        matches!(
            option.name.as_str(),
            "-h" | "-?"
                | "--help"
                | "--help-env"
                | "--help-xoptions"
                | "--help-all"
                | "-V"
                | "-VV"
                | "--version"
        )
    }) {
        return;
    }
    if preceding.iter().any(|option| {
        matches!(
            option.name.as_str(),
            "-W" | "-X" | "--check-hash-based-pycs"
        ) && option.value.is_none()
    }) {
        return;
    }

    let python2 = ctx
        .argv
        .first()
        .and_then(Word::as_literal)
        .is_some_and(|command| {
            command
                .rsplit('/')
                .next()
                .is_some_and(|name| name == "python2" || name.starts_with("python2."))
        });
    let q_option = preceding.iter().find(|option| option.name == "-Q").copied();
    if python2 && q_option.is_some_and(|option| option.value.is_none()) {
        return;
    }

    if let Some(option) = source_option {
        let Some(source) = option.value.as_ref() else {
            return;
        };
        if option.class == effinterp_model_schema::LauncherOptionClassDeclaration::ModuleSelector {
            delegate_module(
                builder,
                ctx,
                model_node,
                source.index as usize,
                Some(&source.word),
                &controls,
                reviewed_runtime,
            );
            return;
        }
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            Some(source.index),
            "argument",
            BTreeMap::new(),
        );
        let Some(code) = source.word.as_literal() else {
            opaque_source(builder, model_node, "python -c with non-literal source");
            return;
        };
        if controls.unknown_code_selector.is_none() && reviewed_runtime {
            python_path_input(builder, ctx, model_node, &controls);
            python_base64_struct_import_inputs(
                builder,
                ctx,
                model_node,
                code,
                &controls,
                ctx.runtime_cwd,
            );
        }
        let arg = arg_node(builder, ctx, source.index);
        nest_python_program(ctx, &controls, reviewed_runtime, ctx.runtime_cwd, || {
            ctx.nest_subject(
                builder,
                Subject::Source {
                    dialect: None,
                    language: "python".into(),
                    source: code.to_string(),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                &[model_node, arg],
            )
        });
        return;
    }

    let script = if !python2 && q_option.is_some() {
        q_option.and_then(|option| option.value.as_ref())
    } else {
        invocation.script.as_ref()
    };
    if let Some(script) = script {
        if script.word.as_literal() == Some("-") {
            stdin_program(
                builder,
                ctx,
                model_node,
                Some(script.index),
                "python reads program from stdin",
                &controls,
                reviewed_runtime,
            );
        } else {
            nest_script(
                builder,
                ctx,
                model_node,
                script.index as usize,
                Some(&script.word),
                &controls,
                reviewed_runtime,
            );
        }
        return;
    }
    if controls.unknown_code_selector.is_none() && reviewed_runtime {
        python_interactive_startup(builder, ctx, model_node, &controls);
    }
    stdin_program(
        builder,
        ctx,
        model_node,
        None,
        "python interactive interpreter",
        &controls,
        reviewed_runtime,
    );
}

/// `ipython -c CELL` runs the cell, with IPython's shell escapes and magics,
/// after Python's own startup and the IPython profile's configuration and
/// startup files. Only the `-c` cell is modeled; a script or an interactive
/// session stays opaque.
fn ipython(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    let source = invocation.inline_source.as_ref();
    let source_index = source.map_or(u32::MAX, |source| source.index);
    if invocation.options.iter().any(|option| {
        option.index < source_index
            && matches!(
                option.name.as_str(),
                "-h" | "--help" | "--help-all" | "-V" | "--version"
            )
    }) {
        return;
    }
    let controls = PythonControls::default();
    python_startup_inputs(builder, ctx, model_node, &controls);
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(
                "IPython startup may execute the profile's configuration, startup files, and PYTHONSTARTUP"
                    .to_string(),
            ),
        },
        CoverageLevel::Partial,
    );
    let Some(source) = source else {
        let (argument, kind, detail) = match &invocation.script {
            Some(script) => (
                Some(script.index),
                "file",
                "ipython script launch is not modeled",
            ),
            None => (None, "stdin", "ipython interactive session"),
        };
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            ctx,
            model_node,
            argument,
            kind,
            BTreeMap::new(),
        );
        opaque_source(builder, model_node, detail);
        return;
    };
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        Some(source.index),
        "argument",
        BTreeMap::new(),
    );
    let Some(code) = source.word.as_literal() else {
        opaque_source(builder, model_node, "ipython -c with non-literal source");
        return;
    };
    let arg = arg_node(builder, ctx, source.index);
    nest_python_program(ctx, &controls, true, ctx.runtime_cwd, || {
        ctx.nest_subject(
            builder,
            Subject::Source {
                dialect: Some(effinterp_proto::SourceDialect::Ipython),
                language: "python".into(),
                source: code.to_string(),
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &[model_node, arg],
        )
    });
}

fn is_ipython(ctx: &InvocationCtx<'_>) -> bool {
    matches!(
        ctx.argv[0]
            .as_literal()
            .and_then(|command| command.rsplit('/').next()),
        Some("ipython" | "ipython3")
    )
}

fn python_reviewed_runtime(ctx: &InvocationCtx<'_>) -> (bool, Option<ExecutionInputReason>) {
    let component = ctx.argv[0]
        .as_literal()
        .and_then(|command| command.rsplit('/').next())
        .unwrap_or("python");
    if matches!(
        component,
        "python" | "python3" | "pypy3" | "ipython" | "ipython3"
    ) {
        return (true, None);
    }
    if component.strip_prefix("python3.").is_some_and(|minor| {
        minor
            .parse::<u8>()
            .is_ok_and(|minor| (8..=14).contains(&minor))
    }) {
        return (true, None);
    }
    if component == "py" {
        return match ctx
            .argv
            .get(1)
            .and_then(Word::as_literal)
            .and_then(launcher_version)
        {
            Some((3, None)) => (true, None),
            Some((3, Some(minor))) if (8..=14).contains(&minor) => (true, None),
            Some(_) => (false, Some(ExecutionInputReason::Mismatched)),
            None => (false, Some(ExecutionInputReason::Ambiguous)),
        };
    }
    (false, Some(ExecutionInputReason::Mismatched))
}

fn python_runtime_boundary(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    reason: ExecutionInputReason,
) {
    let component = ctx.argv[0]
        .as_literal()
        .and_then(|command| command.rsplit('/').next())
        .unwrap_or("python");
    runtime_unobserved_input(
        builder,
        ctx,
        component,
        ExecutionInputRole::ExplicitInvocation,
        ExecutionPhase::Main,
        ExecutionSelector::InvocationPath,
        reason,
    );
}

#[derive(Default)]
struct PythonControls {
    isolated: bool,
    ignore_environment: bool,
    no_user_site: bool,
    no_site: bool,
    safe_path: bool,
    unknown_code_selector: Option<String>,
}

fn python_controls(ctx: &InvocationCtx<'_>) -> PythonControls {
    let mut controls = PythonControls::default();
    let launcher = is_py_launcher(ctx);
    let mut index = 1;
    while let Some(argument) = ctx.argv.get(index).and_then(Word::as_literal) {
        if argument == "--" || argument == "-" || !argument.starts_with('-') {
            break;
        }
        if launcher && launcher_version_selector(argument) {
            index += 1;
            continue;
        }
        if matches!(argument, "-c" | "-m")
            || argument.starts_with("-c")
            || argument.starts_with("-m")
        {
            break;
        }
        if matches!(argument, "-W" | "--check-hash-based-pycs") {
            index += 2;
            continue;
        }
        if argument == "-X" {
            let Some(value) = ctx.argv.get(index + 1).and_then(Word::as_literal) else {
                controls.unknown_code_selector = Some(argument.to_string());
                break;
            };
            if python_inert_xoption(value) {
                index += 2;
                continue;
            }
            controls.unknown_code_selector = Some(format!("-X {value}"));
            break;
        }
        if let Some(value) = argument.strip_prefix("-X") {
            if python_inert_xoption(value) {
                index += 1;
                continue;
            }
            controls.unknown_code_selector = Some(argument.to_string());
            break;
        }
        if argument.starts_with("--")
            && !matches!(
                argument,
                "--help" | "--help-env" | "--help-xoptions" | "--help-all" | "--version"
            )
        {
            controls.unknown_code_selector = Some(argument.to_string());
            break;
        }
        let mut source_selected = false;
        for option in argument.trim_start_matches('-').chars() {
            match option {
                // `c` and `m` consume the rest of the cluster as the program
                // text or the module name.
                'c' | 'm' => {
                    source_selected = true;
                    break;
                }
                'I' => {
                    // CPython defines isolated mode as implying -E, -P, and -s,
                    // but not -S: global site startup still runs under -I.
                    controls.isolated = true;
                    controls.ignore_environment = true;
                    controls.no_user_site = true;
                    controls.safe_path = true;
                }
                'E' => controls.ignore_environment = true,
                'S' => controls.no_site = true,
                'P' => controls.safe_path = true,
                's' => controls.no_user_site = true,
                'b' | 'B' | 'd' | 'i' | 'O' | 'q' | 'u' | 'v' | 'x' | 'V' | 'h' | '?' => {}
                _ => {
                    controls.unknown_code_selector = Some(argument.to_string());
                    break;
                }
            }
        }
        if source_selected || controls.unknown_code_selector.is_some() {
            break;
        }
        index += 1;
    }
    if !controls.ignore_environment {
        if matches!(
            ctx.environment_value("PYTHONNOUSERSITE"),
            Some(ResourceExpr::Literal { value }) if !value.is_empty()
        ) {
            controls.no_user_site = true;
        }
        let minor = ctx.argv[0]
            .as_literal()
            .and_then(|command| command.rsplit('/').next())
            .and_then(|command| command.strip_prefix("python3."))
            .and_then(|minor| minor.parse::<u8>().ok());
        match ctx.environment_value("PYTHONSAFEPATH") {
            Some(ResourceExpr::Literal { value }) if value.is_empty() => {}
            Some(_) if minor.is_some_and(|minor| (8..=10).contains(&minor)) => {}
            Some(ResourceExpr::Literal { .. })
                if minor.is_some_and(|minor| (11..=14).contains(&minor)) =>
            {
                controls.safe_path = true
            }
            Some(_) => controls.unknown_code_selector = Some("PYTHONSAFEPATH".to_string()),
            None => {}
        }
    }
    controls
}

fn python_inert_xoption(value: &str) -> bool {
    matches!(value.split('=').next().unwrap_or(value), "dev" | "utf8")
}

fn python_startup_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    controls: &PythonControls,
) {
    // CPython's -S is the control that suppresses `site`. -E only ignores
    // PYTHON* variables, while -s suppresses the user site but not global site.
    if controls.no_site {
        return;
    }
    if !controls.isolated && !controls.ignore_environment {
        match ctx.environment_value("PYTHONPATH") {
            Some(ResourceExpr::Literal { value }) => {
                if let Some(candidates) = python_module_candidates(
                    builder,
                    ctx.nest,
                    ctx.argv[0].as_literal(),
                    ctx.runtime_cwd,
                    &python_path_entries(&value, ctx.runtime_cwd),
                    "sitecustomize",
                ) {
                    runtime_searched_source(
                        builder,
                        ctx,
                        model_node,
                        "sitecustomize",
                        candidates,
                        ExecutionInputRole::UnexpectedSelected,
                        ExecutionPhase::Startup,
                        ExecutionSelector::Environment {
                            variable: "PYTHONPATH".to_string(),
                        },
                        RuntimeSourceLanguage::PythonModule,
                        false,
                    );
                }
                if !controls.no_user_site
                    && let Some(candidates) = python_module_candidates(
                        builder,
                        ctx.nest,
                        ctx.argv[0].as_literal(),
                        ctx.runtime_cwd,
                        &python_path_entries(&value, ctx.runtime_cwd),
                        "usercustomize",
                    )
                {
                    runtime_searched_source(
                        builder,
                        ctx,
                        model_node,
                        "usercustomize",
                        candidates,
                        ExecutionInputRole::UnexpectedSelected,
                        ExecutionPhase::Startup,
                        ExecutionSelector::Environment {
                            variable: "PYTHONPATH".to_string(),
                        },
                        RuntimeSourceLanguage::PythonModule,
                        false,
                    );
                }
            }
            Some(_) => python_environment_boundary(
                builder,
                model_node,
                "PYTHONPATH",
                "Python startup module search depends on an unobserved PYTHONPATH",
            ),
            None => {}
        }
    }
    python_site_startup_boundary(builder, ctx, model_node, controls);
}

fn python_environment_boundary(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    name: &str,
    detail: &str,
) {
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            }),
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(detail.to_string()),
        },
        CoverageLevel::Partial,
    );
}

fn python_path_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    controls: &PythonControls,
) {
    // -S suppresses site startup, which would normally request PYTHONPATH.
    // The module finder still uses it for both -c imports and -m selection.
    if !controls.no_site || controls.ignore_environment || controls.isolated {
        return;
    }
    match ctx.environment_value("PYTHONPATH") {
        Some(ResourceExpr::Literal { .. }) => {}
        None if ctx.nest.environment_is_closed()
            || ctx.nest.current_environment_unsets().contains("PYTHONPATH") => {}
        _ => python_environment_boundary(
            builder,
            model_node,
            "PYTHONPATH",
            "Python module search depends on an unobserved PYTHONPATH",
        ),
    }
}

/// CPython's `site` import may run `.pth` files, `sitecustomize`, and
/// `usercustomize` from the installation's site directories. Which directories
/// those are depends on the PYTHON* variables below: each one this launch has
/// not observed is named in the affected resource, so a caller can observe it,
/// and leaves the boundary unresolved. Once every one is observed (a value or
/// unset), what remains is the installation's own startup code, which is
/// environment behavior beyond the invocation.
fn python_site_startup_boundary(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    controls: &PythonControls,
) {
    let detail = if controls.no_user_site {
        "CPython site startup may execute global .pth files and sitecustomize; startup paths are unobserved"
    } else {
        "CPython site startup may execute .pth files, sitecustomize, and usercustomize; startup paths are unobserved"
    };
    let unobserved: Vec<ResourceExpr> = [
        Some("PYTHONHOME"),
        Some("PYTHONPATH"),
        (!controls.no_user_site).then_some("PYTHONNOUSERSITE"),
        (!controls.no_user_site).then_some("PYTHONUSERBASE"),
    ]
    .into_iter()
    .flatten()
    .filter(|_| !controls.ignore_environment)
    .filter(|name| {
        !matches!(
            ctx.environment_value(name),
            Some(ResourceExpr::Literal { .. })
        ) && !ctx.nest.current_environment_unsets().contains(*name)
    })
    .map(|name| ResourceExpr::Concrete {
        identity: ResourceIdentity::EnvironmentVariable {
            name: name.to_string(),
        },
    })
    .collect();
    // The installation's own startup code is environment behavior; startup
    // paths an unobserved variable selects leave the invocation unresolved.
    let (class, scope) = if unobserved.is_empty() {
        (BoundaryClass::Unmodeled, BoundaryScope::Environment)
    } else {
        (BoundaryClass::Unresolved, BoundaryScope::Invocation)
    };
    builder.boundary_with_coverage(
        Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class,
            scope,
            affected_resource: (!unobserved.is_empty()).then_some(ResourceExpr::Union {
                alternatives: unobserved,
            }),
            callee: None,
            domains: vec![Domain::new("environment")],
            provenance: vec![model_node],
            limit: None,
            detail: Some(detail.to_string()),
        },
        CoverageLevel::Partial,
    );
}

fn python_interactive_startup(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    controls: &PythonControls,
) {
    if controls.isolated || controls.ignore_environment {
        return;
    }
    match ctx.environment_value("PYTHONSTARTUP") {
        Some(ResourceExpr::Literal { value }) if !value.is_empty() => {
            runtime_selected_source(
                builder,
                ctx,
                model_node,
                &value,
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Startup,
                ExecutionSelector::Environment {
                    variable: "PYTHONSTARTUP".to_string(),
                },
                RuntimeSourceLanguage::Python,
            );
        }
        Some(ResourceExpr::Literal { .. }) | None => {}
        Some(_) => runtime_unobserved_input(
            builder,
            ctx,
            "$PYTHONSTARTUP",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Startup,
            ExecutionSelector::Environment {
                variable: "PYTHONSTARTUP".to_string(),
            },
            ExecutionInputReason::Ambiguous,
        ),
    }
}

/// The reviewed CPython convention that importing the standard `base64` module
/// also imports `struct`, so a `struct.py` on the search path runs. Other
/// imports are not handled here; the Python walk resolves them. A `base64`
/// found on the search path shadows the standard module, so `struct` is only
/// searched when no `base64` candidate exists, and an import demand that is not
/// definite, or a search whose native-extension candidates cannot be
/// excluded, stays ambiguous.
fn python_base64_struct_import_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    source: &str,
    controls: &PythonControls,
    launch_root: Option<&str>,
) {
    let imports = match crate::python::runtime_imports(source, ctx.nest.limits.max_python_nodes) {
        Ok(imports) => imports,
        Err(reason) => {
            runtime_unobserved_input(
                builder,
                ctx,
                "python-runtime-imports",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Import,
                ExecutionSelector::Convention {
                    name: "python-runtime-import-demand".to_string(),
                },
                reason,
            );
            return;
        }
    };
    let search_roots = python_import_search(ctx, controls, launch_root).roots;
    for (module, definite) in imports {
        if module.is_empty() || module.starts_with('.') {
            continue;
        }
        let root = module.split('.').next().unwrap_or(&module);
        if root != "base64" {
            continue;
        }
        if !definite {
            runtime_unobserved_input(
                builder,
                ctx,
                "struct",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Import,
                ExecutionSelector::Convention {
                    name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            continue;
        }
        let Some(candidates) = python_module_candidates(
            builder,
            ctx.nest,
            ctx.argv[0].as_literal(),
            ctx.runtime_cwd,
            &search_roots,
            root,
        ) else {
            runtime_unobserved_input(
                builder,
                ctx,
                "struct",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Import,
                ExecutionSelector::Convention {
                    name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            continue;
        };
        let base64 = runtime_searched_source(
            builder,
            ctx,
            model_node,
            root,
            candidates,
            ExecutionInputRole::DependencyRequest,
            ExecutionPhase::Import,
            ExecutionSelector::Dependency {
                specifier: root.to_string(),
            },
            RuntimeSourceLanguage::Opaque,
            false,
        );
        if base64 != RuntimeSourceOutcome::Missing {
            continue;
        }
        let Some(candidates) = python_module_candidates(
            builder,
            ctx.nest,
            ctx.argv[0].as_literal(),
            ctx.runtime_cwd,
            &search_roots,
            "struct",
        ) else {
            runtime_unobserved_input(
                builder,
                ctx,
                "struct",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Import,
                ExecutionSelector::Convention {
                    name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            );
            continue;
        };
        runtime_searched_source(
            builder,
            ctx,
            model_node,
            "struct",
            candidates,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Import,
            ExecutionSelector::Convention {
                name: "cpython-base64-imports-struct@3.8-3.14".to_string(),
            },
            RuntimeSourceLanguage::PythonModule,
            false,
        );
    }
}

/// The `sys.path` roots a launched main program is observed to import from:
/// its launch root unless safe-path mode, then literal `PYTHONPATH` entries
/// unless isolated or environment-ignoring mode.
fn python_import_search(
    ctx: &InvocationCtx<'_>,
    controls: &PythonControls,
    launch_root: Option<&str>,
) -> PythonImportSearch {
    let mut roots = Vec::new();
    if !controls.safe_path
        && let Some(cwd) = launch_root
    {
        roots.push(cwd.to_string());
    }
    if !controls.isolated
        && !controls.ignore_environment
        && let Some(ResourceExpr::Literal { value }) = ctx.environment_value("PYTHONPATH")
    {
        roots.extend(python_path_entries(&value, ctx.runtime_cwd));
    }
    PythonImportSearch::new(roots, ctx.argv[0].as_literal().map(str::to_string), None)
}

/// Nest a Python main program with its import search handed to its walk.
/// Launches with an unreviewed runtime or unknown code selector keep imports
/// as dependency-request boundaries.
fn nest_python_program(
    ctx: &InvocationCtx<'_>,
    controls: &PythonControls,
    reviewed_runtime: bool,
    launch_root: Option<&str>,
    nest: impl FnOnce(),
) {
    if controls.unknown_code_selector.is_none() && reviewed_runtime {
        *ctx.nest.python_import_search.borrow_mut() =
            Some(python_import_search(ctx, controls, launch_root));
    }
    nest();
    ctx.nest.python_import_search.borrow_mut().take();
}

pub(crate) fn python_path_entries(value: &str, cwd: Option<&str>) -> Vec<String> {
    // CPython ignores an empty variable but treats empty list entries as cwd.
    if value.is_empty() {
        return Vec::new();
    }
    value
        .split(':')
        .filter_map(|entry| {
            if entry.is_empty() {
                cwd.map(str::to_string)
            } else {
                Some(entry.to_string())
            }
        })
        .collect()
}

fn python_extension_suffixes(
    nest: &Nest<'_>,
    executable: Option<&str>,
    runtime_cwd: Option<&str>,
    search_roots: &[String],
) -> Option<Vec<String>> {
    if nest.budget.timed_out() {
        return None;
    }
    if search_roots.is_empty() {
        return Some(Vec::new());
    }
    let suffixes = nest
        .resolver?
        .python_extension_suffixes(executable?, runtime_cwd)?;
    // Bound exact build metadata before constructing demanded candidate paths.
    if suffixes.len() > 16
        || suffixes.iter().any(|suffix| {
            !suffix.starts_with('.')
                || suffix.len() < 2
                || suffix.len() > 128
                || !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                || matches!(suffix.as_str(), ".py" | ".pyc")
        })
    {
        return None;
    }
    Some(suffixes)
}

/// Ordered FileFinder candidates for a dotted module across launch search roots.
/// None means native-extension candidates could not be excluded, so a source
/// winner would be ambiguous.
pub(crate) fn python_module_candidates(
    builder: &PlanBuilder,
    nest: &Nest<'_>,
    executable: Option<&str>,
    runtime_cwd: Option<&str>,
    search_roots: &[String],
    module: &str,
) -> Option<Vec<String>> {
    python_module_candidate_roles(builder, nest, executable, runtime_cwd, search_roots, module)
        .map(|candidates| candidates.into_iter().map(|(path, _)| path).collect())
}

/// The same candidates as [`python_module_candidates`], each marked with the
/// role FileFinder gave it. True means the package-initializer stem
/// (`{module}/__init__`); false means the module-file stem (`{module}`).
/// The search root's basename is not part of that role.
pub(crate) fn python_module_candidate_roles(
    builder: &PlanBuilder,
    nest: &Nest<'_>,
    executable: Option<&str>,
    runtime_cwd: Option<&str>,
    search_roots: &[String],
    module: &str,
) -> Option<Vec<(String, bool)>> {
    let module = module.replace('.', "/");
    let suffixes = match python_extension_suffixes(nest, executable, runtime_cwd, search_roots) {
        Some(suffixes) => suffixes,
        None => {
            if !builder.is_host_realm()
                || nest.source_resolution_disabled.get()
                || search_roots.len() as u64 > nest.limits.max_resolved_source_files
                || !nest
                    .budget
                    .try_charge_steps(search_roots.len() as u64 * 512)
            {
                return None;
            }
            let resolver = nest.resolver?;
            for root in search_roots {
                for stem in [
                    python_search_path(root, &format!("{module}/__init__")),
                    python_search_path(root, &module),
                ] {
                    let (namespace, path) = crate::paths::join_source_path(runtime_cwd, &stem)?;
                    if nest.budget.timed_out()
                        || !resolver.python_native_candidates_absent(crate::SourceRequest {
                            path: &path,
                            namespace,
                            purpose: crate::SourcePurpose::InvocationInput,
                            requester_language: None,
                        })
                    {
                        return None;
                    }
                }
            }
            Vec::new()
        }
    };
    Some(python_candidates_with_suffixes(
        search_roots,
        &module,
        &suffixes,
    ))
}

/// A path beneath one `sys.path` root; the empty root is the namespace root.
pub(crate) fn python_search_path(root: &str, relative: &str) -> String {
    if root.is_empty() {
        relative.to_string()
    } else {
        format!("{}/{relative}", root.trim_end_matches('/'))
    }
}

pub(crate) fn python_candidates_with_suffixes(
    search_roots: &[String],
    module: &str,
    suffixes: &[String],
) -> Vec<(String, bool)> {
    let mut candidates = Vec::new();
    for root in search_roots {
        // FileFinder checks regular packages before files, and extension loaders
        // before source and sourceless bytecode within each group. The role is
        // which stem this is, not whether the absolute path looks like a
        // package: a search root named `__init__` makes the module-file
        // candidate `{root}/__init__.py` end in `/__init__/__init__.py`.
        for (stem, package) in [
            (
                python_search_path(root, &format!("{module}/__init__")),
                true,
            ),
            (python_search_path(root, module), false),
        ] {
            for suffix in suffixes.iter().map(String::as_str).chain([".py", ".pyc"]) {
                let candidate = format!("{stem}{suffix}");
                if candidates.iter().all(|(path, _)| path != &candidate) {
                    candidates.push((candidate, package));
                }
            }
        }
    }
    candidates
}

fn stdin_program(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    argument: Option<u32>,
    unavailable_detail: &str,
    controls: &PythonControls,
    reviewed_runtime: bool,
) {
    let mut attributes = BTreeMap::new();
    if ctx.stdin.is_some_and(|stdin| stdin.spelled) {
        attributes.insert(
            "source_from_subject".to_string(),
            effinterp_proto::AttrValue::Bool(true),
        );
    }
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        argument,
        "stdin",
        attributes,
    );
    if let Some(code) = ctx.stdin_source(builder) {
        if controls.unknown_code_selector.is_none() && reviewed_runtime {
            python_base64_struct_import_inputs(
                builder,
                ctx,
                model_node,
                &code,
                controls,
                ctx.runtime_cwd,
            );
        }
        let mut provenance = vec![model_node];
        provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
        nest_python_program(ctx, controls, reviewed_runtime, ctx.runtime_cwd, || {
            ctx.nest_subject(
                builder,
                Subject::Source {
                    dialect: None,
                    language: "python".into(),
                    source: code.to_string(),
                    cwd: ctx.cwd.map(str::to_string),
                    context: Default::default(),
                },
                &provenance,
            )
        });
    } else if ctx.stdin.is_some() {
        opaque_source(
            builder,
            model_node,
            "stdin program is not statically recoverable",
        );
    } else {
        opaque_source(builder, model_node, unavailable_detail);
    }
}

fn delegate_module(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    module_index: usize,
    module: Option<&Word>,
    controls: &PythonControls,
    reviewed_runtime: bool,
) {
    let Some(module) = module else {
        return;
    };
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        Some(module_index as u32),
        "file",
        BTreeMap::new(),
    );
    let command = module.as_literal().and_then(module_command);
    let mut shadow_refusal = None;
    let local = if let Some(module) = module.as_literal()
        && controls.unknown_code_selector.is_none()
        && reviewed_runtime
        && ctx.nest.resolver.is_some()
    {
        python_path_input(builder, ctx, model_node, controls);
        let search = python_import_search(ctx, controls, ctx.runtime_cwd);
        // A local package or module shadows even a reviewed installed entrypoint.
        let mut local = command.is_none();
        if !local {
            let first = module.split('.').next().unwrap();
            for root in &search.roots {
                let candidates =
                    python_candidates_with_suffixes(std::slice::from_ref(root), first, &[])
                        .into_iter()
                        .filter_map(|(path, _)| {
                            crate::paths::join_source_path(ctx.runtime_cwd, &path)
                        })
                        .collect::<Vec<_>>();
                match ctx.nest.observe_source_search(
                    builder,
                    &candidates,
                    SourcePurpose::InvocationInput,
                ) {
                    SourceSearchObservation::Found { .. } => {
                        local = true;
                        break;
                    }
                    SourceSearchObservation::Refused(refusal) => {
                        if source_search_limit(refusal) {
                            shadow_refusal = Some((module, refusal));
                            break;
                        }
                        shadow_refusal.get_or_insert((module, refusal));
                    }
                    SourceSearchObservation::ResolverUnavailable => break,
                    SourceSearchObservation::Missing => {}
                }
            }
        }
        local.then_some((module, search))
    } else {
        None
    };

    let mut gaps = Vec::new();
    if let Some((module, search)) = local {
        if !nest_local_module(
            builder,
            ctx,
            model_node,
            module_index,
            module,
            &search,
            controls,
            &mut gaps,
        ) {
            opaque_source(builder, model_node, "python module source unavailable");
        }
    } else if let Some(command) = command {
        let module_arg = arg_node(builder, ctx, module_index as u32);
        let tail_start = module_index + 1;
        let mut argv = Vec::with_capacity(1 + ctx.argv.len().saturating_sub(tail_start));
        argv.push(Word::literal(command));
        argv.extend_from_slice(&ctx.argv[tail_start..]);

        let mut argv_provenance = Vec::with_capacity(argv.len());
        argv_provenance.push(vec![model_node, module_arg]);
        argv_provenance.extend(
            (tail_start..ctx.argv.len()).map(|index| vec![arg_node(builder, ctx, index as u32)]),
        );
        let startup_environment = &ctx.nest.python_ignores_startup_environment;
        let previous = startup_environment.replace(controls.ignore_environment);
        ctx.delegate_command_model(
            builder,
            &argv,
            Some(&argv_provenance),
            &[model_node, module_arg],
        );
        startup_environment.set(previous);
    } else {
        opaque_source(builder, model_node, "python module source unavailable");
    }
    // A possible shadow or search gap must not stale the observations of a
    // readable candidate or of the installed model.
    if let Some((module, refusal)) = shadow_refusal {
        let gap = python_module_gap(
            builder,
            ctx,
            module,
            crate::nest::source_refusal_reason(refusal),
        );
        if !gaps.iter().any(|(_, input)| input.content == gap.content) {
            gaps.push((module.to_string(), gap));
        }
    }
    for (path, input) in gaps {
        ctx.nest.record_input_boundary(builder, &path, input);
    }
}

fn source_search_limit(refusal: SourceRefusal) -> bool {
    matches!(
        refusal,
        SourceRefusal::Limit { limit } if limit != "max_source_bytes"
    )
}

fn python_module_gap(
    builder: &PlanBuilder,
    ctx: &InvocationCtx<'_>,
    module: &str,
    reason: ExecutionInputReason,
) -> ExecutionInput {
    let mut input = ctx.nest.source_input(
        builder,
        module,
        SourcePurpose::InvocationInput,
        ExecutionContent::Unobserved { reason },
        ctx.argv[0]
            .as_literal()
            .and_then(|path| path.rsplit('/').next())
            .unwrap_or("python"),
    );
    input.selected = None;
    input.assurance = ExecutionAssurance::Widened;
    input.selector = ExecutionSelector::RuntimeOption {
        option: "-m".into(),
    };
    input
}

/// Resolve `-m` in search order. Each parent package is imported before its
/// child, and a regular or namespace package runs its `__main__`.
#[allow(clippy::too_many_arguments)]
fn nest_local_module(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    module_index: usize,
    module: &str,
    search: &PythonImportSearch,
    controls: &PythonControls,
    gaps: &mut Vec<(String, ExecutionInput)>,
) -> bool {
    let Some(cwd) = ctx.runtime_cwd else {
        return false;
    };
    let mut components = module.split('.').collect::<Vec<_>>();
    if components
        .iter()
        .any(|part| part.is_empty() || part.contains(['/', '\\']))
    {
        return false;
    }
    if search.roots.is_empty() {
        return false;
    }
    let mut directories = PackageDirs {
        roots: search.roots.clone(),
        unordered: false,
    };
    let mut index = 0;
    let mut analyzed_main = false;
    while index < components.len() {
        let component = components[index];
        let specifier = components[..=index].join(".");
        let final_component = index + 1 == components.len();
        let main_component = component == "__main__";
        let mut input = ctx.nest.source_input(
            builder,
            module,
            SourcePurpose::InvocationInput,
            ExecutionContent::Unobserved {
                reason: ExecutionInputReason::ResolverUnavailable,
            },
            "python",
        );
        input.selector = ExecutionSelector::RuntimeOption {
            option: "-m".into(),
        };
        if !final_component {
            input.role = ExecutionInputRole::DependencyRequest;
            input.phase = ExecutionPhase::Import;
            input.selector = ExecutionSelector::Dependency {
                specifier: module.into(),
            };
        }

        // Read the possible winners before analyzing any of them. An effect
        // of one candidate cannot change the file another candidate will run.
        let mut resolved = Vec::new();
        let mut probed_roots = BTreeSet::new();
        let mut namespaces = PackageDirs::default();
        let gaps_at_entry = gaps.len();
        let mut exhausted = false;
        for root in &directories.roots {
            let Some((_, root)) = crate::paths::join_source_path(ctx.runtime_cwd, root) else {
                gaps.push((
                    module.to_string(),
                    python_module_gap(
                        builder,
                        ctx,
                        module,
                        ExecutionInputReason::ResolverUnavailable,
                    ),
                ));
                continue;
            };
            if !probed_roots.insert(root.clone()) {
                continue;
            }
            if ctx.nest.budget.timed_out() {
                gaps.push((
                    module.to_string(),
                    python_module_gap(
                        builder,
                        ctx,
                        module,
                        ExecutionInputReason::BudgetRefused {
                            limit: "invocation_deadline".into(),
                        },
                    ),
                ));
                exhausted = true;
                break;
            }
            let Some(candidates) = python_module_candidate_roles(
                builder,
                ctx.nest,
                search.executable.as_deref(),
                ctx.runtime_cwd,
                std::slice::from_ref(&root),
                component,
            ) else {
                if gaps.len() == gaps_at_entry {
                    gaps.push((
                        module.to_string(),
                        python_module_gap(builder, ctx, module, ExecutionInputReason::Ambiguous),
                    ));
                }
                namespaces.roots.push(python_search_path(&root, component));
                continue;
            };
            let (candidates, roles): (Vec<_>, Vec<_>) = candidates
                .into_iter()
                .filter_map(|(path, package)| {
                    crate::paths::join_source_path(ctx.runtime_cwd, &path)
                        .map(|request| (request, package))
                })
                .unzip();
            let mut package = false;
            let (candidate, _) = ctx.nest.resolve_execution_search_with(
                builder,
                candidates,
                SourcePurpose::InvocationInput,
                input.clone(),
                false,
                |winner, input| {
                    package = roles[winner];
                    if final_component && package {
                        input.role = ExecutionInputRole::DependencyRequest;
                        input.phase = ExecutionPhase::Import;
                        input.selector = ExecutionSelector::Dependency {
                            specifier: module.into(),
                        };
                    }
                },
                |_, path, input| gaps.push((path.to_string(), input)),
            );
            match candidate {
                SourceResolution::Unavailable => {
                    namespaces.roots.push(python_search_path(&root, component));
                }
                SourceResolution::Refused(refusal) => {
                    if source_search_limit(refusal) {
                        exhausted = true;
                        break;
                    }
                    namespaces.roots.push(python_search_path(&root, component));
                }
                _ => {
                    resolved.push((candidate, package));
                    if !directories.unordered {
                        break;
                    }
                }
            }
        }

        let unobserved = gaps.len() != gaps_at_entry;
        let mut children = PackageDirs {
            roots: Vec::new(),
            unordered: directories.unordered || unobserved,
        };
        if resolved.is_empty() {
            if exhausted {
                return true;
            }
            if final_component && main_component {
                if !unobserved {
                    gaps.push((
                        module.to_string(),
                        python_module_gap(builder, ctx, module, ExecutionInputReason::Missing),
                    ));
                }
                return analyzed_main;
            }
            // With no regular winner, directories of this name can be
            // namespace portions. A package entry point is its __main__.
            children.include_portions(&directories, component);
        } else {
            if directories.unordered && !main_component {
                // An unknown path can exclude the roots with regular winners,
                // leaving only the namespace portions to supply children.
                children.merge(namespaces);
            }
            let arms = resolved.len() as u32 + 1;
            let mut found_package = false;
            for (arm, (candidate, package)) in resolved.into_iter().enumerate() {
                let (origin, source) = match candidate {
                    SourceResolution::Source { origin, source } => (origin, source),
                    SourceResolution::AlreadySelected | SourceResolution::UnsupportedEncoding => {
                        analyzed_main |= final_component;
                        continue;
                    }
                    _ => unreachable!(),
                };
                if !origin.ends_with(".py") {
                    ctx.nest.record_unsupported_source(builder, &origin);
                    analyzed_main |= final_component;
                    continue;
                }
                if package && main_component {
                    continue;
                }

                let main = !package && final_component;
                let source_cwd = crate::paths::parent_dir(&origin);
                let mut search = search.clone();
                search.package = (package || index > 0).then(|| source_cwd.clone());
                if package {
                    found_package = true;
                    let mut package_children = package_dirs(
                        builder,
                        ctx.nest,
                        &directories,
                        search.executable.as_deref(),
                        &specifier,
                        Some(&source_cwd),
                        &source,
                    );
                    if package_children.unordered {
                        package_children.include_portions(&directories, component);
                        if !directories.unordered && !unobserved {
                            gaps.push((
                                module.to_string(),
                                python_module_gap(
                                    builder,
                                    ctx,
                                    module,
                                    ExecutionInputReason::Ambiguous,
                                ),
                            ));
                        }
                    }
                    children.merge(package_children);
                    search.package_name = Some(specifier.clone());
                } else if index > 0 {
                    search.package_name = Some(components[..index].join("."));
                }

                let uncertain = directories.unordered || unobserved;
                if uncertain {
                    builder.push_condition(builder.source_condition_path(
                        effinterp_proto::Condition::from_source(
                            &specifier,
                            effinterp_proto::ByteSpan {
                                start: 0,
                                end: specifier.len() as u32,
                            },
                            effinterp_proto::ConditionKind::UnresolvedExecution,
                            arm as u32,
                            arms,
                            false,
                            false,
                        ),
                    ));
                }
                operand_effect(
                    builder,
                    ctx,
                    model_node,
                    module_index as u32,
                    &Word::literal(&origin),
                    "filesystem.read",
                    BTreeMap::new(),
                );
                python_base64_struct_import_inputs(
                    builder,
                    ctx,
                    model_node,
                    &source,
                    controls,
                    Some(cwd),
                );
                *ctx.nest.python_import_search.borrow_mut() = Some(search);
                let arg = arg_node(builder, ctx, module_index as u32);
                let mut argv = vec![
                    crate::nest::word_resource(&ctx.argv[0]),
                    crate::value::fs_path_resource(&origin),
                ];
                argv.extend(
                    ctx.argv[module_index + 1..]
                        .iter()
                        .map(crate::nest::word_resource),
                );
                ctx.nest.nest(
                    builder,
                    crate::nest::Transition::file(Subject::Source {
                        dialect: None,
                        language: "python".into(),
                        source,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                    .kind(if main {
                        effinterp_proto::ExecutionEdgeKind::Launch
                    } else {
                        effinterp_proto::ExecutionEdgeKind::Import
                    })
                    .argv(argv)
                    .origin(origin)
                    .source_cwd(Some(&source_cwd))
                    .runtime_cwd(ctx.runtime_cwd)
                    .cwd(ctx.cwd_resource(), ctx.cwd_node),
                    &[model_node, arg],
                    ctx.depth,
                );
                ctx.nest.python_import_search.borrow_mut().take();
                if uncertain {
                    builder.pop_condition();
                }
                analyzed_main |= main;
            }
            if exhausted || !found_package && children.roots.is_empty() {
                return exhausted || analyzed_main;
            }
        }
        directories = children;
        index += 1;
        if final_component {
            components.push("__main__");
        }
    }
    analyzed_main
}

fn module_command(module: &str) -> Option<&'static str> {
    match module {
        // `django/__main__.py` runs `management.execute_from_command_line()`.
        "django" => Some("django-admin"),
        "pip" => Some("pip"),
        "twine" => Some("twine"),
        "pytest" => Some("pytest"),
        "venv" => Some("venv"),
        "build" => Some("build"),
        "playwright" => Some("playwright"),
        "http.server" => Some("http.server"),
        "json.tool" => Some("json.tool"),
        _ => None,
    }
}

fn is_py_launcher(ctx: &InvocationCtx<'_>) -> bool {
    ctx.argv[0]
        .as_literal()
        .and_then(|command| command.rsplit('/').next())
        == Some("py")
}

/// `py -3` and `py -3.12`: the launcher's own version selector, which it
/// consumes before handing every remaining argument to the interpreter it
/// picks. CPython itself has no such option.
fn launcher_version_selector(argument: &str) -> bool {
    launcher_version(argument).is_some()
}

fn launcher_version(argument: &str) -> Option<(u8, Option<u8>)> {
    let version = argument.strip_prefix('-')?;
    let mut components = version.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next().map(str::parse).transpose().ok()?;
    components.next().is_none().then_some((major, minor))
}

// Narrow proof for the file selector whose request assurance is audited, as
// for `bash FILE` and `node FILE`: the operand after the interpreter is the
// program file CPython reads.
fn accepted_python_file(argv: &[Word]) -> Option<usize> {
    let python = argv
        .first()
        .and_then(Word::as_literal)
        .map(|name| name.rsplit('/').next().unwrap());
    if !matches!(python, Some("python" | "python3"))
        || argv.iter().any(|word| word.as_literal().is_none())
    {
        return None;
    }
    let script = argv.get(1).and_then(Word::as_literal)?;
    (!script.is_empty() && !script.starts_with('-')).then_some(1)
}

fn nest_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    script: Option<&Word>,
    controls: &PythonControls,
    reviewed_runtime: bool,
) {
    let Some(script) = script else {
        return;
    };
    code_execution(
        if accepted_python_file(ctx.argv) == Some(index) {
            effinterp_proto::RequestAssurance::Exact
        } else {
            effinterp_proto::RequestAssurance::Conservative
        },
        builder,
        ctx,
        model_node,
        Some(index as u32),
        "file",
        BTreeMap::new(),
    );
    operand_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        script,
        "filesystem.read",
        BTreeMap::new(),
    );
    let resolved = ctx
        .script_operand_path(script)
        .map_or(SourceResolution::Unavailable, |path| {
            ctx.resolve_source_operand(builder, &path, SourcePurpose::LaunchedScript)
        });
    match resolved {
        SourceResolution::Source {
            origin: path,
            source,
        } => {
            if controls.unknown_code_selector.is_none() && reviewed_runtime {
                python_base64_struct_import_inputs(
                    builder,
                    ctx,
                    model_node,
                    &source,
                    controls,
                    Some(&crate::paths::parent_dir(&path)),
                );
            }
            let arg = arg_node(builder, ctx, index as u32);
            let launch_root = crate::paths::parent_dir(&path);
            nest_python_program(ctx, controls, reviewed_runtime, Some(&launch_root), || {
                ctx.nest_script_subject(
                    builder,
                    Subject::Source {
                        dialect: None,
                        language: "python".into(),
                        source,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    },
                    &[model_node, arg],
                    path,
                    index,
                )
            });
        }
        SourceResolution::Refused(refusal) => {
            if let Some(detail) =
                source_refusal_detail(builder, refusal, "python script source unavailable")
            {
                opaque_source(builder, model_node, &detail);
                unobserved_entry_script(builder, ctx, model_node, index, script);
            }
        }
        SourceResolution::UnsupportedEncoding => opaque_source(
            builder,
            model_node,
            "python script source is not valid UTF-8",
        ),
        SourceResolution::AlreadySelected => (),
        SourceResolution::Unavailable => {
            opaque_source(builder, model_node, "python script source unavailable");
            unobserved_entry_script(builder, ctx, model_node, index, script);
        }
    }
}

/// A `manage.py` Nah cannot read is taken for Django's generated script,
/// which hands its arguments to `django-admin`'s dispatcher. A readable one
/// is analyzed instead, and its `execute_from_command_line` call dispatches.
fn unobserved_entry_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    script: &Word,
) {
    if let Some(command) = script
        .as_literal()
        .and_then(|path| crate::models::framework::dispatcher("python", path))
    {
        crate::models::framework::dispatch_entry_script(
            builder,
            ctx,
            model_node,
            index,
            index + 1,
            command,
        );
    }
}
