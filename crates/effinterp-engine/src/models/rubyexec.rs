//! `ruby`/`irb`: `-e "code"` runs inline Ruby (nested as a Source subject); a
//! script path nests source supplied by a repository resolver, or stays a read
//! plus an explicit boundary when unavailable.

use std::collections::BTreeMap;

use effinterp_proto::{
    ExecutionInputReason, ExecutionInputRole, ExecutionPhase, ExecutionSelector, ProvenanceRef,
    ResourceExpr, Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::common::{
    RuntimeSourceLanguage, arg_node, code_execution, opaque_source, operand_effect,
    runtime_selected_source, runtime_unobserved_input, syntax_check_operand,
};
use crate::models::registry::launcher::LauncherInvocation;
use crate::models::{InvocationCtx, source_refusal_detail};
use crate::nest::SourceResolution;
use crate::word::Word;

pub(crate) fn apply(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    ruby_preload_inputs(builder, ctx, model_node, invocation);
    let is_irb = ctx.argv[0]
        .as_literal()
        .and_then(|command| command.rsplit('/').next())
        == Some("irb");
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
    let mut runtime_cwd = ctx.runtime_cwd.map(str::to_string);
    let mut cwd = ctx.cwd.map(str::to_string);
    let mut cwd_resource = ctx.cwd_resource();
    let mut strip_preamble = false;
    let mut stdin_is_code = true;
    let mut saw_version = false;
    let mut saw_other_switch = false;
    for option in &preceding {
        if matches!(
            option.name.as_str(),
            "-h" | "--help" | "--version" | "--copyright" | "--dump=version"
        ) || option.name == "-v" && is_irb
        {
            return;
        }
        if option.name == "-v" {
            saw_version = true;
            continue;
        }
        if option.name == "-x" {
            strip_preamble = true;
        }
        if option.name == "--verbose" && !is_irb {
            stdin_is_code = false;
        }
        if option.class == effinterp_model_schema::LauncherOptionClassDeclaration::Chdir {
            let Some(directory) = option.value.as_ref() else {
                return;
            };
            change_ruby_cwd(
                &directory.word,
                &mut runtime_cwd,
                &mut cwd,
                &mut cwd_resource,
            );
        }
        if matches!(
            option.class,
            effinterp_model_schema::LauncherOptionClassDeclaration::Value
                | effinterp_model_schema::LauncherOptionClassDeclaration::Preload
        ) && option.value.is_none()
        {
            return;
        }
        if option.name != "--" {
            saw_other_switch = true;
        }
    }
    let current_ctx = InvocationCtx {
        argv: ctx.argv,
        stdin: ctx.stdin,
        argv_provenance: ctx.argv_provenance,
        cwd: cwd.as_deref(),
        cwd_resource,
        runtime_cwd: runtime_cwd.as_deref(),
        scope: ctx.scope,
        cwd_node: ctx.cwd_node,
        nest: ctx.nest,
        depth: ctx.depth,
        model_stack: ctx.model_stack.clone(),
    };

    if let Some(option) = source_option {
        let Some(source) = option.value.as_ref() else {
            return;
        };
        code_execution(
            effinterp_proto::RequestAssurance::Conservative,
            builder,
            &current_ctx,
            model_node,
            Some(source.index),
            "argument",
            BTreeMap::new(),
        );
        if let Some(code) = source.word.as_literal() {
            let arg = arg_node(builder, &current_ctx, source.index);
            current_ctx.nest_subject(
                builder,
                Subject::Source {
                    dialect: None,
                    language: "ruby".to_string(),
                    source: code.to_string(),
                    cwd: cwd.clone(),
                    context: Default::default(),
                },
                &[model_node, arg],
            );
        } else {
            opaque_source(
                builder,
                model_node,
                "ruby script source is not part of the invocation",
            );
        }
        return;
    }
    if let Some(check) = preceding
        .iter()
        .find(|option| matches!(option.name.as_str(), "-c" | "--dump=syntax"))
    {
        syntax_check_operand(builder, &current_ctx, model_node, check.index as usize + 1);
        return;
    }
    if let Some(script) = invocation.script.as_ref() {
        if script.word.as_literal() == Some("-") {
            stdin_program(builder, &current_ctx, model_node, Some(script.index));
        } else {
            nest_script(
                builder,
                &current_ctx,
                model_node,
                script.index as usize,
                &script.word,
                strip_preamble,
                cwd.clone(),
            );
        }
        return;
    }
    if stdin_is_code && (!saw_version || saw_other_switch) {
        stdin_program(builder, &current_ctx, model_node, None);
    }
}

fn nest_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    script: &Word,
    strip_preamble: bool,
    cwd: Option<String>,
) {
    operand_effect(
        builder,
        ctx,
        model_node,
        index as u32,
        script,
        "filesystem.read",
        BTreeMap::new(),
    );
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        Some(index as u32),
        "file",
        BTreeMap::new(),
    );
    let resolved = script
        .as_literal()
        .map_or(SourceResolution::Unavailable, |path| {
            ctx.resolve_source_operand(builder, path, SourcePurpose::InvocationInput)
        });
    match resolved {
        SourceResolution::Source {
            origin: path,
            source,
        } => {
            let source = if strip_preamble {
                let Some(offset) = source
                    .split_inclusive('\n')
                    .scan(0, |offset, line| {
                        let start = *offset;
                        *offset += line.len();
                        Some((start, line))
                    })
                    .find_map(|(offset, line)| {
                        (line.starts_with("#!") && line.contains("ruby")).then_some(offset)
                    })
                else {
                    opaque_source(builder, model_node, "ruby -x source has no ruby shebang");
                    return;
                };
                source[offset..].to_string()
            } else {
                source
            };
            let arg = arg_node(builder, ctx, index as u32);
            ctx.nest_script_subject(
                builder,
                Subject::Source {
                    dialect: None,
                    language: "ruby".to_string(),
                    source,
                    cwd,
                    context: Default::default(),
                },
                &[model_node, arg],
                path,
                index,
            );
        }
        SourceResolution::Refused(refusal) => {
            if let Some(detail) = source_refusal_detail(
                builder,
                refusal,
                "ruby script source is not part of the invocation",
            ) {
                opaque_source(builder, model_node, &detail);
            }
        }
        SourceResolution::UnsupportedEncoding => {
            opaque_source(builder, model_node, "ruby script source is not valid UTF-8")
        }
        SourceResolution::AlreadySelected => (),
        SourceResolution::Unavailable => opaque_source(
            builder,
            model_node,
            "ruby script source is not part of the invocation",
        ),
    }
}

fn ruby_preload_inputs(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    let rubyopt_disabled = ctx.argv.iter().filter_map(Word::as_literal).any(|option| {
        option == "--disable=rubyopt" || option == "--disable=all" || option == "--disable-rubyopt"
    });
    if !rubyopt_disabled {
        match ctx.environment_value("RUBYOPT") {
            Some(ResourceExpr::Literal { value }) => {
                let words = value.split_ascii_whitespace().collect::<Vec<_>>();
                let mut index = 0;
                while index < words.len() {
                    let option = words[index].trim_matches(['\'', '"']);
                    let request = option
                        .strip_prefix("-r")
                        .filter(|request| !request.is_empty())
                        .or_else(|| option.strip_prefix("--require="))
                        .or_else(|| {
                            matches!(option, "-r" | "--require")
                                .then(|| words.get(index + 1).copied())
                                .flatten()
                        });
                    if let Some(request) = request {
                        ruby_preload(
                            builder,
                            ctx,
                            model_node,
                            request.trim_matches(['\'', '"']),
                            ExecutionSelector::Environment {
                                variable: "RUBYOPT".to_string(),
                            },
                        );
                        if matches!(option, "-r" | "--require") {
                            index += 1;
                        }
                    }
                    index += 1;
                }
            }
            Some(_) => runtime_unobserved_input(
                builder,
                ctx,
                "$RUBYOPT",
                ExecutionInputRole::UnexpectedSelected,
                ExecutionPhase::Preload,
                ExecutionSelector::Environment {
                    variable: "RUBYOPT".to_string(),
                },
                ExecutionInputReason::Ambiguous,
            ),
            None => {}
        }
    }
    for option in invocation.options.iter().filter(|option| {
        option.class == effinterp_model_schema::LauncherOptionClassDeclaration::Preload
    }) {
        if let Some(request) = option
            .value
            .as_ref()
            .and_then(|value| value.word.as_literal())
        {
            ruby_preload(
                builder,
                ctx,
                model_node,
                request,
                ExecutionSelector::RuntimeOption {
                    option: "-r".to_string(),
                },
            );
        }
    }
}

fn ruby_preload(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
    request: &str,
    selector: ExecutionSelector,
) {
    if request.starts_with('.') || request.starts_with('/') {
        let request = if std::path::Path::new(request).extension().is_some() {
            request.to_string()
        } else {
            format!("{request}.rb")
        };
        runtime_selected_source(
            builder,
            ctx,
            model_node,
            &request,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            selector,
            RuntimeSourceLanguage::Source("ruby"),
        );
    } else {
        runtime_unobserved_input(
            builder,
            ctx,
            request,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            selector,
            ExecutionInputReason::ResolverUnavailable,
        );
    }
}

fn change_ruby_cwd(
    directory: &Word,
    runtime_cwd: &mut Option<String>,
    cwd: &mut Option<String>,
    cwd_resource: &mut Option<effinterp_proto::ResourceExpr>,
) {
    *cwd_resource = Some(crate::paths::resolve_fs_word_with_cwd(
        directory,
        cwd_resource.take(),
    ));
    let Some(directory) = directory.as_literal() else {
        *runtime_cwd = None;
        *cwd = None;
        return;
    };
    *runtime_cwd = crate::paths::join_relative_file(runtime_cwd.as_deref(), directory);
    *cwd = cwd
        .as_deref()
        .map(|cwd| crate::paths::join_cwd(cwd, directory));
}

fn stdin_program(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    argument: Option<u32>,
) {
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        argument,
        "stdin",
        BTreeMap::new(),
    );
    if let Some(code) = ctx.stdin_literal() {
        let mut provenance = vec![model_node];
        provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
        ctx.nest_subject(
            builder,
            Subject::Source {
                dialect: None,
                language: "ruby".to_string(),
                source: code.to_string(),
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &provenance,
        );
    } else if ctx.stdin.is_some() {
        opaque_source(
            builder,
            model_node,
            "stdin program is not statically recoverable",
        );
    } else {
        opaque_source(
            builder,
            model_node,
            "ruby script source is not part of the invocation",
        );
    }
}
