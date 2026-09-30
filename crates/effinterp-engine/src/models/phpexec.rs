//! The `php` command model: inline `-r` source is analyzed as a nested PHP
//! subject; a script-path operand resolves through the caller's source
//! resolver into a nested PHP subject (from which the include graph is
//! followed), or — when unavailable — a read plus an opaque boundary.

use std::collections::BTreeMap;

use effinterp_proto::{
    ExecutionInputReason, ExecutionInputRole, ExecutionPhase, ExecutionSelector, ProvenanceRef,
    Subject,
};

use crate::SourcePurpose;
use crate::builder::PlanBuilder;
use crate::models::common::{
    RuntimeSourceLanguage, arg_node, code_execution, opaque_source, operand_effect,
    runtime_selected_source, runtime_unobserved_input, syntax_check_operand,
};
use crate::models::registry::launcher::{LauncherArgument, LauncherInvocation};
use crate::models::{InvocationCtx, source_refusal_detail};
use crate::nest::SourceResolution;
use crate::paths::parent_dir;

pub(crate) fn apply(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    php_prepend_input(builder, ctx, model_node);
    let source_index = invocation
        .script
        .as_ref()
        .map(|script| script.index)
        .unwrap_or(u32::MAX);
    let mut has_process_source = false;
    let mut stdin_is_code = true;
    for option in invocation
        .options
        .iter()
        .filter(|option| option.index < source_index)
    {
        match option.name.as_str() {
            "-r" | "--run" => {
                let Some(source) = option.value.as_ref() else {
                    return;
                };
                if source.word.as_literal() == Some("") {
                    continue;
                }
                nest_inline_source(
                    builder,
                    ctx,
                    model_node,
                    source.index as usize,
                    &source.word,
                    "php -r with non-literal source",
                );
                return;
            }
            "-B" | "--process-begin" | "-R" | "--process-code" | "-E" | "--process-end" => {
                let Some(source) = option.value.as_ref() else {
                    return;
                };
                nest_inline_source(
                    builder,
                    ctx,
                    model_node,
                    source.index as usize,
                    &source.word,
                    "php process source is unavailable",
                );
                has_process_source = true;
            }
            "-F" | "--process-file" => {
                let Some(file) = option.value.as_ref() else {
                    return;
                };
                nest_script(builder, ctx, model_node, file.index as usize);
                has_process_source = true;
            }
            "-f" | "--file" => {
                let Some(file) = option.value.as_ref() else {
                    return;
                };
                nest_script(builder, ctx, model_node, file.index as usize);
                // PHP consumes a `--` before the script's arguments.
                let start = file.index as usize + 1;
                let args_start = start
                    + usize::from(
                        ctx.argv.get(start).and_then(crate::word::Word::as_literal) == Some("--"),
                    );
                framework_entry_script(builder, ctx, model_node, file, args_start);
                return;
            }
            "-l"
            | "--syntax-check"
            | "-w"
            | "--strip"
            | "-s"
            | "--syntax-highlight"
            | "--syntax-highlighting" => {
                syntax_check_operand(builder, ctx, model_node, option.index as usize + 1);
                return;
            }
            "-h" | "--help" | "-?" | "--usage" | "-v" | "--version" | "-i" | "--info" | "-m"
            | "--modules" | "--ini" | "--rf" | "--rc" | "--re" | "--rz" | "--ri" => {
                return;
            }
            "-S" | "--server" => {
                if option.value.is_none() {
                    return;
                }
                stdin_is_code = false;
            }
            _ if option.class == effinterp_model_schema::LauncherOptionClassDeclaration::Value
                && option.value.is_none() =>
            {
                return;
            }
            _ => {}
        }
    }
    if let Some(script) = invocation.script.as_ref() {
        if script.word.as_literal() == Some("-") {
            stdin_program(
                builder,
                ctx,
                model_node,
                Some(script.index),
                "php reads program from stdin",
            );
        } else {
            nest_script(builder, ctx, model_node, script.index as usize);
            framework_entry_script(builder, ctx, model_node, script, script.index as usize + 1);
        }
        return;
    }
    if !has_process_source && stdin_is_code {
        stdin_program(
            builder,
            ctx,
            model_node,
            None,
            "php interactive interpreter",
        );
    }
}

/// Laravel's `artisan` and Symfony's `bin/console` boot the application
/// through Composer's autoloader, which Nah does not follow; their file name
/// selects the framework's dispatcher, which reads the words from
/// `args_start` on.
fn framework_entry_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    script: &LauncherArgument,
    args_start: usize,
) {
    if let Some(command) = script
        .word
        .as_literal()
        .and_then(|path| crate::models::framework::dispatcher("php", path))
    {
        crate::models::framework::dispatch_entry_script(
            builder,
            ctx,
            model_node,
            script.index as usize,
            args_start,
            command,
        );
    }
}

fn php_prepend_input(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx<'_>,
    model_node: ProvenanceRef,
) {
    let mut prepend = None;
    let mut prepend_configured = false;
    let mut no_ini = false;
    let mut uncertain = false;
    let mut index = 1;
    while index < ctx.argv.len() {
        let Some(option) = ctx.argv[index].as_literal() else {
            uncertain = true;
            break;
        };
        let setting = if matches!(option, "-d" | "--define") {
            index += 1;
            ctx.argv.get(index).and_then(|word| word.as_literal())
        } else {
            option
                .strip_prefix("-d")
                .filter(|setting| !setting.is_empty())
                .or_else(|| option.strip_prefix("--define="))
        };
        uncertain |= matches!(option, "-d" | "--define")
            && setting.is_none()
            && ctx.argv.get(index).is_some();
        if let Some(setting) = setting
            && let Some((name, value)) = setting.split_once('=')
            && name.trim() == "auto_prepend_file"
        {
            prepend_configured = true;
            prepend = Some(value.trim().trim_matches(['\'', '"']).to_string());
        }
        if option == "-n" || option == "--no-php-ini" {
            no_ini = true;
        }
        if option == "--" || !option.starts_with('-') {
            break;
        }
        index += 1;
    }
    if uncertain {
        runtime_unobserved_input(
            builder,
            ctx,
            "auto_prepend_file",
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: "-d".into(),
            },
            ExecutionInputReason::Ambiguous,
        );
    }
    if prepend_configured {
        let Some(prepend) = prepend.filter(|value| !value.is_empty() && value != "none") else {
            return;
        };
        runtime_selected_source(
            builder,
            ctx,
            model_node,
            &prepend,
            ExecutionInputRole::UnexpectedSelected,
            ExecutionPhase::Preload,
            ExecutionSelector::RuntimeOption {
                option: "-d auto_prepend_file".to_string(),
            },
            RuntimeSourceLanguage::Source("php"),
        );
        return;
    }
    if no_ini {
        return;
    }
    let selector = ["PHPRC", "PHP_INI_SCAN_DIR"]
        .into_iter()
        .find(|variable| ctx.environment_value(variable).is_some())
        .map_or_else(
            || ExecutionSelector::Convention {
                name: "php-ini-startup-search@7-8".to_string(),
            },
            |variable| ExecutionSelector::Environment {
                variable: variable.to_string(),
            },
        );
    runtime_unobserved_input(
        builder,
        ctx,
        "auto_prepend_file",
        ExecutionInputRole::UnexpectedSelected,
        ExecutionPhase::Startup,
        selector,
        ExecutionInputReason::ResolverUnavailable,
    );
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
        BTreeMap::new(),
    );
    if let Some(code) = ctx.stdin_literal() {
        let mut provenance = vec![model_node];
        provenance.extend(ctx.stdin.unwrap().provenance.iter().copied());
        ctx.nest_subject(
            builder,
            Subject::Source {
                dialect: None,
                language: "php".to_string(),
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
        opaque_source(builder, model_node, unavailable_detail);
    }
}

fn nest_inline_source(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
    source: &crate::word::Word,
    unavailable_detail: &str,
) {
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        Some(index as u32),
        "argument",
        BTreeMap::new(),
    );
    if let Some(code) = source.as_literal() {
        let arg = arg_node(builder, ctx, index as u32);
        ctx.nest_subject(
            builder,
            Subject::Source {
                dialect: None,
                language: "php".to_string(),
                source: format!("<?php {code}"),
                cwd: ctx.cwd.map(str::to_string),
                context: Default::default(),
            },
            &[model_node, arg],
        );
    } else {
        opaque_source(builder, model_node, unavailable_detail);
    }
}

fn nest_script(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    index: usize,
) {
    let Some(script) = ctx.argv.get(index) else {
        return;
    };
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
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
            let arg = arg_node(builder, ctx, index as u32);
            let subject = Subject::Source {
                dialect: None,
                language: "php".to_string(),
                source,
                // The script's directory: what `__DIR__` means inside it.
                cwd: Some(parent_dir(&path)),
                context: Default::default(),
            };
            ctx.nest_file_subject(builder, subject, &[model_node, arg], path);
        }
        SourceResolution::Refused(refusal) => {
            if let Some(detail) =
                source_refusal_detail(builder, refusal, "php script source unavailable")
            {
                opaque_source(builder, model_node, &detail);
            }
        }
        SourceResolution::UnsupportedEncoding => {
            opaque_source(builder, model_node, "php script source is not valid UTF-8")
        }
        SourceResolution::AlreadySelected => (),
        SourceResolution::Unavailable => {
            opaque_source(builder, model_node, "php script source unavailable")
        }
    }
}
