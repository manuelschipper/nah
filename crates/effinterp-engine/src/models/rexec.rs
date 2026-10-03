//! The `R` front end: `-e EXPR` runs inline R (nested as a Source subject) and
//! `-f FILE` / `--file=FILE` selects a program file. Unlike `Rscript`, `R`
//! runs no bare operand as a program: an operand after `--args` is data.

use std::collections::BTreeMap;

use effinterp_proto::{ProvenanceRef, Subject};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{arg_node, code_execution, dynamic_source};
use crate::models::registry::launcher::{LauncherBoundary, LauncherInvocation};

pub(crate) fn apply(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    invocation: &LauncherInvocation,
) {
    let mut ran_source = false;
    for option in &invocation.options {
        match option.name.as_str() {
            "-e" | "--expression" => {
                let Some(source) = option.value.as_ref() else {
                    return;
                };
                nest_r_source(builder, ctx, model_node, source);
                ran_source = true;
            }
            "-f" | "--file" => {
                let Some(file) = option.value.as_ref() else {
                    return;
                };
                if file.index == option.index && option.raw.as_literal().is_none() {
                    dynamic_source(builder, model_node, "R option is not a literal argument");
                    return;
                }
                crate::models::sourceexec::nest(
                    builder,
                    ctx,
                    model_node,
                    file.index as usize,
                    &file.word,
                    |text| Subject::Source {
                        dialect: None,
                        language: "r".to_string(),
                        source: text,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    },
                );
                ran_source = true;
            }
            _ if option.class
                == effinterp_model_schema::LauncherOptionClassDeclaration::Unreviewed
                && option.raw.as_literal().is_none() =>
            {
                dynamic_source(builder, model_node, "R option is not a literal argument");
                return;
            }
            _ => {}
        }
    }
    if let Some(argument) = invocation
        .boundaries
        .iter()
        .find_map(|boundary| match boundary {
            LauncherBoundary::UnexpectedOperand(argument) => Some(argument),
            LauncherBoundary::UnreviewedOption(_) => None,
        })
    {
        let detail = if argument.word.as_literal().is_some() {
            "R operand does not select a program"
        } else {
            "R option is not a literal argument"
        };
        dynamic_source(builder, model_node, detail);
        return;
    }
    if !ran_source {
        dynamic_source(builder, model_node, "R interactive interpreter");
    }
}

fn nest_r_source(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    source: &crate::models::registry::launcher::LauncherArgument,
) {
    code_execution(
        effinterp_proto::RequestAssurance::Conservative,
        builder,
        ctx,
        model_node,
        Some(source.index),
        "argument",
        BTreeMap::new(),
    );
    let Some(text) = source.word.as_literal() else {
        dynamic_source(builder, model_node, "R -e with non-literal source");
        return;
    };
    let arg = arg_node(builder, ctx, source.index);
    ctx.nest_subject(
        builder,
        Subject::Source {
            dialect: None,
            language: "r".to_string(),
            source: text.to_string(),
            cwd: ctx.cwd.map(str::to_string),
            context: Default::default(),
        },
        &[model_node, arg],
    );
}
