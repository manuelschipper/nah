//! Remote commands carried by AWS SSM, gcloud SSH, and Azure VM Run Command.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::{attached_value, scan_literal_flags};
use crate::models::common::{
    arg_node, boundary, has_unknown, nest_remote_shell, unrecognized_arguments_boundary,
};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::cloud_args::CLOUD_LITERAL_FLAGS;
use super::cloud_effects::{cloud_effect, cloud_network_effect, symbolic_cloud};

fn unrecoverable_remote_source(
    builder: &mut PlanBuilder,
    model_node: ProvenanceRef,
    argument: ProvenanceRef,
    detail: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOVERABLE_SOURCE,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: ["environment", "filesystem", "network", "process"]
            .into_iter()
            .map(Domain::new)
            .collect(),
        provenance: vec![model_node, argument],
        limit: None,
        detail: Some(detail.to_string()),
    });
}

/// AWS Systems Manager commands reach a remote realm only with recoverable command text.
pub(super) fn aws_ssm_remote_command(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) {
    match ctx.argv.get(2).and_then(Word::as_literal) {
        Some("start-session") => ssm_start_session(builder, ctx, model_node),
        Some("send-command") => ssm_send_command(builder, ctx, model_node),
        _ => boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws ssm subcommand",
        ),
    }
}

fn ssm_start_session(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
    let Some((target_index, target)) = scanned.values_of(&["--target"]).first().copied() else {
        return;
    };
    cloud_effect(
        builder,
        ctx,
        model_node,
        target_index,
        "network.connect",
        unresolved_resource("network"),
    );
    let Some((parameter_index, parameters)) = ssm_parameters(ctx.argv) else {
        return;
    };
    let supported_document = scanned
        .values_of(&["--document-name"])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
        .is_some_and(|document| {
            matches!(
                document,
                "AWS-StartInteractiveCommand" | "AWS-StartNonInteractiveCommand"
            )
        });
    if !supported_document {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws ssm start-session document",
        );
        return;
    }
    let argument = arg_node(builder, ctx, parameter_index);
    let Ok(commands) = parse_ssm_parameters(&parameters, "command") else {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "aws ssm command is not statically recoverable",
        );
        return;
    };
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        commands.join("\n"),
        format!("ssm:{}", target.render_raw()),
    );
}

fn ssm_send_command(builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
    let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
    if scanned
        .values_of(&["--document-name"])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
        != Some("AWS-RunShellScript")
    {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "aws ssm send-command document",
        );
        return;
    }
    let instances = scanned
        .flags
        .iter()
        .find(|flag| flag.name == "--instance-ids")
        .map(|flag| {
            ctx.argv
                .iter()
                .enumerate()
                .skip(flag.index as usize + 1)
                .take_while(|(_, word)| {
                    !word
                        .as_literal()
                        .is_some_and(|value| value.starts_with('-'))
                })
                .map(|(index, word)| (index as u32, word))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let Some((parameter_index, parameters)) = ssm_parameters(ctx.argv) else {
        return;
    };
    let argument = arg_node(builder, ctx, parameter_index);
    let Ok(commands) = parse_ssm_parameters(&parameters, "commands") else {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "aws ssm commands are not statically recoverable",
        );
        return;
    };
    for (instance_index, instance) in instances {
        cloud_effect(
            builder,
            ctx,
            model_node,
            instance_index,
            "network.connect",
            unresolved_resource("network"),
        );
        for command in &commands {
            nest_remote_shell(
                builder,
                ctx,
                &[model_node, argument],
                command.clone(),
                format!("ssm:{}", instance.render_raw()),
            );
        }
    }
}

fn ssm_parameters(argv: &[Word]) -> Option<(u32, Word)> {
    let scanned = scan_literal_flags(argv, &CLOUD_LITERAL_FLAGS);
    if let Some((index, value)) = scanned.values_of(&["--parameters"]).first().copied() {
        return Some((index, value.clone()));
    }
    argv.iter().enumerate().find_map(|(index, word)| {
        attached_value(word, "--parameters=").map(|value| (index as u32, value))
    })
}

fn parse_ssm_parameters(word: &Word, name: &str) -> Result<Vec<String>, ()> {
    let literal = word.as_literal().ok_or(())?;
    if literal.starts_with('{') {
        let object = serde_json::from_str::<serde_json::Value>(literal).map_err(|_| ())?;
        return json_string_array(object.get(name).ok_or(())?);
    }
    let (actual_name, value) = word.split_assignment().ok_or(())?;
    if actual_name != name {
        return Err(());
    }
    let value = value.as_literal().ok_or(())?;
    if name == "command" {
        return Ok(vec![value.to_string()]);
    }
    let array = serde_json::from_str::<serde_json::Value>(value).map_err(|_| ())?;
    json_string_array(&array)
}

fn json_string_array(value: &serde_json::Value) -> Result<Vec<String>, ()> {
    value
        .as_array()
        .ok_or(())?
        .iter()
        .map(|value| value.as_str().map(str::to_string).ok_or(()))
        .collect()
}

/// gcloud SSH uses `--command` when supplied, otherwise the words after `--`.
pub(super) fn gcloud_ssh(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
    instance_index: Option<usize>,
    options_start: usize,
    fixed_instance: Option<&str>,
) {
    let instance = match (
        fixed_instance,
        instance_index.and_then(|index| ctx.argv.get(index)),
    ) {
        (Some(instance), _) => instance.to_string(),
        (None, Some(instance)) => instance
            .render_raw()
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_string(),
        (None, None) => return,
    };
    let connect_index = instance_index.unwrap_or(2) as u32;
    cloud_effect(
        builder,
        ctx,
        model_node,
        connect_index,
        "network.connect",
        unresolved_resource("network"),
    );

    const VALUE_FLAGS: &[&str] = &[
        "--zone",
        "--project",
        "--command",
        "--ssh-flag",
        "--ssh-key-file",
        "--strict-host-key-checking",
    ];
    const BOOLEAN_FLAGS: &[&str] = &[
        "--tunnel-through-iap",
        "--internal-ip",
        "--plain",
        "--dry-run",
    ];
    let mut command = None;
    let mut trailing = None;
    let mut unknown = Vec::new();
    let mut index = options_start;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        match word.as_literal() {
            Some("--command") => {
                if let Some(value) = ctx.argv.get(index + 1) {
                    command = Some((index + 1, vec![value.clone()]));
                    index += 2;
                } else {
                    unknown.push((index as u32, "--command".to_string()));
                    index += 1;
                }
            }
            Some("--") => {
                trailing = Some(index + 1);
                break;
            }
            Some(flag) if VALUE_FLAGS.contains(&flag) => index += 2,
            Some(flag) if BOOLEAN_FLAGS.contains(&flag) => index += 1,
            Some(flag) if flag.starts_with('-') && flag.len() > 1 => {
                if let Some(value) = attached_value(word, "--command=") {
                    command = Some((index, vec![value]));
                } else if !VALUE_FLAGS
                    .iter()
                    .any(|known| flag.starts_with(&format!("{known}=")))
                {
                    unknown.push((index as u32, flag.to_string()));
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    unrecognized_arguments_boundary(
        builder,
        model_node,
        &["cloud", "network", "process"],
        &unknown,
    );
    let (source_index, words) = if let Some(command) = command {
        command
    } else if let Some(start) = trailing {
        (start, ctx.argv[start..].to_vec())
    } else {
        return;
    };
    if words.is_empty() {
        return;
    }
    let argument = arg_node(builder, ctx, source_index as u32);
    if words.iter().any(has_unknown) {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "gcloud remote command is not statically recoverable",
        );
        return;
    }
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        words
            .iter()
            .map(Word::render_raw)
            .collect::<Vec<_>>()
            .join(" "),
        format!("gce:{instance}"),
    );
}

/// Azure VM Run Command recovers shell scripts only for the `RunShellScript` command ID.
pub(super) fn az_vm_run_command(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    model_node: ProvenanceRef,
) {
    let scanned = scan_literal_flags(ctx.argv, &CLOUD_LITERAL_FLAGS);
    if scanned
        .values_of(&["--command-id"])
        .first()
        .map(|(_, value)| *value)
        .and_then(Word::as_literal)
        != Some("RunShellScript")
    {
        boundary(
            builder,
            model_node,
            BoundaryReason::UNMODELED_SUBCOMMAND,
            BoundaryClass::Unmodeled,
            &["cloud", "network"],
            "az vm run-command command id",
        );
        return;
    }
    let Some((_, name)) = scanned.values_of(&["--name", "-n"]).first().copied() else {
        return;
    };
    let argument = arg_node(builder, ctx, 3);
    cloud_network_effect(
        builder,
        ctx,
        &[model_node, argument],
        &symbolic_cloud(),
        "network.connect",
    );
    let mut scripts = Vec::new();
    let mut index = 4;
    while index < ctx.argv.len() {
        if ctx.argv[index].as_literal() != Some("--scripts") {
            index += 1;
            continue;
        }
        index += 1;
        while index < ctx.argv.len()
            && !ctx.argv[index]
                .as_literal()
                .is_some_and(|value| value.starts_with('-'))
        {
            scripts.push((index, &ctx.argv[index]));
            index += 1;
        }
    }
    let Some((script_index, _)) = scripts.first() else {
        return;
    };
    let argument = arg_node(builder, ctx, *script_index as u32);
    if scripts.iter().any(|(_, script)| has_unknown(script)) {
        unrecoverable_remote_source(
            builder,
            model_node,
            argument,
            "az vm run-command source is not statically recoverable",
        );
        return;
    }
    nest_remote_shell(
        builder,
        ctx,
        &[model_node, argument],
        scripts
            .iter()
            .map(|(_, script)| script.render_raw())
            .collect::<Vec<_>>()
            .join("\n"),
        format!("azure-vm:{}", name.render_raw()),
    );
}
