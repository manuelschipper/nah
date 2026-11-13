//! GitHub CLI commands that explicitly print the authentication token. Their
//! `-t` means show-token, unlike the template option on other gh commands.

use effinterp_proto::{AttrValue, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, Scanned, scan_with_named_values};
use crate::models::common::{Attrs, arg_node, unrecognized_arguments_boundary};
use crate::models::{InvocationCtx, ModelBindingEnd, ModelCausalBinding};
use crate::word::{Word, WordPart};

const VALUE_FLAGS: &[&str] = &[
    "--hostname",
    "-h",
    "--user",
    "-u",
    "--json",
    "--jq",
    "--template",
];

fn enabled(argv: &[Word], parsed: &Scanned<'_>, names: &[&str]) -> bool {
    parsed
        .flags
        .iter()
        .enumerate()
        .rev()
        .find(|(_, flag)| names.contains(&flag.name))
        .is_some_and(|(position, flag)| {
            // An equals value belongs only to the last shorthand in its
            // cluster: -ta=false keeps t enabled and disables a.
            if parsed
                .flags
                .get(position + 1)
                .is_some_and(|next| next.index == flag.index)
            {
                return true;
            }
            !matches!(
                argv[flag.index as usize]
                    .as_literal()
                    .and_then(|word| word.split_once('='))
                    .map(|(_, value)| value),
                Some("0" | "f" | "F" | "false" | "FALSE" | "False")
            )
        })
}

fn token_command(argv: &[Word]) -> Option<Scanned<'_>> {
    let mut parsed = scan_with_named_values(
        argv,
        &FlagSpec {
            allow_abbreviation: false,
            value_flags: VALUE_FLAGS,
            known_flags: &["--show-token", "-t", "--active", "-a", "--help"],
        },
        false,
        false,
        &[],
        true,
    );
    // pflag consumes =VALUE on the last Boolean in a shorthand cluster.
    // The generic scanner stops at '=', so admit that suffix only after
    // establishing every shorthand before it and validating its value.
    for (position, flag) in parsed.flags.iter().enumerate() {
        if !matches!(
            flag.name,
            "--show-token" | "-t" | "--active" | "-a" | "--help"
        ) || parsed
            .flags
            .get(position + 1)
            .is_some_and(|next| next.index == flag.index)
        {
            continue;
        }
        let Some((prefix, value)) = argv[flag.index as usize]
            .as_literal()
            .and_then(|word| word.split_once('='))
        else {
            continue;
        };
        if !prefix.starts_with("--") {
            let cluster = format!(
                "-{}",
                parsed
                    .flags
                    .iter()
                    .filter(|other| other.index == flag.index)
                    .map(|other| &other.name[1..])
                    .collect::<String>()
            );
            if prefix != cluster {
                continue;
            }
        }
        if !matches!(
            value,
            "0" | "1"
                | "f"
                | "F"
                | "t"
                | "T"
                | "false"
                | "FALSE"
                | "False"
                | "true"
                | "TRUE"
                | "True"
        ) {
            return None;
        }
        parsed
            .unknown_flags
            .retain(|(index, _)| *index != flag.index);
    }
    let command = parsed
        .operands
        .iter()
        .take(3)
        .map(|(_, word)| word.as_literal())
        .collect::<Vec<_>>();
    (matches!(command.as_slice(), [Some("auth"), Some("token")])
        || matches!(
            command.as_slice(),
            [Some("auth"), Some("git-credential"), Some("get")]
        )
        || matches!(command.as_slice(), [Some("auth"), Some("status")])
            && enabled(argv, &parsed, &["--show-token", "-t"]))
    .then_some(parsed)
}

/// Leave status's authentication work to the generic model without handing
/// it the display switches it reads as template options on other commands.
/// Original indices keep the remaining words tied to their shell sources.
pub(super) fn status_model_argv(argv: &[Word]) -> Option<Vec<(usize, Word)>> {
    let parsed = token_command(argv)?;
    if parsed.operands[1].1.as_literal() != Some("status") {
        return None;
    }
    Some(
        argv.iter()
            .enumerate()
            .filter_map(|(index, word)| {
                let flags = || {
                    parsed
                        .flags
                        .iter()
                        .filter(|flag| flag.index as usize == index)
                };
                if parsed
                    .unknown_flags
                    .iter()
                    .any(|(i, _)| *i as usize == index)
                    || !flags().any(|flag| {
                        matches!(flag.name, "--show-token" | "-t" | "--active" | "-a" | "-h")
                    })
                {
                    return Some((index, word.clone()));
                }
                let flag = flags()
                    .find(|flag| matches!(flag.name, "--hostname" | "-h" | "--user" | "-u"))?;
                let name = if matches!(flag.name, "--hostname" | "-h") {
                    "--hostname"
                } else {
                    "--user"
                };
                let word = if flag.value_index == Some(index as u32) {
                    Word::new(
                        std::iter::once(WordPart::Literal(format!("{name}=")))
                            .chain(flag.value.as_ref()?.parts.clone())
                            .collect(),
                    )
                } else {
                    Word::literal(name)
                };
                Some((index, word))
            })
            .collect(),
    )
}

pub(super) fn bindings(argv: &[Word]) -> Vec<ModelCausalBinding> {
    if token_command(argv).is_none() {
        return Vec::new();
    }
    vec![ModelCausalBinding {
        assurance: effinterp_proto::CausalAssurance::Exact,
        from: ModelBindingEnd::Effect {
            operation: "credential.read_request".into(),
            selection: effinterp_model_schema::EffectSelection::All,
        },
        to: ModelBindingEnd::Port(effinterp_proto::Port::Stdout),
    }]
}

pub(super) fn apply(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: effinterp_proto::ProvenanceRef,
) {
    let Some(parsed) = token_command(ctx.argv) else {
        return;
    };
    unrecognized_arguments_boundary(builder, node, &["credential"], &parsed.unknown_flags);
    if enabled(ctx.argv, &parsed, &["--help"])
        || parsed.operands.len()
            != if parsed.operands[1].1.as_literal() == Some("git-credential") {
                3
            } else {
                2
            }
        || parsed
            .flags
            .iter()
            .any(|flag| VALUE_FLAGS.contains(&flag.name) && flag.value.is_none())
    {
        return;
    }
    builder.declare_coverage(
        effinterp_proto::Domain::new("credential"),
        effinterp_proto::CoverageLevel::Full,
    );
    let argument = arg_node(builder, ctx, parsed.operands[1].0);
    builder.effect(effinterp_proto::Effect {
        id: Default::default(),
        operation: effinterp_proto::Operation::new("credential.read_request"),
        request_assurance: effinterp_proto::RequestAssurance::Exact,
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::CredentialStore {
                provider: "gh".into(),
                store: parsed
                    .value_of(&["--hostname", "-h"])
                    .and_then(Word::as_literal)
                    .map(str::to_owned),
                path: parsed
                    .value_of(&["--user", "-u"])
                    .and_then(Word::as_literal)
                    .map(str::to_owned),
            },
        },
        attributes: Attrs::from([
            ("mode".into(), AttrValue::String("value".into())),
            ("purpose".into(), AttrValue::String("explicit".into())),
            ("output".into(), AttrValue::String("stdout".into())),
        ]),
        modality: effinterp_proto::Modality::MustOnSuccess,
        realm: effinterp_proto::ExecutionRealm::Host,
        execution: effinterp_proto::ExecutionNodeRef(0),
        condition: None,
        provenance: vec![node, argument],
    });
}
