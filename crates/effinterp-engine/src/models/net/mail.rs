use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
    ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan};
use crate::models::common::{arg_effect, symbolic_expr};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

/// Mail models sending to argv recipients. Unknown options leave the invocation unmodeled.
pub(super) struct Mail;

const MAIL_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    value_flags: &["-a", "-b", "-c", "-q", "-r", "-s", "-S"],
    known_flags: &["-E", "-i", "-I", "-n", "-N", "-v", "-~"],
    allow_abbreviation: false,
};

/// The recipient operands of a `mail` send. Options are skipped by the
/// mailx option letters, which all take their value as a separate word;
/// anything else leaves the invocation unmodeled rather than guessed.
fn mail_recipients(argv: &[Word]) -> Result<Vec<(u32, Word)>, &'static str> {
    // `-t` takes the recipients from the message header instead of argv, and
    // `-f`/`-u` open a mailbox to read rather than send.
    let parsed = scan(argv, &MAIL_FLAG_SPEC);
    if !parsed.unknown_flags.is_empty() {
        return Err("mail options are unmodeled");
    }
    Ok(parsed
        .operands
        .iter()
        .map(|(index, word)| (*index, (*word).clone()))
        .collect())
}

impl CommandModel for Mail {
    fn domains(&self) -> &'static [&'static str] {
        &["network", "process"]
    }
    fn id(&self) -> &'static str {
        "network/mail@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["mail", "mailx"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        use crate::models::{ModelBindingEnd, ModelCausalBinding};
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::Port;
        let Ok(recipients) = mail_recipients(argv) else {
            return Vec::new();
        };
        if recipients.is_empty() {
            return Vec::new();
        }
        // `-s` changes only the subject. Other recognized options can add
        // message sources, recipients, or configuration and stay conservative.
        let parsed = scan(argv, &MAIL_FLAG_SPEC);
        let exact = parsed.flags.iter().all(|flag| flag.name == "-s")
            && recipients.iter().all(|(_, word)| {
                word.as_literal().is_some_and(|address| {
                    address.contains('@')
                        && !address.starts_with('-')
                        && !address.contains(['/', '|', ',', ';', '<', '>', ' ', '\t', '\n'])
                })
            });
        vec![ModelCausalBinding {
            assurance: if exact {
                effinterp_proto::CausalAssurance::Exact
            } else {
                effinterp_proto::CausalAssurance::Conservative
            },
            from: ModelBindingEnd::Port(Port::Stdin),
            to: ModelBindingEnd::Effect {
                operation: "network.upload".into(),
                selection: EffectSelection::All,
            },
        }]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let recipients = match mail_recipients(ctx.argv) {
            Ok(recipients) if recipients.is_empty() => {
                // Without a recipient `mail` opens a mailbox instead of sending.
                Err("mail without a recipient reads a mailbox")
            }
            other => other,
        };
        let recipients = match recipients {
            Ok(recipients) => recipients,
            Err(detail) => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("network"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(detail.into()),
                });
                return;
            }
        };
        for (index, word) in recipients {
            // A recipient address names the mailbox the body is delivered to;
            // the transport that carries it there is the host's own.
            let address = match word.as_literal() {
                Some(text) => ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host: text.to_string(),
                        scheme: None,
                        port: None,
                        path: None,
                    },
                },
                None => symbolic_expr(&word, "network"),
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.upload",
                address,
                Default::default(),
            );
        }
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
    }
}
