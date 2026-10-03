//! Renders the engine's plan for a reader: effects, boundaries with the
//! construct they name, and per-domain coverage. `nah test` prints it beneath
//! the decision.

use std::fmt::Write;

use nah_proto::effinterp_proto::{
    self, AttrValue, ExecutionRealm, HostContext, Modality, OsDialect, Plan, ProvenanceKind,
    Subject,
};

/// A short realm prefix (e.g. `container:postgres`) for a non-host effect,
/// or None on the host. Rendered as `<realm>!<resource>` so a consumer sees
/// the resource is scoped to that execution context, not the host.
fn render_realm(realm: &ExecutionRealm) -> Option<String> {
    match realm {
        ExecutionRealm::Host => None,
        ExecutionRealm::Container { runtime, name } => Some(format!("{runtime}:{name}")),
        ExecutionRealm::Kubernetes { pod, .. } => Some(format!("pod:{pod}")),
        ExecutionRealm::Chroot { host_root } => {
            Some(format!("chroot:{}", host_root.as_deref().unwrap_or("?")))
        }
        ExecutionRealm::Remote { endpoint } => Some(format!("remote:{endpoint}")),
    }
}

fn render_modality(modality: Modality) -> &'static str {
    match modality {
        Modality::May => "may",
        Modality::MustOnSuccess => "must-on-success",
    }
}

fn render_attr_value(value: &AttrValue) -> String {
    match value {
        AttrValue::Bool(b) => b.to_string(),
        AttrValue::Int(i) => i.to_string(),
        AttrValue::String(s) => format!("{s:?}"),
        AttrValue::List(values) => format!(
            "[{}]",
            values
                .iter()
                .map(render_attr_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn write_cwd(out: &mut String, cwd: &Option<String>) {
    if let Some(cwd) = cwd {
        let _ = write!(out, " (cwd {cwd})");
    }
}

/// The engine plan as text: subject, effects, host provenance, boundaries,
/// and per-domain coverage.
pub(crate) fn render_engine_plan(plan: &Plan) -> String {
    let mut out = String::new();
    match &plan.subject {
        Subject::Exec { argv, cwd, .. } => {
            let _ = write!(out, "subject: exec {}", argv.join(" "));
            write_cwd(&mut out, cwd);
        }
        Subject::Shell { source, cwd, .. } => {
            let _ = write!(out, "subject: shell {source:?}");
            write_cwd(&mut out, cwd);
        }
        Subject::Sql {
            source, dialect, ..
        } => {
            let _ = write!(out, "subject: sql/{dialect:?} {source:?}");
        }
        Subject::Source {
            language,
            dialect,
            source,
            cwd,
            ..
        } => {
            let _ = write!(out, "subject: {language}");
            if let Some(dialect) = dialect {
                let _ = write!(out, "/{dialect:?}");
            }
            let _ = write!(out, " {source:?}");
            write_cwd(&mut out, cwd);
        }
        Subject::ToolCall { call, cwd, .. } => {
            let _ = write!(out, "subject: tool {}", call.name());
            write_cwd(&mut out, cwd);
        }
    }
    out.push('\n');

    out.push_str("effects:\n");
    for effect in &plan.effects {
        let _ = write!(out, "  {} ", effect.operation.0);
        if let Some(scope) = render_realm(&effect.realm) {
            let _ = write!(out, "{scope}!");
        }
        let _ = write!(
            out,
            "{}",
            effinterp_proto::display_resource_with_scope(&effect.resource)
        );
        if !effect.attributes.is_empty() {
            let attrs: Vec<String> = effect
                .attributes
                .iter()
                .map(|(k, v)| format!("{k}={}", render_attr_value(v)))
                .collect();
            let _ = write!(out, " ({})", attrs.join(", "));
        }
        let _ = write!(out, " [{}]", render_modality(effect.modality));
        if let Some(condition) = &effect.condition {
            let _ = write!(out, " if {}", condition);
        }
        let _ = writeln!(out, " #{}", &effect.id.0[effect.id.0.len() - 12..]);
    }

    // The OS dialect is no value an effect's provenance can trace to.
    let has_host_context = match &plan.subject {
        Subject::Exec { context, .. }
        | Subject::Shell { context, .. }
        | Subject::Source { context, .. }
        | Subject::ToolCall { context, .. } => !HostContext {
            os_dialect: OsDialect::Unknown,
            ..context.clone()
        }
        .is_empty(),
        Subject::Sql { .. } => false,
    };
    if has_host_context && !plan.provenance.is_empty() {
        out.push_str("provenance:\n");
        for (index, node) in plan.provenance.iter().enumerate() {
            let _ = write!(out, "  #{index} ");
            match &node.kind {
                ProvenanceKind::HostContext { name } => {
                    let _ = write!(out, "host_context name={name:?}");
                }
                ProvenanceKind::SourceInput { path, digest } => {
                    let _ = write!(out, "source_input path={path:?} digest={digest}");
                }
                ProvenanceKind::SourceSpan { start, end } => {
                    let _ = write!(out, "source_span {start}..{end}");
                }
                ProvenanceKind::Argument { index } => {
                    let _ = write!(out, "argument index={index}");
                }
                ProvenanceKind::ToolArgument { name } => {
                    let _ = write!(out, "tool_argument name={name:?}");
                }
                ProvenanceKind::ModelApplication { model } => {
                    let _ = write!(out, "model_application model={model:?}");
                }
                ProvenanceKind::Execution { node } => {
                    let _ = write!(out, "execution node={node}");
                }
                ProvenanceKind::HostObservation { query, outcome } => {
                    match query {
                        effinterp_proto::ObservationQuery::Path { path } => {
                            let _ = write!(out, "host_observation path={path:?} ");
                        }
                        effinterp_proto::ObservationQuery::Listing { path, .. } => {
                            let _ = write!(out, "host_observation listing={path:?} ");
                        }
                    }
                    match outcome {
                        effinterp_proto::ObservationOutcome::Refused(refusal) => {
                            let _ = write!(out, "unavailable={}", refusal.code());
                        }
                        effinterp_proto::ObservationOutcome::Path(fact) => {
                            let _ = write!(out, "kind={:?}", fact.kind);
                            match &fact.followed {
                                effinterp_proto::Fact::Known(target) => {
                                    let _ = write!(out, " followed={:?}", target.path);
                                }
                                effinterp_proto::Fact::Unavailable(refusal) => {
                                    let _ = write!(out, " followed_unavailable={}", refusal.code());
                                }
                            }
                        }
                        effinterp_proto::ObservationOutcome::Listing(fact) => {
                            let _ = write!(
                                out,
                                "directory={:?} entries={}",
                                fact.directory,
                                fact.entries.len()
                            );
                        }
                    }
                }
            }
            if !node.antecedents.is_empty() {
                let antecedents = node
                    .antecedents
                    .iter()
                    .map(|antecedent| format!("#{}", antecedent.0))
                    .collect::<Vec<_>>();
                let _ = write!(out, " <- {}", antecedents.join(", "));
            }
            out.push('\n');
        }
    }

    if !plan.boundaries.is_empty() {
        out.push_str("boundaries:\n");
        for (index, boundary) in plan.boundaries.iter().enumerate() {
            let domains: Vec<&str> = boundary.domains.iter().map(|d| d.0.as_str()).collect();
            let _ = write!(
                out,
                "  [{index}] {} ({}) [{}]",
                boundary.reason.as_str(),
                boundary.class,
                domains.join(", ")
            );
            if let Some(limit) = &boundary.limit {
                let _ = write!(out, " limit={limit}");
            }
            if let Some(detail) = &boundary.detail {
                let _ = write!(out, ": {detail}");
            }
            out.push('\n');
        }
    }

    out.push_str("coverage:");
    for (domain, claim) in plan
        .coverage
        .0
        .iter()
        .map(|(domain, claim)| (domain.0.as_str(), claim))
        .chain(std::iter::once(("dataflow", &plan.causality.coverage)))
    {
        let level = match claim.level {
            effinterp_proto::CoverageLevel::Full => "full",
            effinterp_proto::CoverageLevel::Partial => "partial",
            effinterp_proto::CoverageLevel::None => "none",
        };
        let _ = write!(out, " {domain}={level}");
        if !claim.gaps.is_empty() {
            let gaps: Vec<u32> = claim.gaps.iter().map(|reference| reference.0).collect();
            let _ = write!(out, " gaps={gaps:?}");
        }
    }
    out.push('\n');
    out
}
