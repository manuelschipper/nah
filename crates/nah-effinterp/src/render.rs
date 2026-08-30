// UNDOCUMENTED-EFFINTERP: compact side-by-side rendering for the hidden CLI opt-in.
#![cfg(feature = "engine")]

use std::fmt::Write;

use effinterp_proto::{CoverageLevel, ExecutionRealm, Modality, Plan, display_resource};

/// Render effectinterp effects, boundaries, and domain coverage for humans.
pub fn render(plan: &Plan) -> String {
    let mut out = String::new();
    writeln!(out, "effinterp effects:").expect("writing to a string succeeds");
    for effect in &plan.effects {
        let realm = match &effect.realm {
            ExecutionRealm::Host => String::new(),
            ExecutionRealm::Container { runtime, name } => format!("{runtime}:{name}!"),
            ExecutionRealm::Kubernetes { pod, .. } => format!("pod:{pod}!"),
            ExecutionRealm::Chroot { host_root } => {
                format!("chroot:{}!", host_root.as_deref().unwrap_or("?"))
            }
            ExecutionRealm::Remote { endpoint } => format!("remote:{endpoint}!"),
        };
        let modality = match effect.modality {
            Modality::May => "may",
            Modality::MustOnSuccess => "must-on-success",
        };
        write!(
            out,
            "- {} {realm}{} [{modality}]",
            effect.operation.0,
            display_resource(&effect.resource)
        )
        .expect("writing to a string succeeds");
        if let Some(condition) = &effect.condition {
            write!(out, " if {}", condition.expression).expect("writing to a string succeeds");
        }
        out.push('\n');
    }
    if !plan.boundaries.is_empty() {
        writeln!(out, "effinterp boundaries:").expect("writing to a string succeeds");
        for boundary in &plan.boundaries {
            let domains = boundary
                .domains
                .iter()
                .map(|domain| domain.0.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            write!(out, "- {} [{domains}]", boundary.reason.as_str())
                .expect("writing to a string succeeds");
            if let Some(limit) = &boundary.limit {
                write!(out, " limit={limit}").expect("writing to a string succeeds");
            }
            if let Some(detail) = &boundary.detail {
                write!(out, ": {detail}").expect("writing to a string succeeds");
            }
            out.push('\n');
        }
    }
    let coverage = plan
        .coverage
        .0
        .iter()
        .map(|(domain, level)| format!("{}={}", domain.0, coverage_name(level)))
        .collect::<Vec<_>>()
        .join(" ");
    if coverage.is_empty() {
        out.push_str("effinterp coverage: no domains claimed\n");
    } else {
        writeln!(out, "effinterp coverage: {coverage}").expect("writing to a string succeeds");
    }
    out
}

const fn coverage_name(level: &CoverageLevel) -> &'static str {
    match level {
        CoverageLevel::Full => "full",
        CoverageLevel::Partial => "partial",
        CoverageLevel::None => "none",
    }
}
