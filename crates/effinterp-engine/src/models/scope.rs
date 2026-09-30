use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef, ResourceExpr,
    ResourceFamily, ResourceScope, ScopeEvidence, ScopeEvidenceKind, ScopeValue,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::args::attached_value;
use crate::models::common::arg_node;
use crate::word::Word;

pub(crate) fn scope_boundary(
    builder: &mut PlanBuilder,
    provenance: &[ProvenanceRef],
    domain: &str,
) {
    builder.boundary(Boundary {
        reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
        class: BoundaryClass::Unresolved,
        scope: BoundaryScope::Invocation,
        affected_resource: None,
        callee: None,
        domains: vec![Domain::new(domain)],
        provenance: provenance.to_vec(),
        limit: None,
        detail: Some(
            "resource scope input is missing, conflicting, or requires unread configuration".into(),
        ),
    });
}

/// Bounded option values retain shell expressions; repeated conflicts retract this field.
pub(crate) fn scope_option(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    names: &[&str],
    equals: bool,
    domain: &str,
) -> Option<ScopeValue> {
    let mut found = Vec::new();
    let mut invalid = false;
    for (i, word) in ctx.argv.iter().enumerate().skip(1) {
        let value = if word.as_literal().is_some_and(|w| names.contains(&w)) {
            provenance.push(arg_node(builder, ctx, i as u32));
            match ctx.argv.get(i + 1) {
                Some(value) if !value.as_literal().is_some_and(|s| s.starts_with('-')) => {
                    provenance.push(arg_node(builder, ctx, (i + 1) as u32));
                    Some(value.clone())
                }
                _ => {
                    invalid = true;
                    None
                }
            }
        } else if equals {
            names
                .iter()
                .filter(|n| n.starts_with("--"))
                .find_map(|name| {
                    attached_value(word, &format!("{name}=")).inspect(|_| {
                        provenance.push(arg_node(builder, ctx, i as u32));
                    })
                })
        } else {
            None
        };
        if let Some(word) = value {
            if word.as_literal() == Some("") && !names.contains(&"--vhost") {
                invalid = true;
            }
            found.push(match word.as_literal() {
                Some(value) => ResourceExpr::Literal {
                    value: value.to_string(),
                },
                None => crate::nest::word_resource(&word),
            });
        }
    }
    if found.windows(2).any(|pair| pair[0] != pair[1]) {
        invalid = true;
    }
    if invalid {
        scope_boundary(builder, provenance, domain);
        Some(ScopeValue::Unknown)
    } else {
        found.into_iter().next().map(ScopeValue::value)
    }
}

pub(crate) fn access_value(scope: &mut ResourceScope, kind: ScopeEvidenceKind, value: ScopeValue) {
    let value = match value {
        ScopeValue::Value(value) => *value,
        _ => ResourceExpr::Unresolved {
            family: ResourceFamily::new("value"),
        },
    };
    scope.access.push(ScopeEvidence {
        kind,
        value,
        origin: None,
    });
}

/// Only explicit connection evidence is retained. Credentials are discarded before emission.
pub(crate) fn endpoint_evidence(
    scope: &mut ResourceScope,
    kind: ScopeEvidenceKind,
    value: ScopeValue,
) {
    access_value(scope, kind, value);
    effinterp_proto::normalize_scope(scope, effinterp_proto::PathPlatform::Posix);
}

/// Position of a command after supported global options; option operands are never verbs.
pub(crate) fn command_position(argv: &[Word], value_flags: &[&str]) -> usize {
    crate::models::args::scan_detached(
        argv,
        &crate::models::args::FlagSpec {
            value_flags,
            known_flags: &[],
            allow_abbreviation: false,
        },
        false,
    )
    .operands
    .iter()
    .find(|(_, word)| word.as_literal() != Some("-"))
    .map_or(argv.len(), |(index, _)| *index as usize)
}

pub(crate) fn unmodeled_scope_options(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &[ProvenanceRef],
    scope: &mut ResourceScope,
    supported: &[&str],
    domain: &str,
) {
    if ctx.argv.iter().skip(1).any(|word| {
        word.as_literal().is_some_and(|word| {
            word.starts_with('-')
                && word != "-"
                && word != "--"
                && !supported.contains(&word.split('=').next().unwrap())
        })
    }) {
        scope_boundary(builder, provenance, domain);
        access_value(
            scope,
            ScopeEvidenceKind::UnresolvedConfiguration,
            ScopeValue::Unknown,
        );
    }
}

pub(crate) fn resolve_scope_environment(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    provenance: &mut Vec<ProvenanceRef>,
    expr: &mut ResourceExpr,
) {
    match expr {
        ResourceExpr::Environment { name } => {
            if let Some(value) = ctx.environment_value(name) {
                if let Some(node) = ctx.nest.current_environment_node(name) {
                    provenance.push(node);
                } else if ctx.tracks_host_context_environment() {
                    provenance.push(builder.node(
                        effinterp_proto::ProvenanceKind::HostContext {
                            name: format!("env.{name}"),
                        },
                        &[],
                    ));
                }
                *expr = value;
            }
        }
        ResourceExpr::Concrete { identity } => {
            if let Some(scope) = identity.scope_mut() {
                for value in scope.values_mut() {
                    resolve_scope_environment(builder, ctx, provenance, value);
                }
            }
        }
        ResourceExpr::Join { parts }
        | ResourceExpr::Union {
            alternatives: parts,
        } => {
            for value in parts {
                resolve_scope_environment(builder, ctx, provenance, value);
            }
        }
        ResourceExpr::Property { base, .. } => {
            resolve_scope_environment(builder, ctx, provenance, base)
        }
        _ => {}
    }
}

/// Network access established by a resource scope, without deriving service hostnames.
pub(crate) fn network_resource(scope: &ResourceScope) -> ResourceExpr {
    let mut endpoints: Vec<_> = scope
        .access
        .iter()
        .filter_map(|evidence| match evidence.kind {
            ScopeEvidenceKind::Endpoint | ScopeEvidenceKind::Seed => Some(evidence.value.clone()),
            ScopeEvidenceKind::Node => match &evidence.value {
                ResourceExpr::Literal { value } => value
                    .split_once('@')
                    .filter(|(_, host)| !host.is_empty())
                    .map(|(_, host)| ResourceExpr::Concrete {
                        identity: effinterp_proto::ResourceIdentity::NetworkEndpoint {
                            host: host.to_string(),
                            scheme: None,
                            port: None,
                            path: None,
                        },
                    }),
                _ => None,
            },
            _ => None,
        })
        .collect();
    endpoints.sort_by_cached_key(effinterp_proto::canonical_json);
    endpoints.dedup();
    match endpoints.len() {
        0 => ResourceExpr::Unresolved {
            family: ResourceFamily::new("network"),
        },
        1 => endpoints.pop().unwrap(),
        _ => ResourceExpr::Union {
            alternatives: endpoints,
        },
    }
}
