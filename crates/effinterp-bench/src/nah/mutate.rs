use std::collections::BTreeMap;
use std::sync::Arc;

use effinterp_engine::{Engine, ObservationResolver, SourceResolver};
use effinterp_proto::{Domain, Effect, Plan, ResourceExpr, Subject};
use serde::{Deserialize, Serialize};

use crate::nah::goldens::Req;

use effinterp_engine::operand::{
    SYMBOLIC_OPERAND, literal_shell_operand_spans, operand_cites, shell_operand_subject,
};
const MUTANT_CAP: usize = 16;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MutationMeasurement {
    pub attempted: usize,
    pub exercised: usize,
    pub not_exercised: usize,
    pub reasons: BTreeMap<String, usize>,
    pub findings: Vec<SilentSymbolicDrop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentSymbolicDrop {
    pub operation: String,
    pub domain: String,
    pub source_start: u32,
    pub source_end: u32,
}

impl MutationMeasurement {
    pub(crate) fn skip(&mut self, reason: &str) {
        self.not_exercised += 1;
        *self.reasons.entry(reason.into()).or_default() += 1;
    }
}

#[derive(Clone)]
struct Slot {
    start: u32,
    end: u32,
    evidence: (u32, u32),
    operation: Option<&'static str>,
}

/// Measure only independently required operations with original occurrence evidence.
/// Unsupported transforms and budget stops remain visible even when there are no findings.
/// Mutants are analyzed against the same host observation as the baseline plan,
/// so a difference is the mutation's and not the resolver's.
pub fn measure_symbolic_mutations(
    engine: &Engine,
    baseline: &Plan,
    oracle: &[Req],
    resolver: Option<&dyn SourceResolver>,
    observations: Option<Arc<dyn ObservationResolver>>,
) -> MutationMeasurement {
    measure_with(engine, baseline, oracle, resolver, observations, |_| {})
}

fn measure_with(
    engine: &Engine,
    original: &Plan,
    oracle: &[Req],
    resolver: Option<&dyn SourceResolver>,
    observations: Option<Arc<dyn ObservationResolver>>,
    mut alter: impl FnMut(&mut Plan),
) -> MutationMeasurement {
    let analyze = |subject: &Subject| {
        engine.analyze_with_observations(subject, None, resolver, observations.clone())
    };
    let mut result = MutationMeasurement::default();
    if effinterp_proto::validate_plan(original).is_err() {
        result.skip("invalid_baseline");
        return result;
    }
    let mut subject = shell_operand_subject(&original.subject);
    if let Subject::Shell { context, .. } = &mut subject {
        context
            .env
            .insert("ORACLE_CONTEXT".into(), "present".into());
    }
    let baseline = if subject != original.subject {
        match analyze(&subject) {
            Ok(plan) if effinterp_proto::validate_plan(&plan).is_ok() => plan,
            _ => {
                result.skip("invalid_exec_adapter");
                return result;
            }
        }
    } else {
        original.clone()
    };
    let candidates = match slots(&subject) {
        Ok(slots) => slots,
        Err(reason) => {
            result.skip(reason);
            return result;
        }
    };
    let mut eligible = Vec::new();
    for slot in candidates {
        let effects: Vec<_> =
            baseline
                .effects
                .iter()
                .filter(|effect| {
                    let domain = effect.operation.as_str().split('.').next().unwrap();
                    baseline.coverage.is_full(&Domain::new(domain))
                        && original.coverage.is_full(&Domain::new(domain))
                        && slot
                            .operation
                            .is_none_or(|op| op == effect.operation.as_str())
                        && operand_cites(&baseline, &effect.provenance, slot.evidence)
                        && shell_resource_role(&subject, &slot, effect)
                        && oracle.iter().any(|req| {
                            req.attributes_match(&effect.attributes)
                                && (req.op == effect.operation.as_str() || req.op == domain)
                                && req.resource.matches(
                                    &effinterp_matcher::render::rendered_resource(&effect.resource),
                                )
                        })
                        && original.effects.iter().any(|e| {
                            e.operation == effect.operation
                                && e.resource == effect.resource
                                && e.realm == effect.realm
                        })
                })
                .cloned()
                .collect();
        if !effects.is_empty() {
            eligible.push((slot, effects));
        }
    }
    if eligible.is_empty() {
        result.skip("no_full_oracle_resource_slot");
    }
    for (index, (slot, effects)) in eligible.into_iter().enumerate() {
        if index >= MUTANT_CAP {
            result.skip("mutant_budget");
            continue;
        }
        result.attempted += 1;
        let (mutant, replacement_len) = rewrite(&subject, &slot);
        let mut plan = match analyze(&mutant) {
            Ok(plan) if effinterp_proto::validate_plan(&plan).is_ok() => plan,
            _ => {
                result.skip("invalid_mutant");
                continue;
            }
        };
        // Reparse the replacement and reject new unresolved helpers or parse failures.
        if !valid_source(&mutant)
            || plan.boundaries.iter().any(|b| {
                matches!(b.reason.as_str(), "parse_error" | "syntax_error")
                    || (b.reason.as_str() == "unresolved_call"
                        && !baseline
                            .boundaries
                            .iter()
                            .any(|old| old.callee == b.callee && old.detail == b.detail))
            })
        {
            result.skip("contaminated_mutant");
            continue;
        }
        let delta = replacement_len as i64 - (slot.end - slot.start) as i64;
        let evidence = (slot.evidence.0, (slot.evidence.1 as i64 + delta) as u32);
        alter(&mut plan);
        result.exercised += 1;
        for effect in effects {
            if !retained(&plan, &effect, evidence) {
                result.findings.push(SilentSymbolicDrop {
                    operation: effect.operation.as_str().into(),
                    domain: effect.operation.as_str().split('.').next().unwrap().into(),
                    source_start: slot.start,
                    source_end: slot.end,
                });
            }
        }
    }
    result
}

fn shell_resource_role(subject: &Subject, slot: &Slot, effect: &Effect) -> bool {
    let Subject::Shell { cwd, .. } = subject else {
        return true;
    };
    let Some(value) =
        effinterp_engine::operand::shell_operand_literal(subject, (slot.start, slot.end))
    else {
        return false;
    };
    match &effect.resource {
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::FsPath { path },
        } => {
            let target = if value.starts_with('/') {
                value
            } else {
                match cwd {
                    Some(cwd) => format!("{cwd}/{value}"),
                    None => value,
                }
            };
            effinterp_proto::normalize_path(&target, effinterp_proto::PathPlatform::Posix) == *path
        }
        ResourceExpr::Concrete {
            identity: effinterp_proto::ResourceIdentity::NetworkEndpoint { .. },
        } => {
            effinterp_engine::SemanticValue::source_literal(value)
                .lower_resource_for_domain("network")
                == effect.resource
        }
        _ => false,
    }
}

fn slots(subject: &Subject) -> Result<Vec<Slot>, &'static str> {
    let mut slots = match subject {
        Subject::Shell { .. } => literal_shell_operand_spans(subject)?
            .into_iter()
            .map(|(start, end)| Slot {
                start,
                end,
                evidence: (start, end),
                operation: None,
            })
            .collect(),
        Subject::Source {
            language,
            source,
            dialect: Some(dialect),
            ..
        } if language == "js" => js_slots(source, *dialect)?,
        Subject::Source {
            language, source, ..
        } if language == "rust" => rust_slots(source)?,
        Subject::ToolCall { .. } => return Err("native_fields_have_no_symbolic_transform"),
        _ => return Err("source_language_transform_unsupported"),
    };
    slots.sort_by_key(|s| (s.start, s.end));
    Ok(slots)
}

fn rewrite(subject: &Subject, slot: &Slot) -> (Subject, usize) {
    let mut subject = subject.clone();
    let (source, context, replacement) = match &mut subject {
        Subject::Shell {
            source, context, ..
        } => (source, context, format!("\"${SYMBOLIC_OPERAND}\"")),
        Subject::Source {
            language,
            source,
            context,
            ..
        } if language == "js" => (source, context, format!("process.env.{SYMBOLIC_OPERAND}")),
        Subject::Source {
            source, context, ..
        } => (
            source,
            context,
            format!("std::env::var(\"{SYMBOLIC_OPERAND}\").unwrap()"),
        ),
        _ => unreachable!(),
    };
    context.env.remove(SYMBOLIC_OPERAND);
    source.replace_range(slot.start as usize..slot.end as usize, &replacement);
    (subject, replacement.len())
}

fn valid_source(subject: &Subject) -> bool {
    match subject {
        Subject::Shell { .. } => true,
        Subject::Source {
            language,
            source,
            dialect: Some(dialect),
            ..
        } if language == "js" => {
            let allocator = oxc_allocator::Allocator::default();
            let source_type = if *dialect == effinterp_proto::SourceDialect::Ts {
                oxc_span::SourceType::ts()
            } else {
                oxc_span::SourceType::mjs()
            };
            oxc_parser::Parser::new(&allocator, source, source_type)
                .parse()
                .errors
                .is_empty()
        }
        Subject::Source { source, .. } => syn::parse_file(source).is_ok(),
        _ => false,
    }
}

fn symbolic(resource: &ResourceExpr, domain: &str) -> bool {
    match resource {
        ResourceExpr::Environment { name } => name == SYMBOLIC_OPERAND,
        ResourceExpr::Unresolved { family } => {
            matches!(family.0.as_ref(), "unknown" | "value") || family.0 == domain
        }
        ResourceExpr::Join { parts } => parts.iter().any(|r| symbolic(r, domain)),
        ResourceExpr::Union { alternatives } => alternatives.iter().any(|r| symbolic(r, domain)),
        _ => false,
    }
}

fn retained(plan: &Plan, original: &Effect, span: (u32, u32)) -> bool {
    let domain = original.operation.as_str().split('.').next().unwrap();
    plan.effects.iter().any(|e| {
        e.operation == original.operation
            && e.realm == original.realm
            && operand_cites(plan, &e.provenance, span)
            && symbolic(&e.resource, domain)
    }) || plan.boundaries.iter().any(|b| {
        b.domains.iter().any(|d| d.0 == domain)
            && (operand_cites(plan, &b.provenance, span)
                || !plan.coverage.is_full(&Domain::new(domain)))
    })
}

fn js_slots(
    source: &str,
    dialect: effinterp_proto::SourceDialect,
) -> Result<Vec<Slot>, &'static str> {
    use oxc_ast::ast::{CallExpression, Expression};
    use oxc_ast_visit::{Visit, walk};
    struct Collector {
        slots: Vec<Slot>,
    }
    impl<'a> Visit<'a> for Collector {
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            let operation = match &call.callee {
                Expression::Identifier(id) if id.name == "fetch" => Some("network.request"),
                Expression::StaticMemberExpression(member) => {
                    let module = match &member.object {
                        Expression::CallExpression(require) if matches!(&require.callee, Expression::Identifier(id) if id.name == "require") => {
                            require
                                .arguments
                                .first()
                                .and_then(|a| a.as_expression())
                                .and_then(|a| match a {
                                    Expression::StringLiteral(s) => Some(s.value.as_str()),
                                    _ => None,
                                })
                        }
                        _ => None,
                    };
                    match (module, member.property.name.as_str()) {
                        (Some("fs" | "node:fs"), "readFileSync") => Some("filesystem.read"),
                        (Some("fs" | "node:fs"), "writeFileSync") => Some("filesystem.write"),
                        (Some("fs" | "node:fs"), "unlinkSync" | "rmSync") => {
                            Some("filesystem.delete")
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(operation) = operation
                && let Some(Expression::StringLiteral(literal)) =
                    call.arguments.first().and_then(|a| a.as_expression())
            {
                self.slots.push(Slot {
                    start: literal.span.start,
                    end: literal.span.end,
                    evidence: (call.span.start, call.span.end),
                    operation: Some(operation),
                });
            }
            walk::walk_call_expression(self, call);
        }
    }
    if source.contains(SYMBOLIC_OPERAND) {
        return Err("variable_collision");
    }
    // These source candidates are restricted to direct runtime APIs. Any authored
    // process binding could change the replacement's meaning.
    if source.contains("process") {
        return Err("source_process_binding_not_proven");
    }
    let allocator = oxc_allocator::Allocator::default();
    let ty = if dialect == effinterp_proto::SourceDialect::Ts {
        oxc_span::SourceType::ts()
    } else {
        oxc_span::SourceType::mjs()
    };
    let parsed = oxc_parser::Parser::new(&allocator, source, ty).parse();
    if !parsed.errors.is_empty() {
        return Err("invalid_source");
    }
    let mut collector = Collector { slots: Vec::new() };
    collector.visit_program(&parsed.program);
    Ok(collector.slots)
}

fn rust_slots(source: &str) -> Result<Vec<Slot>, &'static str> {
    use syn::{spanned::Spanned, visit::Visit};
    struct Collector {
        slots: Vec<Slot>,
    }
    impl<'a> Visit<'a> for Collector {
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let path = path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                let operation = match path.as_str() {
                    "std::fs::read" | "std::fs::read_to_string" => Some("filesystem.read"),
                    "std::fs::write" => Some("filesystem.write"),
                    "std::fs::remove_file" => Some("filesystem.delete"),
                    "std::net::TcpStream::connect" => Some("network.connect"),
                    _ => None,
                };
                if let Some(operation) = operation
                    && let Some(syn::Expr::Lit(literal)) = call.args.first()
                    && matches!(literal.lit, syn::Lit::Str(_))
                {
                    let range = literal.span().byte_range();
                    let call_range = call.span().byte_range();
                    self.slots.push(Slot {
                        start: range.start as u32,
                        end: range.end as u32,
                        evidence: (call_range.start as u32, call_range.end as u32),
                        operation: Some(operation),
                    });
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    if source.contains(SYMBOLIC_OPERAND) {
        return Err("variable_collision");
    }
    if source.contains("mod std") || source.contains("as std") {
        return Err("source_std_binding_not_proven");
    }
    let parsed = syn::parse_file(source).map_err(|_| "invalid_source")?;
    let mut collector = Collector { slots: Vec::new() };
    collector.visit_file(&parsed);
    Ok(collector.slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nah::goldens::ResourceMatch;

    #[test]
    fn detector_rejects_same_operation_masking() {
        let engine = Engine::new().with_causality_detail(true);
        let subject = Subject::Shell {
            source: "rm /first /second".into(),
            cwd: None,
            context: Default::default(),
        };
        let baseline = engine.analyze(&subject).unwrap();
        let oracle = [Req {
            attributes: Default::default(),
            op: "filesystem.delete".into(),
            resource: ResourceMatch::Any(true),
        }];
        let sound = measure_symbolic_mutations(&engine, &baseline, &oracle, None, None);
        assert_eq!(sound.exercised, 2);
        assert!(sound.findings.is_empty());
        let broken = measure_with(&engine, &baseline, &oracle, None, None, |plan| {
            plan.effects
                .retain(|e| !symbolic(&e.resource, "filesystem"));
        });
        assert_eq!(broken.exercised, 2);
        assert_eq!(broken.findings.len(), 2);
    }
    #[test]
    fn source_detector_controls_and_contamination() {
        for subject in [
            Subject::Exec { argv: vec!["rm".into(), "/first".into(), "/second".into()], cwd: None, context: Default::default() },
            Subject::Source { language: "js".into(), source: "require('fs').unlinkSync('/first'); require('fs').unlinkSync('/second');".into(), dialect: Some(effinterp_proto::SourceDialect::Js), cwd: None, context: Default::default() },
            Subject::Source { dialect: None, language: "rust".into(), source: r#"fn main() { std::fs::remove_file("/first"); std::fs::remove_file("/second"); }"#.into(), cwd: None, context: Default::default() },
        ] {
            let engine = Engine::new().with_causality_detail(true);
            let plan = engine.analyze(&subject).unwrap();
            let oracle = [Req { attributes: Default::default(), op: "filesystem.delete".into(), resource: ResourceMatch::Any(true) }];
            let broken = measure_with(&engine, &plan, &oracle, None, None, |plan| {
                plan.effects.retain(|e| !symbolic(&e.resource, "filesystem"));
                plan.boundaries.clear();
            });
            assert_eq!(broken.exercised, 2, "{broken:?}");
            assert_eq!(broken.findings.len(), 2, "{broken:?}");
        }
        assert!(
            js_slots(
                "require('fs').unlinkSync(",
                effinterp_proto::SourceDialect::Js
            )
            .is_err()
        );
        assert!(rust_slots("fn main( {").is_err());
        let subject = Subject::Shell {
            source: "dd of=/file".into(),
            cwd: None,
            context: Default::default(),
        };
        assert!(matches!(
            slots(&subject),
            Err("shell_embedded_operands_unsupported")
        ));
    }
}
