//! Identifier references proven by semantic scope, including runtime globals and aliases.

use std::collections::HashSet;

use oxc_ast::ast::{
    BindingPattern, Expression, FormalParameters, FunctionBody, Statement, VariableDeclaration,
    VariableDeclarationKind,
};
use oxc_ast_visit::{Visit, walk};

use super::bindings::{Bindings, binding_declares};
use super::expression_values::unparen;
use super::{MAX_WALK_DEPTH, model};

/// References, by span start and name, to each `const` local initialized to
/// the runtime's own `process`. Any other alias stays unknown.
pub(super) fn process_alias_references(
    program: &oxc_ast::ast::Program<'_>,
    semantic: &oxc_semantic::Semantic<'_>,
) -> HashSet<(u32, String)> {
    struct Aliases<'s> {
        global: HashSet<u32>,
        symbols: Vec<(oxc_semantic::SymbolId, &'s str)>,
        depth: u32,
    }
    impl<'a> Visit<'a> for Aliases<'a> {
        fn visit_statement(&mut self, it: &Statement<'a>) {
            // Past the depth limit an alias is simply not recognized.
            if self.depth >= MAX_WALK_DEPTH {
                return;
            }
            self.depth += 1;
            walk::walk_statement(self, it);
            self.depth -= 1;
        }
        fn visit_expression(&mut self, it: &Expression<'a>) {
            if self.depth >= MAX_WALK_DEPTH {
                return;
            }
            self.depth += 1;
            walk::walk_expression(self, it);
            self.depth -= 1;
        }
        fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
            if it.kind == VariableDeclarationKind::Const {
                for declarator in &it.declarations {
                    if let BindingPattern::BindingIdentifier(alias) = &declarator.id
                        && let Some(Expression::Identifier(process)) =
                            declarator.init.as_ref().map(unparen)
                        && process.name.as_str() == "process"
                        && self.global.contains(&process.span.start)
                        && let Some(symbol) = alias.symbol_id.get()
                    {
                        self.symbols.push((symbol, alias.name.as_str()));
                    }
                }
            }
            walk::walk_variable_declaration(self, it);
        }
    }
    let mut aliases = Aliases {
        global: global_reference_spans(semantic, "process"),
        symbols: Vec::new(),
        depth: 0,
    };
    aliases.visit_program(program);
    let scoping = semantic.scoping();
    aliases
        .symbols
        .into_iter()
        .flat_map(|(symbol, name)| {
            scoping
                .get_resolved_reference_ids(symbol)
                .iter()
                .map(move |reference| {
                    let span = semantic.reference_span(scoping.get_reference(*reference));
                    (span.start, name.to_string())
                })
        })
        .collect()
}

/// Spans of the references to `name` that no scope binds, so they reach the
/// runtime's global. Empty when the program writes that global.
pub(super) fn global_reference_spans(
    semantic: &oxc_semantic::Semantic<'_>,
    name: &str,
) -> HashSet<u32> {
    let scoping = semantic.scoping();
    let Some(references) = scoping.root_unresolved_references().get(name) else {
        return HashSet::new();
    };
    let references = references
        .iter()
        .map(|reference| scoping.get_reference(*reference))
        .collect::<Vec<_>>();
    if references.iter().any(|reference| reference.is_write()) {
        return HashSet::new();
    }
    references
        .into_iter()
        .map(|reference| semantic.reference_span(reference).start)
        .collect()
}

/// Collect writes to const bindings. None means the summary budget prevented a complete scan.
pub(super) fn readonly_write_spans(semantic: &oxc_semantic::Semantic<'_>) -> Option<HashSet<u32>> {
    let limit = crate::AnalysisLimits::default().max_causal_pairs;
    if semantic.nodes().len() as u64 > limit {
        return None;
    }
    let scoping = semantic.scoping();
    let mut spans = HashSet::new();
    for symbol in scoping.symbol_ids() {
        if !crate::limits::summary_step() {
            return None;
        }
        if !scoping.symbol_flags(symbol).is_const_variable() {
            continue;
        }
        for reference in scoping.get_resolved_reference_ids(symbol) {
            if !crate::limits::summary_step() {
                return None;
            }
            let reference = scoping.get_reference(*reference);
            if reference.is_write() {
                spans.insert(semantic.reference_span(reference).start);
            }
        }
    }
    Some(spans)
}

/// Resolve only evidence introduced by this function. `None` leaves the
/// caller to supply the lexically enclosing process receiver.
pub(super) fn function_process_scope(
    body: &FunctionBody<'_>,
    parameters: &FormalParameters<'_>,
) -> Option<bool> {
    if formal_parameters_declare_process(parameters) {
        return Some(false);
    }
    let mut locals = Bindings::default();
    for statement in &body.statements {
        locals.visit_statement(statement);
    }
    if locals.process_bindings == 0 && !locals.process_reassigned {
        None
    } else {
        Some(locals.process_runtime())
    }
}

fn formal_parameters_declare_process(parameters: &FormalParameters<'_>) -> bool {
    parameters
        .items
        .iter()
        .any(|parameter| binding_declares(&parameter.pattern, "process"))
        || parameters
            .rest
            .as_ref()
            .is_some_and(|rest| binding_declares(&rest.rest.argument, "process"))
}

/// Runtime identifier reads may throw when their names have neither a binding nor a runtime global.
pub(super) fn runtime_missing_identifier_spans(
    semantic: &oxc_semantic::Semantic<'_>,
) -> HashSet<u32> {
    let scoping = semantic.scoping();
    let can_throw = |reference_id| {
        let reference = scoping.get_reference(reference_id);
        reference.is_read()
    };
    let mut runtime_missing_identifier_spans: HashSet<_> = scoping
        .root_unresolved_references()
        .iter()
        .filter(|(name, _)| !model::RUNTIME_GLOBALS.contains(&name.as_str()))
        .flat_map(|(_, reference_ids)| reference_ids.iter().copied())
        .filter(|reference_id| can_throw(*reference_id))
        .map(|reference_id| {
            semantic
                .reference_span(scoping.get_reference(reference_id))
                .start
        })
        .collect();
    for symbol_id in scoping
        .symbol_ids()
        .filter(|symbol_id| scoping.symbol_flags(*symbol_id).is_ambient())
        .filter(|symbol_id| !model::RUNTIME_GLOBALS.contains(&scoping.symbol_name(*symbol_id)))
    {
        runtime_missing_identifier_spans.extend(
            scoping
                .get_resolved_reference_ids(symbol_id)
                .iter()
                .copied()
                .filter(|reference_id| can_throw(*reference_id))
                .map(|reference_id| {
                    semantic
                        .reference_span(scoping.get_reference(reference_id))
                        .start
                }),
        );
    }
    runtime_missing_identifier_spans
}
