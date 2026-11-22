//! Pytest collection in Python analysis.
//! Hooks and parameter ID callbacks run through dispatch even without direct calls in the file.

use std::collections::BTreeSet;

use effinterp_proto::{BoundaryClass, BoundaryReason};
use rustpython_parser::ast;
use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{Expr, Stmt};
use rustpython_parser::text_size::TextRange;

use super::call_resolution::python_call_argument;
use super::name_bindings::{possibly_written_names, rebound_body_names};
use super::{PythonWalker, definitions, python_boundary};

impl PythonWalker<'_, '_> {
    /// Apply callables reached by the selected pytest collection mode under dispatch conditions.
    pub(super) fn apply_pytest_collected(&mut self, suite: &[Stmt]) {
        let Some(mode) = self
            .import_search
            .as_ref()
            .and_then(|search| search.pytest_mode)
        else {
            return;
        };
        if let Some(path) = self
            .import_search
            .as_ref()
            .and_then(|search| search.pytest_path.clone())
            .or_else(|| self.builder.current_source_origin())
            && !self
                .nest
                .python_imports
                .record_pytest_source(self.builder, path)
        {
            return;
        }
        // A callable can be registered with pytest without a direct call
        // from this file. Keep the effects conditional on that dispatch.
        let (roots, bindings) = definitions::pytest_callables(suite, &mut self.defs, mode);
        for (name, range) in roots {
            self.push_pytest_dispatch(range);
            self.apply_local_root(&name);
            self.builder.pop_condition();
        }
        if !bindings.is_empty() {
            python_boundary(
                self.builder,
                self.scope,
                BoundaryReason::FRONTEND_PARTIAL,
                BoundaryClass::Unmodeled,
                None,
                Some(format!(
                    "pytest callable binding could not be resolved: {}",
                    bindings.into_iter().collect::<Vec<_>>().join(", ")
                )),
            );
        }
        let registrations: BTreeSet<_> = possibly_written_names(suite, false, true, false)
            .into_iter()
            .chain(rebound_body_names(suite, true))
            .filter(|name| mode.enters_hook(name))
            .collect();
        if !registrations.is_empty() {
            python_boundary(
                self.builder,
                self.scope,
                BoundaryReason::FRONTEND_PARTIAL,
                BoundaryClass::Unmodeled,
                None,
                Some(format!(
                    "pytest registration binding is outside plain collection: {}",
                    registrations.into_iter().collect::<Vec<_>>().join(", ")
                )),
            );
        }
    }

    pub(super) fn apply_pytest_parametrize_ids(&mut self, call: &ast::ExprCall) {
        let Some(ids) = python_call_argument(call, 3, "ids") else {
            return;
        };
        if matches!(
            ids,
            Expr::Constant(_) | Expr::List(_) | Expr::Tuple(_) | Expr::Set(_) | Expr::Dict(_)
        ) {
            return;
        }
        self.push_pytest_dispatch(call.range);
        if let Expr::Lambda(lambda) = ids {
            let name = definitions::pytest_lambda(
                &mut self.defs,
                lambda,
                self.current_class.as_deref(),
                self.current_function.as_deref(),
            );
            self.apply_local_arguments(&name, &[], ids.range());
        } else if let Some(name) = self.imports.resolve_local_callee(ids)
            && self.apply_imported_arguments(&name, &[], ids.range())
        {
            // The resolved callback's summary has supplied its effects.
        } else if let Some(name) = self.local_callee(ids) {
            self.apply_local_arguments(&name, &[], ids.range());
        } else {
            self.emit_unresolved_call(
                "pytest parameter ID callback",
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                ids.range(),
                None,
            );
        }
        self.builder.pop_condition();
    }

    fn push_pytest_dispatch(&mut self, range: TextRange) {
        self.builder
            .push_condition(self.builder.source_condition_path(
                effinterp_proto::Condition::from_source_with_digest(
                    self.source,
                    self.condition_source.digest().to_string(),
                    effinterp_proto::ByteSpan {
                        start: range.start().into(),
                        end: range.end().into(),
                    },
                    effinterp_proto::ConditionKind::Dispatch,
                    0,
                    2,
                    false,
                    true,
                ),
            ));
    }
}
