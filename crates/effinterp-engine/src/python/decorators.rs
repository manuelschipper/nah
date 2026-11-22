//! Python decorators.
//! Applying a decorator can run its own code even when its decorated definition is never called.

use effinterp_proto::{BoundaryClass, BoundaryReason, CalleeReference};
use rustpython_parser::ast::{Expr, Ranged};

use crate::control_flow::SiteFacts;

use super::ast_expressions::callee_written;
use super::call_resolution::python_callee_reference;
use super::definitions::decorator_names;
use super::imports::PytestMode;
use super::{PythonWalker, control};

impl PythonWalker<'_, '_> {
    /// Apply decorator effects at definition time, before any call to the decorated callable.
    pub(super) fn apply_decorator(&mut self, decorator: &Expr) {
        let written = decorator_names(std::slice::from_ref(decorator)).remove(0);
        if let Expr::Call(call) = decorator
            && self.decorator_is_transparent(&written)
            && !self.local_decorator_factory(&call.func)
        {
            // Applying a known wrapper can be effect-free. Python still
            // evaluates the arguments to its factory at definition time.
            for argument in call
                .args
                .iter()
                .chain(call.keywords.iter().map(|kw| &kw.value))
            {
                self.walk_expr(argument);
            }
            if self
                .import_search
                .as_ref()
                .and_then(|search| search.pytest_mode)
                == Some(PytestMode::Collect)
                && self.imports.resolve_callee(&call.func).as_deref()
                    == Some("pytest.mark.parametrize")
            {
                self.apply_pytest_parametrize_ids(call);
            }
        } else {
            self.walk_expr(decorator);
        }
        let applications = std::mem::take(&mut self.control_applications);
        let facts = self.apply_decorator_inner(decorator);
        self.control_applications = applications;
        self.builder.control_site(
            self.source,
            self.capture.is_some(),
            control::decorator_span(decorator),
            facts,
        );
    }

    fn local_decorator_factory(&mut self, callee: &Expr) -> bool {
        self.local_callee(callee).is_some() || self.imported_decorator_factory(callee).is_some()
    }

    fn imported_decorator_factory(&mut self, callee: &Expr) -> Option<String> {
        let written = callee_written(callee)?;
        let canonical = self.imports.canonical_import(&written)?;
        let (module, _) = canonical.rsplit_once('.')?;
        (self.traversed_python_module(module) == Some(true)).then_some(canonical)
    }

    fn apply_decorator_inner(&mut self, decorator: &Expr) -> SiteFacts {
        let written = decorator_names(std::slice::from_ref(decorator)).remove(0);
        let factory = match decorator {
            Expr::Call(call) => self.imported_decorator_factory(&call.func),
            _ => None,
        };
        if self.decorator_is_transparent(&written) && factory.is_none() {
            // A bare local decorator is applied directly to the definition.
            if !matches!(decorator, Expr::Call(_))
                && let Some(canonical) = self.imports.canonical_import(&written)
                && self.apply_imported_arguments(&canonical, &[], decorator.range())
            {
                return match std::mem::take(&mut self.control_applications).as_slice() {
                    [application] => application.clone(),
                    _ => SiteFacts::unknown(),
                };
            }
            return SiteFacts::known(Vec::new());
        }
        if let Some(factory) = factory {
            self.emit_unresolved_call(
                &format!("{factory} decorator factory result"),
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                decorator.range(),
                python_callee_reference(&factory),
            );
            return SiteFacts::unknown();
        }
        if let Some(name) = self.local_callee(decorator) {
            self.apply_local_arguments(&name, &[], decorator.range());
            match std::mem::take(&mut self.control_applications).as_slice() {
                [application] => application.clone(),
                _ => SiteFacts::unknown(),
            }
        } else if !matches!(decorator, Expr::Call(_))
            && let Some(canonical) = self.imports.canonical_import(&written)
            && self.apply_imported_arguments(&canonical, &[], decorator.range())
        {
            // A bare imported decorator runs at definition time. Its body is
            // applied even when the replacement is not a proven identity; a
            // body that cannot be summarized stays an unresolved call below.
            match std::mem::take(&mut self.control_applications).as_slice() {
                [application] => application.clone(),
                _ => SiteFacts::unknown(),
            }
        } else {
            let name = self.imports.resolve_callee(decorator).unwrap_or(written);
            self.emit_unresolved_call(
                &name,
                BoundaryReason::UNRESOLVED_CALL,
                BoundaryClass::Unresolved,
                crate::external::ALL_DOMAINS,
                decorator.range(),
                python_callee_reference(&name).or_else(|| {
                    Some(CalleeReference {
                        module: "python".into(),
                        symbol: name.clone(),
                    })
                }),
            );
            SiteFacts::unknown()
        }
    }
}
