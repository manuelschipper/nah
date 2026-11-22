//! The module loads a repository module summary records. The loader owner
//! (`module_load`) classifies each load in the file; this walk turns every
//! module it names into an import or a scoped import, and every load it
//! cannot name into a dependency gap of the top-level function or module
//! that holds it.

use effinterp_proto::{Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain};
use oxc_ast::ast::{CallExpression, Expression, Program, Statement};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

use super::{JS_DOMAINS, MAX_WALK_DEPTH, resolve};
use crate::module_summary::{FunctionEntry, ImportBinding};

/// The module loads the loader owner (`module_load`) finds in one file. The
/// import collector sees only `require('literal')` bound to a name; every
/// other loader use the owner names is an import here, and every one it
/// cannot name is a dependency gap, so a composed plan never treats an
/// unread module as absent.
#[derive(Default)]
pub(super) struct LoadSites {
    /// Each named module, where it is loaded, and whether a function body
    /// loads it.
    named: Vec<(String, u32, bool)>,
    /// Where an unnamed load sits, and whether a function body holds it.
    gaps: Vec<(u32, bool)>,
}

impl LoadSites {
    /// Every load in one file, by the loader owner's classification. A
    /// summarized file is a source file, never `deno eval` code or a direct
    /// `eval`, so only a module-scope binding replaces `require` here.
    pub(super) fn collect(
        program: &Program<'_>,
        semantic: &oxc_semantic::Semantic<'_>,
        dynamic_imports: &resolve::DynamicImportFacts,
    ) -> Self {
        let require_shadowed = semantic
            .scoping()
            .get_root_binding("require".into())
            .is_some();
        let loads = super::module_load::collect(
            program,
            semantic,
            require_shadowed,
            &super::module_load::global_require_spans(semantic),
            None,
        );
        let mut walk = LoadSiteWalk {
            loads: &loads,
            dynamic_imports,
            sites: LoadSites::default(),
            function_depth: 0,
            walk_depth: 0,
        };
        walk.visit_program(program);
        walk.sites
    }

    /// Add the named modules to the module's imports (a function body's to
    /// its scoped imports), and each gap to the boundaries of the top-level
    /// function that holds it, or of the module.
    ///
    /// Composition runs a scoped import's module only when a composed call
    /// reaches a definition in it, not because the function that loads it
    /// ran. A function's load of a module no module-level import already
    /// runs is therefore also a gap of that function.
    pub(super) fn apply(
        self,
        imports: &mut Vec<ImportBinding>,
        scoped_imports: &mut Vec<ImportBinding>,
        functions: &mut [FunctionEntry],
        module_boundaries: &mut Vec<Boundary>,
    ) {
        let mut gaps = self
            .gaps
            .into_iter()
            .map(|(start, scoped)| (start, scoped, "module load whose target is not named"))
            .collect::<Vec<_>>();
        for (module, start, scoped) in self.named {
            if super::model::is_node_builtin_module(&module)
                || imports.iter().any(|binding| binding.module == module)
            {
                continue;
            }
            let target = if scoped {
                gaps.push((
                    start,
                    true,
                    "a function loads a module its call does not run",
                ));
                &mut *scoped_imports
            } else {
                &mut *imports
            };
            if !target.iter().any(|binding| binding.module == module) {
                target.push(ImportBinding {
                    local: String::new(),
                    module,
                    imported: None,
                });
            }
        }
        for (start, scoped, detail) in gaps {
            let owner = scoped
                .then(|| {
                    functions
                        .iter_mut()
                        .filter(|function| {
                            function
                                .lexical_span
                                .is_some_and(|(body_start, end)| body_start <= start && start < end)
                        })
                        .min_by_key(|function| {
                            function
                                .lexical_span
                                .map(|(body_start, end)| end - body_start)
                        })
                })
                .flatten();
            let boundaries = match owner {
                Some(function) => &mut function.summary.boundaries,
                None => &mut *module_boundaries,
            };
            boundaries.push(Boundary {
                reason: BoundaryReason::UNRECOVERABLE_SOURCE,
                class: BoundaryClass::Unresolved,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: JS_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
                provenance: Vec::new(),
                limit: None,
                detail: Some(detail.to_string()),
            });
        }
    }
}

struct LoadSiteWalk<'l> {
    loads: &'l super::module_load::ModuleLoads,
    /// `import()` of a literal is already a scoped or module import.
    dynamic_imports: &'l resolve::DynamicImportFacts,
    sites: LoadSites,
    function_depth: u32,
    walk_depth: u32,
}

impl LoadSiteWalk<'_> {
    fn named(&mut self, specifier: &str, start: u32) {
        self.sites.named.push((
            resolve::canonical_module(specifier),
            start,
            self.function_depth > 0,
        ));
    }

    fn gap(&mut self, start: u32) {
        self.sites.gaps.push((start, self.function_depth > 0));
    }

    /// One loader call, as the effect walk reads it. A specifier rebased
    /// onto another file's directory is not a module this file names.
    fn call(&mut self, call: &CallExpression<'_>) {
        let key = (call.span.start, call.span.end);
        if let Some(source) = self.loads.call(key) {
            let specifier = match source {
                super::module_load::SpecifierSource::Known(specifier) => Some(specifier.clone()),
                super::module_load::SpecifierSource::Gap => None,
                super::module_load::SpecifierSource::Argument(_)
                | super::module_load::SpecifierSource::Apply(_) => {
                    self.loads.loaded_literals.get(&key).cloned()
                }
            };
            match specifier {
                Some(specifier)
                    if self.loads.rebase(key, Some(specifier.clone())).as_ref()
                        == Some(&specifier) =>
                {
                    self.named(&specifier, call.span.start)
                }
                _ => self.gap(call.span.start),
            }
        }
        match self.loads.escape(key) {
            Some(super::module_load::LoaderEscape::Follow(specifier)) => {
                let specifier = specifier.clone();
                self.named(&specifier, call.span.start);
            }
            Some(super::module_load::LoaderEscape::Gap) => self.gap(call.span.start),
            None => {}
        }
    }
}

impl<'a> Visit<'a> for LoadSiteWalk<'_> {
    fn enter_node(&mut self, kind: oxc_ast::AstKind<'a>) {
        let span = kind.span();
        if self.loads.stored_gap((span.start, span.end)) {
            self.gap(span.start);
        }
        match kind {
            oxc_ast::AstKind::CallExpression(call) => self.call(call),
            oxc_ast::AstKind::ImportExpression(import) => {
                if self.dynamic_imports.is_literal_import(import.span.start) {
                } else if let Some(specifier) = self.loads.resolved_specifier(&import.source) {
                    self.named(&specifier, import.span.start);
                } else {
                    self.gap(import.span.start);
                }
            }
            oxc_ast::AstKind::TSImportEqualsDeclaration(declaration) => {
                if let Some(specifier) = super::module_load::import_equals_specifier(declaration) {
                    self.named(specifier, declaration.span.start);
                }
            }
            oxc_ast::AstKind::Function(_) | oxc_ast::AstKind::ArrowFunctionExpression(_) => {
                self.function_depth += 1;
            }
            _ => {}
        }
    }

    fn leave_node(&mut self, kind: oxc_ast::AstKind<'a>) {
        if let oxc_ast::AstKind::Function(_) | oxc_ast::AstKind::ArrowFunctionExpression(_) = kind {
            self.function_depth -= 1;
        }
    }

    // A tree deeper than the walk may hold a load it never saw.
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.gap(it.span().start);
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        if self.walk_depth >= MAX_WALK_DEPTH {
            self.gap(it.span().start);
            return;
        }
        self.walk_depth += 1;
        walk::walk_statement(self, it);
        self.walk_depth -= 1;
    }
}
