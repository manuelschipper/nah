//! Module-scope execution used to discover scripts and list their runtime imports.

use effinterp_proto::SourceDialect;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    CallExpression, ClassBody, Expression, FormalParameters, FunctionBody, NewExpression,
    Statement, TaggedTemplateExpression,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;

use super::{MAX_WALK_DEPTH, module_load};

/// Whether the module runs a call while it loads: a top-level expression
/// statement (or `export default <expression>`) that evaluates a call outside
/// any function body. Discovery uses this parser-owned answer to recognize
/// scripts whose only module-scope work is a call the semantic summaries omit,
/// such as `console.log('loaded')` or a bootstrap IIFE. Declarations and calls
/// that only appear inside an uncalled body are not module-scope execution.
/// Returns None when a parse error prevents reliable root classification.
pub fn js_runs_module_scope_call(source: &str) -> Option<bool> {
    if crate::lang::depth::js_nesting_exceeds(source) {
        return None;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    if !parsed.errors.is_empty() {
        return None;
    }
    Some(parsed.program.body.iter().any(|statement| {
        let expression = match statement {
            Statement::ExpressionStatement(statement) => &statement.expression,
            Statement::ExportDefaultDeclaration(export) => {
                match export.declaration.as_expression() {
                    Some(expression) => expression,
                    None => return false,
                }
            }
            _ => return false,
        };
        let mut calls = ModuleScopeCalls::default();
        calls.visit_expression(expression);
        calls.found
    }))
}

/// Finds a call evaluated by the expression it visits, without entering the
/// function bodies, parameter defaults, or class bodies that only run later.
#[derive(Default)]
struct ModuleScopeCalls {
    pub(super) found: bool,
    pub(super) walk_depth: u32,
}

impl<'a> Visit<'a> for ModuleScopeCalls {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if self.found || self.walk_depth >= MAX_WALK_DEPTH {
            return;
        }
        self.walk_depth += 1;
        walk::walk_expression(self, it);
        self.walk_depth -= 1;
    }

    fn visit_call_expression(&mut self, _it: &CallExpression<'a>) {
        self.found = true;
    }

    fn visit_new_expression(&mut self, _it: &NewExpression<'a>) {
        self.found = true;
    }

    fn visit_tagged_template_expression(&mut self, _it: &TaggedTemplateExpression<'a>) {
        self.found = true;
    }

    fn visit_function_body(&mut self, _it: &FunctionBody<'a>) {}

    fn visit_formal_parameters(&mut self, _it: &FormalParameters<'a>) {}

    fn visit_class_body(&mut self, _it: &ClassBody<'a>) {}
}

/// Literal static imports executed while one JavaScript module initializes.
pub(crate) fn runtime_imports(source: &str, dialect: SourceDialect) -> Option<Vec<String>> {
    if crate::lang::depth::js_nesting_exceeds(source) {
        return None;
    }
    let allocator = Allocator::default();
    let source_type = match dialect {
        SourceDialect::Js => SourceType::mjs(),
        SourceDialect::Ts => SourceType::ts(),
        SourceDialect::Ipython => {
            unreachable!("validated JavaScript dialect")
        }
    };
    let parsed = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty().then(|| {
        parsed
            .program
            .body
            .iter()
            .filter_map(|statement| match statement {
                Statement::ImportDeclaration(import) if !import.import_kind.is_type() => {
                    Some(module_load::static_import(import).to_string())
                }
                _ => None,
            })
            .collect()
    })
}
