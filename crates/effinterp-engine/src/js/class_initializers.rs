//! Class instance initializers, conditional on whether the class may be instantiated.

use std::collections::HashSet;

use oxc_ast::ast::{ClassElement, Expression};
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

use super::walker::JsWalker;

/// Span starts of class declarations that nothing can instantiate: ambient
/// declarations, and unexported, undecorated ones whose name no value
/// expression references, even from inside the class, and whose static
/// initializers never use `this`, which is the class there (`new this()`).
/// A reference only as a TypeScript type constructs nothing. Any other class
/// may be instantiated.
pub(super) fn uninstantiated_class_spans(semantic: &oxc_semantic::Semantic<'_>) -> HashSet<u32> {
    /// Whether code that runs with the class as `this` uses it. A nested
    /// non-arrow function binds its own `this`.
    #[derive(Default)]
    struct UsesThis(bool);
    impl<'a> Visit<'a> for UsesThis {
        fn visit_this_expression(&mut self, _it: &oxc_ast::ast::ThisExpression) {
            self.0 = true;
        }
        fn visit_function(
            &mut self,
            _it: &oxc_ast::ast::Function<'a>,
            _flags: oxc_semantic::ScopeFlags,
        ) {
        }
    }
    let nodes = semantic.nodes();
    let scoping = semantic.scoping();
    nodes
        .iter()
        .filter_map(|node| {
            let oxc_ast::AstKind::Class(class) = node.kind() else {
                return None;
            };
            if class.declare {
                return Some(class.span.start);
            }
            let id = class.id.as_ref().filter(|_| class.is_declaration())?;
            if matches!(
                nodes.parent_kind(node.id()),
                oxc_ast::AstKind::ExportNamedDeclaration(_)
                    | oxc_ast::AstKind::ExportDefaultDeclaration(_)
            ) || !class.decorators.is_empty()
            {
                return None;
            }
            let mut uses_this = UsesThis::default();
            for element in &class.body.body {
                match element {
                    ClassElement::StaticBlock(block) => uses_this.visit_static_block(block),
                    ClassElement::PropertyDefinition(property) if property.r#static => {
                        if let Some(value) = &property.value {
                            uses_this.visit_expression(value);
                        }
                    }
                    ClassElement::AccessorProperty(property) if property.r#static => {
                        if let Some(value) = &property.value {
                            uses_this.visit_expression(value);
                        }
                    }
                    _ => {}
                }
                let decorated = match element {
                    ClassElement::MethodDefinition(method) => !method.decorators.is_empty(),
                    ClassElement::PropertyDefinition(property) => !property.decorators.is_empty(),
                    ClassElement::AccessorProperty(property) => !property.decorators.is_empty(),
                    _ => false,
                };
                if decorated {
                    return None;
                }
            }
            if uses_this.0 {
                return None;
            }
            scoping
                .get_resolved_reference_ids(id.symbol_id())
                .iter()
                .all(|reference| !scoping.get_reference(*reference).is_value())
                .then_some(class.span.start)
        })
        .collect()
}

impl<'a> JsWalker<'_, 'a> {
    /// An instance field initializer runs each time its class is
    /// instantiated, which may or may not happen, so it is walked where the
    /// class is defined under a dispatch condition. As with a branch that may
    /// be skipped, the state after it joins the state before it.
    pub(super) fn instance_field_initializer(&mut self, value: &Expression<'a>) {
        let flow_entry = self.flow_entry();
        let entry = self.source_string_state();
        self.push_callback_condition(value.span(), effinterp_proto::ConditionKind::Dispatch, None);
        self.visit_expression(value);
        self.builder.pop_condition();
        let exit = self.source_string_state();
        self.join_source_string_states(exit, entry, value.span());
        self.flow_join(flow_entry);
    }
}
