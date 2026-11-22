//! Logical call argument positions across literal and unknown spreads.

use std::collections::HashSet;

use oxc_ast::ast::{Argument, ArrayExpressionElement, Expression};

use super::binding_paths::expression_flow_key;
use super::expression_values::unparen;
use super::literal_members::{
    array_element, array_elements_at_position_match, array_literal_len, position_can_match,
};

/// The expression carried by a non-spread argument.
pub(super) fn argument_expr<'a, 'b>(arg: &'b Argument<'a>) -> Option<&'b Expression<'a>> {
    arg.as_expression()
}

/// Resolve a call's logical argument position across statically sized array spreads.
/// The syntax index selects the source-string state captured after that argument.
pub(super) fn logical_call_argument<'a, 'b>(
    arguments: &'b [Argument<'a>],
    wanted: usize,
) -> Option<(Option<&'b Expression<'a>>, usize)> {
    let mut logical_index = 0;
    for (syntax_index, argument) in arguments.iter().enumerate() {
        match argument {
            Argument::SpreadElement(spread) => {
                let Some(len) = array_literal_len(&spread.argument) else {
                    return (logical_index <= wanted).then_some((None, syntax_index));
                };
                if wanted < logical_index + len {
                    return Some((
                        array_element(&spread.argument, wanted - logical_index),
                        syntax_index,
                    ));
                }
                logical_index += len;
            }
            _ => {
                if logical_index == wanted {
                    return Some((argument_expr(argument), syntax_index));
                }
                logical_index += 1;
            }
        }
    }
    None
}

pub(super) fn logical_call_argument_bindings(
    arguments: &[Argument<'_>],
    wanted: usize,
) -> HashSet<String> {
    let mut bindings = HashSet::new();
    let mut min_index = 0;
    let mut max_index = Some(0);
    for argument in arguments {
        match argument {
            Argument::SpreadElement(spread) => {
                collect_array_element_bindings_at_position(
                    &spread.argument,
                    wanted,
                    &mut min_index,
                    &mut max_index,
                    &mut bindings,
                );
            }
            _ => {
                if position_can_match(wanted, min_index, max_index)
                    && let Some(name) = argument_expr(argument).and_then(expression_flow_key)
                {
                    bindings.insert(name);
                }
                min_index += 1;
                max_index = max_index.map(|index| index + 1);
            }
        }
    }
    bindings
}

fn collect_array_element_bindings_at_position(
    expr: &Expression<'_>,
    wanted: usize,
    min_index: &mut usize,
    max_index: &mut Option<usize>,
    bindings: &mut HashSet<String>,
) {
    let array = match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            collect_array_element_bindings_at_position(
                &awaited.argument,
                wanted,
                min_index,
                max_index,
                bindings,
            );
            return;
        }
        Expression::ArrayExpression(array) => array,
        _ => {
            if *min_index <= wanted
                && let Some(name) = expression_flow_key(expr)
            {
                let max_start = max_index.unwrap_or(wanted).min(wanted);
                for start in *min_index..=max_start {
                    bindings.insert(format!("{name}.{}", wanted - start));
                }
            }
            *max_index = None;
            return;
        }
    };
    for element in &array.elements {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                collect_array_element_bindings_at_position(
                    &spread.argument,
                    wanted,
                    min_index,
                    max_index,
                    bindings,
                );
            }
            ArrayExpressionElement::Elision(_) => {
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
            element => {
                if position_can_match(wanted, *min_index, *max_index)
                    && let Some(name) = element.as_expression().and_then(expression_flow_key)
                {
                    bindings.insert(name);
                }
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
        }
    }
}

pub(super) fn logical_call_argument_count(arguments: &[Argument<'_>]) -> Option<usize> {
    arguments.iter().try_fold(0, |count, argument| {
        Some(match argument {
            Argument::SpreadElement(spread) => count + array_literal_len(&spread.argument)?,
            _ => count + 1,
        })
    })
}

pub(super) fn logical_call_argument_at_matches<'a>(
    arguments: &[Argument<'a>],
    wanted: usize,
    mut predicate: impl FnMut(usize, &Expression<'a>) -> bool,
) -> bool {
    let mut min_index = 0;
    let mut max_index = Some(0);
    for (syntax_index, argument) in arguments.iter().enumerate() {
        match argument {
            Argument::SpreadElement(spread) => {
                if array_elements_at_position_match(
                    &spread.argument,
                    wanted,
                    syntax_index,
                    &mut min_index,
                    &mut max_index,
                    &mut predicate,
                ) {
                    return true;
                }
            }
            _ => {
                if position_can_match(wanted, min_index, max_index)
                    && argument_expr(argument).is_some_and(|expr| predicate(syntax_index, expr))
                {
                    return true;
                }
                min_index += 1;
                max_index = max_index.map(|index| index + 1);
            }
        }
    }
    false
}
