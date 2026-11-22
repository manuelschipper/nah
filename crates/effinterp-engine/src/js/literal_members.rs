//! Literal array and object members recovered across spreads.

use oxc_ast::ast::{ArrayExpressionElement, Expression};

use super::expression_values::unparen;

/// A computed property is known only when its key has a literal spelling.
pub(super) fn literal_property_name(expr: &Expression<'_>) -> Option<String> {
    match unparen(expr) {
        Expression::StringLiteral(value) => Some(value.value.as_str().to_string()),
        Expression::NumericLiteral(value) => Some(value.value.to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => Some(
            template
                .quasis
                .first()?
                .value
                .cooked
                .as_ref()?
                .as_str()
                .to_string(),
        ),
        _ => None,
    }
}

/// Resolve a literal array element when preceding spread lengths fix its index.
pub(super) fn array_element<'a, 'b>(
    expr: &'b Expression<'a>,
    wanted: usize,
) -> Option<&'b Expression<'a>> {
    match unparen(expr) {
        Expression::AwaitExpression(awaited) => array_element(&awaited.argument, wanted),
        Expression::ArrayExpression(array) => {
            let mut index = 0;
            for element in &array.elements {
                match element {
                    oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                        let len = array_literal_len(&spread.argument)?;
                        if wanted < index + len {
                            return array_element(&spread.argument, wanted - index);
                        }
                        index += len;
                    }
                    oxc_ast::ast::ArrayExpressionElement::Elision(_) => index += 1,
                    element => {
                        if index == wanted {
                            return element.as_expression();
                        }
                        index += 1;
                    }
                }
            }
            None
        }
        _ => None,
    }
}

pub(super) fn array_literal_len(expr: &Expression<'_>) -> Option<usize> {
    let Expression::ArrayExpression(array) = unparen(expr) else {
        return None;
    };
    let mut len = 0;
    for element in &array.elements {
        len += match element {
            oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                array_literal_len(&spread.argument)?
            }
            _ => 1,
        };
    }
    Some(len)
}

pub(super) enum ObjectPropertyProjection<'r, 'a> {
    Value(&'r Expression<'a>),
    Missing,
    Unbounded,
}

/// Project the last write to a property, widening at an unknown overriding key or spread.
pub(super) fn object_property_projection<'r, 'a>(
    expr: &'r Expression<'a>,
    wanted: &str,
) -> ObjectPropertyProjection<'r, 'a> {
    match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            object_property_projection(&awaited.argument, wanted)
        }
        Expression::ObjectExpression(object) => {
            for property in object.properties.iter().rev() {
                match property {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(property) => {
                        match property.key.static_name() {
                            Some(name) if name == wanted => {
                                return ObjectPropertyProjection::Value(&property.value);
                            }
                            Some(_) => {}
                            None => return ObjectPropertyProjection::Unbounded,
                        }
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                        match object_property_projection(&spread.argument, wanted) {
                            ObjectPropertyProjection::Missing => {}
                            projection => return projection,
                        }
                    }
                }
            }
            ObjectPropertyProjection::Missing
        }
        _ => ObjectPropertyProjection::Unbounded,
    }
}

pub(super) fn object_property<'a, 'b>(
    expr: &'b Expression<'a>,
    wanted: &str,
) -> Option<&'b Expression<'a>> {
    match object_property_projection(expr, wanted) {
        ObjectPropertyProjection::Value(value) => Some(value),
        ObjectPropertyProjection::Missing | ObjectPropertyProjection::Unbounded => None,
    }
}

/// An unknown spread widens the later positions while preserving their minimum index.
pub(super) fn array_elements_at_position_match<'a>(
    expr: &Expression<'a>,
    wanted: usize,
    syntax_index: usize,
    min_index: &mut usize,
    max_index: &mut Option<usize>,
    predicate: &mut impl FnMut(usize, &Expression<'a>) -> bool,
) -> bool {
    let array = match unparen(expr) {
        Expression::AwaitExpression(awaited) => {
            return array_elements_at_position_match(
                &awaited.argument,
                wanted,
                syntax_index,
                min_index,
                max_index,
                predicate,
            );
        }
        Expression::ArrayExpression(array) => array,
        _ => {
            *max_index = None;
            return false;
        }
    };
    for element in &array.elements {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                if array_elements_at_position_match(
                    &spread.argument,
                    wanted,
                    syntax_index,
                    min_index,
                    max_index,
                    predicate,
                ) {
                    return true;
                }
            }
            ArrayExpressionElement::Elision(_) => {
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
            element => {
                if position_can_match(wanted, *min_index, *max_index)
                    && element
                        .as_expression()
                        .is_some_and(|expr| predicate(syntax_index, expr))
                {
                    return true;
                }
                *min_index += 1;
                *max_index = max_index.map(|index| index + 1);
            }
        }
    }
    false
}

pub(super) fn position_can_match(
    wanted: usize,
    min_index: usize,
    max_index: Option<usize>,
) -> bool {
    min_index <= wanted && max_index.is_none_or(|max_index| wanted <= max_index)
}
