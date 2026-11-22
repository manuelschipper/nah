//! Expression wrappers erased by JavaScript or TypeScript and literal branch tests.

use oxc_ast::ast::Expression;

/// The truth of an `if` test that is a literal, whose other arm never runs.
pub(super) fn literal_truth(test: &Expression<'_>) -> Option<bool> {
    match unparen(test) {
        Expression::BooleanLiteral(literal) => Some(literal.value),
        Expression::NullLiteral(_) => Some(false),
        Expression::NumericLiteral(literal) => {
            Some(literal.value != 0.0 && !literal.value.is_nan())
        }
        _ => None,
    }
}

/// Unwrap parentheses and erased TypeScript syntax to reach the runtime expression.
pub(super) fn unparen<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(p) => unparen(&p.expression),
        Expression::TSAsExpression(e) => unparen(&e.expression),
        Expression::TSSatisfiesExpression(e) => unparen(&e.expression),
        Expression::TSTypeAssertion(e) => unparen(&e.expression),
        Expression::TSNonNullExpression(e) => unparen(&e.expression),
        Expression::TSInstantiationExpression(e) => unparen(&e.expression),
        other => other,
    }
}

/// A comma expression exposes only its last value as the callee.
pub(super) fn sequence_callee_value<'a, 'b>(expr: &'b Expression<'a>) -> &'b Expression<'a> {
    let expr = unparen(expr);
    match expr {
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .last()
            .map(sequence_callee_value)
            .unwrap_or(expr),
        _ => expr,
    }
}
