//! Shared value and execution semantics for runtime-specific APIs.

use super::*;

pub(super) fn known_object_like(value: &Value) -> bool {
    matches!(
        value,
        Value::Module(_)
            | Value::Known(_)
            | Value::Function(_)
            | Value::Require
            | Value::Eval
            | Value::FunctionConstructor
            | Value::DynamicFunction(_)
            | Value::ObjectBuiltin
            | Value::Process
            | Value::Environment
            | Value::Deno
            | Value::DenoCommandConstructor
            | Value::DenoCommand(_)
            | Value::Bun
            | Value::BunFile(_)
            | Value::OpenClawTools
            | Value::Promise
            | Value::RejectedPromise
    )
}

pub(super) fn merge_execution(
    left: ExecutionCertainty,
    right: ExecutionCertainty,
) -> ExecutionCertainty {
    match (left, right) {
        (ExecutionCertainty::Invalid, _) | (_, ExecutionCertainty::Invalid) => {
            ExecutionCertainty::Invalid
        }
        (ExecutionCertainty::Unknown, _) | (_, ExecutionCertainty::Unknown) => {
            ExecutionCertainty::Unknown
        }
        (ExecutionCertainty::Known, ExecutionCertainty::Known) => ExecutionCertainty::Known,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ShapeValue {
    Exact,
    Partial,
    Invalid,
}

pub(super) fn valid_u32(value: i64) -> bool {
    (0..=i64::from(u32::MAX)).contains(&value)
}
