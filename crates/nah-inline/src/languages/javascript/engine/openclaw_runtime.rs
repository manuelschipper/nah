//! OpenClaw tool API semantics.

use super::*;

pub(super) fn openclaw_member(property: &str) -> Option<OpenClawMember> {
    match property {
        "call" => Some(OpenClawMember::Call),
        "callValue" => Some(OpenClawMember::CallValue),
        _ => None,
    }
}

pub(super) fn summarize_openclaw_call(arguments: &Arguments) -> RuntimeCallSummary<()> {
    if !arguments.complete {
        return RuntimeCallSummary::Partial;
    }
    let valid_target = match arguments.values.first() {
        Some(Value::String(target)) => !target.trim().is_empty(),
        Some(value) if unknown_value(value) => true,
        _ => false,
    };
    if !valid_target {
        return RuntimeCallSummary::Invalid;
    }
    RuntimeCallSummary::Partial
}
