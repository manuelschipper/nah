//! Encodes bounded native evidence for interpreted JavaScript calls.

use super::*;

pub(super) fn language_call_input(
    syntax: SyntaxProfile,
    callable: &str,
    arguments: &Arguments,
) -> InvocationInput {
    let mut complete = arguments.complete;
    let represented = arguments.values.len();
    let mut positional = Vec::with_capacity(represented.min(MAX_NATIVE_ARGUMENTS));
    for value in arguments.values.iter().take(MAX_NATIVE_ARGUMENTS) {
        let (value, exact) = native_value(value, 0);
        complete &= exact;
        positional.push(value);
    }
    if represented > MAX_NATIVE_ARGUMENTS {
        complete = false;
        if let Some(value) = positional.last_mut() {
            *value = native_unknown();
        }
    }
    let mut payload = language_call_payload(syntax, callable, positional);
    if serde_json::to_vec(&payload).map_or(true, |bytes| bytes.len() > MAX_NATIVE_EVIDENCE_BYTES) {
        complete = false;
        payload = language_call_payload(syntax, callable, vec![native_unknown()]);
    }
    InvocationInput::native(payload, complete)
}

pub(super) fn language_call_payload(
    syntax: SyntaxProfile,
    callable: &str,
    positional: Vec<JsonValue>,
) -> JsonValue {
    let language = match syntax {
        SyntaxProfile::JavaScript => "javascript",
        SyntaxProfile::TypeScript => "typescript",
        SyntaxProfile::Tsx => "tsx",
        SyntaxProfile::Ambiguous => unreachable!(),
    };
    let mut payload = Map::new();
    // JavaScript v2 adds object and undefined values without changing frozen v1.
    payload.insert("v".into(), JsonValue::from(2));
    payload.insert("language".into(), JsonValue::String(language.into()));
    payload.insert("callable".into(), JsonValue::String(callable.into()));
    payload.insert("positional".into(), JsonValue::Array(positional));
    payload.insert("keywords".into(), JsonValue::Array(Vec::new()));
    JsonValue::Object(payload)
}

pub(super) fn native_value(value: &Value, depth: usize) -> (JsonValue, bool) {
    if depth >= 16 {
        return (native_unknown(), false);
    }
    match value {
        Value::Undefined => (native_tag("undefined", None), true),
        Value::Null => (native_tag("null", None), true),
        Value::Bool(value) => (native_tag("bool", Some(JsonValue::Bool(*value))), true),
        Value::Number(value) => (native_tag("int", Some(JsonValue::from(*value))), true),
        Value::String(value) => bounded_native_string(value),
        Value::Array(values) if values.len() <= MAX_NATIVE_COLLECTION_ITEMS => {
            let mut exact = true;
            let items = values
                .iter()
                .map(|value| {
                    let (value, item_exact) = native_value(value, depth + 1);
                    exact &= item_exact;
                    value
                })
                .collect();
            (native_sequence(items), exact)
        }
        Value::Object(properties) if properties.len() <= MAX_NATIVE_COLLECTION_ITEMS => {
            let mut exact = true;
            let properties = properties
                .iter()
                .map(|(name, value)| {
                    let (value, property_exact) = native_value(value, depth + 1);
                    exact &= property_exact;
                    let mut property = Map::new();
                    property.insert("name".into(), JsonValue::String(name.clone()));
                    property.insert("value".into(), value);
                    JsonValue::Object(property)
                })
                .collect();
            (native_object(properties), exact)
        }
        Value::Invalid
        | Value::NonCallablePrimitive
        | Value::SynchronousThrow
        | Value::Divergent
        | Value::Promise
        | Value::RejectedPromise
        | Value::Unknown
        | Value::Array(_)
        | Value::Object(_)
        | Value::Module(_)
        | Value::Known(_)
        | Value::Function(_)
        | Value::Accessor
        | Value::AccessorGetter(_)
        | Value::Require
        | Value::Eval
        | Value::DynamicEvalResult
        | Value::FunctionConstructor
        | Value::DynamicFunction(_)
        | Value::ObjectBuiltin
        | Value::Process
        | Value::Environment
        | Value::CommonJsModule
        | Value::InheritedNodeProperty(_)
        | Value::NodeModule
        | Value::LoadedModule(_)
        | Value::NodeModulePrototype
        | Value::NodeModuleMember(_)
        | Value::Deno
        | Value::DenoCommandConstructor
        | Value::DenoCommand(_)
        | Value::Bun
        | Value::BunFile(_)
        | Value::OpenClawTools
        | Value::UnknownModuleMember(_)
        | Value::UnknownReceiver(_) => (native_unknown(), false),
    }
}

pub(super) fn bounded_native_string(value: &str) -> (JsonValue, bool) {
    if value.len() > MAX_NATIVE_EVIDENCE_BYTES {
        (native_unknown(), false)
    } else {
        (
            native_tag("string", Some(JsonValue::String(value.to_owned()))),
            true,
        )
    }
}

pub(super) fn native_unknown() -> JsonValue {
    native_tag("unknown", None)
}

pub(super) fn native_sequence(items: Vec<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String("sequence".into()));
    tagged.insert("items".into(), JsonValue::Array(items));
    JsonValue::Object(tagged)
}

pub(super) fn native_object(properties: Vec<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String("object".into()));
    tagged.insert("properties".into(), JsonValue::Array(properties));
    JsonValue::Object(tagged)
}

pub(super) fn native_tag(kind: &str, value: Option<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String(kind.into()));
    if let Some(value) = value {
        tagged.insert("value".into(), value);
    }
    JsonValue::Object(tagged)
}
