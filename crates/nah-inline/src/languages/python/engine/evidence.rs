//! Encodes bounded native evidence for interpreted Python calls.

use super::*;

pub(super) fn language_call_input(
    callable: &str,
    arguments: &Arguments,
    state: &State,
) -> InvocationInput {
    let mut complete = arguments.complete;
    let mut positional = Vec::new();
    let mut keywords = Vec::new();
    let represented = arguments.positional.len() + arguments.keywords.len();
    let limit = represented.min(MAX_NATIVE_ARGUMENTS);
    let positional_limit = arguments.positional.len().min(limit);
    for value in arguments.positional.iter().take(positional_limit) {
        let (value, exact) = native_value(value, state, &mut BTreeSet::new());
        complete &= exact;
        positional.push(value);
    }
    for (name, value) in arguments
        .keywords
        .iter()
        .take(limit.saturating_sub(positional_limit))
    {
        let (value, exact) = native_value(value, state, &mut BTreeSet::new());
        complete &= exact;
        let mut keyword = Map::new();
        keyword.insert("name".into(), JsonValue::String(name.clone()));
        keyword.insert("value".into(), value);
        keywords.push(JsonValue::Object(keyword));
    }
    if represented > MAX_NATIVE_ARGUMENTS {
        complete = false;
        if let Some(value) = keywords.last_mut() {
            if let Some(value) = value.get_mut("value") {
                *value = native_unknown();
            }
        } else if let Some(value) = positional.last_mut() {
            *value = native_unknown();
        }
    }
    let mut payload = language_call_payload(callable, positional, keywords);
    if serde_json::to_vec(&payload).map_or(true, |bytes| bytes.len() > MAX_NATIVE_EVIDENCE_BYTES) {
        complete = false;
        payload = language_call_payload(callable, vec![native_unknown()], Vec::new());
    }
    InvocationInput::native(payload, complete)
}

pub(super) fn language_call_payload(
    callable: &str,
    positional: Vec<JsonValue>,
    keywords: Vec<JsonValue>,
) -> JsonValue {
    let mut payload = Map::new();
    payload.insert("v".into(), JsonValue::from(1));
    payload.insert("language".into(), JsonValue::String("python".into()));
    payload.insert("callable".into(), JsonValue::String(callable.into()));
    payload.insert("positional".into(), JsonValue::Array(positional));
    payload.insert("keywords".into(), JsonValue::Array(keywords));
    JsonValue::Object(payload)
}

pub(super) fn native_value(
    value: &Value,
    state: &State,
    visiting: &mut BTreeSet<usize>,
) -> (JsonValue, bool) {
    match value {
        Value::None => (native_tag("null", None), true),
        Value::Bool(value) => (native_tag("bool", Some(JsonValue::Bool(*value))), true),
        Value::Int(value) => (native_tag("int", Some(JsonValue::from(*value))), true),
        Value::String(value) | Value::ImplicitString(value) => {
            bounded_native_string("string", value)
        }
        Value::Bytes(value) => {
            if value.len() > MAX_NATIVE_EVIDENCE_BYTES {
                return (native_unknown(), false);
            }
            (
                native_tag("bytes", Some(JsonValue::String(lower_hex(value)))),
                true,
            )
        }
        Value::Path(value) => bounded_native_string("path", value),
        Value::Cell(cell) => {
            let Some(Cell::Sequence { values, .. }) = state.cells.get(*cell) else {
                return (native_unknown(), false);
            };
            if values.len() > MAX_NATIVE_COLLECTION_ITEMS || !visiting.insert(*cell) {
                return (native_unknown(), false);
            }
            let mut exact = true;
            let items = values
                .iter()
                .map(|value| {
                    let (value, item_exact) = native_value(value, state, visiting);
                    exact &= item_exact;
                    value
                })
                .collect();
            visiting.remove(cell);
            (native_sequence(items), exact)
        }
        Value::Decoded(value) => native_value(value, state, visiting),
        Value::Unknown
        | Value::EmptyDictionary
        | Value::ImportRegistry
        | Value::ImportRegistryMutator(_)
        | Value::ImportRegistryRead(_)
        | Value::Module(_)
        | Value::Known(_)
        | Value::LocalFunction(_)
        | Value::PathMethod { .. }
        | Value::CellMethod { .. }
        | Value::StringMethod { .. }
        | Value::BytesMethod { .. }
        | Value::DecodedMethod { .. }
        | Value::ModuleMethod(_)
        | Value::Compiled { .. }
        | Value::Produced(_) => (native_unknown(), false),
    }
}

pub(super) fn bounded_native_string(kind: &str, value: &str) -> (JsonValue, bool) {
    if value.len() > MAX_NATIVE_EVIDENCE_BYTES {
        (native_unknown(), false)
    } else {
        (
            native_tag(kind, Some(JsonValue::String(value.to_owned()))),
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

pub(super) fn native_tag(kind: &str, value: Option<JsonValue>) -> JsonValue {
    let mut tagged = Map::new();
    tagged.insert("kind".into(), JsonValue::String(kind.into()));
    if let Some(value) = value {
        tagged.insert("value".into(), value);
    }
    JsonValue::Object(tagged)
}

pub(super) fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
