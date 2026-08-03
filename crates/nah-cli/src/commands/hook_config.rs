//! Shared mutation of the PreToolUse group inside runtime hook JSON.

use serde_json::{Map, Value, json};

use crate::runtime::FailurePolicy;

use super::RuntimeHookStatus;

pub(super) fn inspect(
    config: &Value,
    desired: &Value,
    is_owned: fn(&Value) -> bool,
    invalid: &'static str,
) -> Result<RuntimeHookStatus, String> {
    let count = matching_handler_count(config, is_owned, invalid)?;
    Ok(if count == 0 {
        RuntimeHookStatus::NotConfigured
    } else if count == 1 && has_global_hook(config, desired) {
        RuntimeHookStatus::WiringCurrent
    } else {
        RuntimeHookStatus::NeedsReinstall
    })
}

pub(super) fn inspect_modes(
    config: &Value,
    delegate: &Value,
    fail_closed: &Value,
    is_owned: fn(&Value) -> bool,
    is_fail_closed: fn(&Value) -> bool,
    invalid: &'static str,
) -> Result<RuntimeHookStatus, String> {
    let count = matching_handler_count(config, is_owned, invalid)?;
    if count == 0 {
        return Ok(RuntimeHookStatus::NotConfigured);
    }
    if count == 1 && has_global_hook(config, delegate) {
        return Ok(RuntimeHookStatus::WiringCurrent);
    }
    if count == 1 && has_global_hook(config, fail_closed) {
        return Ok(RuntimeHookStatus::WiringCurrentFailClosed);
    }
    let mut owned = config["hooks"]["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter(|handler| is_owned(handler));
    let strict = owned.next().is_some_and(is_fail_closed) && owned.all(is_fail_closed);
    Ok(RuntimeHookStatus::stale(if strict {
        FailurePolicy::Block
    } else {
        FailurePolicy::Delegate
    }))
}

pub(super) fn add(
    config: &mut Value,
    desired: Value,
    is_owned: fn(&Value) -> bool,
    invalid: &'static str,
) -> Result<bool, String> {
    if matching_handler_count(config, is_owned, invalid)? == 1 && has_global_hook(config, &desired)
    {
        return Ok(false);
    }
    remove(config, is_owned, invalid)?;
    pre_tool_hooks(config, invalid)?.push(json!({
        "matcher": "*",
        "hooks": [desired]
    }));
    Ok(true)
}

pub(super) fn remove(
    config: &mut Value,
    is_owned: fn(&Value) -> bool,
    invalid: &'static str,
) -> Result<bool, String> {
    let root = config.as_object_mut().ok_or_else(|| invalid.to_owned())?;
    let Some(hooks_value) = root.get_mut("hooks") else {
        return Ok(false);
    };
    let hooks = hooks_value
        .as_object_mut()
        .ok_or_else(|| invalid.to_owned())?;
    let Some(groups_value) = hooks.get_mut("PreToolUse") else {
        return Ok(false);
    };
    let groups = groups_value
        .as_array_mut()
        .ok_or_else(|| invalid.to_owned())?;
    for group in groups.iter() {
        if group
            .as_object()
            .and_then(|group| group.get("hooks"))
            .is_some_and(|handlers| !handlers.is_array())
        {
            return Err(invalid.into());
        }
    }
    let mut changed = false;
    groups.retain_mut(|group| {
        let Some(handlers) = group
            .as_object_mut()
            .and_then(|group| group.get_mut("hooks"))
            .and_then(Value::as_array_mut)
        else {
            return true;
        };
        let before = handlers.len();
        handlers.retain(|handler| !is_owned(handler));
        let removed = handlers.len() != before;
        changed |= removed;
        !removed || !handlers.is_empty()
    });
    if changed && groups.is_empty() {
        hooks.remove("PreToolUse");
    }
    if changed && hooks.is_empty() {
        root.remove("hooks");
    }
    Ok(changed)
}

fn matching_handler_count(
    config: &Value,
    is_owned: fn(&Value) -> bool,
    invalid: &'static str,
) -> Result<usize, String> {
    let Some(hooks_value) = config.get("hooks") else {
        return Ok(0);
    };
    let hooks = hooks_value.as_object().ok_or_else(|| invalid.to_owned())?;
    let Some(groups_value) = hooks.get("PreToolUse") else {
        return Ok(0);
    };
    let groups = groups_value.as_array().ok_or_else(|| invalid.to_owned())?;
    let mut count = 0;
    for group in groups {
        let Some(handlers_value) = group.as_object().and_then(|group| group.get("hooks")) else {
            continue;
        };
        let handlers = handlers_value
            .as_array()
            .ok_or_else(|| invalid.to_owned())?;
        count += handlers.iter().filter(|handler| is_owned(handler)).count();
    }
    Ok(count)
}

fn has_global_hook(config: &Value, desired: &Value) -> bool {
    config["hooks"]["PreToolUse"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|group| group["matcher"].as_str() == Some("*"))
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .any(|handler| handler == desired)
}

fn pre_tool_hooks<'a>(
    config: &'a mut Value,
    invalid: &'static str,
) -> Result<&'a mut Vec<Value>, String> {
    let root = config.as_object_mut().ok_or_else(|| invalid.to_owned())?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| invalid.to_owned())?;
    hooks
        .entry("PreToolUse")
        .or_insert_with(|| Value::Array(vec![]))
        .as_array_mut()
        .ok_or_else(|| invalid.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(handler: &Value) -> bool {
        handler.get("owned").and_then(Value::as_bool) == Some(true)
    }

    fn fail_closed(handler: &Value) -> bool {
        handler.get("strict").and_then(Value::as_bool) == Some(true)
    }

    #[test]
    fn inspection_distinguishes_absent_current_and_stale_wiring() {
        let desired = json!({"owned":true,"command":"nah"});
        assert_eq!(
            inspect(&json!({}), &desired, owned, "invalid").unwrap(),
            RuntimeHookStatus::NotConfigured
        );
        assert_eq!(
            inspect(
                &json!({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[desired.clone()]}]}}),
                &desired,
                owned,
                "invalid"
            )
            .unwrap(),
            RuntimeHookStatus::WiringCurrent
        );
        assert_eq!(
            inspect(
                &json!({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"owned":true,"command":"old"}]}]}}),
                &desired,
                owned,
                "invalid"
            )
            .unwrap(),
            RuntimeHookStatus::NeedsReinstall
        );
    }

    #[test]
    fn mixed_stale_modes_default_to_delegate() {
        let delegate = json!({"owned":true,"strict":false});
        let strict = json!({"owned":true,"strict":true});
        let config = json!({"hooks":{"PreToolUse":[{
            "matcher":"*",
            "hooks":[delegate.clone(),strict.clone()]
        }]}});
        assert_eq!(
            inspect_modes(&config, &delegate, &strict, owned, fail_closed, "invalid").unwrap(),
            RuntimeHookStatus::NeedsReinstall
        );
    }
}
