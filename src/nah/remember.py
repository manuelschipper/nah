"""Config writer — CLI commands delegate here to modify config YAML files."""

import os

from nah import taxonomy
from nah.config import get_global_config_path, get_project_config_path
from nah.paths import get_project_root


class CustomTypeError(ValueError):
    """Unknown action type with no close matches — likely intentional custom type."""
    pass


def _ensure_yaml():
    """Raise RuntimeError if PyYAML is not available."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        raise RuntimeError("PyYAML required. Install with: pip install nah[config]")


def _read_config(path: str) -> dict:
    """Read YAML config file. Returns {} if missing."""
    if not os.path.isfile(path):
        return {}
    import yaml
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def _write_config(path: str, data: dict) -> None:
    """Write YAML config file. Creates parent dirs if needed."""
    import yaml
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def has_comments(path: str) -> bool:
    """Check if YAML file contains comment lines."""
    if not os.path.isfile(path):
        return False
    with open(path) as f:
        for line in f:
            stripped = line.lstrip()
            if stripped.startswith("#") and not stripped.startswith("#!"):
                return True
    return False


def _get_config_path(project: bool) -> str:
    """Get the appropriate config path."""
    if project:
        path = get_project_config_path()
        if not path:
            raise ValueError("Not in a git repository — cannot use --project")
        return path
    return get_global_config_path()


def _validate_action_scope(action_type: str, policy: str, project: bool) -> None:
    """Check that a project config doesn't loosen policy relative to global + defaults."""
    if not project:
        return
    # Read global config to find the effective policy
    global_path = get_global_config_path()
    global_data = _read_config(global_path)
    global_actions = global_data.get("actions", {})
    if isinstance(global_actions, dict) and action_type in global_actions:
        effective = global_actions[action_type]
    else:
        effective = taxonomy._POLICIES.get(action_type, taxonomy.ASK)
    # Project policy must be at least as strict
    if taxonomy.STRICTNESS.get(policy, 2) < taxonomy.STRICTNESS.get(effective, 2):
        raise ValueError(
            f"Project config cannot loosen '{action_type}' from {effective} to {policy}. "
            f"Use global config to allow, or set a stricter policy."
        )


def write_action(action_type: str, policy: str, project: bool = False,
                  allow_custom: bool = False) -> str:
    """Write an action policy to config. Returns confirmation message."""
    _ensure_yaml()
    if not allow_custom:
        valid, close = taxonomy.validate_action_type(action_type)
        if not valid:
            if close:
                raise ValueError(
                    f"Unknown action type: {action_type}. Did you mean: {', '.join(close)}?"
                )
            raise CustomTypeError(action_type)
    _validate_action_scope(action_type, policy, project)
    path = _get_config_path(project)
    data = _read_config(path)
    actions = data.setdefault("actions", {})
    old = actions.get(action_type)
    actions[action_type] = policy
    _write_config(path, data)
    if old and old == policy:
        return f"{action_type}: already set to {policy}"
    scope = "project" if project else "global"
    return f"{action_type}: {policy} ({scope})"


def write_allow_path(raw_path: str) -> str:
    """Write an allow_paths entry to global config. Returns confirmation message."""
    _ensure_yaml()
    from nah.paths import resolve_path
    resolved = resolve_path(raw_path)
    project_root = get_project_root()
    if not project_root:
        raise ValueError("Not in a git repository — cannot determine project root for allow_paths")
    path = get_global_config_path()
    data = _read_config(path)
    allow_paths = data.setdefault("allow_paths", {})
    roots = allow_paths.setdefault(resolved, [])
    if project_root in roots:
        return f"Already allowed: {raw_path} for {project_root}"
    roots.append(project_root)
    _write_config(path, data)
    return f"Allowed: {raw_path} → {project_root}"


def write_classify(command: str, action_type: str, project: bool = False,
                    allow_custom: bool = False) -> str:
    """Write a classify entry. Returns confirmation message."""
    _ensure_yaml()
    if not allow_custom:
        valid, close = taxonomy.validate_action_type(action_type)
        if not valid:
            if close:
                raise ValueError(
                    f"Unknown action type: {action_type}. Did you mean: {', '.join(close)}?"
                )
            raise CustomTypeError(action_type)
    path = _get_config_path(project)
    data = _read_config(path)
    classify = data.setdefault("classify", {})
    entries = classify.setdefault(action_type, [])
    if command in entries:
        return f"Already classified: '{command}' as {action_type}"
    entries.append(command)
    _write_config(path, data)
    scope = "project" if project else "global"
    return f"Classified: '{command}' → {action_type} ({scope})"


def write_trust_host(host: str) -> str:
    """Write a known_registries entry to global config. Returns confirmation message."""
    _ensure_yaml()
    path = _get_config_path(project=False)  # always global
    data = _read_config(path)
    raw = data.get("known_registries", [])
    if isinstance(raw, dict):
        # Dict form: append to add list
        add_list = raw.setdefault("add", [])
        if host in add_list:
            return f"Already trusted: {host}"
        add_list.append(host)
    else:
        # List form (or missing): append to list
        registries = data.setdefault("known_registries", [])
        if not isinstance(registries, list):
            registries = []
            data["known_registries"] = registries
        if host in registries:
            return f"Already trusted: {host}"
        registries.append(host)
    _write_config(path, data)
    return f"Trusted: {host} (global)"


def forget_rule(arg: str, project: bool | None = None, global_only: bool | None = None) -> str:
    """Find and remove a rule matching arg. Returns confirmation message."""
    _ensure_yaml()
    matches: list[tuple[str, str, str]] = []  # (config_path, section, key_or_value)

    paths_to_check: list[tuple[str, str]] = []  # (path, label)
    if global_only:
        paths_to_check.append((get_global_config_path(), "global"))
    elif project:
        proj_path = get_project_config_path()
        if not proj_path:
            raise ValueError("Not in a git repository — cannot use --project")
        paths_to_check.append((proj_path, "project"))
    else:
        paths_to_check.append((get_global_config_path(), "global"))
        proj_path = get_project_config_path()
        if proj_path:
            paths_to_check.append((proj_path, "project"))

    for cfg_path, label in paths_to_check:
        data = _read_config(cfg_path)
        # Check actions
        actions = data.get("actions", {})
        if isinstance(actions, dict) and arg in actions:
            matches.append((cfg_path, "actions", arg))
        # Check allow_paths
        allow_paths = data.get("allow_paths", {})
        if isinstance(allow_paths, dict):
            from nah.paths import resolve_path
            resolved_arg = resolve_path(arg)
            for key in allow_paths:
                if key == arg or key == resolved_arg:
                    matches.append((cfg_path, "allow_paths", key))
        # Check classify (scan all lists)
        classify = data.get("classify", {})
        if isinstance(classify, dict):
            for action_type, prefixes in classify.items():
                if isinstance(prefixes, list) and arg in prefixes:
                    matches.append((cfg_path, f"classify.{action_type}", arg))
        # Check known_registries (polymorphic)
        registries = data.get("known_registries", [])
        if isinstance(registries, list) and arg in registries:
            matches.append((cfg_path, "known_registries", arg))
        elif isinstance(registries, dict):
            add = registries.get("add", [])
            if isinstance(add, list) and arg in add:
                matches.append((cfg_path, "known_registries.add", arg))
        # Check exec_sinks
        exec_sinks = data.get("exec_sinks", [])
        if isinstance(exec_sinks, list) and arg in exec_sinks:
            matches.append((cfg_path, "exec_sinks", arg))
        elif isinstance(exec_sinks, dict):
            add = exec_sinks.get("add", [])
            if isinstance(add, list) and arg in add:
                matches.append((cfg_path, "exec_sinks.add", arg))
        # Check sensitive_basenames
        basenames = data.get("sensitive_basenames", {})
        if isinstance(basenames, dict) and arg in basenames:
            matches.append((cfg_path, "sensitive_basenames", arg))
        # Check decode_commands
        decode_cmds = data.get("decode_commands", [])
        if isinstance(decode_cmds, list) and arg in decode_cmds:
            matches.append((cfg_path, "decode_commands", arg))
        elif isinstance(decode_cmds, dict):
            add = decode_cmds.get("add", [])
            if isinstance(add, list) and arg in add:
                matches.append((cfg_path, "decode_commands.add", arg))

    if not matches:
        raise ValueError(f"No rule found matching: {arg}")
    if len(matches) > 1:
        details = "\n".join(f"  - {label}: {section}" for path, section, _ in matches
                            for label in [_label_for_path(path)])
        raise ValueError(f"Ambiguous — '{arg}' found in multiple places:\n{details}\nUse --project or --global to disambiguate.")

    cfg_path, section, key = matches[0]
    data = _read_config(cfg_path)
    if section == "actions":
        data["actions"].pop(key, None)
        if not data["actions"]:
            del data["actions"]
    elif section == "allow_paths":
        data["allow_paths"].pop(key, None)
        if not data["allow_paths"]:
            del data["allow_paths"]
    elif section.startswith("classify."):
        action_type = section.split(".", 1)[1]
        entries = data.get("classify", {}).get(action_type, [])
        if key in entries:
            entries.remove(key)
        if not entries:
            data["classify"].pop(action_type, None)
        if not data.get("classify"):
            data.pop("classify", None)
    elif section == "known_registries":
        registries = data.get("known_registries", [])
        if isinstance(registries, list) and key in registries:
            registries.remove(key)
        if not registries:
            data.pop("known_registries", None)
    elif section == "known_registries.add":
        raw = data.get("known_registries", {})
        if isinstance(raw, dict):
            add = raw.get("add", [])
            if isinstance(add, list) and key in add:
                add.remove(key)
            if not add:
                raw.pop("add", None)
            if not raw:
                data.pop("known_registries", None)
    elif section == "exec_sinks":
        sinks = data.get("exec_sinks", [])
        if isinstance(sinks, list) and key in sinks:
            sinks.remove(key)
        if not sinks:
            data.pop("exec_sinks", None)
    elif section == "exec_sinks.add":
        raw = data.get("exec_sinks", {})
        if isinstance(raw, dict):
            add = raw.get("add", [])
            if isinstance(add, list) and key in add:
                add.remove(key)
            if not add:
                raw.pop("add", None)
            if not raw:
                data.pop("exec_sinks", None)
    elif section == "sensitive_basenames":
        basenames = data.get("sensitive_basenames", {})
        if isinstance(basenames, dict):
            basenames.pop(key, None)
        if not basenames:
            data.pop("sensitive_basenames", None)
    elif section == "decode_commands":
        cmds = data.get("decode_commands", [])
        if isinstance(cmds, list) and key in cmds:
            cmds.remove(key)
        if not cmds:
            data.pop("decode_commands", None)
    elif section == "decode_commands.add":
        raw = data.get("decode_commands", {})
        if isinstance(raw, dict):
            add = raw.get("add", [])
            if isinstance(add, list) and key in add:
                add.remove(key)
            if not add:
                raw.pop("add", None)
            if not raw:
                data.pop("decode_commands", None)
    _write_config(cfg_path, data)
    label = _label_for_path(cfg_path)
    return f"Removed: {arg} from {section} ({label})"


def _label_for_path(cfg_path: str) -> str:
    """Return 'global' or 'project' label for a config path."""
    if cfg_path == get_global_config_path():
        return "global"
    return "project"


def list_rules() -> dict:
    """List all custom rules from both configs. Returns structured dict."""
    _ensure_yaml()
    result: dict = {"global": {}, "project": {}}
    global_path = get_global_config_path()
    global_data = _read_config(global_path) if os.path.isfile(global_path) else {}
    proj_path = get_project_config_path()
    proj_data = _read_config(proj_path) if proj_path and os.path.isfile(proj_path) else {}

    for label, data in [("global", global_data), ("project", proj_data)]:
        actions = data.get("actions", {})
        if isinstance(actions, dict) and actions:
            result[label]["actions"] = actions
        allow_paths = data.get("allow_paths", {})
        if isinstance(allow_paths, dict) and allow_paths:
            result[label]["allow_paths"] = allow_paths
        classify = data.get("classify", {})
        if isinstance(classify, dict) and classify:
            result[label]["classify"] = classify
        registries = data.get("known_registries", [])
        if isinstance(registries, (list, dict)) and registries:
            result[label]["known_registries"] = registries
        exec_sinks = data.get("exec_sinks", [])
        if isinstance(exec_sinks, (list, dict)) and exec_sinks:
            result[label]["exec_sinks"] = exec_sinks
        sensitive_basenames = data.get("sensitive_basenames", {})
        if isinstance(sensitive_basenames, dict) and sensitive_basenames:
            result[label]["sensitive_basenames"] = sensitive_basenames
        decode_commands = data.get("decode_commands", [])
        if isinstance(decode_commands, (list, dict)) and decode_commands:
            result[label]["decode_commands"] = decode_commands

    return result
