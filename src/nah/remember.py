"""Config writer — CLI commands delegate here to modify config YAML files."""

import os

from nah import taxonomy
from nah.config import get_global_config_path, get_project_config_path
from nah.paths import get_project_root


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


def write_action(action_type: str, policy: str, project: bool = False) -> str:
    """Write an action policy to config. Returns confirmation message."""
    _ensure_yaml()
    valid, close = taxonomy.validate_action_type(action_type)
    if not valid:
        msg = f"Unknown action type: {action_type}"
        if close:
            msg += f". Did you mean: {', '.join(close)}?"
        raise ValueError(msg)
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


def write_classify(command: str, action_type: str, project: bool = False) -> str:
    """Write a classify entry. Returns confirmation message."""
    _ensure_yaml()
    valid, close = taxonomy.validate_action_type(action_type)
    if not valid:
        msg = f"Unknown action type: {action_type}"
        if close:
            msg += f". Did you mean: {', '.join(close)}?"
        raise ValueError(msg)
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


def write_trust_host(host: str, project: bool = False) -> str:
    """Write a known_registries entry. Returns confirmation message."""
    _ensure_yaml()
    path = _get_config_path(project)
    data = _read_config(path)
    registries = data.setdefault("known_registries", [])
    if host in registries:
        return f"Already trusted: {host}"
    registries.append(host)
    _write_config(path, data)
    scope = "project" if project else "global"
    return f"Trusted: {host} ({scope})"


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
        # Check known_registries
        registries = data.get("known_registries", [])
        if isinstance(registries, list) and arg in registries:
            matches.append((cfg_path, "known_registries", arg))

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
        if key in registries:
            registries.remove(key)
        if not registries:
            data.pop("known_registries", None)
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
        if isinstance(registries, list) and registries:
            result[label]["known_registries"] = registries

    return result
