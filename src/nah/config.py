"""Config loading — YAML config with global + project merge."""

import os
from dataclasses import dataclass, field

_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "nah")
_GLOBAL_CONFIG = os.path.join(_CONFIG_DIR, "config.yaml")
_PROJECT_CONFIG_NAME = ".nah.yaml"

# Strictness ordering for tighten-only merge.
_STRICTNESS = {"allow": 0, "context": 1, "ask": 2, "block": 3}


@dataclass
class NahConfig:
    classify: dict[str, list[str]] = field(default_factory=dict)
    actions: dict[str, str] = field(default_factory=dict)
    sensitive_paths_default: str = "ask"
    sensitive_paths: dict[str, str] = field(default_factory=dict)
    allow_paths: dict[str, list[str]] = field(default_factory=dict)
    known_registries: list[str] = field(default_factory=list)


_cached_config: NahConfig | None = None


def get_config() -> NahConfig:
    """Load and return merged config. Cached for process lifetime."""
    global _cached_config
    if _cached_config is not None:
        return _cached_config

    global_data = _load_yaml_file(_GLOBAL_CONFIG)

    # Find project config via project root
    project_data: dict = {}
    from nah.paths import get_project_root  # lazy import to avoid circular
    project_root = get_project_root()
    if project_root:
        project_config_path = os.path.join(project_root, _PROJECT_CONFIG_NAME)
        project_data = _load_yaml_file(project_config_path)

    _cached_config = _merge_configs(global_data, project_data)
    return _cached_config


def reset_config() -> None:
    """Clear cached config (for testing)."""
    global _cached_config
    _cached_config = None


def _load_yaml_file(path: str) -> dict:
    """Load YAML file. Returns {} if file missing or yaml unavailable."""
    if not os.path.isfile(path):
        return {}
    try:
        import yaml
    except ImportError:
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _merge_configs(global_cfg: dict, project_cfg: dict) -> NahConfig:
    """Merge global and project configs with security rules."""
    config = NahConfig()

    # classify: union (project extends global)
    g_classify = global_cfg.get("classify", {})
    p_classify = project_cfg.get("classify", {})
    if not isinstance(g_classify, dict):
        g_classify = {}
    if not isinstance(p_classify, dict):
        p_classify = {}
    merged_classify: dict[str, list[str]] = {}
    all_keys = set(g_classify) | set(p_classify)
    for key in all_keys:
        g_list = g_classify.get(key, [])
        p_list = p_classify.get(key, [])
        if not isinstance(g_list, list):
            g_list = []
        if not isinstance(p_list, list):
            p_list = []
        merged_classify[key] = list(dict.fromkeys(g_list + p_list))  # dedupe, preserve order
    config.classify = merged_classify

    # actions: project overrides, tighten only
    g_actions = global_cfg.get("actions", {})
    p_actions = project_cfg.get("actions", {})
    if not isinstance(g_actions, dict):
        g_actions = {}
    if not isinstance(p_actions, dict):
        p_actions = {}
    merged_actions = dict(g_actions)
    for key, val in p_actions.items():
        if key in merged_actions:
            # Tighten only: project can only make stricter
            if _STRICTNESS.get(val, 2) >= _STRICTNESS.get(merged_actions[key], 2):
                merged_actions[key] = val
        else:
            merged_actions[key] = val
    config.actions = merged_actions

    # sensitive_paths_default: use project if stricter
    g_default = global_cfg.get("sensitive_paths_default", "ask")
    p_default = project_cfg.get("sensitive_paths_default", "")
    if p_default and _STRICTNESS.get(p_default, 2) >= _STRICTNESS.get(g_default, 2):
        config.sensitive_paths_default = p_default
    else:
        config.sensitive_paths_default = g_default if g_default in _STRICTNESS else "ask"

    # sensitive_paths: union, tighten only per path
    g_paths = global_cfg.get("sensitive_paths", {})
    p_paths = project_cfg.get("sensitive_paths", {})
    if not isinstance(g_paths, dict):
        g_paths = {}
    if not isinstance(p_paths, dict):
        p_paths = {}
    merged_paths = dict(g_paths)
    for path, policy in p_paths.items():
        if path in merged_paths:
            if _STRICTNESS.get(policy, 2) >= _STRICTNESS.get(merged_paths[path], 2):
                merged_paths[path] = policy
        else:
            merged_paths[path] = policy
    config.sensitive_paths = merged_paths

    # allow_paths: global config ONLY — project .nah.yaml silently ignored
    g_allow = global_cfg.get("allow_paths", {})
    if isinstance(g_allow, dict):
        config.allow_paths = {k: v for k, v in g_allow.items() if isinstance(v, list)}

    # known_registries: union
    g_reg = global_cfg.get("known_registries", [])
    p_reg = project_cfg.get("known_registries", [])
    if not isinstance(g_reg, list):
        g_reg = []
    if not isinstance(p_reg, list):
        p_reg = []
    config.known_registries = list(dict.fromkeys(g_reg + p_reg))

    return config


def is_path_allowed(sensitive_path: str, project_root: str | None) -> bool:
    """Check if a sensitive path is exempted via allow_paths for the given project root."""
    if not project_root:
        return False

    cfg = get_config()
    if not cfg.allow_paths:
        return False

    real_root = os.path.realpath(project_root)
    real_path = os.path.realpath(os.path.expanduser(sensitive_path))

    for pattern, roots in cfg.allow_paths.items():
        resolved_pattern = os.path.realpath(os.path.expanduser(pattern))
        if real_path == resolved_pattern or real_path.startswith(resolved_pattern + os.sep):
            for root in roots:
                resolved_root = os.path.realpath(os.path.expanduser(root))
                if real_root == resolved_root:
                    return True
    return False


def get_global_config_path() -> str:
    """Return the global config file path."""
    return _GLOBAL_CONFIG


def get_project_config_path() -> str | None:
    """Return the project config file path, or None if no project root."""
    from nah.paths import get_project_root
    project_root = get_project_root()
    if project_root:
        return os.path.join(project_root, _PROJECT_CONFIG_NAME)
    return None
