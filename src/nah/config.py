"""Config loading — YAML config with global + project merge."""

import os
import sys
from dataclasses import dataclass, field

from nah.taxonomy import STRICTNESS as _STRICTNESS

_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "nah")
_GLOBAL_CONFIG = os.path.join(_CONFIG_DIR, "config.yaml")
_PROJECT_CONFIG_NAME = ".nah.yaml"


@dataclass
class NahConfig:
    classify: dict[str, list[str]] = field(default_factory=dict)
    actions: dict[str, str] = field(default_factory=dict)
    sensitive_paths_default: str = "ask"
    sensitive_paths: dict[str, str] = field(default_factory=dict)
    allow_paths: dict[str, list[str]] = field(default_factory=dict)
    known_registries: list[str] = field(default_factory=list)
    llm: dict = field(default_factory=dict)
    ask_fallback: str = "deny"


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
        sys.stderr.write("nah: yaml module not available, config ignored\n")
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        sys.stderr.write(f"nah: config parse error in {path}: {e}\n")
        return {}


def _validate_dict(val) -> dict:
    """Return val if dict, else empty dict."""
    return val if isinstance(val, dict) else {}


def _merge_dict_tighten(global_d: dict, project_d: dict) -> dict:
    """Merge two dicts — project can only tighten (stricter policy wins)."""
    merged = dict(global_d)
    for key, val in project_d.items():
        if key in merged:
            if _STRICTNESS.get(val, 2) >= _STRICTNESS.get(merged[key], 2):
                merged[key] = val
        else:
            merged[key] = val
    return merged


def _merge_list_union(global_l, project_l) -> list:
    """Union two lists, deduped, preserving order."""
    if not isinstance(global_l, list):
        global_l = []
    if not isinstance(project_l, list):
        project_l = []
    return list(dict.fromkeys(global_l + project_l))


def _merge_configs(global_cfg: dict, project_cfg: dict) -> NahConfig:
    """Merge global and project configs with security rules."""
    config = NahConfig()

    # classify: union per key
    g_classify = _validate_dict(global_cfg.get("classify", {}))
    p_classify = _validate_dict(project_cfg.get("classify", {}))
    for key in set(g_classify) | set(p_classify):
        config.classify[key] = _merge_list_union(g_classify.get(key, []), p_classify.get(key, []))

    # actions: tighten only
    config.actions = _merge_dict_tighten(
        _validate_dict(global_cfg.get("actions", {})),
        _validate_dict(project_cfg.get("actions", {})),
    )

    # sensitive_paths_default: use project if stricter
    g_default = global_cfg.get("sensitive_paths_default", "ask")
    p_default = project_cfg.get("sensitive_paths_default", "")
    if p_default and _STRICTNESS.get(p_default, 2) >= _STRICTNESS.get(g_default, 2):
        config.sensitive_paths_default = p_default
    else:
        config.sensitive_paths_default = g_default if g_default in _STRICTNESS else "ask"

    # sensitive_paths: tighten only
    config.sensitive_paths = _merge_dict_tighten(
        _validate_dict(global_cfg.get("sensitive_paths", {})),
        _validate_dict(project_cfg.get("sensitive_paths", {})),
    )

    # allow_paths: global config ONLY — project .nah.yaml silently ignored
    g_allow = global_cfg.get("allow_paths", {})
    if isinstance(g_allow, dict):
        config.allow_paths = {k: v for k, v in g_allow.items() if isinstance(v, list)}

    # known_registries: union
    config.known_registries = _merge_list_union(
        global_cfg.get("known_registries", []),
        project_cfg.get("known_registries", []),
    )

    # llm: global config ONLY — project .nah.yaml silently ignored
    config.llm = _validate_dict(global_cfg.get("llm", {}))

    # ask_fallback: global config ONLY
    raw_fallback = global_cfg.get("ask_fallback", "deny")
    config.ask_fallback = raw_fallback if raw_fallback in ("deny", "allow") else "deny"

    return config


def is_path_allowed(sensitive_path: str, project_root: str | None) -> bool:
    """Check if a sensitive path is exempted via allow_paths for the given project root."""
    if not project_root:
        return False

    cfg = get_config()
    if not cfg.allow_paths:
        return False

    from nah.paths import resolve_path  # lazy import to avoid circular
    real_root = resolve_path(project_root)
    real_path = resolve_path(sensitive_path)

    for pattern, roots in cfg.allow_paths.items():
        resolved_pattern = resolve_path(pattern)
        if real_path == resolved_pattern or real_path.startswith(resolved_pattern + os.sep):
            for root in roots:
                resolved_root = resolve_path(root)
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
