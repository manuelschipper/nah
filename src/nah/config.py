"""Config loading — YAML config with global + project merge."""

import os
import sys
from dataclasses import dataclass, field

from nah.taxonomy import POLICIES as _POLICIES, PROFILES as _PROFILES, STRICTNESS as _STRICTNESS

class ConfigError(Exception):
    """Raised when a config file exists but fails to parse."""

_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "nah")
_GLOBAL_CONFIG = os.path.join(_CONFIG_DIR, "config.yaml")
_PROJECT_CONFIG_NAME = ".nah.yaml"


@dataclass
class NahConfig:
    profile: str = "full"
    classify_global: dict[str, list[str]] = field(default_factory=dict)
    classify_project: dict[str, list[str]] = field(default_factory=dict)
    actions: dict[str, str] = field(default_factory=dict)
    sensitive_paths_default: str = "ask"
    sensitive_paths: dict[str, str] = field(default_factory=dict)
    allow_paths: dict[str, list[str]] = field(default_factory=dict)
    known_registries: list | dict = field(default_factory=list)
    exec_sinks: list | dict = field(default_factory=list)
    sensitive_basenames: dict = field(default_factory=dict)
    decode_commands: list | dict = field(default_factory=list)
    content_patterns_add: list = field(default_factory=list)
    content_patterns_suppress: list = field(default_factory=list)
    content_policies: dict = field(default_factory=dict)
    credential_patterns_add: list = field(default_factory=list)
    credential_patterns_suppress: list = field(default_factory=list)
    llm: dict = field(default_factory=dict)
    llm_max_decision: str = "ask"  # default: LLM can't escalate past ask
    llm_eligible: str | list = "default"
    trusted_paths: list[str] = field(default_factory=list)
    db_targets: list[dict] = field(default_factory=list)
    log: dict = field(default_factory=dict)


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


def apply_override(override_data: dict) -> None:
    """Apply inline config override for single-shot CLI use (nah test --config).

    Merges override_data onto the current config. No cleanup needed —
    the override only lives for the process lifetime.
    """
    global _cached_config
    cfg = get_config()  # ensure base is loaded

    if "profile" in override_data:
        profile = override_data["profile"]
        if profile in _PROFILES:
            cfg.profile = profile
    if "classify" in override_data:
        cfg.classify_global.update(_validate_dict(override_data["classify"]))
    if "actions" in override_data:
        cfg.actions.update(_validate_dict(override_data["actions"]))
    if "sensitive_paths" in override_data:
        cfg.sensitive_paths.update(_validate_dict(override_data["sensitive_paths"]))
    if "trusted_paths" in override_data:
        tp = override_data["trusted_paths"]
        if isinstance(tp, list):
            cfg.trusted_paths = [str(p) for p in tp]
    if "known_registries" in override_data:
        cfg.known_registries = override_data["known_registries"]
    if "exec_sinks" in override_data:
        cfg.exec_sinks = override_data["exec_sinks"]
    if "content_patterns" in override_data:
        cp = _validate_dict(override_data["content_patterns"])
        if "suppress" in cp:
            cfg.content_patterns_suppress = cp["suppress"]
        if "add" in cp:
            cfg.content_patterns_add = cp["add"]
    if "credential_patterns" in override_data:
        cp = _validate_dict(override_data["credential_patterns"])
        if "suppress" in cp:
            cfg.credential_patterns_suppress = cp["suppress"]
        if "add" in cp:
            cfg.credential_patterns_add = cp["add"]

    _cached_config = cfg

    # Reset lazy-merge caches so they re-read from the updated config
    from nah import paths, content, context, taxonomy
    paths.reset_sensitive_paths()
    content.reset_content_patterns()
    context.reset_known_hosts()
    taxonomy.reset_exec_sinks()
    taxonomy.reset_decode_commands()


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
        raise ConfigError(f"config parse error in {path}: {e}") from e


def _validate_dict(val) -> dict:
    """Return val if dict, else empty dict."""
    return val if isinstance(val, dict) else {}


def _merge_dict_tighten(global_d: dict, project_d: dict, defaults: dict | None = None) -> dict:
    """Merge two dicts — project can only tighten (stricter policy wins)."""
    merged = dict(global_d)
    for key, val in project_d.items():
        if key in merged:
            if _STRICTNESS.get(val, 2) >= _STRICTNESS.get(merged[key], 2):
                merged[key] = val
        else:
            # New key: only accept if at least as strict as the built-in default
            base = defaults.get(key, "ask") if defaults else "ask"
            if _STRICTNESS.get(val, 2) >= _STRICTNESS.get(base, 2):
                merged[key] = val
    return merged


def _parse_add_remove(raw) -> tuple[list, list]:
    """Parse polymorphic config: list = add-only, dict = add/remove."""
    if isinstance(raw, list):
        return raw, []
    if isinstance(raw, dict):
        add = raw.get("add", [])
        remove = raw.get("remove", [])
        return (add if isinstance(add, list) else []), (remove if isinstance(remove, list) else [])
    return [], []


def _merge_configs(global_cfg: dict, project_cfg: dict) -> NahConfig:
    """Merge global and project configs with security rules."""
    config = NahConfig()

    # profile: global config ONLY, validated
    profile = global_cfg.get("profile", "full")
    if profile not in _PROFILES:
        sys.stderr.write(f"nah: unknown profile '{profile}', using 'full'\n")
        profile = "full"
    config.profile = profile

    # classify: keep global and project SEPARATE for three-table lookup
    config.classify_global = _validate_dict(global_cfg.get("classify", {}))
    config.classify_project = _validate_dict(project_cfg.get("classify", {}))

    # actions: tighten only (compare new keys against built-in defaults)
    config.actions = _merge_dict_tighten(
        _validate_dict(global_cfg.get("actions", {})),
        _validate_dict(project_cfg.get("actions", {})),
        defaults=_POLICIES,
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

    # known_registries: global only, polymorphic (list = add-only, dict = add/remove)
    raw_kr = global_cfg.get("known_registries", [])
    if isinstance(raw_kr, (list, dict)):
        config.known_registries = raw_kr
    else:
        config.known_registries = []

    # exec_sinks: global only, polymorphic (list = add-only, dict = add/remove)
    raw_es = global_cfg.get("exec_sinks", [])
    if isinstance(raw_es, (list, dict)):
        config.exec_sinks = raw_es
    else:
        config.exec_sinks = []

    # sensitive_basenames: global only, flat dict (name → policy)
    config.sensitive_basenames = _validate_dict(global_cfg.get("sensitive_basenames", {}))

    # decode_commands: global only, polymorphic (list = add-only, dict = add/remove)
    raw_dc = global_cfg.get("decode_commands", [])
    if isinstance(raw_dc, (list, dict)):
        config.decode_commands = raw_dc
    else:
        config.decode_commands = []

    # content_patterns: add/suppress global-only, policies tighten-only
    g_content = _validate_dict(global_cfg.get("content_patterns", {}))
    p_content = _validate_dict(project_cfg.get("content_patterns", {}))
    raw_cp_add = g_content.get("add", [])
    config.content_patterns_add = raw_cp_add if isinstance(raw_cp_add, list) else []
    raw_cp_suppress = g_content.get("suppress", [])
    config.content_patterns_suppress = raw_cp_suppress if isinstance(raw_cp_suppress, list) else []
    g_policies = _validate_dict(g_content.get("policies", {}))
    p_policies = _validate_dict(p_content.get("policies", {}))
    config.content_policies = _merge_dict_tighten(g_policies, p_policies)

    # credential_patterns: entirely global-only
    g_cred = _validate_dict(global_cfg.get("credential_patterns", {}))
    raw_cred_add = g_cred.get("add", [])
    config.credential_patterns_add = raw_cred_add if isinstance(raw_cred_add, list) else []
    raw_cred_suppress = g_cred.get("suppress", [])
    config.credential_patterns_suppress = raw_cred_suppress if isinstance(raw_cred_suppress, list) else []

    # llm: global config ONLY — project .nah.yaml silently ignored
    config.llm = _validate_dict(global_cfg.get("llm", {}))

    # llm.max_decision: cap on LLM escalation (global only)
    raw_max = config.llm.get("max_decision", "")
    if raw_max and raw_max in _STRICTNESS:
        config.llm_max_decision = raw_max

    # llm.eligible: which ask categories are LLM-eligible (global only)
    raw_eligible = config.llm.get("eligible", "default")
    if raw_eligible == "all":
        config.llm_eligible = "all"
    elif isinstance(raw_eligible, list):
        config.llm_eligible = [str(v) for v in raw_eligible]
    else:
        config.llm_eligible = "default"

    # trusted_paths: global config ONLY (project .nah.yaml cannot set)
    g_trusted = global_cfg.get("trusted_paths", [])
    if isinstance(g_trusted, list):
        config.trusted_paths = [str(p) for p in g_trusted]

    # db_targets: global config ONLY — project .nah.yaml silently ignored
    g_targets = global_cfg.get("db_targets", [])
    if isinstance(g_targets, list):
        config.db_targets = [t for t in g_targets if isinstance(t, dict)]

    # log: global config ONLY — project .nah.yaml silently ignored
    config.log = _validate_dict(global_cfg.get("log", {}))

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
