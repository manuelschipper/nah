"""Config loading — YAML config with global + project merge."""

import copy
import os
import sys
from dataclasses import dataclass, field

from nah import taxonomy
from nah.messages import normalize_color_mode
from nah.platform_paths import nah_config_dir
from nah.taxonomy import POLICIES as _POLICIES, STRICTNESS as _STRICTNESS

class ConfigError(Exception):
    """Raised when a config file exists but fails to parse."""

_CONFIG_DIR = nah_config_dir()
_GLOBAL_CONFIG = os.path.join(_CONFIG_DIR, "config.yaml")
_PROJECT_CONFIG_NAME = ".nah.yaml"
_PRESET_ENV = "NAH_PRESET"
_ASK_FALLBACKS = {"allow", "block"}


@dataclass
class NahConfig:
    target: str = ""
    selected_preset: str = ""
    # Compatibility only. Older configs/callers may still pass profile, but
    # nah always runs the full built-in taxonomy and never reads this value.
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
    llm_mode: str = "off"
    trusted_paths: list[str] = field(default_factory=list)
    trusted_containers: list[str] = field(default_factory=list)
    db_targets: list[dict] = field(default_factory=list)
    log: dict = field(default_factory=dict)
    active_allow: bool | list = True
    ui: dict = field(default_factory=dict)
    ui_color: str = "auto"
    project_root: str = ""
    project_config_path: str = ""
    project_config_trusted: bool = False
    trusted_project_configs: list[str] = field(default_factory=list)
    trust_project_config: bool = False
    targets: dict = field(default_factory=dict)
    ask_fallback: str = ""
    terminal: dict = field(default_factory=dict)


_cached_config: NahConfig | None = None
_cached_target: str | None = None
_cached_preset: str | None = None
_active_target = ""
_active_preset = ""


def _roots_are_related(real_root: str, allowed_root: str) -> bool:
    """Return true for identical or parent/child project roots."""
    return (
        real_root == allowed_root
        or real_root.startswith(allowed_root + os.sep)
        or allowed_root.startswith(real_root + os.sep)
    )


def set_active_target(target: str | None, *, reset_cache: bool = True) -> None:
    """Set the process-local target used by get_config()."""
    global _active_target
    _active_target = target or ""
    if reset_cache:
        reset_config()


def get_active_target() -> str:
    """Return the process-local target used by get_config()."""
    return _active_target


def set_active_preset(preset: str | None, *, reset_cache: bool = True) -> None:
    """Set the process-local preset used by get_config()."""
    global _active_preset
    _active_preset = str(preset or "").strip()
    if reset_cache:
        reset_config()


def get_active_preset() -> str:
    """Return the process-local or environment-selected preset."""
    return _resolve_selected_preset(None)


def _resolve_selected_preset(preset: str | None) -> str:
    """Return explicit preset, process preset, or NAH_PRESET."""
    if preset is not None:
        return str(preset).strip()
    if _active_preset:
        return _active_preset
    return os.environ.get(_PRESET_ENV, "").strip()


def get_config(target: str | None = None, preset: str | None = None) -> NahConfig:
    """Load and return merged config. Cached for process lifetime."""
    global _cached_config, _cached_target, _cached_preset
    effective_target = target if target is not None else _active_target
    selected_preset = _resolve_selected_preset(preset)
    if (
        _cached_config is not None
        and (_cached_target is None or _cached_target == effective_target)
        and (_cached_preset is None or _cached_preset == selected_preset)
    ):
        return _cached_config

    global_data = _load_yaml_file(_GLOBAL_CONFIG)

    # Find project config via project root
    project_data: dict = {}
    from nah.paths import get_project_root  # lazy import to avoid circular
    project_root = get_project_root()
    project_config_path = ""
    if project_root:
        project_config_path = os.path.join(project_root, _PROJECT_CONFIG_NAME)
        project_data = _load_yaml_file(project_config_path)

    _cached_config = _merge_configs(
        global_data,
        project_data,
        effective_target,
        selected_preset=selected_preset,
        project_root=project_root or "",
        project_config_path=project_config_path,
    )
    _cached_target = effective_target
    _cached_preset = selected_preset
    return _cached_config


def reset_config() -> None:
    """Clear cached config (for testing)."""
    global _cached_config, _cached_target, _cached_preset
    _cached_config = None
    _cached_target = None
    _cached_preset = None


def _reset_lazy_merge_caches() -> None:
    """Reset config-derived lazy caches after changing the process config."""
    from nah import paths, content, context, taxonomy
    paths.reset_sensitive_paths()
    content.reset_content_patterns()
    context.reset_known_hosts()
    taxonomy.reset_exec_sinks()
    taxonomy.reset_decode_commands()


def use_defaults() -> None:
    """Use packaged defaults for the current process, ignoring config files."""
    global _cached_config, _cached_target, _cached_preset
    _cached_config = _merge_configs({}, {}, _active_target, selected_preset="")
    _cached_target = _active_target
    _cached_preset = ""
    _reset_lazy_merge_caches()


def apply_override(override_data: dict) -> None:
    """Apply inline config override for single-shot CLI use (nah test --config).

    Merges override_data onto the current config. No cleanup needed —
    the override only lives for the process lifetime.
    """
    global _cached_config
    cfg = get_config()  # ensure base is loaded

    if "classify" in override_data:
        cfg.classify_global.update(_canonicalize_classify(override_data["classify"]))
    if "actions" in override_data:
        cfg.actions.update(_canonicalize_actions(override_data["actions"]))
    if "sensitive_paths" in override_data:
        cfg.sensitive_paths.update(_validate_dict(override_data["sensitive_paths"]))
    if "trusted_paths" in override_data:
        tp = override_data["trusted_paths"]
        if isinstance(tp, list):
            cfg.trusted_paths = [str(p) for p in tp]
    if "trusted_containers" in override_data:
        cfg.trusted_containers = _normalize_trusted_containers(
            override_data["trusted_containers"]
        )
    if "trusted_project_configs" in override_data:
        tpc = override_data["trusted_project_configs"]
        if isinstance(tpc, list):
            cfg.trusted_project_configs = [str(p) for p in tpc]
            from nah.paths import get_project_root
            project_root = get_project_root()
            cfg.project_config_trusted = _project_root_matches_trusted(
                project_root, cfg.trusted_project_configs
            )
            if cfg.project_config_trusted and cfg.project_config_path:
                project_cfg = _load_yaml_file(cfg.project_config_path)
                cfg.classify_project = _canonicalize_classify(project_cfg.get("classify", {}))
    if "known_registries" in override_data:
        cfg.known_registries = override_data["known_registries"]
    if "exec_sinks" in override_data:
        cfg.exec_sinks = override_data["exec_sinks"]
    if "sensitive_basenames" in override_data:
        cfg.sensitive_basenames.update(_validate_dict(override_data["sensitive_basenames"]))
    if "decode_commands" in override_data:
        raw_dc = override_data["decode_commands"]
        if isinstance(raw_dc, (list, dict)):
            cfg.decode_commands = raw_dc
    if "db_targets" in override_data:
        raw_dt = override_data["db_targets"]
        if isinstance(raw_dt, list):
            cfg.db_targets = [t for t in raw_dt if isinstance(t, dict)]
    if "content_patterns" in override_data:
        cp = _validate_dict(override_data["content_patterns"])
        if "suppress" in cp:
            cfg.content_patterns_suppress = cp["suppress"]
        if "add" in cp:
            cfg.content_patterns_add = cp["add"]
        if "policies" in cp:
            cfg.content_policies.update(_validate_dict(cp["policies"]))
    if "credential_patterns" in override_data:
        cp = _validate_dict(override_data["credential_patterns"])
        if "suppress" in cp:
            cfg.credential_patterns_suppress = cp["suppress"]
        if "add" in cp:
            cfg.credential_patterns_add = cp["add"]

    if "llm" in override_data:
        cfg.llm = _validate_dict(override_data["llm"])
        mode = _normalize_llm_mode(cfg.llm.get("mode", ""))
        if mode:
            cfg.llm_mode = mode
        elif "mode" not in cfg.llm and bool(cfg.llm.get("enabled", False)):
            cfg.llm_mode = "on"
    if "llm_mode" in override_data:
        mode = _normalize_llm_mode(override_data["llm_mode"])
        if mode:
            cfg.llm_mode = mode
    if "active_allow" in override_data:
        raw_aa = override_data["active_allow"]
        if isinstance(raw_aa, bool):
            cfg.active_allow = raw_aa
        elif isinstance(raw_aa, list):
            cfg.active_allow = [str(t) for t in raw_aa]
    if "ui" in override_data:
        cfg.ui = _validate_dict(override_data["ui"])
        if "color" in cfg.ui:
            cfg.ui_color = normalize_color_mode(cfg.ui.get("color"))
    if "ui_color" in override_data:
        cfg.ui_color = normalize_color_mode(override_data["ui_color"])

    if "targets" in override_data:
        targets = _validate_dict(override_data["targets"])
        cfg.targets.update(targets)
        active = cfg.target or _active_target
        if active:
            _apply_target_data(
                cfg,
                _validate_dict(targets.get(active, {})),
                trusted=True,
                explicit_shell_llm=True,
            )

    _cached_config = cfg

    # Reset lazy-merge caches so they re-read from the updated config.
    _reset_lazy_merge_caches()


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


def _canonicalize_actions(raw: dict) -> dict:
    """Canonicalize action-type keys in config data."""
    result: dict = {}
    for action_type, policy in _validate_dict(raw).items():
        raw_action_type = str(action_type)
        successors = taxonomy.split_type_successors(raw_action_type)
        if successors:
            taxonomy.warn_split_type_alias(raw_action_type, fanout=True)
            for successor in successors:
                result[successor] = policy
            continue
        result[taxonomy.canonicalize_action_type(raw_action_type)] = policy
    return result


def _canonicalize_classify(raw: dict) -> dict:
    """Canonicalize classify action-type keys in config data."""
    result: dict = {}
    for action_type, prefixes in _validate_dict(raw).items():
        canonical = taxonomy.canonicalize_action_type(str(action_type))
        if isinstance(prefixes, list):
            result.setdefault(canonical, []).extend(prefixes)
    return result


def _deep_overlay(base, overlay):
    """Overlay config values: dicts recurse, scalars/lists replace."""
    if isinstance(base, dict) and isinstance(overlay, dict):
        result = copy.deepcopy(base)
        for key, value in overlay.items():
            if key in result:
                result[key] = _deep_overlay(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result
    return copy.deepcopy(overlay)


def _global_presets_from_config(global_cfg: dict) -> dict:
    raw = global_cfg.get("presets", {})
    return raw if isinstance(raw, dict) else {}


def list_global_presets() -> list[str]:
    """Return configured global preset names."""
    presets = _global_presets_from_config(_load_yaml_file(_GLOBAL_CONFIG))
    return sorted(str(name) for name in presets)


def get_global_preset(name: str) -> dict:
    """Return one raw global preset block or raise ConfigError."""
    global_cfg = _load_yaml_file(_GLOBAL_CONFIG)
    presets = _global_presets_from_config(global_cfg)
    preset_name = str(name or "").strip()
    for raw_name, raw_value in presets.items():
        if str(raw_name) == preset_name:
            if not isinstance(raw_value, dict):
                raise ConfigError(f"preset '{preset_name}' must be a mapping")
            return copy.deepcopy(raw_value)
    raise ConfigError(f"unknown preset '{preset_name}'")


def _apply_global_preset(global_cfg: dict, preset_name: str) -> tuple[dict, str]:
    """Return global config with selected preset overlaid."""
    selected = str(preset_name or "").strip()
    if not selected:
        return copy.deepcopy(global_cfg), ""

    presets = _global_presets_from_config(global_cfg)
    matched = None
    for raw_name, raw_value in presets.items():
        if str(raw_name) == selected:
            matched = raw_value
            break
    if matched is None:
        raise ConfigError(f"unknown preset '{selected}'")
    if not isinstance(matched, dict):
        raise ConfigError(f"preset '{selected}' must be a mapping")

    preset_data = copy.deepcopy(matched)
    if "presets" in preset_data:
        sys.stderr.write(
            f"nah: preset '{selected}' contains nested presets; ignoring nested presets\n"
        )
        preset_data.pop("presets", None)

    return _deep_overlay(global_cfg, preset_data), selected


def _normalize_llm_mode(raw) -> str:
    """Normalize YAML/JSON LLM mode values to ``on`` / ``off`` / empty."""
    if raw in ("off", "on"):
        return raw
    if isinstance(raw, bool):
        return "on" if raw else "off"
    return ""


def _normalize_ask_fallback(raw, *, context: str) -> str:
    """Normalize target ask fallback to allow/block/empty or raise."""
    if raw in (None, ""):
        return ""
    if raw in _ASK_FALLBACKS:
        return raw
    raise ConfigError(
        f"{context}.ask_fallback must be 'allow' or 'block', got {raw!r}"
    )


_TRUSTED_CONTAINER_PREFIXES = frozenset({"container", "compose"})
_TRUSTED_CONTAINER_WILDCARDS = frozenset("*?[]{}")


def normalize_trusted_container_identity(raw) -> str | None:
    """Normalize a trusted container/service identity, or return None."""
    if not isinstance(raw, str):
        sys.stderr.write("nah: trusted_containers contains a non-string entry, ignored\n")
        return None

    value = raw.strip()
    if not value:
        sys.stderr.write("nah: trusted_containers contains an empty entry, ignored\n")
        return None
    if any(ch.isspace() for ch in value):
        sys.stderr.write(f"nah: trusted_containers entry {raw!r} contains whitespace, ignored\n")
        return None
    if any(ch in value for ch in _TRUSTED_CONTAINER_WILDCARDS):
        sys.stderr.write(f"nah: trusted_containers entry {raw!r} uses wildcards, ignored\n")
        return None

    if ":" in value:
        prefix, name = value.split(":", 1)
        if prefix not in _TRUSTED_CONTAINER_PREFIXES:
            sys.stderr.write(f"nah: trusted_containers entry {raw!r} has unknown prefix, ignored\n")
            return None
    else:
        prefix, name = "container", value

    if not name or name.startswith("-"):
        sys.stderr.write(f"nah: trusted_containers entry {raw!r} is not a valid identity, ignored\n")
        return None
    return f"{prefix}:{name}"


def _normalize_trusted_containers(raw) -> list[str]:
    """Parse trusted_containers defensively into exact normalized identities."""
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        sys.stderr.write("nah: trusted_containers must be a list, ignored\n")
        return []

    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        identity = normalize_trusted_container_identity(item)
        if identity and identity not in seen:
            result.append(identity)
            seen.add(identity)
    return result


def _normalize_config_root(path: str) -> str:
    """Return a canonical path for project config trust comparisons."""
    return os.path.normcase(os.path.realpath(os.path.expanduser(path)))


def _normalize_trusted_project_configs(raw) -> list[str]:
    """Parse global trusted_project_configs list defensively."""
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        sys.stderr.write("nah: trusted_project_configs must be a list, ignored\n")
        return []
    result: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            sys.stderr.write("nah: trusted_project_configs contains a non-string entry, ignored\n")
            continue
        result.append(entry)
    return result


def _project_root_matches_trusted(project_root: str | None, trusted_roots: list[str]) -> bool:
    """Return true when project_root exactly matches a trusted config root."""
    if not project_root:
        return False
    try:
        real_project_root = _normalize_config_root(project_root)
    except (OSError, ValueError):
        return False
    for entry in trusted_roots:
        try:
            if real_project_root == _normalize_config_root(entry):
                return True
        except (OSError, ValueError):
            continue
    return False


def _is_project_config_trusted(project_root: str | None, global_cfg: dict) -> bool:
    """Return whether the active project config root is explicitly trusted."""
    trusted = _normalize_trusted_project_configs(global_cfg.get("trusted_project_configs", []))
    return _project_root_matches_trusted(project_root, trusted)


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


def _merge_dict_override(global_d: dict, project_d: dict, defaults: dict | None = None) -> dict:
    """Merge two dicts — project values override global (any valid policy accepted)."""
    merged = dict(global_d)
    for key, val in project_d.items():
        if val in _STRICTNESS:
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


def _merge_configs(
    global_cfg: dict,
    project_cfg: dict,
    target: str | None = None,
    *,
    selected_preset: str = "",
    project_root: str = "",
    project_config_path: str = "",
    project_config_trusted: bool | None = None,
) -> NahConfig:
    """Merge global and project configs with security rules."""
    global_cfg, selected_preset = _apply_global_preset(global_cfg, selected_preset)
    config = NahConfig()
    config.target = target or ""
    config.selected_preset = selected_preset
    config.project_root = project_root
    config.project_config_path = project_config_path
    config.trusted_project_configs = _normalize_trusted_project_configs(
        global_cfg.get("trusted_project_configs", [])
    )
    if project_config_trusted is None:
        project_config_trusted = _project_root_matches_trusted(
            project_root,
            config.trusted_project_configs,
        )
    config.project_config_trusted = bool(project_config_trusted)
    config.trust_project_config = False
    if "trust_project_config" in global_cfg:
        sys.stderr.write(
            "nah: trust_project_config is no longer supported and is ignored; "
            "use trusted_project_configs or nah trust-project\n"
        )
    _merge = _merge_dict_override if config.project_config_trusted else _merge_dict_tighten

    # classify: keep global and trusted project SEPARATE for three-table lookup
    config.classify_global = _canonicalize_classify(global_cfg.get("classify", {}))
    config.classify_project = (
        _canonicalize_classify(project_cfg.get("classify", {}))
        if config.project_config_trusted
        else {}
    )

    # actions: tighten only (or override if project config root is trusted)
    config.actions = _merge(
        _canonicalize_actions(global_cfg.get("actions", {})),
        _canonicalize_actions(project_cfg.get("actions", {})),
        defaults=_POLICIES,
    )

    # sensitive_paths_default: use project if stricter (or any valid value if trusted)
    g_default = global_cfg.get("sensitive_paths_default", "ask")
    p_default = project_cfg.get("sensitive_paths_default", "")
    if p_default and config.project_config_trusted and p_default in _STRICTNESS:
        config.sensitive_paths_default = p_default
    elif p_default and _STRICTNESS.get(p_default, 2) >= _STRICTNESS.get(g_default, 2):
        config.sensitive_paths_default = p_default
    else:
        config.sensitive_paths_default = g_default if g_default in _STRICTNESS else "ask"

    # sensitive_paths: tighten only (or override if project config root is trusted)
    config.sensitive_paths = _merge(
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
    config.content_policies = _merge(g_policies, p_policies)

    # credential_patterns: entirely global-only
    g_cred = _validate_dict(global_cfg.get("credential_patterns", {}))
    raw_cred_add = g_cred.get("add", [])
    config.credential_patterns_add = raw_cred_add if isinstance(raw_cred_add, list) else []
    raw_cred_suppress = g_cred.get("suppress", [])
    config.credential_patterns_suppress = raw_cred_suppress if isinstance(raw_cred_suppress, list) else []

    # llm: global config ONLY — project .nah.yaml silently ignored
    config.llm = _validate_dict(global_cfg.get("llm", {}))

    # llm.mode: global only. Backward compat for legacy llm.enabled=true.
    mode = _normalize_llm_mode(config.llm.get("mode", ""))
    if mode:
        config.llm_mode = mode
    elif "mode" not in config.llm and bool(config.llm.get("enabled", False)):
        config.llm_mode = "on"

    # Deprecation warning for removed llm.max_decision
    if config.llm.get("max_decision"):
        sys.stderr.write(
            "nah: llm.max_decision is deprecated and ignored"
            " — LLM decisions are now capped to ask\n"
        )

    # trusted_paths: global config ONLY (project .nah.yaml cannot set).
    # /tmp and /private/tmp are default scratch space; prompting on every temp
    # file write is pure friction.
    _default_trusted = ["/tmp", "/private/tmp"]
    g_trusted = global_cfg.get("trusted_paths", [])
    if isinstance(g_trusted, list):
        config.trusted_paths = [str(p) for p in g_trusted]
    # Merge defaults (user entries take priority, defaults just fill in)
    existing = set(config.trusted_paths)
    for p in _default_trusted:
        if p not in existing:
            config.trusted_paths.append(p)

    # trusted_containers: global config plus trusted project append only.
    # This loosens docker exec review, so untrusted project and target-scoped
    # config cannot influence it.
    config.trusted_containers = _normalize_trusted_containers(
        global_cfg.get("trusted_containers", [])
    )
    if config.project_config_trusted:
        existing_containers = set(config.trusted_containers)
        for identity in _normalize_trusted_containers(project_cfg.get("trusted_containers", [])):
            if identity not in existing_containers:
                config.trusted_containers.append(identity)
                existing_containers.add(identity)

    # db_targets: global config ONLY — project .nah.yaml silently ignored
    g_targets = global_cfg.get("db_targets", [])
    if isinstance(g_targets, list):
        config.db_targets = [t for t in g_targets if isinstance(t, dict)]

    # log: global config ONLY — project .nah.yaml silently ignored
    config.log = _validate_dict(global_cfg.get("log", {}))

    # active_allow: global config ONLY — controls whether ALLOW emits JSON
    raw_aa = global_cfg.get("active_allow", True)
    if isinstance(raw_aa, bool):
        config.active_allow = raw_aa
    elif isinstance(raw_aa, list):
        config.active_allow = [str(t) for t in raw_aa]
    else:
        config.active_allow = True

    # ui: global config ONLY — project .nah.yaml cannot affect prompt rendering
    config.ui = _validate_dict(global_cfg.get("ui", {}))
    config.ui_color = normalize_color_mode(config.ui.get("color", "auto"))

    global_targets = _validate_dict(global_cfg.get("targets", {}))
    project_targets = _validate_dict(project_cfg.get("targets", {}))
    config.targets = dict(global_targets)
    for key, val in project_targets.items():
        if isinstance(val, dict) and config.project_config_trusted:
            merged = dict(_validate_dict(config.targets.get(key, {})))
            merged.update(val)
            config.targets[key] = merged

    if target:
        _apply_target_config(config, target, global_targets, project_targets)

    return config


def _apply_target_config(
    config: NahConfig, target: str, global_targets: dict, project_targets: dict,
) -> None:
    """Apply target-scoped global/project overrides to an effective config."""
    global_data = _validate_dict(global_targets.get(target, {}))
    project_data = _validate_dict(project_targets.get(target, {}))

    shell_target = target in ("bash", "zsh")
    explicit_shell_llm = _has_target_llm_mode(global_data) or (
        config.project_config_trusted and _has_target_llm_mode(project_data)
    )

    _apply_target_data(config, global_data, trusted=True, explicit_shell_llm=True)
    _apply_target_data(
        config,
        project_data,
        trusted=config.project_config_trusted,
        explicit_shell_llm=True,
    )

    if shell_target and not explicit_shell_llm:
        config.llm_mode = "off"


def _has_target_llm_mode(data: dict) -> bool:
    llm_data = _validate_dict(data.get("llm", {}))
    return bool(_normalize_llm_mode(llm_data.get("mode")))


def _apply_target_data(
    config: NahConfig, data: dict, *, trusted: bool, explicit_shell_llm: bool,
) -> None:
    """Apply one target override block to ``config``."""
    if not data:
        return
    merge = _merge_dict_override if trusted else _merge_dict_tighten

    actions = _canonicalize_actions(data.get("actions", {}))
    if actions:
        config.actions = merge(config.actions, actions, defaults=_POLICIES)

    if "sensitive_paths_default" in data:
        raw = data.get("sensitive_paths_default")
        if raw in _STRICTNESS and (
            trusted
            or _STRICTNESS.get(raw, 2) >= _STRICTNESS.get(config.sensitive_paths_default, 2)
        ):
            config.sensitive_paths_default = raw

    sensitive = _validate_dict(data.get("sensitive_paths", {}))
    if sensitive:
        config.sensitive_paths = merge(config.sensitive_paths, sensitive)

    content = _validate_dict(data.get("content_patterns", {}))
    policies = _validate_dict(content.get("policies", {}))
    if policies:
        config.content_policies = merge(config.content_policies, policies)

    terminal = _validate_dict(data.get("terminal", {}))
    if trusted and terminal:
        merged_terminal = dict(config.terminal)
        merged_terminal.update(terminal)
        config.terminal = merged_terminal

    ui = _validate_dict(data.get("ui", {}))
    if trusted and ui:
        merged_ui = dict(config.ui)
        merged_ui.update(ui)
        config.ui = merged_ui
        if "color" in ui:
            config.ui_color = normalize_color_mode(ui.get("color"))

    llm = _validate_dict(data.get("llm", {}))
    if trusted and llm:
        mode = _normalize_llm_mode(llm.get("mode"))
        if mode:
            config.llm_mode = mode
    if trusted and "ask_fallback" in data:
        config.ask_fallback = _normalize_ask_fallback(
            data.get("ask_fallback"),
            context=f"targets.{config.target or '<unknown>'}",
        )


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
                if _roots_are_related(real_root, resolved_root):
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
