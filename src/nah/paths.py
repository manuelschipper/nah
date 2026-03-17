"""Path resolution, sensitive path matching, and project root detection."""

import os
import subprocess
import sys

from nah import taxonomy

_HOME = os.path.expanduser("~")
_HOOKS_DIR = os.path.realpath(os.path.join(_HOME, ".claude", "hooks"))
_NAH_CONFIG_DIR = os.path.realpath(os.path.join(_HOME, ".config", "nah"))

# Sensitive paths: (resolved_dir, display_name, policy)
# Hook path (~/.claude/hooks) and nah config (~/.config/nah) are NOT in this list —
# checked separately via is_hook_path() / is_nah_config_path() so they survive profile: none.
# These are hardcoded defaults for FD-004. FD-006 makes them configurable.
_SENSITIVE_DIRS: list[tuple[str, str, str]] = [
    (os.path.realpath(os.path.join(_HOME, ".ssh")), "~/.ssh", "block"),
    (os.path.realpath(os.path.join(_HOME, ".gnupg")), "~/.gnupg", "block"),
    (os.path.realpath(os.path.join(_HOME, ".git-credentials")), "~/.git-credentials", "block"),
    (os.path.realpath(os.path.join(_HOME, ".netrc")), "~/.netrc", "block"),
    (os.path.realpath(os.path.join(_HOME, ".aws")), "~/.aws", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".azure")), "~/.azure", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".config", "gcloud")), "~/.config/gcloud", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".docker", "config.json")), "~/.docker/config.json", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".terraform.d", "credentials.tfrc.json")), "~/.terraform.d/credentials.tfrc.json", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".terraformrc")), "~/.terraformrc", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".claude", "settings.json")), "~/.claude/settings.json", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".claude", "settings.local.json")), "~/.claude/settings.local.json", "ask"),
]

# Basename patterns: (basename, display_name, policy)
_SENSITIVE_BASENAMES: list[tuple[str, str, str]] = [
    (".env", ".env", "ask"),
    (".env.local", ".env.local", "ask"),
    (".env.production", ".env.production", "ask"),
    (".npmrc", ".npmrc", "ask"),
    (".pypirc", ".pypirc", "ask"),
]

_project_root: str | None = None
_project_root_resolved = False

# Snapshot of hardcoded defaults for reset (testing).
_SENSITIVE_DIRS_DEFAULTS = list(_SENSITIVE_DIRS)
_SENSITIVE_BASENAMES_DEFAULTS = list(_SENSITIVE_BASENAMES)
_sensitive_paths_merged = False


def resolve_path(raw: str) -> str:
    """Expand ~ and env vars, then resolve to absolute canonical path."""
    if not raw:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(raw))
    return os.path.realpath(expanded)


def friendly_path(resolved: str) -> str:
    """Replace home directory prefix with ~ for display."""
    if resolved.startswith(_HOME + os.sep):
        return "~" + resolved[len(_HOME):]
    if resolved == _HOME:
        return "~"
    return resolved


def is_hook_path(resolved: str) -> bool:
    """Check if path targets ~/.claude/hooks/ (self-protection)."""
    if not resolved:
        return False
    return resolved == _HOOKS_DIR or resolved.startswith(_HOOKS_DIR + os.sep)


def is_nah_config_path(resolved: str) -> bool:
    """Check if path targets ~/.config/nah/ (self-protection)."""
    if not resolved:
        return False
    return resolved == _NAH_CONFIG_DIR or resolved.startswith(_NAH_CONFIG_DIR + os.sep)


def is_sensitive(resolved: str) -> tuple[bool, str, str]:
    """Check path against sensitive paths list.

    Returns (matched, pattern_display, policy) where policy is "ask" or "block".
    """
    _ensure_sensitive_paths_merged()
    if not resolved:
        return False, "", ""

    # Check directory patterns
    for dir_path, display, policy in _SENSITIVE_DIRS:
        if resolved == dir_path or resolved.startswith(dir_path + os.sep):
            return True, display, policy

    # Check basename patterns
    basename = os.path.basename(resolved)
    for name, display, policy in _SENSITIVE_BASENAMES:
        if basename == name:
            return True, display, policy

    return False, "", ""


def _split_path_parts(raw: str) -> list[str]:
    """Split a Unix-like path into normalized components.

    This is intentionally string-based so it can reason about wildcard and
    command-substitution-style segments without executing shell syntax.
    """
    return [part for part in raw.split("/") if part and part != "."]


def _home_relative_sensitive_entries() -> list[tuple[tuple[str, ...], str, str]]:
    """Return sensitive entries expressed relative to the current home dir."""
    _ensure_sensitive_paths_merged()
    entries: list[tuple[tuple[str, ...], str, str]] = []
    for resolved, display, policy in _SENSITIVE_DIRS:
        if resolved == _HOME:
            continue
        if not resolved.startswith(_HOME + os.sep):
            continue
        rel = os.path.relpath(resolved, _HOME)
        parts = tuple(part for part in rel.split(os.sep) if part and part != ".")
        if parts:
            entries.append((parts, display, policy))
    return entries


def _check_dynamic_home_sensitive_path(raw: str) -> tuple[str, str] | None:
    """Conservatively detect sensitive home-style paths with dynamic user segments.

    Examples:
    - /home/*/.aws/credentials
    - /Users/$(whoami)/.ssh/id_rsa

    This does not execute shell syntax. It only matches sensitive home-relative
    suffixes immediately after a home-style prefix.
    """
    if not raw:
        return None

    expanded = os.path.expanduser(os.path.expandvars(raw))
    parts = _split_path_parts(expanded)
    if not parts:
        return None

    tails: list[list[str]] = []
    if parts[0] in ("home", "Users") and len(parts) >= 3:
        tails.append(parts[2:])
    elif parts[0] == "root" and len(parts) >= 2:
        tails.append(parts[1:])

    if not tails:
        return None

    for tail in tails:
        for rel_parts, display, policy in _home_relative_sensitive_entries():
            if len(tail) >= len(rel_parts) and tuple(tail[:len(rel_parts)]) == rel_parts:
                return policy, f"targets sensitive path: {display}"
    return None


def check_path_basic_raw(raw: str) -> tuple[str, str] | None:
    """Core path check that preserves conservative matching on raw input."""
    resolved = resolve_path(raw)
    basic = check_path_basic(resolved)
    if basic:
        return basic
    return _check_dynamic_home_sensitive_path(raw)


def check_path_basic(resolved: str) -> tuple[str, str] | None:
    """Core path check: hook → nah config → sensitive. Returns (decision, reason) or None."""
    if is_hook_path(resolved):
        return (taxonomy.ASK, f"targets hook directory: {friendly_path(resolved)}")
    if is_nah_config_path(resolved):
        return (taxonomy.ASK, f"targets nah config: {friendly_path(resolved)}")
    matched, pattern, policy = is_sensitive(resolved)
    if matched:
        return (policy, f"targets sensitive path: {pattern}")
    return None


def build_merged_sensitive_paths(config_paths: dict[str, str], config_default: str) -> None:
    """Merge user sensitive_paths with hardcoded lists. Modifies _SENSITIVE_DIRS in place.

    Global config can override hardcoded policies (e.g., ~/.ssh block -> ask).
    """
    existing_resolved = {entry[0] for entry in _SENSITIVE_DIRS}
    for path_str, policy in config_paths.items():
        expanded = os.path.expanduser(path_str)
        resolved = os.path.realpath(expanded)
        if policy == "allow":
            # Remove from sensitive list entirely (desensitize hardcoded entry)
            _SENSITIVE_DIRS[:] = [e for e in _SENSITIVE_DIRS if e[0] != resolved]
            existing_resolved.discard(resolved)
            continue
        if policy not in ("ask", "block"):
            continue
        if resolved in existing_resolved:
            # Override existing entry's policy
            for i, (dir_path, display, _old_policy) in enumerate(_SENSITIVE_DIRS):
                if dir_path == resolved:
                    _SENSITIVE_DIRS[i] = (dir_path, display, policy)
                    break
        else:
            display = path_str if path_str.startswith("~") else resolved
            _SENSITIVE_DIRS.append((resolved, display, policy))
            existing_resolved.add(resolved)


def _merge_sensitive_basenames(config: dict) -> None:
    """Merge user sensitive_basenames config into _SENSITIVE_BASENAMES.

    Policies: ask/block = add or override, allow = remove from defaults.
    """
    existing = {e[0] for e in _SENSITIVE_BASENAMES}
    for basename, policy in config.items():
        name = str(basename)
        policy = str(policy)
        if policy == "allow":
            # Remove from list
            _SENSITIVE_BASENAMES[:] = [e for e in _SENSITIVE_BASENAMES if e[0] != name]
            existing.discard(name)
        elif policy in ("ask", "block"):
            if name in existing:
                for i, (n, d, _) in enumerate(_SENSITIVE_BASENAMES):
                    if n == name:
                        _SENSITIVE_BASENAMES[i] = (n, d, policy)
                        break
            else:
                _SENSITIVE_BASENAMES.append((name, name, policy))
                existing.add(name)


def _ensure_sensitive_paths_merged() -> None:
    """Lazy one-time merge of config sensitive_paths and basenames."""
    global _sensitive_paths_merged
    if _sensitive_paths_merged:
        return
    _sensitive_paths_merged = True
    from nah.config import get_config  # lazy import to avoid circular
    cfg = get_config()
    if cfg.profile == "none":
        _SENSITIVE_DIRS.clear()
        _SENSITIVE_BASENAMES.clear()
    if cfg.sensitive_paths:
        build_merged_sensitive_paths(cfg.sensitive_paths, cfg.sensitive_paths_default)
    if cfg.sensitive_basenames:
        _merge_sensitive_basenames(cfg.sensitive_basenames)


def reset_sensitive_paths() -> None:
    """Restore _SENSITIVE_DIRS and _SENSITIVE_BASENAMES to hardcoded defaults (for testing)."""
    global _sensitive_paths_merged
    _sensitive_paths_merged = False
    _SENSITIVE_DIRS.clear()
    _SENSITIVE_DIRS.extend(_SENSITIVE_DIRS_DEFAULTS)
    _SENSITIVE_BASENAMES.clear()
    _SENSITIVE_BASENAMES.extend(_SENSITIVE_BASENAMES_DEFAULTS)


def check_path(tool_name: str, raw_path: str) -> dict | None:
    """Check a path for hook/sensitive violations. Returns decision dict or None (= allow)."""
    if not raw_path:
        return None

    # Tools where hook-path access is hard-blocked (self-protection).
    hook_block_tools = {"Write", "Edit"}

    resolved = resolve_path(raw_path)

    # Hook self-protection — Write/Edit get block (not just ask)
    if is_hook_path(resolved):
        if tool_name in hook_block_tools:
            return {
                "decision": taxonomy.BLOCK,
                "reason": f"{tool_name} targets hook directory: ~/.claude/hooks/ (self-modification blocked)",
            }
        return {
            "decision": taxonomy.ASK,
            "reason": f"{tool_name} targets hook directory: ~/.claude/hooks/",
        }

    # Config self-protection — ASK for all tools (users legitimately edit config)
    if is_nah_config_path(resolved):
        return {
            "decision": taxonomy.ASK,
            "reason": f"{tool_name} targets nah config: ~/.config/nah/ (guard self-protection)",
        }

    # Core check: sensitive paths
    basic = check_path_basic_raw(raw_path)
    if basic:
        decision, reason = basic
        # Check allow_paths exemption before returning
        from nah.config import is_path_allowed  # lazy import to avoid circular
        project_root = get_project_root()
        if is_path_allowed(raw_path, project_root):
            return None  # exempted

        if decision == taxonomy.BLOCK:
            return {
                "decision": taxonomy.BLOCK,
                "reason": f"{tool_name} {reason}",
            }
        return {
            "decision": taxonomy.ASK,
            "reason": f"{tool_name} {reason}",
            "_hint": f"To always allow: nah allow-path {friendly_path(resolved)}",
        }

    return None


def is_trusted_path(resolved: str) -> bool:
    """Check if resolved path is inside a trusted_paths directory."""
    from nah.config import get_config  # lazy import to avoid circular
    cfg = get_config()
    if cfg.profile == "none":
        return True  # boundary check disabled; defense in depth
    for entry in cfg.trusted_paths:
        trust_dir = resolve_path(entry)
        if resolved == trust_dir or resolved.startswith(trust_dir + os.sep):
            return True
    return False


def _suggest_trust_dir(raw_path: str) -> str:
    """Suggest a directory to trust for a given path.

    Under $HOME: ~/first_component (e.g. ~/builds).
    Elsewhere: parent directory (e.g. /tmp/foo/bar.txt → /tmp/foo).
    Special: if parent is root (/), return the resolved path itself.
    """
    resolved = resolve_path(raw_path)
    home = os.path.realpath(os.path.expanduser("~"))
    if resolved.startswith(home + os.sep):
        # Under home: return ~/first_component
        rel = resolved[len(home) + 1:]  # strip home + /
        first_component = rel.split(os.sep)[0]
        return f"~/{first_component}"
    # Outside home: return parent directory
    parent = os.path.dirname(resolved)
    if parent == "/":
        return resolved
    return parent


def check_project_boundary(tool_name: str, raw_path: str) -> dict | None:
    """Check if path is outside project root + trusted_paths. Returns dict or None (= allow)."""
    if not raw_path:
        return None
    from nah.config import get_config  # lazy import to avoid circular
    if get_config().profile == "none":
        return None  # boundary check disabled (D9)
    resolved = resolve_path(raw_path)
    if is_trusted_path(resolved):
        return None  # trusted — allow regardless of git root (FD-107)
    project_root = get_project_root()
    if project_root is None:
        return {
            "decision": taxonomy.ASK,
            "reason": f"{tool_name} outside project (no git root): {friendly_path(resolved)}",
            "_hint": f"To always allow: nah trust {_suggest_trust_dir(raw_path)}",
        }
    real_root = os.path.realpath(project_root)
    if resolved == real_root or resolved.startswith(real_root + os.sep):
        return None  # inside project
    if is_trusted_path(resolved):
        return None  # inside trusted directory
    return {
        "decision": taxonomy.ASK,
        "reason": f"{tool_name} outside project: {friendly_path(resolved)}",
        "_hint": f"To always allow: nah trust {_suggest_trust_dir(raw_path)}",
    }


def set_project_root(path: str) -> None:
    """Override project root (for testing). Bypasses git auto-detection."""
    global _project_root, _project_root_resolved
    _project_root = path
    _project_root_resolved = True


def reset_project_root() -> None:
    """Clear project root override, restoring auto-detection."""
    global _project_root, _project_root_resolved
    _project_root = None
    _project_root_resolved = False


def get_project_root() -> str | None:
    """Detect project root via git. Cached for process lifetime."""
    global _project_root, _project_root_resolved
    if _project_root_resolved:
        return _project_root
    _project_root_resolved = True
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=2,
        )
        if result.returncode == 0 and result.stdout.strip():
            _project_root = result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        sys.stderr.write("nah: git not available, project root detection skipped\n")
    return _project_root
