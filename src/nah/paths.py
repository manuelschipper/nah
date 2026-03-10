"""Path resolution, sensitive path matching, and project root detection."""

import os
import subprocess

_HOME = os.path.expanduser("~")
_HOOKS_DIR = os.path.realpath(os.path.join(_HOME, ".claude", "hooks"))

# Sensitive paths: (resolved_dir, display_name, policy)
# Hook path (~/.claude/hooks) is NOT in this list — checked separately via is_hook_path().
# These are hardcoded defaults for FD-004. FD-006 makes them configurable.
_SENSITIVE_DIRS: list[tuple[str, str, str]] = [
    (os.path.realpath(os.path.join(_HOME, ".ssh")), "~/.ssh", "block"),
    (os.path.realpath(os.path.join(_HOME, ".gnupg")), "~/.gnupg", "block"),
    (os.path.realpath(os.path.join(_HOME, ".git-credentials")), "~/.git-credentials", "block"),
    (os.path.realpath(os.path.join(_HOME, ".netrc")), "~/.netrc", "block"),
    (os.path.realpath(os.path.join(_HOME, ".aws")), "~/.aws", "ask"),
    (os.path.realpath(os.path.join(_HOME, ".config", "gcloud")), "~/.config/gcloud", "ask"),
]

# Basename patterns: (basename, display_name, policy)
_SENSITIVE_BASENAMES: list[tuple[str, str, str]] = [
    (".env", ".env", "ask"),
]

_project_root: str | None = None
_project_root_resolved = False


def resolve_path(raw: str) -> str:
    """Expand ~ and resolve to absolute canonical path."""
    if not raw:
        return ""
    return os.path.realpath(os.path.expanduser(raw))


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


def is_sensitive(resolved: str) -> tuple[bool, str, str]:
    """Check path against sensitive paths list.

    Returns (matched, pattern_display, policy) where policy is "ask" or "block".
    """
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
        pass
    return _project_root
