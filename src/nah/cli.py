"""CLI entry point — install/uninstall commands."""

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from nah import __version__

_HOOKS_DIR = Path.home() / ".claude" / "hooks"
_HOOK_SCRIPT = _HOOKS_DIR / "nah_guard.py"
_SETTINGS_FILE = Path.home() / ".claude" / "settings.json"
_SETTINGS_BACKUP = Path.home() / ".claude" / "settings.json.bak"

_TOOL_NAMES = ["Bash", "Read", "Write", "Edit", "Glob", "Grep"]

_SHIM_TEMPLATE = '''\
#!{interpreter}
"""nah guard — thin shim that imports from the installed nah package."""
import sys, json
try:
    from nah.hook import main
    main()
except ImportError:
    sys.stderr.write("nah: package not found, allowing (run `nah install` to fix)\\n")
    json.dump({{"decision": "allow"}}, sys.stdout)
    sys.stdout.write("\\n")
except Exception as e:
    sys.stderr.write(f"nah: error: {{e}}, allowing\\n")
    json.dump({{"decision": "allow"}}, sys.stdout)
    sys.stdout.write("\\n")
'''


def _hook_command() -> str:
    """Build the command string for settings.json hook entries."""
    return f'{sys.executable} "$HOME/.claude/hooks/nah_guard.py"'


def _read_settings() -> dict:
    """Read ~/.claude/settings.json, return empty structure if missing."""
    if _SETTINGS_FILE.exists():
        with open(_SETTINGS_FILE) as f:
            return json.load(f)
    return {}


def _write_settings(data: dict) -> None:
    """Write settings.json with backup."""
    if _SETTINGS_FILE.exists():
        # Backup before modifying
        with open(_SETTINGS_FILE) as f:
            backup_content = f.read()
        with open(_SETTINGS_BACKUP, "w") as f:
            f.write(backup_content)

    _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _is_nah_hook(hook_entry: dict) -> bool:
    """Check if a hook entry belongs to nah."""
    for hook in hook_entry.get("hooks", []):
        if "nah_guard.py" in hook.get("command", ""):
            return True
    return False


def cmd_install(args: argparse.Namespace) -> None:
    # 1. Create hooks directory
    _HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Write shim script
    if _HOOK_SCRIPT.exists():
        # Make writable first (it's chmod 444)
        os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    shim_content = _SHIM_TEMPLATE.format(interpreter=sys.executable)
    with open(_HOOK_SCRIPT, "w") as f:
        f.write(shim_content)

    # 3. Set read-only
    os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444

    # 4. Patch settings.json
    settings = _read_settings()
    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    command = _hook_command()

    for tool_name in _TOOL_NAMES:
        # Check if nah entry already exists for this tool
        existing = None
        for entry in pre_tool_use:
            if entry.get("matcher") == tool_name and _is_nah_hook(entry):
                existing = entry
                break

        if existing is not None:
            # Update command in case interpreter path changed
            existing["hooks"] = [{"type": "command", "command": command}]
        else:
            pre_tool_use.append({
                "matcher": tool_name,
                "hooks": [{"type": "command", "command": command}],
            })

    _write_settings(settings)

    print(f"nah {__version__} installed:")
    print(f"  Hook script: {_HOOK_SCRIPT} (read-only)")
    print(f"  Settings:    {_SETTINGS_FILE} (6 PreToolUse matchers)")
    print(f"  Interpreter: {sys.executable}")
    if _SETTINGS_BACKUP.exists():
        print(f"  Backup:      {_SETTINGS_BACKUP}")


def cmd_uninstall(args: argparse.Namespace) -> None:
    # 1. Remove nah entries from settings.json
    if _SETTINGS_FILE.exists():
        settings = _read_settings()
        hooks = settings.get("hooks", {})
        pre_tool_use = hooks.get("PreToolUse", [])

        # Filter out nah entries
        filtered = [entry for entry in pre_tool_use if not _is_nah_hook(entry)]

        if filtered:
            hooks["PreToolUse"] = filtered
        else:
            hooks.pop("PreToolUse", None)

        _write_settings(settings)
        print(f"  Settings:    {_SETTINGS_FILE} (nah hooks removed)")
    else:
        print("  Settings:    not found (nothing to clean)")

    # 2. Remove hook script
    if _HOOK_SCRIPT.exists():
        os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR)  # make writable
        _HOOK_SCRIPT.unlink()
        print(f"  Hook script: {_HOOK_SCRIPT} (deleted)")
    else:
        print(f"  Hook script: {_HOOK_SCRIPT} (not found)")

    print("nah uninstalled.")


def main():
    parser = argparse.ArgumentParser(
        prog="nah",
        description="Context-aware safety guard for Claude Code.",
    )
    parser.add_argument(
        "--version", action="version", version=f"nah {__version__}",
    )

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("install", help="Install nah hook into Claude Code")
    sub.add_parser("uninstall", help="Remove nah hook from Claude Code")

    args = parser.parse_args()

    if args.command == "install":
        cmd_install(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
