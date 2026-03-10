"""CLI entry point — install/uninstall/test commands."""

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
import signal, sys, json, os

# Die silently on broken pipe instead of cascading BrokenPipeError.
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

def _allow():
    """Write allow decision, suppressing broken pipe."""
    try:
        json.dump({{"decision": "allow"}}, sys.stdout)
        sys.stdout.write("\\n")
        sys.stdout.flush()
    except BrokenPipeError:
        os._exit(0)

try:
    from nah.hook import main
    main()
except ImportError:
    sys.stderr.write("nah: package not found, allowing (run `nah install` to fix)\\n")
    _allow()
except BaseException as e:
    sys.stderr.write(f"nah: error: {{e}}, allowing\\n")
    _allow()

try:
    sys.stdout.flush()
except BrokenPipeError:
    os._exit(0)
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


def cmd_update(args: argparse.Namespace) -> None:
    """Update hook script: unlock → overwrite → re-lock."""
    if not _HOOK_SCRIPT.exists():
        print(f"Hook script not found: {_HOOK_SCRIPT}")
        print("Run `nah install` first.")
        return

    # 1. Unlock (chmod 644)
    os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    # 2. Overwrite with latest shim
    shim_content = _SHIM_TEMPLATE.format(interpreter=sys.executable)
    with open(_HOOK_SCRIPT, "w") as f:
        f.write(shim_content)

    # 3. Re-lock (chmod 444)
    os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    # 4. Update settings.json command in case interpreter changed
    if _SETTINGS_FILE.exists():
        settings = _read_settings()
        hooks = settings.get("hooks", {})
        pre_tool_use = hooks.get("PreToolUse", [])
        command = _hook_command()
        updated = 0
        for entry in pre_tool_use:
            if _is_nah_hook(entry):
                entry["hooks"] = [{"type": "command", "command": command}]
                updated += 1
        if updated:
            _write_settings(settings)

    print(f"nah {__version__} updated:")
    print(f"  Hook script: {_HOOK_SCRIPT} (re-locked read-only)")
    print(f"  Interpreter: {sys.executable}")


def cmd_config(args: argparse.Namespace) -> None:
    """Config subcommands."""
    sub = getattr(args, "config_command", None)
    if sub == "show":
        from nah.config import get_config
        cfg = get_config()
        print("Effective config (merged):")
        print(f"  classify:              {cfg.classify or '{}'}")
        print(f"  actions:               {cfg.actions or '{}'}")
        print(f"  sensitive_paths_default: {cfg.sensitive_paths_default}")
        print(f"  sensitive_paths:       {cfg.sensitive_paths or '{}'}")
        print(f"  allow_paths:           {cfg.allow_paths or '{}'}")
        print(f"  known_registries:      {cfg.known_registries or '[]'}")
    elif sub == "path":
        from nah.config import get_global_config_path, get_project_config_path
        print(f"Global:  {get_global_config_path()}")
        proj = get_project_config_path()
        print(f"Project: {proj or '(no project root)'}")
    else:
        print("Usage: nah config {show|path}")


def cmd_test(args: argparse.Namespace) -> None:
    """Dry-run classification for a command or tool input."""
    tool = getattr(args, "tool", None) or "Bash"
    input_args = args.args

    if tool == "Bash":
        command = " ".join(input_args)
        from nah.bash import classify_command
        result = classify_command(command)

        print(f"Command:  {result.command}")
        if result.stages:
            print("Stages:")
            for i, sr in enumerate(result.stages, 1):
                tokens_str = " ".join(sr.tokens)
                print(f"  [{i}] {tokens_str} → {sr.action_type} → {sr.policy} → {sr.decision} ({sr.reason})")
        if result.composition_rule:
            print(f"Composition: {result.composition_rule} → {result.final_decision.upper()}")
        print(f"Decision:    {result.final_decision.upper()}")
        print(f"Reason:      {result.reason}")
    elif tool in ("Write", "Edit"):
        # Write/Edit: path check + content inspection
        from nah import paths
        from nah.content import scan_content, format_content_message
        raw_input = " ".join(input_args)
        # Path check
        check = paths.check_path(tool, raw_input)
        if check:
            decision = check
        else:
            # Content inspection
            matches = scan_content(raw_input)
            if matches:
                decision = {"decision": "ask", "message": format_content_message(tool, matches)}
            else:
                decision = {"decision": "allow"}
        print(f"Tool:     {tool}")
        print(f"Input:    {raw_input[:100]}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", decision.get("message", ""))
        if reason:
            print(f"Reason:   {reason}")
    else:
        # Non-Bash tools — use hook handlers
        from nah import paths
        raw_path = " ".join(input_args)
        check = paths.check_path(tool, raw_path)
        decision = check or {"decision": "allow"}
        print(f"Tool:     {tool}")
        print(f"Input:    {raw_path}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", decision.get("message", ""))
        if reason:
            print(f"Reason:   {reason}")


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
    sub.add_parser("update", help="Update hook script (unlock, overwrite, re-lock)")
    sub.add_parser("uninstall", help="Remove nah hook from Claude Code")
    test_parser = sub.add_parser("test", help="Dry-run classification for a command")
    test_parser.add_argument("--tool", default=None, help="Tool name (default: Bash)")
    test_parser.add_argument("args", nargs="+", help="Command string or tool input")
    config_parser = sub.add_parser("config", help="Show config info")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_sub.add_parser("show", help="Display effective merged config")
    config_sub.add_parser("path", help="Show config file paths")

    args = parser.parse_args()

    if args.command == "install":
        cmd_install(args)
    elif args.command == "update":
        cmd_update(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "config":
        cmd_config(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
