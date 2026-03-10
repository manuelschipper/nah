"""CLI entry point — install/uninstall/test commands."""

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from nah import __version__, agents

_HOOKS_DIR = Path.home() / ".claude" / "hooks"
_HOOK_SCRIPT = _HOOKS_DIR / "nah_guard.py"

_SHIM_TEMPLATE = '''\
#!{interpreter}
"""nah guard — thin shim that imports from the installed nah package."""
import sys, json, os, io

# Capture real stdout immediately — before anything can reassign it.
_REAL_STDOUT = sys.stdout
_ASK = '{{"hookSpecificOutput": {{"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "nah: error, requesting confirmation"}}}}\\n'
_LOG_PATH = os.path.join(os.path.expanduser("~"), ".config", "nah", "hook-errors.log")
_LOG_MAX = 1_000_000  # 1 MB

def _log_error(tool_name, error):
    """Append crash entry to log file. Never raises."""
    try:
        from datetime import datetime
        ts = datetime.now().isoformat(timespec="seconds")
        etype = type(error).__name__
        msg = str(error)[:200]
        line = f"{{ts}} {{tool_name or 'unknown'}} {{etype}}: {{msg}}\\n"
        os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
        try:
            size = os.path.getsize(_LOG_PATH)
        except OSError:
            size = 0
        if size > _LOG_MAX:
            with open(_LOG_PATH, "w") as f:
                f.write(line)
        else:
            with open(_LOG_PATH, "a") as f:
                f.write(line)
    except Exception:
        pass

def _safe_write(data):
    """Write string to real stdout, exit clean on broken pipe."""
    try:
        _REAL_STDOUT.write(data)
        _REAL_STDOUT.flush()
    except BrokenPipeError:
        pass

tool_name = ""
try:
    buf = io.StringIO()
    sys.stdout = buf
    from nah.hook import main
    main()
    sys.stdout = _REAL_STDOUT
    output = buf.getvalue()
    # Validate JSON
    try:
        json.loads(output)
        _safe_write(output)
    except (json.JSONDecodeError, ValueError):
        _log_error(tool_name, ValueError(f"invalid JSON from main: {{output[:200]}}"))
        _safe_write(_ASK)
except BaseException as e:
    sys.stdout = _REAL_STDOUT
    _log_error(tool_name, e)
    _safe_write(_ASK)

# Always exit clean — prevent Python shutdown from flushing/crashing.
os._exit(0)
'''


def _hook_command() -> str:
    """Build the command string for settings.json hook entries."""
    return f"{sys.executable} {_HOOK_SCRIPT}"


def _read_settings(settings_file: Path) -> dict:
    """Read a settings.json file, return empty structure if missing."""
    if settings_file.exists():
        with open(settings_file) as f:
            return json.load(f)
    return {}


def _write_settings(settings_file: Path, data: dict) -> None:
    """Write settings.json with backup."""
    backup = settings_file.with_suffix(".json.bak")
    if settings_file.exists():
        with open(settings_file) as f:
            backup_content = f.read()
        with open(backup, "w") as f:
            f.write(backup_content)

    settings_file.parent.mkdir(parents=True, exist_ok=True)
    with open(settings_file, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _is_nah_hook(hook_entry: dict) -> bool:
    """Check if a hook entry belongs to nah."""
    for hook in hook_entry.get("hooks", []):
        if "nah_guard.py" in hook.get("command", ""):
            return True
    return False


def _resolve_agents(args: argparse.Namespace) -> list[str]:
    """Resolve --agent flag to list of agent keys."""
    agent_arg = getattr(args, "agent", None) or agents.CLAUDE
    if agent_arg == "all":
        # Only install for agents whose settings dir exists
        result = []
        for key in sorted(agents.INSTALLABLE_AGENTS):
            settings_file = agents.AGENT_SETTINGS[key]
            if settings_file.parent.exists():
                result.append(key)
        if not result:
            print("No supported agent directories found.")
        return result
    if agent_arg not in agents.INSTALLABLE_AGENTS:
        print(f"Agent '{agent_arg}' is not installable. Supported: {', '.join(sorted(agents.INSTALLABLE_AGENTS))}")
        return []
    return [agent_arg]


def _write_hook_script() -> None:
    """Write the shared hook shim script (used by all agents)."""
    _HOOKS_DIR.mkdir(parents=True, exist_ok=True)

    if _HOOK_SCRIPT.exists():
        os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    shim_content = _SHIM_TEMPLATE.format(interpreter=sys.executable)
    with open(_HOOK_SCRIPT, "w") as f:
        f.write(shim_content)

    os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444


def _install_for_agent(agent_key: str) -> None:
    """Patch a single agent's settings.json with nah hook entries."""
    settings_file = agents.AGENT_SETTINGS[agent_key]
    tool_names = agents.AGENT_TOOL_MATCHERS[agent_key]
    agent_name = agents.AGENT_NAMES[agent_key]

    settings = _read_settings(settings_file)
    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    command = _hook_command()

    for tool_name in tool_names:
        existing = None
        for entry in pre_tool_use:
            if entry.get("matcher") == tool_name and _is_nah_hook(entry):
                existing = entry
                break

        if existing is not None:
            existing["hooks"] = [{"type": "command", "command": command}]
        else:
            pre_tool_use.append({
                "matcher": tool_name,
                "hooks": [{"type": "command", "command": command}],
            })

    _write_settings(settings_file, settings)
    backup = settings_file.with_suffix(".json.bak")

    print(f"  {agent_name}:")
    print(f"    Settings:  {settings_file} ({len(tool_names)} PreToolUse matchers)")
    if backup.exists():
        print(f"    Backup:    {backup}")


def cmd_install(args: argparse.Namespace) -> None:
    agent_keys = _resolve_agents(args)
    if not agent_keys:
        return

    _write_hook_script()

    print(f"nah {__version__} installed:")
    print(f"  Hook script: {_HOOK_SCRIPT} (read-only)")
    print(f"  Interpreter: {sys.executable}")

    for key in agent_keys:
        _install_for_agent(key)


def cmd_update(args: argparse.Namespace) -> None:
    """Update hook script: unlock → overwrite → re-lock. Update settings for targeted agents."""
    if not _HOOK_SCRIPT.exists():
        print(f"Hook script not found: {_HOOK_SCRIPT}")
        print("Run `nah install` first.")
        return

    _write_hook_script()

    agent_keys = _resolve_agents(args)
    command = _hook_command()

    for key in agent_keys:
        settings_file = agents.AGENT_SETTINGS[key]
        if settings_file.exists():
            settings = _read_settings(settings_file)
            hooks = settings.get("hooks", {})
            pre_tool_use = hooks.get("PreToolUse", [])
            updated = 0
            for entry in pre_tool_use:
                if _is_nah_hook(entry):
                    entry["hooks"] = [{"type": "command", "command": command}]
                    updated += 1
            if updated:
                _write_settings(settings_file, settings)
                print(f"  {agents.AGENT_NAMES[key]}: {settings_file} ({updated} hooks updated)")

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
                print(f"  [{i}] {tokens_str} → {sr.action_type} → {sr.default_policy} → {sr.decision} ({sr.reason})")
        if result.composition_rule:
            print(f"Composition: {result.composition_rule} → {result.final_decision.upper()}")
        print(f"Decision:    {result.final_decision.upper()}")
        print(f"Reason:      {result.reason}")
    elif tool in ("Write", "Edit"):
        # Write/Edit: reuse hook handlers
        from nah.hook import handle_write, handle_edit
        raw_input = " ".join(input_args)
        content_field = "content" if tool == "Write" else "new_string"
        handler = handle_write if tool == "Write" else handle_edit
        decision = handler({"file_path": raw_input, content_field: raw_input})
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
        decision = check or {"decision": "allow"}  # JSON protocol
        print(f"Tool:     {tool}")
        print(f"Input:    {raw_path}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", decision.get("message", ""))
        if reason:
            print(f"Reason:   {reason}")


def cmd_uninstall(args: argparse.Namespace) -> None:
    agent_keys = _resolve_agents(args)
    if not agent_keys:
        return

    # 1. Remove nah entries from each agent's settings.json
    for key in agent_keys:
        settings_file = agents.AGENT_SETTINGS[key]
        agent_name = agents.AGENT_NAMES[key]
        if settings_file.exists():
            settings = _read_settings(settings_file)
            hooks = settings.get("hooks", {})
            pre_tool_use = hooks.get("PreToolUse", [])

            filtered = [entry for entry in pre_tool_use if not _is_nah_hook(entry)]

            if filtered:
                hooks["PreToolUse"] = filtered
            else:
                hooks.pop("PreToolUse", None)

            _write_settings(settings_file, settings)
            print(f"  {agent_name}: {settings_file} (nah hooks removed)")
        else:
            print(f"  {agent_name}: settings not found (nothing to clean)")

    # 2. Remove hook script only if no other agents still have nah hooks
    any_remaining = False
    for key in agents.INSTALLABLE_AGENTS:
        if key in agent_keys:
            continue
        sf = agents.AGENT_SETTINGS[key]
        if sf.exists():
            try:
                data = _read_settings(sf)
                for entry in data.get("hooks", {}).get("PreToolUse", []):
                    if _is_nah_hook(entry):
                        any_remaining = True
                        break
            except Exception:
                pass

    if any_remaining:
        print(f"  Hook script: {_HOOK_SCRIPT} (kept — other agents still use it)")
    elif _HOOK_SCRIPT.exists():
        os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR)
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
    agent_help = "Agent to target: claude (default), cortex, or all"
    install_parser = sub.add_parser("install", help="Install nah hook into coding agents")
    install_parser.add_argument("--agent", default=None, help=agent_help)
    update_parser = sub.add_parser("update", help="Update hook script (unlock, overwrite, re-lock)")
    update_parser.add_argument("--agent", default=None, help=agent_help)
    uninstall_parser = sub.add_parser("uninstall", help="Remove nah hook from coding agents")
    uninstall_parser.add_argument("--agent", default=None, help=agent_help)
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
