"""CLI entry point — install/uninstall/test commands."""

import argparse
import json
import os
import shlex
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
    # Non-empty output = active decision (allow, ask, or deny).
    # Empty output = active_allow disabled, falls through to Claude Code's permission system.
    if not output.strip():
        pass  # active_allow disabled — fall through to Claude Code
    else:
        try:
            json.loads(output)
            _safe_write(output)
        except (json.JSONDecodeError, ValueError):
            _log_error(tool_name, ValueError(f"invalid JSON from main: {{output[:200]}}"))
            _safe_write(_ASK)
except SystemExit as e:
    sys.stdout = _REAL_STDOUT
    os._exit(e.code if e.code is not None else 0)
except BaseException as e:
    sys.stdout = _REAL_STDOUT
    _log_error(tool_name, e)
    _safe_write(_ASK)

# Always exit clean — prevent Python shutdown from flushing/crashing.
os._exit(0)
'''


def _hook_command() -> str:
    """Build the command string for settings.json hook entries."""
    # Use POSIX forward-slash paths: safe in both bash and cmd.exe on Windows.
    # shlex.quote() produces POSIX single-quoting which only works when the
    # command is interpreted by a POSIX shell. Claude Code may invoke hooks
    # via cmd.exe or direct OS spawn, where single quotes are literal chars.
    # as_posix() eliminates backslashes at the source, sidestepping the issue.
    exe = Path(sys.executable).as_posix()
    script = _HOOK_SCRIPT.as_posix()
    return f'"{exe}" "{script}"'


def _build_hooks_settings() -> dict:
    """Build a settings dict containing nah PreToolUse hooks for Claude Code."""
    command = _hook_command()
    pre_tool_use = []
    for tool_name in agents.AGENT_TOOL_MATCHERS[agents.CLAUDE]:
        pre_tool_use.append({
            "matcher": tool_name,
            "hooks": [{"type": "command", "command": command}],
        })
    return {"hooks": {"PreToolUse": pre_tool_use}}


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

    shim_content = _SHIM_TEMPLATE.format(interpreter=sys.executable)

    # Skip write if content is identical
    if _HOOK_SCRIPT.exists():
        try:
            if _HOOK_SCRIPT.read_text() == shim_content:
                return
        except OSError:
            # Read is best-effort optimization; if it fails (race with
            # deletion, permissions, disk), the safe default is to fall
            # through to the write path which will surface real errors.
            pass

    if _HOOK_SCRIPT.exists():
        os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

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

    print()
    print("Ready. Safe commands go through silently, dangerous ones are")
    print("blocked, ambiguous ones ask for confirmation.")


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
        print(f"  profile:               {cfg.profile}")
        print(f"  classify_global:       {cfg.classify_global or '{}'}")
        print(f"  classify_project:      {cfg.classify_project or '{}'}")
        print(f"  actions:               {cfg.actions or '{}'}")
        print(f"  sensitive_paths_default: {cfg.sensitive_paths_default}")
        print(f"  sensitive_paths:       {cfg.sensitive_paths or '{}'}")
        print(f"  allow_paths:           {cfg.allow_paths or '{}'}")
        print(f"  trusted_paths:         {cfg.trusted_paths or '[]'}")
        print(f"  known_registries:      {cfg.known_registries or '[]'}")
        print(f"  exec_sinks:            {cfg.exec_sinks or '[]'}")
        print(f"  sensitive_basenames:   {cfg.sensitive_basenames or '{}'}")
        print(f"  decode_commands:       {cfg.decode_commands or '[]'}")
        print(f"  content_patterns_add:  {cfg.content_patterns_add or '[]'}")
        print(f"  content_patterns_suppress: {cfg.content_patterns_suppress or '[]'}")
        print(f"  content_policies:      {cfg.content_policies or '{}'}")
        print(f"  credential_patterns_add: {cfg.credential_patterns_add or '[]'}")
        print(f"  credential_patterns_suppress: {cfg.credential_patterns_suppress or '[]'}")
        print(f"  db_targets:            {cfg.db_targets or '[]'}")
        print(f"  llm:                   {cfg.llm or '{}'}")
        print(f"  llm_max_decision:      {cfg.llm_max_decision}")
        print(f"  llm_eligible:          {cfg.llm_eligible}")
        print(f"  log:                   {cfg.log or '{}'}")
        print(f"  active_allow:          {cfg.active_allow}")
    elif sub == "path":
        from nah.config import get_global_config_path, get_project_config_path
        print(f"Global:  {get_global_config_path()}")
        proj = get_project_config_path()
        print(f"Project: {proj or '(no project root)'}")
    else:
        print("Usage: nah config {show|path}")


def cmd_test(args: argparse.Namespace) -> None:
    """Dry-run classification for a command or tool input."""
    if getattr(args, "config", None):
        import json as json_mod
        try:
            override = json_mod.loads(args.config)
        except json.JSONDecodeError as e:
            print(f"Error: invalid --config JSON: {e}", file=sys.stderr)
            raise SystemExit(1)
        from nah.config import apply_override
        apply_override(override)

    tool = getattr(args, "tool", None) or "Bash"
    input_args = args.args

    if tool == "Bash":
        if not input_args:
            print("Error: nah test requires a command string", file=sys.stderr)
            raise SystemExit(1)
        command = input_args[0] if len(input_args) == 1 else shlex.join(input_args)
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
        if result.final_decision == "ask":
            from nah.hook import _is_llm_eligible
            eligible = _is_llm_eligible(result)
            print(f"LLM eligible: {'yes' if eligible else 'no'}")
            if eligible:
                from nah.config import get_config
                cfg = get_config()
                if not cfg.llm:
                    print("LLM config:   not configured")
                elif not cfg.llm.get("enabled", False):
                    print("LLM config:   disabled (set enabled: true to activate)")
                else:
                    from nah.llm import try_llm
                    llm_call = try_llm(result, cfg.llm)
                    if llm_call.decision is not None:
                        d = llm_call.decision.get("decision", "uncertain")
                        print(f"LLM decision: {d.upper()}")
                        print(f"LLM provider: {llm_call.provider} ({llm_call.model})")
                        print(f"LLM latency:  {llm_call.latency_ms}ms")
                        if llm_call.reasoning:
                            print(f"LLM reason:   {llm_call.reasoning}")
                    else:
                        if llm_call.cascade:
                            statuses = ", ".join(f"{a.provider}={a.status}" for a in llm_call.cascade)
                            print(f"LLM decision: (uncertain or unavailable) [{statuses}]")
                        else:
                            print("LLM decision: (no providers responded)")
    elif tool in ("Write", "Edit"):
        # Write/Edit: path + content inspection
        from nah.hook import handle_write, handle_edit
        file_path = getattr(args, "path", None) or " ".join(input_args)
        content = getattr(args, "content", None) or ""
        content_field = "content" if tool == "Write" else "new_string"
        handler = handle_write if tool == "Write" else handle_edit
        decision = handler({"file_path": file_path, content_field: content})
        print(f"Tool:     {tool}")
        print(f"Path:     {file_path}")
        if content:
            print(f"Content:  {content[:100]}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", "")
        if reason:
            print(f"Reason:   {reason}")
    elif tool == "Grep":
        # Grep: path + credential pattern detection
        from nah.hook import handle_grep
        raw_path = getattr(args, "path", None) or " ".join(input_args)
        pattern = getattr(args, "pattern", None) or ""
        decision = handle_grep({"path": raw_path, "pattern": pattern})
        print(f"Tool:     {tool}")
        print(f"Path:     {raw_path}")
        if pattern:
            print(f"Pattern:  {pattern}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", "")
        if reason:
            print(f"Reason:   {reason}")
    elif tool.startswith("mcp__"):
        # MCP tools: classify via taxonomy
        from nah.hook import _classify_unknown_tool
        decision = _classify_unknown_tool(tool)
        print(f"Tool:     {tool}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", "")
        if reason:
            print(f"Reason:   {reason}")
    else:
        # Path-only tools (Read, Glob, etc.)
        from nah import paths
        raw_path = getattr(args, "path", None) or " ".join(input_args)
        check = paths.check_path(tool, raw_path)
        decision = check or {"decision": "allow"}  # JSON protocol
        print(f"Tool:     {tool}")
        print(f"Input:    {raw_path}")
        print(f"Decision: {decision['decision'].upper()}")
        reason = decision.get("reason", "")
        if reason:
            print(f"Reason:   {reason}")


def cmd_uninstall(args: argparse.Namespace) -> None:
    agent_keys = _resolve_agents(args)
    if not agent_keys:
        return

    # 1. Remove nah entries from each agent's config
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
            except Exception as exc:
                sys.stderr.write(f"nah: uninstall: {exc}\n")

    if any_remaining:
        print(f"  Hook script: {_HOOK_SCRIPT} (kept — other agents still use it)")
    elif _HOOK_SCRIPT.exists():
        os.chmod(_HOOK_SCRIPT, stat.S_IRUSR | stat.S_IWUSR)
        _HOOK_SCRIPT.unlink()
        print(f"  Hook script: {_HOOK_SCRIPT} (deleted)")
    else:
        print(f"  Hook script: {_HOOK_SCRIPT} (not found)")

    print("nah uninstalled.")


def _confirm(message: str) -> bool:
    """Prompt y/N. Non-interactive (piped) → False."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(f"{message} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def _warn_comments(project: bool) -> None:
    """Warn and confirm if config has comments. Exits on deny."""
    from nah.remember import has_comments
    from nah.config import get_global_config_path, get_project_config_path
    path = get_project_config_path() if project else get_global_config_path()
    if path and has_comments(path):
        if not _confirm(
            f"\u26a0 {os.path.basename(path)} has comments that will be removed by this write.\nProceed?"
        ):
            sys.exit(1)


def cmd_allow(args: argparse.Namespace) -> None:
    """Allow an action type."""
    from nah.remember import write_action, CustomTypeError
    _warn_comments(args.project)
    try:
        msg = write_action(args.action_type, "allow", project=args.project)
        print(msg)
    except CustomTypeError:
        if not _confirm(f"\u26a0 '{args.action_type}' is not a built-in type. Create it?"):
            sys.exit(1)
        msg = write_action(args.action_type, "allow", project=args.project, allow_custom=True)
        print(msg)
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_deny(args: argparse.Namespace) -> None:
    """Deny an action type."""
    from nah.remember import write_action, CustomTypeError
    _warn_comments(args.project)
    try:
        msg = write_action(args.action_type, "block", project=args.project)
        print(msg)
    except CustomTypeError:
        if not _confirm(f"\u26a0 '{args.action_type}' is not a built-in type. Create it?"):
            sys.exit(1)
        msg = write_action(args.action_type, "block", project=args.project, allow_custom=True)
        print(msg)
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_allow_path(args: argparse.Namespace) -> None:
    """Allow a sensitive path for the current project."""
    from nah.remember import write_allow_path
    _warn_comments(project=False)
    try:
        msg = write_allow_path(args.path)
        print(msg)
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_classify(args: argparse.Namespace) -> None:
    """Classify a command prefix as an action type."""
    from nah.remember import write_classify, CustomTypeError
    _warn_comments(args.project)
    try:
        msg = write_classify(args.command_prefix, args.type, project=args.project)
        print(msg)
    except CustomTypeError:
        if not _confirm(f"\u26a0 '{args.type}' is not a built-in type. Create it?"):
            sys.exit(1)
        msg = write_classify(args.command_prefix, args.type, project=args.project, allow_custom=True)
        print(msg)
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_trust(args: argparse.Namespace) -> None:
    """Trust a path or network host (global config only)."""
    target = args.target
    is_path = target.startswith(("/", "~", "."))

    if is_path and getattr(args, "project", False):
        print("trusted_paths is global-only — cannot use --project", file=sys.stderr)
        sys.exit(1)

    _warn_comments(project=False)

    if is_path:
        from nah.remember import write_trust_path
        from nah.paths import resolve_path, is_sensitive
        resolved = resolve_path(target)
        if resolved == "/":
            print("nah: refusing to trust filesystem root", file=sys.stderr)
            sys.exit(1)
        home = os.path.realpath(os.path.expanduser("~"))
        if resolved == home:
            print("\u26a0 Trusting ~ allows writes to your entire home directory.")
            print("  Sensitive paths (~/.ssh, ~/.aws, ...) are still protected.")
            if not _confirm("Continue?"):
                sys.exit(1)
        # Informational warning if path overlaps a sensitive path
        matched, pattern, _policy = is_sensitive(resolved)
        if matched:
            print(f"\u26a0 {pattern} is a sensitive path \u2014 still blocked/asked regardless.")
        try:
            msg = write_trust_path(target)
            print(msg)
        except (ValueError, RuntimeError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
    else:
        from nah.remember import write_trust_host
        try:
            msg = write_trust_host(target)
            print(msg)
        except (ValueError, RuntimeError) as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)


def cmd_status(args: argparse.Namespace) -> None:
    """Show all custom rules."""
    from nah.remember import list_rules
    try:
        rules = list_rules()
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    any_rules = False
    for scope in ("global", "project"):
        scope_rules = rules.get(scope, {})
        if not scope_rules:
            continue
        any_rules = True
        print(f"{scope.upper()} config:")
        if "actions" in scope_rules:
            for action_type, policy in scope_rules["actions"].items():
                print(f"  action: {action_type} → {policy}")
        if "allow_paths" in scope_rules:
            for path, roots in scope_rules["allow_paths"].items():
                print(f"  allow-path: {path} → {', '.join(roots)}")
        if "classify" in scope_rules:
            # Shadow warnings only for global scope — project entries are
            # Phase 3 (checked after builtin), so they can't shadow.
            table_shadows: dict = {}
            flag_shadows: set = set()
            if scope == "global":
                from nah.taxonomy import (build_user_table, get_builtin_table,
                                          find_table_shadows, find_flag_classifier_shadows)
                from nah.config import get_config
                cfg = get_config()
                user_classify = scope_rules["classify"]
                user_table = build_user_table(user_classify)
                builtin_table = get_builtin_table(cfg.profile) if cfg.profile != "none" else []
                table_shadows = find_table_shadows(user_table, builtin_table)
                flag_shadows = set(find_flag_classifier_shadows(user_table))
            for action_type, prefixes in scope_rules["classify"].items():
                for prefix in prefixes:
                    prefix_tuple = tuple(prefix.split())
                    annotations = []
                    if prefix_tuple in table_shadows:
                        count = len(table_shadows[prefix_tuple])
                        annotations.append(f"shadows {count} built-in rule{'s' if count != 1 else ''}")
                    if prefix_tuple in flag_shadows:
                        annotations.append("shadows flag classifier")
                    suffix = f"  ({'; '.join(annotations)})" if annotations else ""
                    print(f"  classify: '{prefix}' → {action_type}{suffix}")
        if "known_registries" in scope_rules:
            kr = scope_rules["known_registries"]
            if isinstance(kr, list):
                for host in kr:
                    print(f"  trust: {host}")
            elif isinstance(kr, dict):
                from nah.config import _parse_add_remove
                add, remove = _parse_add_remove(kr)
                for host in add:
                    print(f"  trust: {host}")
                for host in remove:
                    print(f"  trust: !{host}")
        if "exec_sinks" in scope_rules:
            from nah.config import _parse_add_remove
            add, remove = _parse_add_remove(scope_rules["exec_sinks"])
            for s in add:
                print(f"  exec-sink: {s}")
            for s in remove:
                print(f"  exec-sink: !{s}")
        if "sensitive_basenames" in scope_rules:
            for name, policy in scope_rules["sensitive_basenames"].items():
                print(f"  sensitive-basename: {name} → {policy}")
        if "trusted_paths" in scope_rules:
            for p in scope_rules["trusted_paths"]:
                print(f"  trust-path: {p}")
        if "decode_commands" in scope_rules:
            from nah.config import _parse_add_remove
            add, remove = _parse_add_remove(scope_rules["decode_commands"])
            for d in add:
                print(f"  decode-command: {d}")
            for d in remove:
                print(f"  decode-command: !{d}")

    if not any_rules:
        print("No custom rules configured.")


def cmd_forget(args: argparse.Namespace) -> None:
    """Remove a rule."""
    from nah.remember import forget_rule
    try:
        msg = forget_rule(args.arg, project=args.project, global_only=args.global_flag)
        print(msg)
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_types(args: argparse.Namespace) -> None:
    """List all action types."""
    from nah.taxonomy import (load_type_descriptions, get_policy, build_user_table,
                              get_builtin_table, find_table_shadows,
                              find_flag_classifier_shadows)
    from nah.remember import list_rules
    from nah.config import get_config

    descriptions = load_type_descriptions()
    cfg = get_config()

    # Gather shadow data from global classify entries only — project entries
    # are Phase 3 (checked after builtin), so they can't shadow.
    override_notes: dict[str, list[str]] = {}
    try:
        rules = list_rules()
    except RuntimeError:
        rules = {}
    user_classify = rules.get("global", {}).get("classify", {})
    if user_classify:
        builtin_table = get_builtin_table(cfg.profile) if cfg.profile != "none" else []
        user_table = build_user_table(user_classify)
        table_shadows = find_table_shadows(user_table, builtin_table)
        flag_shadows = set(find_flag_classifier_shadows(user_table))
        for action_type, prefixes in user_classify.items():
            for prefix in prefixes:
                prefix_tuple = tuple(prefix.split())
                parts = []
                if prefix_tuple in table_shadows:
                    count = len(table_shadows[prefix_tuple])
                    parts.append(f"overrides {count} built-in rule{'s' if count != 1 else ''}")
                if prefix_tuple in flag_shadows:
                    parts.append("overrides flag classifier")
                if parts:
                    note = f"'{prefix}' {'; '.join(parts)} (nah forget {prefix} to use built-in)"
                    override_notes.setdefault(action_type, []).append(note)

    for name, desc in descriptions.items():
        policy = get_policy(name)
        print(f"  {name:<25} {policy:<8} {desc}")
        for note in override_notes.get(name, []):
            print(f"    \u21b3 {note}")


def cmd_log(args: argparse.Namespace) -> None:
    """Display recent decision log entries."""
    from nah.log import read_log

    filters: dict = {}
    if getattr(args, "blocks", False):
        filters["decision"] = "block"
    elif getattr(args, "asks", False):
        filters["decision"] = "ask"
    tool = getattr(args, "tool", None)
    if tool:
        filters["tool"] = tool

    limit = getattr(args, "limit", 50)
    json_output = getattr(args, "json", False)

    entries = read_log(filters=filters, limit=limit)

    if not entries:
        print("No log entries found.")
        return

    if json_output:
        for entry in entries:
            print(json.dumps(entry))
        return

    for entry in entries:
        ts = entry.get("ts", "?")[:19]
        tool_name = entry.get("tool", "?")
        decision = entry.get("decision", "?").upper()
        reason = entry.get("reason", "")
        summary = entry.get("input", "")
        total_ms = entry.get("ms", "")

        if decision == "BLOCK":
            marker = "! "
        elif decision == "ASK":
            marker = "? "
        else:
            marker = "  "

        line = f"{ts}  {marker}{decision:<5}  {tool_name:<5}  {summary[:60]}"
        if reason:
            line += f"  ({reason[:40]})"
        if total_ms != "":
            line += f"  [{total_ms}ms]"
        llm_prov = entry.get("llm", {}).get("provider", "")
        if llm_prov:
            llm_model = entry.get("llm", {}).get("model", "")
            llm_tag = f"  LLM:{llm_prov}"
            if llm_model:
                llm_tag += f"/{llm_model}"
            line += llm_tag
        print(line)


def cmd_claude(user_args: list[str]) -> None:
    """Launch Claude Code with nah hooks active for this session."""
    import shutil

    for arg in user_args:
        if arg == "--settings" or arg.startswith("--settings="):
            print("nah claude: --settings is managed by nah; pass other flags directly",
                  file=sys.stderr)
            raise SystemExit(1)

    claude_path = shutil.which("claude")
    if claude_path is None:
        print("nah claude: 'claude' not found on PATH", file=sys.stderr)
        raise SystemExit(1)

    settings_file = agents.AGENT_SETTINGS[agents.CLAUDE]
    already_installed = False
    if settings_file.exists():
        settings = _read_settings(settings_file)
        for entry in settings.get("hooks", {}).get("PreToolUse", []):
            if _is_nah_hook(entry):
                already_installed = True
                break

    if already_installed:
        os.execvp(claude_path, ["claude"] + user_args)
    else:
        _write_hook_script()
        settings_json = json.dumps(_build_hooks_settings())
        os.execvp(claude_path, ["claude", "--settings", settings_json] + user_args)


def main():
    parser = argparse.ArgumentParser(
        prog="nah",
        description="Context-aware safety guard for Claude Code.",
    )
    parser.add_argument(
        "--version", action="version", version=f"nah {__version__}",
    )

    sub = parser.add_subparsers(dest="command")
    agent_help = "Agent to target: claude (default)"
    install_parser = sub.add_parser("install", help="Install nah hook into coding agents")
    install_parser.add_argument("--agent", default=None, help=agent_help)
    update_parser = sub.add_parser("update", help="Update hook script (unlock, overwrite, re-lock)")
    update_parser.add_argument("--agent", default=None, help=agent_help)
    uninstall_parser = sub.add_parser("uninstall", help="Remove nah hook from coding agents")
    uninstall_parser.add_argument("--agent", default=None, help=agent_help)
    test_parser = sub.add_parser("test", help="Dry-run classification for a command")
    test_parser.add_argument("--tool", default=None, help="Tool name (default: Bash)")
    test_parser.add_argument("--path", default=None, help="File/dir path for tool input")
    test_parser.add_argument("--content", default=None, help="Content for Write/Edit inspection")
    test_parser.add_argument("--pattern", default=None, help="Search pattern for Grep")
    test_parser.add_argument("--config", default=None, help="Inline JSON config override")
    test_parser.add_argument("args", nargs="*", help="Command string or tool input")
    config_parser = sub.add_parser("config", help="Show config info")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_sub.add_parser("show", help="Display effective merged config")
    config_sub.add_parser("path", help="Show config file paths")
    log_parser = sub.add_parser("log", help="Show recent hook decisions")
    log_parser.add_argument("--blocks", action="store_true", help="Show only blocked decisions")
    log_parser.add_argument("--asks", action="store_true", help="Show only ask decisions")
    log_parser.add_argument("--tool", default=None, help="Filter by tool name (Bash, Read, Write, ...)")
    log_parser.add_argument("-n", "--limit", type=int, default=50, help="Number of entries (default: 50)")
    log_parser.add_argument("--json", action="store_true", help="Output as JSON lines")

    allow_parser = sub.add_parser("allow", help="Allow an action type")
    allow_parser.add_argument("action_type", help="Action type to allow")
    allow_parser.add_argument("--project", action="store_true", help="Write to project config")
    deny_parser = sub.add_parser("deny", help="Deny an action type")
    deny_parser.add_argument("action_type", help="Action type to deny")
    deny_parser.add_argument("--project", action="store_true", help="Write to project config")
    allow_path_parser = sub.add_parser("allow-path", help="Allow a sensitive path for the current project")
    allow_path_parser.add_argument("path", help="Path to allow")
    classify_parser = sub.add_parser("classify", help="Classify a command prefix as an action type")
    classify_parser.add_argument("command_prefix", help="Command prefix to classify")
    classify_parser.add_argument("type", help="Action type to assign")
    classify_parser.add_argument("--project", action="store_true", help="Write to project config")
    trust_parser = sub.add_parser("trust", help="Trust a path or network host (global only)")
    trust_parser.add_argument("target", help="Path or hostname to trust")
    trust_parser.add_argument("--project", action="store_true", help="Write to project config (rejected for paths)")
    sub.add_parser("status", help="Show all custom rules")
    forget_parser = sub.add_parser("forget", help="Remove a rule")
    forget_parser.add_argument("arg", help="Rule to remove (action type, path, command, or host)")
    forget_parser.add_argument("--project", action="store_true", help="Search only project config")
    forget_parser.add_argument("--global", dest="global_flag", action="store_true", help="Search only global config")
    sub.add_parser("types", help="List all action types with descriptions and default policies")
    sub.add_parser("claude", help="Launch Claude Code with nah hooks active")

    # Manual intercept: "nah claude ..." bypasses argparse for user_args
    # because argparse.REMAINDER fails when first arg starts with "--".
    if len(sys.argv) >= 2 and sys.argv[1] == "claude":
        cmd_claude(sys.argv[2:])
        return

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
    elif args.command == "log":
        cmd_log(args)
    elif args.command == "allow":
        cmd_allow(args)
    elif args.command == "deny":
        cmd_deny(args)
    elif args.command == "allow-path":
        cmd_allow_path(args)
    elif args.command == "classify":
        cmd_classify(args)
    elif args.command == "trust":
        cmd_trust(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "forget":
        cmd_forget(args)
    elif args.command == "types":
        cmd_types(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
