"""Interactive bash/zsh terminal guard support."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from nah import __version__, taxonomy
from nah.bash import classify_command
from nah.platform_paths import nah_config_dir

BASH = "bash"
ZSH = "zsh"
SHELLS = {BASH, ZSH}

EXIT_ALLOW = 0
EXIT_ASK_DECLINED = 10
EXIT_BLOCK = 20
EXIT_ERROR = 2

MARKER_START = "# >>> nah terminal guard >>>"
MARKER_END = "# <<< nah terminal guard <<<"

_BYPASS_PREFIX_RE = re.compile(
    r"^\s*(?:export\s+)?NAH_TERMINAL_BYPASS=(?:1|true|yes|on)(?:\s+|$)"
)
_UNSUPPORTED_LINE_RE = re.compile(r"<<-?\s*\S")


@dataclass(frozen=True)
class ShellPaths:
    shell: str
    rc_file: Path
    snippet: Path


@dataclass
class TerminalDecision:
    decision: str
    reason: str
    exit_code: int
    command: str
    target: str
    bypass: bool = False
    confirmed: bool = False
    denied: bool = False
    action_type: str = ""
    meta: dict | None = None


def shell_paths(shell: str) -> ShellPaths:
    """Return rc/snippet paths for a supported shell."""
    _require_shell(shell)
    home = Path.home()
    rc_name = ".bashrc" if shell == BASH else ".zshrc"
    snippet_name = "bash.sh" if shell == BASH else "zsh.zsh"
    return ShellPaths(
        shell=shell,
        rc_file=home / rc_name,
        snippet=Path(nah_config_dir()) / "terminal" / snippet_name,
    )


def install_shell(shell: str) -> None:
    """Install or refresh the shell guard snippet and managed rc block."""
    paths = shell_paths(shell)
    _write_snippet(paths)
    block = _managed_block(paths)
    _write_text(paths.rc_file, _upsert_block(_read_text(paths.rc_file), block))


def update_shell(shell: str) -> None:
    """Refresh shell guard files."""
    install_shell(shell)


def uninstall_shell(shell: str) -> None:
    """Remove the shell guard snippet and managed rc block."""
    paths = shell_paths(shell)
    _write_text(paths.rc_file, _remove_block(_read_text(paths.rc_file)))
    if paths.snippet.exists():
        paths.snippet.unlink()


def shell_status(shell: str) -> dict:
    """Return installation/loading status for a shell target."""
    paths = shell_paths(shell)
    rc_text = _read_text(paths.rc_file)
    loaded = (
        os.environ.get("NAH_TERMINAL_GUARD") == "1"
        and os.environ.get("NAH_TERMINAL_SHELL") == shell
    )
    return {
        "target": shell,
        "rc_file": str(paths.rc_file),
        "snippet": str(paths.snippet),
        "rc_block": _has_block(rc_text),
        "snippet_exists": paths.snippet.exists(),
        "installed": _has_block(rc_text) and paths.snippet.exists(),
        "loaded": loaded,
    }


def shell_doctor(shell: str) -> dict:
    """Return deeper diagnostics for a shell target."""
    status = shell_status(shell)
    status.update({
        "current_shell": Path(os.environ.get("SHELL", "")).name,
        "nah_path": shutil.which("nah") or "",
        "nah_version": __version__,
        "supports_shell": shutil.which(shell) is not None,
        "guard_env": os.environ.get("NAH_TERMINAL_GUARD", ""),
        "guard_shell": os.environ.get("NAH_TERMINAL_SHELL", ""),
        "conflicts": [],
    })
    if shell == BASH:
        status["readline_required"] = True
    if shell == ZSH:
        status["zle_required"] = True
    return status


def decide_terminal_command(
    command: str,
    target: str,
    *,
    confirm: bool = False,
    stdin=None,
    stderr=None,
) -> TerminalDecision:
    """Classify and optionally prompt for an interactive terminal command."""
    _require_shell(target)
    stdin = stdin if stdin is not None else sys.stdin
    stderr = stderr if stderr is not None else sys.stderr

    from nah.config import get_config, set_active_target

    set_active_target(target)
    cfg = get_config()
    bypass_env = str(cfg.terminal.get("bypass_env", "NAH_TERMINAL_BYPASS"))
    bypass = _is_bypass_enabled(bypass_env, command)
    unsupported = _unsupported_line_reason(command)

    if bypass:
        result = TerminalDecision(
            decision=taxonomy.ALLOW,
            reason="terminal bypass requested",
            exit_code=EXIT_ALLOW,
            command=command,
            target=target,
            bypass=True,
            meta={"terminal_event": "bypass", "terminal_bypass": True},
        )
        _log_terminal_decision(result, cfg.log)
        return result

    if unsupported:
        result = TerminalDecision(
            decision=taxonomy.BLOCK,
            reason=unsupported,
            exit_code=EXIT_BLOCK,
            command=command,
            target=target,
            meta={"terminal_event": "unsupported"},
        )
        _log_terminal_decision(result, cfg.log)
        return result

    classified = classify_command(command)
    decision = classified.final_decision
    reason = classified.reason
    meta = _classify_meta(classified)

    if decision == taxonomy.ALLOW:
        return TerminalDecision(
            decision=taxonomy.ALLOW,
            reason=reason,
            exit_code=EXIT_ALLOW,
            command=command,
            target=target,
            action_type=_first_action_type(meta),
            meta=meta,
        )

    if decision == taxonomy.BLOCK:
        result = TerminalDecision(
            decision=taxonomy.BLOCK,
            reason=reason,
            exit_code=EXIT_BLOCK,
            command=command,
            target=target,
            action_type=_first_action_type(meta),
            meta={**meta, "terminal_event": "block"},
        )
        _log_terminal_decision(result, cfg.log)
        return result

    if confirm and _stdin_is_tty(stdin):
        stderr.write(f"nah? {reason}\nRun anyway? [y/N] ")
        stderr.flush()
        answer = stdin.readline().strip().lower()
        if answer in ("y", "yes"):
            result = TerminalDecision(
                decision=taxonomy.ASK,
                reason=reason,
                exit_code=EXIT_ALLOW,
                command=command,
                target=target,
                confirmed=True,
                action_type=_first_action_type(meta),
                meta={**meta, "terminal_event": "ask_confirmed", "terminal_confirmed": True},
            )
            _log_terminal_decision(result, cfg.log)
            return result

    result = TerminalDecision(
        decision=taxonomy.ASK,
        reason=reason,
        exit_code=EXIT_ASK_DECLINED,
        command=command,
        target=target,
        denied=True,
        action_type=_first_action_type(meta),
        meta={**meta, "terminal_event": "ask_denied"},
    )
    _log_terminal_decision(result, cfg.log)
    return result


def decision_to_payload(result: TerminalDecision) -> dict:
    """Return a stable JSON payload for the hidden helper."""
    return {
        "target": result.target,
        "command": result.command,
        "decision": result.decision,
        "reason": result.reason,
        "exit_code": result.exit_code,
        "bypass": result.bypass,
        "confirmed": result.confirmed,
        "denied": result.denied,
        "action_type": result.action_type,
    }


def print_status(shell: str) -> None:
    """Print shell status in a compact human format."""
    st = shell_status(shell)
    state = "installed" if st["installed"] else "not installed"
    loaded = "loaded" if st["loaded"] else "not loaded in this shell"
    print(f"{shell}: {state}, {loaded}")
    print(f"  rc file: {st['rc_file']}")
    print(f"  snippet: {st['snippet']}")


def print_doctor(shell: str) -> None:
    """Print shell diagnostics."""
    st = shell_doctor(shell)
    print(f"target: {shell}")
    print(f"current shell: {st['current_shell'] or '(unknown)'}")
    print(f"nah path: {st['nah_path'] or '(not on PATH)'}")
    print(f"nah version: {st['nah_version']}")
    print(f"installed: {'yes' if st['installed'] else 'no'}")
    print(f"loaded in current shell: {'yes' if st['loaded'] else 'no'}")
    print(f"rc file: {st['rc_file']}")
    print(f"snippet: {st['snippet']}")
    print(f"{shell} available: {'yes' if st['supports_shell'] else 'no'}")
    if st["conflicts"]:
        print("conflicts:")
        for conflict in st["conflicts"]:
            print(f"  {conflict}")
    else:
        print("conflicts: none detected")


def render_bash_snippet() -> str:
    """Return the managed bash snippet."""
    return """# nah terminal guard for interactive bash
if [[ $- == *i* && -n ${BASH_VERSION:-} && -z ${NAH_TERMINAL_GUARD_ACTIVE:-} ]]; then
  export NAH_TERMINAL_GUARD=1
  export NAH_TERMINAL_SHELL=bash
  export NAH_TERMINAL_GUARD_ACTIVE=1

  __nah_terminal_accept_line() {
    local line="$READLINE_LINE"
    local status

    if [[ -z "${line//[[:space:]]/}" ]]; then
      READLINE_LINE=
      READLINE_POINT=0
      return 0
    fi

    READLINE_LINE=
    READLINE_POINT=0

    command nah _terminal-decision --target bash --confirm -- "$line"
    status=$?
    if [[ $status -eq 0 ]]; then
      history -s -- "$line"
      builtin eval "$line"
      return $?
    fi

    READLINE_LINE="$line"
    READLINE_POINT=${#READLINE_LINE}
    return 0
  }

  bind -x '"\\C-j":__nah_terminal_accept_line'
  bind -x '"\\C-m":__nah_terminal_accept_line'
fi
"""


def render_zsh_snippet() -> str:
    """Return the managed zsh snippet."""
    return """# nah terminal guard for interactive zsh
if [[ -o interactive && -n ${ZSH_VERSION:-} && -z ${NAH_TERMINAL_GUARD_ACTIVE:-} ]]; then
  export NAH_TERMINAL_GUARD=1
  export NAH_TERMINAL_SHELL=zsh
  export NAH_TERMINAL_GUARD_ACTIVE=1

  if zle -l accept-line >/dev/null 2>&1; then
    zle -A accept-line __nah_original_accept_line
  fi

  __nah_terminal_accept_line() {
    local line="$BUFFER"
    if command nah _terminal-decision --target zsh --confirm -- "$line"; then
      zle __nah_original_accept_line
    else
      zle -M "nah: command was not run"
    fi
  }

  zle -N accept-line __nah_terminal_accept_line
fi
"""


def _require_shell(shell: str) -> None:
    if shell not in SHELLS:
        raise ValueError(f"unsupported shell target: {shell}")


def _write_snippet(paths: ShellPaths) -> None:
    content = render_bash_snippet() if paths.shell == BASH else render_zsh_snippet()
    _write_text(paths.snippet, content)


def _managed_block(paths: ShellPaths) -> str:
    return "\n".join([
        MARKER_START,
        f"# Managed by nah. Remove with: nah uninstall {paths.shell}",
        f"[ -r {shlex.quote(str(paths.snippet))} ] && . {shlex.quote(str(paths.snippet))}",
        MARKER_END,
        "",
    ])


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _has_block(text: str) -> bool:
    return MARKER_START in text and MARKER_END in text


def _upsert_block(text: str, block: str) -> str:
    cleaned = _remove_block(text).rstrip()
    if cleaned:
        return f"{cleaned}\n\n{block}"
    return block


def _remove_block(text: str) -> str:
    if not text:
        return ""
    pattern = re.compile(
        rf"\n?{re.escape(MARKER_START)}.*?{re.escape(MARKER_END)}\n?",
        re.DOTALL,
    )
    return pattern.sub("\n", text).strip("\n") + ("\n" if text.strip() else "")


def _stdin_is_tty(stdin) -> bool:
    isatty = getattr(stdin, "isatty", None)
    return bool(isatty and isatty())


def _is_bypass_enabled(env_name: str, command: str) -> bool:
    raw = os.environ.get(env_name, "")
    if raw.lower() in ("1", "true", "yes", "on"):
        return True
    return bool(_BYPASS_PREFIX_RE.match(command))


def _unsupported_line_reason(command: str) -> str:
    if "\n" in command:
        return "terminal guard supports complete single-line commands only"
    stripped = command.rstrip()
    if stripped.endswith("\\"):
        return "terminal guard cannot safely run a line ending in continuation backslash"
    if _UNSUPPORTED_LINE_RE.search(command):
        return "terminal guard cannot safely run here-doc input"
    try:
        shlex.split(command)
    except ValueError as exc:
        return f"terminal guard cannot safely run incomplete shell input: {exc}"
    return ""


def _classify_meta(result) -> dict:
    stages = [
        {
            "tokens": stage.tokens,
            "action_type": stage.action_type,
            "policy": stage.default_policy,
            "decision": stage.decision,
            "reason": stage.reason,
        }
        for stage in result.stages
    ]
    meta: dict = {"stages": stages, "source": "terminal"}
    if result.composition_rule:
        meta["composition_rule"] = result.composition_rule
    return meta


def _first_action_type(meta: dict) -> str:
    for stage in meta.get("stages", []):
        if stage.get("decision") in (taxonomy.ASK, taxonomy.BLOCK):
            return stage.get("action_type", "")
    stages = meta.get("stages", [])
    return stages[0].get("action_type", "") if stages else ""


def _log_terminal_decision(result: TerminalDecision, log_config: dict | None) -> None:
    try:
        from nah.log import build_entry, log_decision, redact_input

        meta = dict(result.meta or {})
        meta.update({
            "target": result.target,
            "source": "terminal",
        })
        entry = build_entry(
            "Bash",
            redact_input("Bash", {"command": result.command}),
            result.decision,
            result.reason,
            "terminal",
            __version__,
            0,
            meta,
        )
        entry["target"] = result.target
        log_decision(entry, log_config)
    except Exception as exc:
        try:
            sys.stderr.write(f"nah: terminal log: {exc}\n")
        except Exception:
            pass
