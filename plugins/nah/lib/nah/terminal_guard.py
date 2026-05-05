"""Interactive bash/zsh terminal guard support."""

from __future__ import annotations

import json
import contextlib
import io
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
from nah.messages import brand, human_reason
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
    r"^\s*(?:(?:export\s+)?NAH_TERMINAL_BYPASS=(?:1|true|yes|on)|nah-bypass)(?:\s+|$)"
)
_UNSUPPORTED_LINE_RE = re.compile(r"<<-?\s*\S")


@dataclass(frozen=True)
class ShellPaths:
    shell: str
    rc_file: Path
    snippet: Path
    login_rc_file: Path | None = None


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
    human_reason: str = ""
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
        login_rc_file=home / ".bash_profile" if shell == BASH else None,
    )


def _startup_files_to_install(paths: ShellPaths) -> list[Path]:
    """Return shell startup files that should receive the managed block."""
    files = [paths.rc_file]
    if paths.login_rc_file and paths.login_rc_file.exists():
        files.append(paths.login_rc_file)
    return files


def _startup_files_with_blocks(paths: ShellPaths) -> list[Path]:
    """Return startup files that currently contain the managed block."""
    files = [paths.rc_file]
    if paths.login_rc_file and _has_block(_read_text(paths.login_rc_file)):
        files.append(paths.login_rc_file)
    return files


def install_shell(shell: str) -> None:
    """Install or refresh the shell guard snippet and managed rc block."""
    paths = shell_paths(shell)
    _write_snippet(paths)
    block = _managed_block(paths)
    for rc_file in _startup_files_to_install(paths):
        _write_text(rc_file, _upsert_block(_read_text(rc_file), block))


def update_shell(shell: str) -> None:
    """Refresh shell guard files."""
    install_shell(shell)


def uninstall_shell(shell: str) -> None:
    """Remove the shell guard snippet and managed rc block."""
    paths = shell_paths(shell)
    for rc_file in _startup_files_with_blocks(paths):
        _write_text(rc_file, _remove_block(_read_text(rc_file)))
    if paths.snippet.exists():
        paths.snippet.unlink()


def shell_status(shell: str) -> dict:
    """Return installation/loading status for a shell target."""
    paths = shell_paths(shell)
    rc_text = _read_text(paths.rc_file)
    login_rc_text = _read_text(paths.login_rc_file) if paths.login_rc_file else ""
    rc_block = _has_block(rc_text)
    login_rc_block = _has_block(login_rc_text)
    loaded = (
        os.environ.get("NAH_TERMINAL_GUARD") == "1"
        and os.environ.get("NAH_TERMINAL_SHELL") == shell
    )
    return {
        "target": shell,
        "rc_file": str(paths.rc_file),
        "login_rc_file": str(paths.login_rc_file) if paths.login_rc_file else "",
        "snippet": str(paths.snippet),
        "rc_block": rc_block,
        "login_rc_block": login_rc_block,
        "snippet_exists": paths.snippet.exists(),
        "installed": (rc_block or login_rc_block) and paths.snippet.exists(),
        "loaded": loaded,
    }


def shell_doctor(shell: str) -> dict:
    """Return deeper diagnostics for a shell target."""
    status = shell_status(shell)
    conflicts: list[str] = []
    status.update({
        "current_shell": Path(os.environ.get("SHELL", "")).name,
        "nah_path": shutil.which("nah") or "",
        "nah_version": __version__,
        "supports_shell": shutil.which(shell) is not None,
        "guard_env": os.environ.get("NAH_TERMINAL_GUARD", ""),
        "guard_shell": os.environ.get("NAH_TERMINAL_SHELL", ""),
        "conflicts": conflicts,
    })
    if shell == BASH:
        status["readline_required"] = True
        status["readline_bind_cj"] = os.environ.get("NAH_TERMINAL_BASH_BIND_CJ", "")
        status["readline_bind_cm"] = os.environ.get("NAH_TERMINAL_BASH_BIND_CM", "")
        status["debug_trap"] = os.environ.get("NAH_TERMINAL_BASH_DEBUG_TRAP", "")
        if status["loaded"]:
            for key, binding in (("\\C-j", status["readline_bind_cj"]), ("\\C-m", status["readline_bind_cm"])):
                if binding and "accept-line" not in binding:
                    conflicts.append(f"existing bash {key} binding before nah loaded: {binding}")
            if status["debug_trap"]:
                conflicts.append(f"existing bash DEBUG trap before nah loaded: {status['debug_trap']}")
    if shell == ZSH:
        status["zle_required"] = True
        status["accept_line_preserved"] = os.environ.get("NAH_TERMINAL_ZSH_ACCEPT_LINE", "")
        if status["loaded"] and status["accept_line_preserved"] not in ("", "preserved"):
            conflicts.append("zsh accept-line widget could not be preserved")
    return status


def decide_terminal_command(
    command: str,
    target: str,
    *,
    confirm: bool = False,
    assume_confirmed: bool = False,
    skip_llm: bool = False,
    log: bool = True,
    stdin=None,
    stderr=None,
) -> TerminalDecision:
    """Classify and optionally prompt for an interactive terminal command."""
    _require_shell(target)
    command = _strip_accept_line_ending(command)
    stdin = stdin if stdin is not None else sys.stdin
    stderr = stderr if stderr is not None else sys.stderr
    tty_handle = None
    if confirm and not _stdin_is_tty(stdin):
        try:
            tty_handle = open("/dev/tty", "r+", encoding="utf-8")
        except OSError:
            tty_handle = None
        else:
            stdin = tty_handle
            stderr = tty_handle

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
        if log:
            _log_terminal_decision(result, cfg.log)
        return result

    if unsupported:
        human = human_reason(unsupported, decision=taxonomy.BLOCK, tool="Bash")
        result = TerminalDecision(
            decision=taxonomy.BLOCK,
            reason=unsupported,
            exit_code=EXIT_BLOCK,
            command=command,
            target=target,
            human_reason=human,
            meta={"terminal_event": "unsupported"},
        )
        result.meta["human_reason"] = human
        if log:
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
        action_type = _first_action_type(meta)
        human = human_reason(reason, decision=taxonomy.BLOCK, action_type=action_type, tool="Bash", meta=meta)
        result = TerminalDecision(
            decision=taxonomy.BLOCK,
            reason=reason,
            exit_code=EXIT_BLOCK,
            command=command,
            target=target,
            action_type=action_type,
            human_reason=human,
            meta={**meta, "terminal_event": "block", "human_reason": human},
        )
        if log:
            _log_terminal_decision(result, cfg.log)
        return result

    if not assume_confirmed and not skip_llm:
        llm_result = _try_terminal_llm(command, target, reason, meta, cfg)
        if llm_result is not None:
            llm_decision, llm_reason, llm_meta = llm_result
            meta.update(llm_meta)
            if llm_decision == taxonomy.ALLOW:
                action_type = _first_action_type(meta)
                result = TerminalDecision(
                    decision=taxonomy.ALLOW,
                    reason=llm_reason or reason,
                    exit_code=EXIT_ALLOW,
                    command=command,
                    target=target,
                    action_type=action_type,
                    meta={**meta, "terminal_event": "llm_allowed"},
                )
                if log:
                    _log_terminal_decision(result, cfg.log)
                return result

    if assume_confirmed:
        action_type = _first_action_type(meta)
        human = human_reason(reason, decision=taxonomy.ASK, action_type=action_type, tool="Bash", meta=meta)
        result = TerminalDecision(
            decision=taxonomy.ASK,
            reason=reason,
            exit_code=EXIT_ALLOW,
            command=command,
            target=target,
            confirmed=True,
            action_type=action_type,
            human_reason=human,
            meta={**meta, "terminal_event": "ask_confirmed", "terminal_confirmed": True, "human_reason": human},
        )
        if log:
            _log_terminal_decision(result, cfg.log)
        return result

    if confirm and _stdin_is_tty(stdin):
        action_type = _first_action_type(meta)
        human = human_reason(reason, decision=taxonomy.ASK, action_type=action_type, tool="Bash", meta=meta)
        prompt_result = TerminalDecision(
            decision=taxonomy.ASK,
            reason=reason,
            exit_code=EXIT_ASK_DECLINED,
            command=command,
            target=target,
            action_type=action_type,
            human_reason=human,
            meta=meta,
        )
        stderr.write(f"{format_terminal_message(prompt_result, 'nah paused')}\nRun anyway? [y/N] ")
        stderr.flush()
        answer = _read_confirmation_answer(stdin, stderr)
        if answer in ("y", "yes"):
            result = TerminalDecision(
                decision=taxonomy.ASK,
                reason=reason,
                exit_code=EXIT_ALLOW,
                command=command,
                target=target,
                confirmed=True,
                action_type=action_type,
                human_reason=human,
                meta={**meta, "terminal_event": "ask_confirmed", "terminal_confirmed": True, "human_reason": human},
            )
            if log:
                _log_terminal_decision(result, cfg.log)
            return result

    action_type = _first_action_type(meta)
    human = human_reason(reason, decision=taxonomy.ASK, action_type=action_type, tool="Bash", meta=meta)
    result = TerminalDecision(
        decision=taxonomy.ASK,
        reason=reason,
        exit_code=EXIT_ASK_DECLINED,
        command=command,
        target=target,
        denied=True,
        action_type=action_type,
        human_reason=human,
        meta={**meta, "terminal_event": "ask_denied", "human_reason": human},
    )
    if log:
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
        "human_reason": result.human_reason,
    }


def format_terminal_message(result: TerminalDecision, prefix: str) -> str:
    """Return the interactive terminal message for a guarded command."""
    lines = [brand(prefix, result.human_reason or result.reason)]
    command = _display_command(result.command)
    if command:
        lines.append(f"Command: {command}")
    llm_reason = str((result.meta or {}).get("llm_reasoning", "")).strip()
    if llm_reason:
        lines.append(f"LLM: {llm_reason}")
    return "\n".join(lines)


def print_status(shell: str) -> None:
    """Print shell status in a compact human format."""
    st = shell_status(shell)
    state = "installed" if st["installed"] else "not installed"
    loaded = "loaded" if st["loaded"] else "not loaded in this shell"
    print(f"{shell}: {state}, {loaded}")
    print(f"  rc file: {st['rc_file']}")
    if st["login_rc_file"]:
        print(f"  login rc file: {st['login_rc_file']}")
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
    if st["login_rc_file"]:
        print(f"login rc file: {st['login_rc_file']}")
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
if [[ $- == *i* && -n ${BASH_VERSION:-} ]]; then
  if [[ -z ${NAH_TERMINAL_GUARD_ACTIVE:-} ]]; then
    export NAH_TERMINAL_BASH_BIND_CJ="$(bind -p 2>/dev/null | command grep -F '"\\C-j"' || true)"
    export NAH_TERMINAL_BASH_BIND_CM="$(bind -p 2>/dev/null | command grep -F '"\\C-m"' || true)"
    export NAH_TERMINAL_BASH_DEBUG_TRAP="$(trap -p DEBUG || true)"
  fi
  export NAH_TERMINAL_GUARD=1
  export NAH_TERMINAL_SHELL=bash
  export NAH_TERMINAL_GUARD_ACTIVE=1

  __nah_terminal_filter_line() {
    local line="$READLINE_LINE"
    local run_line="$line"
    local prefix_line="$line"
    local bypass=0
    local status
    bind '"\\C-x\\C-m": accept-line'

    if [[ -z "${line//[[:space:]]/}" ]]; then
      READLINE_LINE="$line"
      READLINE_POINT=0
      return 0
    fi

    while [[ "$prefix_line" == [[:space:]]* ]]; do
      prefix_line="${prefix_line#?}"
    done
    if [[ "$prefix_line" == nah-bypass || "$prefix_line" == nah-bypass[[:space:]]* ]]; then
      bypass=1
      run_line="${prefix_line#nah-bypass}"
      while [[ "$run_line" == [[:space:]]* ]]; do
        run_line="${run_line#?}"
      done
      if [[ -z "${run_line//[[:space:]]/}" ]]; then
        READLINE_LINE=
        READLINE_POINT=0
        bind '"\\C-x\\C-m": abort'
        return 0
      fi
    fi

    if [[ $bypass -eq 1 ]]; then
      NAH_TERMINAL_BYPASS=1 command nah _terminal-decision --target bash -- "$run_line"
    else
      command nah _terminal-decision --target bash --no-log --skip-llm -- "$line" >/dev/null 2>&1
    fi
    status=$?
    if [[ $status -eq 0 ]]; then
      READLINE_LINE="$run_line"
      READLINE_POINT=${#READLINE_LINE}
      return 0
    fi

    if [[ $status -eq 10 ]]; then
      if command nah _terminal-decision --target bash --confirm -- "$line"; then
        READLINE_LINE="$run_line"
        READLINE_POINT=${#READLINE_LINE}
      else
        READLINE_LINE=
        READLINE_POINT=0
        bind '"\\C-x\\C-m": abort'
      fi
      return 0
    elif [[ $status -eq 20 ]]; then
      command nah _terminal-decision --target bash -- "$line" || true
    elif [[ $status -ne 0 ]]; then
      command nah _terminal-decision --target bash -- "$line" || true
    fi

    READLINE_LINE=
    READLINE_POINT=0
    bind '"\\C-x\\C-m": abort'
    return 0
  }

  bind -x '"\\C-x\\C-n":__nah_terminal_filter_line'
  bind '"\\C-x\\C-m": accept-line'
  bind '"\\C-j":"\\C-x\\C-n\\C-x\\C-m"'
  bind '"\\C-m":"\\C-x\\C-n\\C-x\\C-m"'
fi
"""


def render_zsh_snippet() -> str:
    """Return the managed zsh snippet."""
    return """# nah terminal guard for interactive zsh
if [[ -o interactive && -n ${ZSH_VERSION:-} && ${NAH_TERMINAL_SHELL:-} != zsh ]]; then
  export NAH_TERMINAL_GUARD=1
  export NAH_TERMINAL_SHELL=zsh
  export NAH_TERMINAL_GUARD_ACTIVE=1

  if zle -A accept-line __nah_original_accept_line 2>/dev/null || zle -A .accept-line __nah_original_accept_line 2>/dev/null; then
    export NAH_TERMINAL_ZSH_ACCEPT_LINE=preserved
  else
    export NAH_TERMINAL_ZSH_ACCEPT_LINE=missing
  fi

  if [[ $NAH_TERMINAL_ZSH_ACCEPT_LINE == preserved ]]; then
    __nah_terminal_accept_line() {
      local line="$BUFFER"
      local run_line="$line"
      local prefix_line="$line"
      local bypass=0
      while [[ "$prefix_line" == [[:space:]]* ]]; do
        prefix_line="${prefix_line#?}"
      done
      if [[ "$prefix_line" == nah-bypass || "$prefix_line" == nah-bypass[[:space:]]* ]]; then
        bypass=1
        run_line="${prefix_line#nah-bypass}"
        while [[ "$run_line" == [[:space:]]* ]]; do
          run_line="${run_line#?}"
        done
        if [[ -z "${run_line//[[:space:]]/}" ]]; then
          BUFFER=
          zle redisplay
          return
        fi
      fi
      if [[ $bypass -eq 1 ]]; then
        NAH_TERMINAL_BYPASS=1 command nah _terminal-decision --target zsh -- "$run_line"
      else
        command nah _terminal-decision --target zsh --no-log --skip-llm -- "$line" >/dev/null 2>&1
      fi
      local nah_status=$?
      if [[ $nah_status -eq 0 ]]; then
        BUFFER="$run_line"
        zle __nah_original_accept_line
      else
        zle -I
        if [[ $nah_status -eq 10 ]]; then
          if command nah _terminal-decision --target zsh --confirm -- "$line" < /dev/tty > /dev/tty 2>&1; then
            BUFFER="$run_line"
            zle __nah_original_accept_line
            return
          fi
        elif [[ $nah_status -eq 20 ]]; then
          command nah _terminal-decision --target zsh -- "$line" >/dev/null 2>&1 || true
          command nah _terminal-decision --target zsh --no-log --skip-llm -- "$line" || true
        else
          command nah _terminal-decision --target zsh -- "$line" || true
        fi
        BUFFER=
        printf 'nah: command was not run\n' > /dev/tty
        zle reset-prompt
      fi
    }

    zle -N accept-line __nah_terminal_accept_line
  fi
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


def _strip_accept_line_ending(command: str) -> str:
    """Remove one trailing Readline accept-line newline, but not real multiline input."""
    if command.endswith("\r\n"):
        candidate = command[:-2]
    elif command.endswith(("\n", "\r")):
        candidate = command[:-1]
    else:
        return command

    if "\n" in candidate or "\r" in candidate:
        return command
    return candidate


def _read_confirmation_answer(stdin, stderr) -> str:
    """Read a terminal confirmation in both canonical and Readline raw modes."""
    fileno = getattr(stdin, "fileno", None)
    if fileno is None:
        return stdin.readline().strip().lower()

    try:
        fd = fileno()
    except (OSError, ValueError):
        return stdin.readline().strip().lower()
    if not isinstance(fd, int):
        return stdin.readline().strip().lower()

    echo_enabled = True
    try:
        import termios
    except ImportError:
        # Echo detection is best-effort. If termios is unavailable, assume
        # canonical terminal behavior so normal CLI input is not double-echoed.
        echo_enabled = True
    else:
        try:
            echo_enabled = bool(termios.tcgetattr(fd)[3] & termios.ECHO)
        except (OSError, ValueError, termios.error):
            # Echo detection is best-effort. If it fails, assume canonical
            # terminal behavior so we do not duplicate visible input in normal
            # CLI use.
            echo_enabled = True

    try:
        raw = os.read(fd, 1)
    except OSError:
        return ""

    if not raw:
        return ""

    if raw in (b" ", b"\t"):
        raw = _read_nonspace_confirmation_byte(fd, raw)
        if not raw:
            return ""

    if raw == b"\x03":
        if not echo_enabled:
            stderr.write("^C\n")
            stderr.flush()
        return ""

    answer = raw.decode(errors="ignore").lower()
    if answer in ("\r", "\n"):
        if not echo_enabled:
            stderr.write("\n")
            stderr.flush()
        return ""

    _drain_confirmation_line(fd)
    if not echo_enabled:
        stderr.write(f"{answer}\n")
        stderr.flush()
    return answer


def _read_nonspace_confirmation_byte(fd: int, fallback: bytes) -> bytes:
    """Skip leading spaces when the terminal supplied a full canonical line."""
    try:
        import select

        current = fallback
        for _ in range(32):
            if current not in (b" ", b"\t"):
                return current
            ready, _, _ = select.select([fd], [], [], 0.03)
            if not ready:
                return fallback
            current = os.read(fd, 1)
            if not current:
                return b""
            if current in (b"\r", b"\n"):
                return current
        return fallback
    except (OSError, ValueError):
        # Leading-space normalization is best-effort. If the fd stops being
        # readable after the first byte, fall back to that byte so the prompt
        # denies rather than guessing approval.
        return fallback


def _drain_confirmation_line(fd: int) -> None:
    try:
        import select

        for _ in range(32):
            ready, _, _ = select.select([fd], [], [], 0.03)
            if not ready:
                return
            chunk = os.read(fd, 1)
            if not chunk or chunk in (b"\r", b"\n"):
                return
    except (OSError, ValueError):
        # Draining is best-effort after the confirmation key is captured. If
        # the fd becomes unreadable, the safe fallback is to stop draining and
        # return the captured answer.
        return


def _display_command(command: str) -> str:
    """Return a one-line terminal-safe command display string."""
    text = str(command or "").replace("\r", "\\r").replace("\n", "\\n")
    return "".join(ch if ch == "\t" or ord(ch) >= 32 else "?" for ch in text).strip()


def _is_bypass_enabled(env_name: str, command: str) -> bool:
    raw = os.environ.get(env_name, "")
    if raw.lower() in ("1", "true", "yes", "on"):
        return True
    return bool(_BYPASS_PREFIX_RE.match(command))


def _unsupported_line_reason(command: str) -> str:
    if "\n" in command or "\r" in command:
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


def _try_terminal_llm(command: str, target: str, reason: str, meta: dict, cfg) -> tuple[str, str, dict] | None:
    """Run optional LLM ask refinement for terminal commands."""
    if cfg.llm_mode != "on" or not cfg.llm:
        return None
    try:
        from nah.hook import _build_llm_meta, _is_llm_eligible_stages
        from nah.llm import try_llm_terminal_guard
        from nah.log import redact_input

        action_type = _first_action_type(meta) or taxonomy.UNKNOWN
        if not _is_llm_eligible_stages(
            action_type,
            meta.get("stages", []),
            cfg.llm_eligible,
            meta.get("composition_rule", ""),
        ):
            return None

        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            llm_call = try_llm_terminal_guard(
                redact_input("Bash", {"command": command}),
                action_type,
                reason,
                cfg.llm,
                target=target,
                stages=meta.get("stages", []),
            )
        llm_meta = _build_llm_meta(llm_call, cfg)
        if llm_call.decision is None:
            return None if not llm_meta else ("", "", llm_meta)
        llm_decision = llm_call.decision.get("decision", "")
        llm_reason = (
            llm_call.decision.get("reason", "")
            or llm_call.reasoning
            or llm_call.reasoning_long
        )
        return llm_decision, llm_reason, llm_meta
    except Exception as exc:
        try:
            sys.stderr.write(f"nah: terminal LLM: {exc}\n")
        except Exception:
            pass
        return None


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
            # Terminal decision logging must never break the guarded command
            # path. If even stderr is unavailable, there is nowhere useful to
            # report this secondary logging failure.
            pass
