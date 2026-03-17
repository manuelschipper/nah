"""Bash command classifier — tokenize, decompose, classify, compose."""

import os.path
import re
import shlex
import sys
from dataclasses import dataclass, field

from nah import context, paths, taxonomy
from nah.content import scan_content, format_content_message

_MAX_UNWRAP_DEPTH = 5

# Safe redirect sinks — /dev/ special files that are not real file writes.
# Excludes block devices (/dev/sda, /dev/disk*) which are dangerous.
_REDIRECT_SAFE_SINKS = frozenset({"/dev/null", "/dev/stderr", "/dev/stdout", "/dev/tty"})


@dataclass
class Stage:
    tokens: list[str]
    operator: str = ""  # |, &&, ||, ;
    redirect_fd: str = ""
    redirect_target: str = ""
    redirect_append: bool = False
    heredoc_literal: str = ""
    action_hint: str = ""  # Pre-set action type (e.g. env var exec sink)
    action_reason: str = ""


@dataclass
class StageResult:
    tokens: list[str]
    action_type: str = taxonomy.UNKNOWN
    default_policy: str = taxonomy.ASK
    decision: str = taxonomy.ASK
    reason: str = ""
    redirect_target: str = ""


@dataclass
class ClassifyResult:
    command: str
    stages: list[StageResult] = field(default_factory=list)
    final_decision: str = taxonomy.ASK
    reason: str = ""
    composition_rule: str = ""


def classify_command(command: str) -> ClassifyResult:
    """Main entry point: classify a bash command string."""
    result = ClassifyResult(command=command)

    if not command.strip():
        result.final_decision = taxonomy.ALLOW
        result.reason = "empty command"
        return result

    # Split on top-level shell operators while quoting context is available,
    # then shlex.split each stage independently (FD-095).
    try:
        raw_stages = _split_on_operators(command)
    except ValueError:
        result.final_decision = taxonomy.ASK
        result.reason = "unparseable command (shlex error)"
        return result

    # Load config for custom classify/actions — three-table lookup
    global_table = None
    builtin_table = None
    project_table = None
    user_actions = None
    profile = "full"
    trust_project = False
    try:
        from nah.config import get_config  # lazy import
        cfg = get_config()
        profile = cfg.profile
        trust_project = cfg.trust_project_config
        if cfg.classify_global:
            global_table = taxonomy.build_user_table(cfg.classify_global)
        builtin_table = taxonomy.get_builtin_table(cfg.profile)
        if cfg.classify_project:
            project_table = taxonomy.build_user_table(cfg.classify_project)
        if cfg.actions:
            user_actions = cfg.actions
    except Exception as e:
        sys.stderr.write(f"nah: config load error: {e}\n")

    # Decompose each raw stage into classified stages
    stages: list[Stage] = []
    for stage_str, op in raw_stages:
        stage_str = stage_str.strip()
        if not stage_str:
            continue
        action_reason = _detect_shell_substitution(stage_str)
        heredoc_literal = _extract_heredoc_literal(stage_str)
        try:
            tokens = shlex.split(stage_str)
        except ValueError:
            result.final_decision = taxonomy.ASK
            result.reason = "unparseable command (shlex error)"
            return result
        if tokens:
            stages.extend(_decompose(
                tokens,
                operator=op,
                action_hint=taxonomy.OBFUSCATED if action_reason else "",
                action_reason=action_reason or "",
                heredoc_literal=heredoc_literal,
            ))

    if not stages:
        result.final_decision = taxonomy.ALLOW
        result.reason = "empty command"
        return result

    # Classify each stage
    for stage in stages:
        sr = _classify_stage(stage, global_table=global_table, builtin_table=builtin_table,
                             project_table=project_table, user_actions=user_actions,
                             profile=profile, trust_project=trust_project)
        result.stages.append(sr)

    # Check pipe composition rules
    comp_decision, comp_reason, comp_rule = _check_composition(result.stages, stages)
    if comp_decision:
        result.final_decision = comp_decision
        result.reason = comp_reason
        result.composition_rule = comp_rule
        return result

    # Aggregate: most restrictive wins
    _aggregate(result)
    return result


def _split_on_operators(command: str) -> list[tuple[str, str]]:
    """Split raw command string on top-level shell operators (|, &&, ||, ;).

    Respects single quotes, double quotes, and backslash escapes so that
    operators inside quoted strings (e.g. grep regex alternation ``\\|``)
    are never treated as pipeline separators (FD-095).

    Returns list of (stage_string, operator) pairs where operator is the
    separator that follows the stage (empty string for the last stage).
    """
    stages: list[tuple[str, str]] = []
    current: list[str] = []
    i = 0
    n = len(command)

    while i < n:
        c = command[i]

        # Single quote: consume until closing ' (everything literal)
        if c == "'":
            j = i + 1
            while j < n and command[j] != "'":
                j += 1
            # Include both quotes in the stage string
            current.append(command[i:j + 1] if j < n else command[i:])
            i = j + 1
            continue

        # Double quote: consume until unescaped closing "
        if c == '"':
            j = i + 1
            while j < n:
                if command[j] == '\\' and j + 1 < n:
                    j += 2  # skip escaped char
                elif command[j] == '"':
                    break
                else:
                    j += 1
            current.append(command[i:j + 1] if j < n else command[i:])
            i = j + 1
            continue

        # Backslash escape outside quotes: next char is literal
        if c == '\\' and i + 1 < n:
            current.append(command[i:i + 2])
            i += 2
            continue

        # Check for operators (order matters: && and || before | to avoid partial match)
        if c == '&' and i + 1 < n and command[i + 1] == '&':
            stages.append((''.join(current), '&&'))
            current = []
            i += 2
            continue
        if c == '|' and current and current[-1] == '>':
            # `>|` is a shell clobber redirect, not a pipeline separator.
            current.append(c)
            i += 1
            continue
        if c == '|' and i + 1 < n and command[i + 1] == '|':
            stages.append((''.join(current), '||'))
            current = []
            i += 2
            continue
        if c == '|':
            stages.append((''.join(current), '|'))
            current = []
            i += 1
            continue
        if c == ';':
            stages.append((''.join(current), ';'))
            current = []
            i += 1
            continue

        current.append(c)
        i += 1

    # Last stage (no trailing operator)
    stages.append((''.join(current), ''))

    return stages


def _detect_shell_substitution(command: str) -> str | None:
    """Detect shell substitution syntax outside single-quoted literals.

    This is intentionally fail-closed: if shell substitution syntax appears in a
    stage, treat it as obfuscated rather than trying to model a hidden command
    through argv tokenization.
    """
    in_single = False
    i = 0
    n = len(command)

    while i < n:
        c = command[i]

        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue

        if c == "\\" and i + 1 < n:
            i += 2
            continue

        if c == "'":
            in_single = True
            i += 1
            continue

        if c == '`':
            return "backtick substitution"
        if c == '$' and i + 1 < n and command[i + 1] == '(':
            return "command substitution"
        if c in '<>' and i + 1 < n and command[i + 1] == '(':
            return "process substitution"

        i += 1

    return None


def _parse_output_redirect(tok: str) -> tuple[str, bool, str, bool, str] | None:
    """Parse shell output redirect tokens.

    Supports operator-only and glued forms for >, >>, and >|, including
    fd-prefixed variants like 1>, 2>>, 1>|, combined stdout/stderr forms like
    &> and &>>, and descriptor-duplication redirects like >&2 or 2>&1.

    Returns ``(fd, append, target, needs_target, kind)`` where ``kind`` is one
    of:
    - ``"file"`` for redirects that write to a path-like target
    - ``"dup"`` for descriptor duplication / close redirects
    - ``"dup_or_file"`` for operator-only ``>&`` forms that need the next token
    """
    if not tok:
        return None

    if tok.startswith("&"):
        fd = "&"
        rest = tok[1:]
    else:
        i = 0
        while i < len(tok) and tok[i].isdigit():
            i += 1

        fd = tok[:i]
        rest = tok[i:]

    if rest == ">&":
        return fd, False, "", True, "dup_or_file"
    if rest.startswith(">&") and len(rest) > 2:
        target = rest[2:]
        if target == "-" or target.isdigit():
            return fd, False, target, False, "dup"
        if fd in ("", "1"):
            fd = "&"
        return fd, False, target, False, "file"

    for op, append in ((">>", True), (">|", False), (">", False)):
        if rest == op:
            return fd, append, "", True, "file"
        if rest.startswith(op) and len(rest) > len(op):
            return fd, append, rest[len(op):], False, "file"
    return None


def _split_embedded_output_redirect(tok: str) -> tuple[str, str] | None:
    """Split a token like ``ok>file`` into argv and redirect pieces.

    ``shlex.split`` leaves fully glued redirects attached to the preceding word,
    so shell forms like ``echo ok>file`` arrive as ``["echo", "ok>file"]``.
    This helper peels off the first output redirect operator so ``_decompose``
    can treat it exactly like the spaced form.
    """
    if not tok:
        return None

    for op in (">>", ">|", ">"):
        idx = tok.find(op)
        if idx > 0:
            return tok[:idx], tok[idx:]
    return None


def _extract_heredoc_literal(stage_str: str) -> str:
    """Best-effort extraction of a heredoc body from the raw stage string."""
    if "<<" not in stage_str or "\n" not in stage_str:
        return ""

    match = re.search(r"<<-?\s*(?P<quote>['\"]?)(?P<delim>[^\s'\"<>|;&]+)(?P=quote)", stage_str)
    if not match:
        return ""

    delimiter = match.group("delim")
    strip_tabs = match.group(0).startswith("<<-")
    body_lines: list[str] = []
    for line in stage_str.splitlines()[1:]:
        candidate = line.lstrip("\t") if strip_tabs else line
        if candidate == delimiter:
            return "\n".join(body_lines)
        body_lines.append(line)
    return ""


def _decompose(
    tokens: list[str],
    operator: str = "",
    action_hint: str = "",
    action_reason: str = "",
    heredoc_literal: str = "",
) -> list[Stage]:
    """Process tokens for a single pipeline stage. Detect redirects and here-strings.

    Operator splitting is handled upstream by ``_split_on_operators`` on the
    raw command string where quoting context is preserved (FD-095).  This
    function only handles here-strings and redirects within a single stage.
    """
    stages: list[Stage] = []
    current_tokens: list[str] = []
    stdout_redirected = False
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # Handle glued here-string operators so forms like cat -n<<<'secret',
        # bash -s<<<'script', and cat --<<<'payload' are tokenized like
        # their spaced equivalents.
        if "<<<" in tok and tok != "<<<":
            prefix, suffix = tok.split("<<<", 1)
            if prefix:
                current_tokens.append(prefix)
            current_tokens.append("<<<")
            if suffix:
                current_tokens.append(suffix)
            i += 1
            continue

        # Redirect detection: > foo, >> foo, >| foo, >foo, >>foo, >|foo,
        # fd-prefixed variants like 1> foo or 2>>foo, and fully glued shell
        # forms like ok>foo where shlex leaves the redirect attached to argv.
        parsed_redirect = _parse_output_redirect(tok)
        if parsed_redirect is None:
            embedded_redirect = _split_embedded_output_redirect(tok)
            if embedded_redirect is not None:
                prefix, redirect_tok = embedded_redirect
                current_tokens.append(prefix)
                parsed_redirect = _parse_output_redirect(redirect_tok)
        if parsed_redirect is not None:
            redirect_fd, redirect_append, target, needs_target, redirect_kind = parsed_redirect
            step = 1
            if needs_target:
                target = tokens[i + 1] if i + 1 < len(tokens) else ""
                step = 2
                if redirect_kind == "dup_or_file":
                    if target == "-" or target.isdigit():
                        redirect_kind = "dup"
                    else:
                        redirect_kind = "file"
                        if redirect_fd in ("", "1"):
                            redirect_fd = "&"
            if redirect_fd in ("", "1", "&"):
                stdout_redirected = True
            if redirect_kind == "dup":
                i += step
                continue
            stage = _make_stage(current_tokens, "", action_hint=action_hint,
                                action_reason=action_reason)
            if stage:
                stage.redirect_fd = redirect_fd
                stage.redirect_target = target
                stage.redirect_append = redirect_append
                stage.heredoc_literal = heredoc_literal
                stages.append(stage)
            i += step
            continue

        current_tokens.append(tok)
        i += 1

    # Last stage — attach the operator from the raw-string split, unless a
    # stdout redirect has already consumed the pipe payload.
    final_operator = "" if stdout_redirected and operator == "|" else operator
    stage = _make_stage(current_tokens, final_operator, action_hint=action_hint,
                        action_reason=action_reason)
    if stage:
        stage.heredoc_literal = heredoc_literal
        stages.append(stage)

    return stages


def _env_var_has_exec(value: str) -> bool:
    """Check if an env var value contains an exec sink as its base command.

    Returns True (fail-closed) on parse errors to avoid silently allowing
    malformed values through.
    """
    if not value:
        return False
    try:
        tokens = shlex.split(value)
    except ValueError:
        return True  # Fail-closed: unparseable value → escalate
    if not tokens:
        return False
    base = os.path.basename(tokens[0])
    return taxonomy.is_exec_sink(base)


def _make_stage(
    tokens: list[str],
    operator: str,
    action_hint: str = "",
    action_reason: str = "",
) -> Stage | None:
    """Create a Stage from tokens, stripping env var assignments.

    Inspects env var values for exec sinks before stripping — if any value
    invokes a shell interpreter, the stage keeps all tokens so it classifies
    as lang_exec (ask) rather than silently allowing the trailing command.
    """
    if not tokens:
        return None
    # Skip leading env assignments (FOO=bar cmd ...)
    start = 0
    for start, tok in enumerate(tokens):
        if "=" not in tok or tok.startswith("-"):
            break
        # Inspect the value portion for exec sinks
        _, value = tok.split("=", 1)
        if _env_var_has_exec(value):
            # Dangerous env var — flag as lang_exec
            return Stage(tokens=tokens, operator=operator,
                         action_hint=taxonomy.LANG_EXEC)
    else:
        # All tokens were env assignments
        return Stage(tokens=tokens, operator=operator,
                     action_hint=action_hint, action_reason=action_reason)
    return Stage(tokens=tokens[start:], operator=operator,
                 action_hint=action_hint, action_reason=action_reason)


def _classify_stage(
    stage: Stage,
    depth: int = 0,
    *,
    global_table: list | None = None,
    builtin_table: list | None = None,
    project_table: list | None = None,
    user_actions: dict[str, str] | None = None,
    profile: str = "full",
    trust_project: bool = False,
) -> StageResult:
    """Classify a single pipeline stage."""
    tokens = stage.tokens
    sr = StageResult(tokens=tokens)

    if not tokens:
        sr.reason = "empty stage"
        return sr

    # Pre-set action type (e.g. env var with exec sink)
    if stage.action_hint:
        sr.action_type = stage.action_hint
        sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)
        _apply_policy(sr)
        sr.reason = stage.action_reason or f"env var exec sink: {sr.action_type} → {sr.decision}"
        return _apply_redirect_guard(stage, sr, user_actions=user_actions)

    # Shell unwrapping
    unwrapped = _unwrap_shell(stage, depth, global_table=global_table,
                              builtin_table=builtin_table, project_table=project_table,
                              user_actions=user_actions, profile=profile,
                              trust_project=trust_project)
    if unwrapped is not None:
        return _apply_redirect_guard(stage, unwrapped, user_actions=user_actions)

    # Classify tokens
    sr.action_type = taxonomy.classify_tokens(tokens, global_table, builtin_table, project_table,
                                              profile=profile, trust_project=trust_project)
    sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)

    # Apply policy → decision
    _apply_policy(sr)

    # Path extraction + checking (regardless of policy)
    path_decision, path_reason = _check_extracted_paths(tokens)
    if path_decision == taxonomy.BLOCK or (path_decision == taxonomy.ASK and sr.decision == taxonomy.ALLOW):
        sr.decision = path_decision
        sr.reason = path_reason

    return _apply_redirect_guard(stage, sr, user_actions=user_actions)


def _obfuscated_result(tokens: list[str], reason: str, user_actions: dict[str, str] | None) -> StageResult:
    """Build a StageResult for obfuscated commands."""
    sr = StageResult(tokens=tokens)
    sr.action_type = taxonomy.OBFUSCATED
    sr.default_policy = taxonomy.get_policy(taxonomy.OBFUSCATED, user_actions)
    sr.decision = sr.default_policy
    sr.reason = reason
    return sr


def _strip_command_builtin(tokens: list[str]) -> list[str] | None:
    """Strip 'command' builtin wrapper, returning inner tokens.

    Returns None for introspection forms (-v/-V) or bare 'command'."""
    i = 1
    while i < len(tokens) and tokens[i].startswith("-"):
        flag = tokens[i]
        if "v" in flag or "V" in flag:
            return None  # Introspection
        if flag == "-p":
            i += 1
            continue
        break
    if i < len(tokens):
        return tokens[i:]
    return None


_ENV_NOARG_FLAGS = {"-i", "--ignore-environment"}
_ENV_ARG_FLAGS = {"-u", "--unset", "-C", "--chdir", "--argv0"}
_ENV_ARG_FLAG_PREFIXES = ("--unset=", "--chdir=", "--argv0=")


def _is_env_assignment(tok: str) -> bool:
    """Return True for env-style NAME=value assignments."""
    if "=" not in tok or tok.startswith("="):
        return False
    name, _ = tok.split("=", 1)
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(
        ch.isalnum() or ch == "_" for ch in name
    )


def _strip_env_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip env wrapper and supported flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "env":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if _is_env_assignment(tok):
            i += 1
            continue

        if tok in _ENV_NOARG_FLAGS:
            i += 1
            continue

        if tok in _ENV_ARG_FLAGS:
            i += 2
            continue

        if any(tok.startswith(prefix) for prefix in _ENV_ARG_FLAG_PREFIXES):
            i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_nice_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip nice wrapper and supported flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "nice":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-n", "--adjustment"}:
            i += 2
            continue

        if tok.startswith("--adjustment="):
            i += 1
            continue

        if tok.startswith("-n") and len(tok) > 2:
            i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_time_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip time wrapper and supported flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "time":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok == "-p":
            i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_nohup_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip nohup wrapper, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "nohup":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_stdbuf_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip stdbuf wrapper and supported flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "stdbuf":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-i", "-o", "-e"}:
            i += 2
            continue

        if tok.startswith(("-i", "-o", "-e")) and len(tok) > 2:
            i += 1
            continue

        if tok.startswith(("--input=", "--output=", "--error=")):
            i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_setsid_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip setsid wrapper and supported flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "setsid":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-c", "-f", "-w", "--ctty", "--fork", "--wait"}:
            i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_timeout_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip timeout wrapper and supported flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "timeout":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-f", "-p", "-v", "--foreground", "--preserve-status", "--verbose"}:
            i += 1
            continue

        if tok in {"-k", "-s"}:
            if i + 1 >= n:
                return None
            i += 2
            continue

        if tok.startswith(("-k", "-s")) and len(tok) > 2:
            i += 1
            continue

        if tok.startswith(("--kill-after=", "--signal=")):
            i += 1
            continue

        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2:
            cluster = tok[1:]
            j = 0
            while j < len(cluster):
                flag = cluster[j]
                if flag in {"f", "p", "v"}:
                    j += 1
                    continue
                if flag in {"k", "s"}:
                    if j + 1 == len(cluster):
                        if i + 1 >= n:
                            return None
                        i += 2
                    else:
                        i += 1
                    break
                return None
            else:
                i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    if i >= n:
        return None

    i += 1  # duration
    if i < n and tokens[i] == "--":
        i += 1

    inner = tokens[i:]
    return inner if inner else None


def _strip_ionice_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip ionice wrapper and supported command-mode flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "ionice":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-t", "--ignore"}:
            i += 1
            continue

        if tok in {"-c", "-n", "--class", "--classdata"}:
            if i + 1 >= n:
                return None
            i += 2
            continue

        if tok.startswith(("-c", "-n")) and len(tok) > 2:
            i += 1
            continue

        if tok.startswith(("--class=", "--classdata=")):
            i += 1
            continue

        if tok in {"-p", "-P", "-u", "--pid", "--pgid", "--uid"}:
            return None

        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2:
            cluster = tok[1:]
            j = 0
            while j < len(cluster):
                flag = cluster[j]
                if flag == "t":
                    j += 1
                    continue
                if flag in {"c", "n"}:
                    if j + 1 == len(cluster):
                        if i + 1 >= n:
                            return None
                        i += 2
                    else:
                        i += 1
                    break
                if flag in {"p", "P", "u"}:
                    return None
                return None
            else:
                i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    inner = tokens[i:]
    return inner if inner else None


def _strip_taskset_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip command-mode taskset wrapper, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "taskset":
        return None

    i = 1
    n = len(tokens)
    expect_mask = True
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-p", "--pid", "-a", "--all-tasks"}:
            return None

        if tok in {"-c", "--cpu-list"}:
            if i + 1 >= n:
                return None
            i += 2
            expect_mask = False
            continue

        if tok.startswith("--cpu-list="):
            i += 1
            expect_mask = False
            continue

        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2:
            cluster = tok[1:]
            if cluster[0] == "c" and len(cluster) > 1:
                i += 1
                expect_mask = False
                continue
            return None

        if tok.startswith("-"):
            return None

        break

    if i >= n:
        return None

    if expect_mask:
        i += 1
        if i >= n:
            return None

    if i < n and tokens[i] == "--":
        i += 1

    inner = tokens[i:]
    return inner if inner else None


def _strip_passthrough_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip one supported passthrough wrapper layer, if present."""
    if not tokens:
        return None

    if tokens[0] == "command":
        return _strip_command_builtin(tokens)

    return (
        _strip_env_wrapper(tokens)
        or _strip_nice_wrapper(tokens)
        or _strip_time_wrapper(tokens)
        or _strip_nohup_wrapper(tokens)
        or _strip_stdbuf_wrapper(tokens)
        or _strip_setsid_wrapper(tokens)
        or _strip_timeout_wrapper(tokens)
        or _strip_ionice_wrapper(tokens)
        or _strip_taskset_wrapper(tokens)
    )


# xargs flags: bail-out triggers, no-arg flags, arg flags (short prefix → consumes value)
_XARGS_BAILOUT_SHORT = {"-I", "-J", "-a"}
_XARGS_BAILOUT_LONG = {"--replace", "--arg-file"}  # also checked as prefix for =value form
_XARGS_NOARG_SHORT = {"-0", "-o", "-p", "-r", "-t", "-x"}
_XARGS_NOARG_LONG = {"--null", "--interactive", "--no-run-if-empty", "--verbose", "--exit"}
# Short flags that take an argument (next token or glued): -n1, -P 4, -d '\n', etc.
_XARGS_ARG_SHORT = {"-d", "-E", "-L", "-n", "-P", "-R", "-S", "-s"}
_XARGS_ARG_LONG_PREFIX = (
    "--delimiter=", "--max-lines=", "--max-args=", "--max-procs=", "--max-chars=",
)


def _strip_xargs(tokens: list[str]) -> list[str] | None:
    """Strip xargs wrapper and flags, returning inner command tokens (FD-089).

    Returns None if:
    - bare xargs (no inner command)
    - -I/-J/--replace/-a/--arg-file present (placeholder semantics, Phase 2)
    - unrecognized flag (fail-closed → unknown → ask)
    """
    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        # End of options
        if tok == "--":
            i += 1
            break

        # Not a flag → start of inner command
        if not tok.startswith("-"):
            break

        # Bail-out: exact short flags
        if tok in _XARGS_BAILOUT_SHORT:
            return None

        # Bail-out: long flags (exact or =value form)
        for prefix in _XARGS_BAILOUT_LONG:
            if tok == prefix or tok.startswith(prefix + "="):
                return None

        # No-arg flags
        if tok in _XARGS_NOARG_SHORT or tok in _XARGS_NOARG_LONG:
            i += 1
            continue

        # Arg flags: check exact match (consume next token) or glued form
        matched = False
        for flag in _XARGS_ARG_SHORT:
            if tok == flag:
                # Exact: consume next token as value
                i += 2
                matched = True
                break
            if tok.startswith(flag) and len(tok) > len(flag):
                # Glued: -n1, -P4, -d'\n'
                i += 1
                matched = True
                break
        if matched:
            continue

        # Arg long flags with =value
        if any(tok.startswith(p) for p in _XARGS_ARG_LONG_PREFIX):
            i += 1
            continue

        # Unknown flag → fail-closed
        return None

    inner = tokens[i:]
    return inner if inner else None


def _unwrap_shell(
    stage: Stage,
    depth: int,
    *,
    global_table: list | None,
    builtin_table: list | None,
    project_table: list | None,
    user_actions: dict[str, str] | None,
    profile: str = "full",
    trust_project: bool = False,
) -> StageResult | None:
    """Try shell unwrapping. Returns StageResult if handled, None if not a wrapper."""
    tokens = stage.tokens

    if depth >= _MAX_UNWRAP_DEPTH:
        return _obfuscated_result(tokens, "excessive shell nesting", user_actions)

    # command builtin unwrap
    if tokens and tokens[0] == "command":
        inner = _strip_command_builtin(tokens)
        if inner:
            inner_stage = Stage(tokens=inner, operator=stage.operator)
            return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                                   builtin_table=builtin_table, project_table=project_table,
                                   user_actions=user_actions, profile=profile,
                                   trust_project=trust_project)
        return None  # Introspection or bare — fall through to classify

    if tokens and os.path.basename(tokens[0]) == "time":
        passthrough_tokens = _strip_time_wrapper(tokens)
        if passthrough_tokens is not None:
            inner_stage = _make_stage(passthrough_tokens, stage.operator) or Stage(
                tokens=passthrough_tokens, operator=stage.operator
            )
            return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                                   builtin_table=builtin_table, project_table=project_table,
                                   user_actions=user_actions, profile=profile)
        sr = StageResult(tokens=tokens)
        sr.action_type = taxonomy.UNKNOWN
        sr.default_policy = taxonomy.get_policy(taxonomy.UNKNOWN, user_actions)
        _apply_policy(sr)
        sr.reason = "unsupported time wrapper flags"
        return sr

    # env/nice passthrough wrappers
    passthrough_tokens = _strip_passthrough_wrapper(tokens)
    if passthrough_tokens is not None:
        inner_stage = _make_stage(passthrough_tokens, stage.operator) or Stage(
            tokens=passthrough_tokens, operator=stage.operator
        )
        return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                               builtin_table=builtin_table, project_table=project_table,
                               user_actions=user_actions, profile=profile)

    # xargs unwrap (FD-089)
    if tokens and tokens[0] == "xargs":
        inner_tokens = _strip_xargs(tokens)
        if inner_tokens is None:
            return None  # bare xargs, -I/-J, or unknown flag → fall through
        if taxonomy.is_exec_sink(inner_tokens[0]):
            # xargs bash, xargs eval, etc. → lang_exec (don't recurse into exec sink)
            sr = StageResult(tokens=tokens)
            sr.action_type = taxonomy.LANG_EXEC
            sr.default_policy = taxonomy.get_policy(taxonomy.LANG_EXEC, user_actions)
            _apply_policy(sr)
            sr.reason = f"xargs wraps exec sink: {inner_tokens[0]}"
            return sr
        inner_stage = Stage(tokens=inner_tokens, operator=stage.operator)
        return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                               builtin_table=builtin_table, project_table=project_table,
                               user_actions=user_actions, profile=profile,
                               trust_project=trust_project)

    is_wrapper, inner = taxonomy.is_shell_wrapper(tokens)
    if not is_wrapper or inner is None:
        return None

    # Check for $() or backticks in eval — obfuscated
    if tokens[0] == "eval" and ("$(" in inner or "`" in inner):
        return _obfuscated_result(tokens, "eval with command substitution", user_actions)

    # Use _split_on_operators on the raw inner string to preserve quoting
    # context (FD-095), then shlex.split each stage independently.
    try:
        raw_stages = _split_on_operators(inner)
    except ValueError:
        return _obfuscated_result(tokens, "unparseable inner command", user_actions)

    inner_stages: list[Stage] = []
    for stage_str, op in raw_stages:
        stage_str = stage_str.strip()
        if not stage_str:
            continue
        action_reason = _detect_shell_substitution(stage_str)
        heredoc_literal = _extract_heredoc_literal(stage_str)
        try:
            inner_tokens = shlex.split(stage_str)
        except ValueError:
            return _obfuscated_result(tokens, "unparseable inner command", user_actions)
        if inner_tokens:
            inner_stages.extend(_decompose(
                inner_tokens,
                operator=op,
                action_hint=taxonomy.OBFUSCATED if action_reason else "",
                action_reason=action_reason or "",
                heredoc_literal=heredoc_literal,
            ))

    if inner_stages:
        return _classify_inner(inner_stages, stage, depth + 1,
                               global_table=global_table, builtin_table=builtin_table,
                               project_table=project_table, user_actions=user_actions,
                               profile=profile, trust_project=trust_project)

    return None


def _classify_inner(
    inner_stages: list[Stage],
    outer_stage: Stage,
    depth: int,
    *,
    global_table: list | None,
    builtin_table: list | None,
    project_table: list | None,
    user_actions: dict[str, str] | None,
    profile: str = "full",
    trust_project: bool = False,
) -> StageResult:
    """Classify pre-decomposed inner stages."""
    kw = dict(global_table=global_table, builtin_table=builtin_table,
              project_table=project_table, user_actions=user_actions, profile=profile,
              trust_project=trust_project)

    if len(inner_stages) <= 1:
        # Simple case — single command, no operators
        s = inner_stages[0] if inner_stages else Stage(tokens=[])
        return _classify_stage(s, depth, **kw)

    # Multiple stages — classify each, check composition, aggregate
    inner_results = []
    for s in inner_stages:
        sr = _classify_stage(s, depth, **kw)
        inner_results.append(sr)

    # Check pipe composition rules on inner pipeline
    comp_decision, comp_reason, comp_rule = _check_composition(inner_results, inner_stages)
    if comp_decision:
        sr = StageResult(tokens=outer_stage.tokens)
        sr.action_type = inner_results[0].action_type
        sr.decision = comp_decision
        sr.reason = f"unwrapped: {comp_reason}"
        return sr

    # No composition trigger — return most restrictive stage
    worst = inner_results[0]
    for sr in inner_results[1:]:
        if taxonomy.STRICTNESS.get(sr.decision, 2) > taxonomy.STRICTNESS.get(worst.decision, 2):
            worst = sr
    return worst


def _apply_policy(sr: StageResult) -> None:
    """Map default_policy to decision + reason. Mutates sr in place."""
    if sr.default_policy in (taxonomy.ALLOW, taxonomy.BLOCK, taxonomy.ASK):
        sr.decision = sr.default_policy
        sr.reason = f"{sr.action_type} → {sr.default_policy}"
    elif sr.default_policy == taxonomy.CONTEXT:
        sr.decision, sr.reason = _resolve_context(sr.action_type, sr.tokens)
    else:
        sr.decision = taxonomy.ASK
        sr.reason = f"unknown policy: {sr.default_policy}"


def _extract_here_string_operand(args: list[str]) -> str:
    """Return the literal operand from a here-string argv suffix, if present."""
    if not args:
        return ""

    for i, tok in enumerate(args):
        if tok == "<<<" and i + 1 < len(args):
            return args[i + 1]
        if tok.startswith("<<<") and len(tok) > 3:
            return tok[3:]
    return ""


def _extract_wrapped_redirect_literal(inner: str) -> str:
    """Extract redirect literal text from a single inner shell command string."""
    try:
        raw_stages = [(stage_str.strip(), op) for stage_str, op in _split_on_operators(inner) if stage_str.strip()]
        if len(raw_stages) != 1 or raw_stages[0][1]:
            return ""
        inner_tokens = shlex.split(raw_stages[0][0])
    except ValueError:
        return ""
    if not inner_tokens:
        return ""
    inner_stages = _decompose(inner_tokens)
    if len(inner_stages) != 1:
        return ""
    return _extract_redirect_literal(inner_stages[0])


def _extract_redirect_literal(stage: Stage) -> str:
    """Best-effort extraction of literal text written by redirects."""
    if stage.heredoc_literal:
        return stage.heredoc_literal

    tokens = stage.tokens
    if not tokens:
        return ""

    cmd = os.path.basename(tokens[0])
    args = tokens[1:]

    passthrough_tokens = _strip_passthrough_wrapper(tokens)
    if passthrough_tokens is not None:
        inner_stage = _make_stage(passthrough_tokens, stage.operator) or Stage(
            tokens=passthrough_tokens, operator=stage.operator
        )
        return _extract_redirect_literal(inner_stage)

    if cmd == "echo":
        i = 0
        while i < len(args):
            tok = args[i]
            if tok.startswith("-") and len(tok) > 1 and set(tok[1:]) <= {"n", "e", "E"}:
                i += 1
                continue
            break
        return " ".join(args[i:])

    if cmd == "printf":
        return " ".join(args)

    if cmd == "command":
        inner_tokens = _strip_command_builtin(tokens)
        if inner_tokens:
            return _extract_redirect_literal(Stage(tokens=inner_tokens, operator=stage.operator))

    if cmd in taxonomy._SHELL_WRAPPERS:
        is_wrapper, inner = taxonomy.is_shell_wrapper(tokens)
        if is_wrapper and inner:
            return _extract_wrapped_redirect_literal(inner)

    if cmd == "cat":
        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--":
                i += 1
                break
            if tok.startswith("-") and tok != "<<<" and not tok.startswith("<<<"):
                i += 1
                continue
            break
        if i < len(args):
            return _extract_here_string_operand(args[i:])

    return ""


def _classify_redirect_write(stage: Stage, user_actions: dict[str, str] | None) -> StageResult:
    """Classify shell output redirection as a filesystem write."""
    sr = StageResult(tokens=stage.tokens)
    sr.action_type = taxonomy.FILESYSTEM_WRITE
    sr.default_policy = taxonomy.get_policy(taxonomy.FILESYSTEM_WRITE, user_actions)
    _apply_policy(sr)

    if sr.default_policy == taxonomy.CONTEXT:
        sr.decision, reason = _check_redirect(stage.redirect_target)
        sr.reason = f"redirect target: {reason}"

    literal = _extract_redirect_literal(stage) if stage.redirect_fd in ("", "1", "&") else ""
    matches = scan_content(literal)
    if matches:
        content_decision = max(
            (m.policy for m in matches),
            key=lambda p: taxonomy.STRICTNESS.get(p, 2),
        )
        if taxonomy.STRICTNESS.get(content_decision, 0) > taxonomy.STRICTNESS.get(sr.decision, 0):
            sr.decision = content_decision
            sr.reason = format_content_message("Write", matches)

    return sr


def _apply_redirect_guard(
    stage: Stage,
    sr: StageResult,
    *,
    user_actions: dict[str, str] | None = None,
) -> StageResult:
    """Escalate a stage result when the outer stage redirects output to disk."""
    if not stage.redirect_target:
        return sr

    redirect_sr = _classify_redirect_write(stage, user_actions)
    redirect_strictness = taxonomy.STRICTNESS.get(redirect_sr.decision, 0)
    current_strictness = taxonomy.STRICTNESS.get(sr.decision, 0)

    if redirect_strictness > current_strictness or sr.decision == taxonomy.ALLOW:
        sr.redirect_target = stage.redirect_target
        sr.action_type = redirect_sr.action_type
        sr.default_policy = redirect_sr.default_policy
        sr.decision = redirect_sr.decision
        sr.reason = redirect_sr.reason
    return sr


def _check_redirect(target: str) -> tuple[str, str]:
    """Check redirect target as a filesystem write."""
    if not target:
        return taxonomy.ALLOW, ""
    if target in _REDIRECT_SAFE_SINKS or target.startswith("/dev/fd/"):
        return taxonomy.ALLOW, ""
    basic = paths.check_path_basic_raw(target)
    if basic:
        decision, reason = basic
        # reason is "targets X: detail" — rewrite as "redirect to X: detail"
        display = reason.replace("targets ", "", 1) if reason.startswith("targets ") else reason
        return decision, f"redirect to {display}"

    return context.resolve_filesystem_context(target)


def _resolve_context(action_type: str, tokens: list[str]) -> tuple[str, str]:
    """Resolve 'context' policy by checking filesystem or network context."""
    target_path = None
    if action_type in (taxonomy.FILESYSTEM_READ, taxonomy.FILESYSTEM_WRITE,
                       taxonomy.FILESYSTEM_DELETE):
        target_path = _extract_primary_target(tokens)
    elif action_type == taxonomy.LANG_EXEC:
        target_path = _resolve_script_path(tokens)
    return context.resolve_context(action_type, tokens=tokens, target_path=target_path)


def _extract_primary_target(tokens: list[str]) -> str:
    """Extract the primary filesystem target from command tokens.

    Heuristic: last non-flag argument that looks like a path.
    """
    candidates = []
    last_non_flag = ""
    for tok in tokens[1:]:  # skip command name
        if tok.startswith("-"):
            continue
        last_non_flag = tok
        if "/" in tok or tok.startswith("~") or tok.startswith("."):
            candidates.append(tok)
    # Return last path-like candidate, or fall back to last non-flag arg
    # (handles bare relative paths like "new_dir")
    return candidates[-1] if candidates else last_non_flag


def _resolve_script_path(tokens: list[str]) -> str | None:
    """Extract script file path from interpreter command tokens.

    Returns resolved path if the file exists, None otherwise.
    Handles: python script.py, python -m module, ./script.py, etc.
    Returns None for inline code (python -c) so context resolver falls
    through to ask.
    """
    if not tokens:
        return None

    cmd = os.path.basename(tokens[0])

    from nah.taxonomy import _INLINE_FLAGS, _MODULE_FLAGS

    inline = _INLINE_FLAGS.get(cmd, set())
    module = _MODULE_FLAGS.get(cmd, set())

    for i, tok in enumerate(tokens[1:], 1):
        if tok in inline:
            return None  # inline code, no file
        if tok in module and i + 1 < len(tokens):
            return _resolve_module_path(tokens[i + 1])
        if tok.startswith("-"):
            continue
        if os.path.isabs(tok):
            return tok if os.path.isfile(tok) else None
        cwd = os.getcwd()
        path = os.path.join(cwd, tok)
        return path if os.path.isfile(path) else None

    # ./script.py — tokens[0] is the script itself
    if cmd != tokens[0] and os.path.isfile(tokens[0]):
        return os.path.realpath(tokens[0])

    return None


def _resolve_module_path(module_name: str) -> str | None:
    """Best-effort resolution of python -m module_name to a file path."""
    cwd = os.getcwd()
    pkg_main = os.path.join(cwd, module_name, "__main__.py")
    if os.path.isfile(pkg_main):
        return pkg_main
    mod_file = os.path.join(cwd, module_name + ".py")
    if os.path.isfile(mod_file):
        return mod_file
    return None


def _check_extracted_paths(tokens: list[str]) -> tuple[str, str]:
    """Check all path-like tokens against sensitive paths. Most restrictive wins."""
    from nah.config import is_path_allowed  # lazy import to avoid circular

    block_result = None
    ask_result = None
    project_root = paths.get_project_root()

    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if "/" in tok or tok.startswith("~") or tok.startswith("."):
            basic = paths.check_path_basic_raw(tok)
            if basic:
                decision, reason = basic
                # Check allow_paths exemption (same as check_path does for file tools)
                if is_path_allowed(tok, project_root):
                    continue  # exempted
                if decision == taxonomy.BLOCK:
                    block_result = (taxonomy.BLOCK, reason)
                elif ask_result is None:
                    ask_result = (taxonomy.ASK, reason)

    if block_result:
        return block_result
    if ask_result:
        return ask_result
    return taxonomy.ALLOW, ""


def _check_composition(stage_results: list[StageResult], stages: list[Stage]) -> tuple[str, str, str]:
    """Check pipe composition rules. Returns (decision, reason, rule) or ('', '', '')."""
    if len(stage_results) < 2:
        return "", "", ""

    for i in range(len(stage_results) - 1):
        # Only check pipe compositions (not && or ||)
        if i < len(stages) and stages[i].operator != "|":
            continue

        left = stage_results[i]
        right = stage_results[i + 1]

        # sensitive_read | network → block (exfiltration)
        if _is_sensitive_read(left) and right.action_type in (taxonomy.NETWORK_OUTBOUND, taxonomy.NETWORK_WRITE):
            return taxonomy.BLOCK, f"data exfiltration: {right.tokens[0]} receives sensitive input", "sensitive_read | network"

        # network | exec → block (remote code execution)
        if left.action_type in (taxonomy.NETWORK_OUTBOUND, taxonomy.NETWORK_WRITE) and _is_exec_sink_stage(right):
            return taxonomy.BLOCK, f"remote code execution: {right.tokens[0]} receives network input", "network | exec"

        # decode | exec → block (obfuscation)
        if taxonomy.is_decode_stage(left.tokens) and _is_exec_sink_stage(right):
            return taxonomy.BLOCK, f"obfuscated execution: {right.tokens[0]} receives decoded input", "decode | exec"

        # any_read | exec → ask
        if left.action_type == taxonomy.FILESYSTEM_READ and _is_exec_sink_stage(right):
            return taxonomy.ASK, f"local code execution: {right.tokens[0]} receives file input", "read | exec"

    return "", "", ""


def _is_sensitive_read(sr: StageResult) -> bool:
    """Check if a stage reads from a sensitive path."""
    if sr.action_type != taxonomy.FILESYSTEM_READ:
        return False
    for tok in sr.tokens[1:]:
        if tok.startswith("-"):
            continue
        basic = paths.check_path_basic_raw(tok)
        if not basic:
            continue
        _decision, reason = basic
        if "hook directory" in reason:
            return True
        if "sensitive path" in reason:
            return True
    return False


def _is_exec_sink_stage(sr: StageResult) -> bool:
    """Check if a stage is an exec sink."""
    return bool(sr.tokens) and taxonomy.is_exec_sink(sr.tokens[0])


def _aggregate(result: ClassifyResult) -> None:
    """Aggregate stage decisions — most restrictive wins."""
    if not result.stages:
        result.final_decision = taxonomy.ALLOW
        result.reason = "no stages"
        return

    worst = result.stages[0]
    for sr in result.stages[1:]:
        if taxonomy.STRICTNESS.get(sr.decision, 2) > taxonomy.STRICTNESS.get(worst.decision, 2):
            worst = sr

    result.final_decision = worst.decision
    result.reason = worst.reason
