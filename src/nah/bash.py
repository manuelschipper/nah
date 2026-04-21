"""Bash command classifier — tokenize, decompose, classify, compose."""

import os.path
import re
import shlex
import sys
from dataclasses import dataclass, field, replace

from nah import context, paths, taxonomy
from nah.content import scan_content, format_content_message

_MAX_UNWRAP_DEPTH = 5

# Safe redirect sinks — /dev/ special files that are not real file writes.
# Excludes block devices (/dev/sda, /dev/disk*) which are dangerous.
_REDIRECT_SAFE_SINKS = frozenset({"/dev/null", "/dev/stderr", "/dev/stdout", "/dev/tty"})
_WINDOWS_REDIRECT_SAFE_SINKS = frozenset({"nul", "con"})
_WINDOWS_QUOTED_TRAILING_BACKSLASH_RE = re.compile(r"""(["'])([A-Za-z]:\\[^"']*\\)\1""")

_PYTHON_READ_ONLY_MODULES = frozenset({"json.tool", "tabnanny", "tokenize"})
_PYTHON_WRITE_MODULES = frozenset({"py_compile", "compileall"})
_PYTHON_SAFE_MODULES = _PYTHON_READ_ONLY_MODULES | _PYTHON_WRITE_MODULES
_PYTHON_ENV_RISK_VARS = frozenset({
    "HOME",
    "PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONPYCACHEPREFIX",
    "PYTHONUSERBASE",
})


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
    python_env_risk: str = ""
    python_prior_env_risk: str = ""
    python_prior_cwd_risk: bool = False


@dataclass
class StageResult:
    tokens: list[str]
    action_type: str = taxonomy.UNKNOWN
    default_policy: str = taxonomy.ASK
    decision: str = taxonomy.ASK
    reason: str = ""
    redirect_target: str = ""
    python_module: str = ""
    transparent_python_formatter: bool = False


@dataclass
class ClassifyResult:
    command: str
    stages: list[StageResult] = field(default_factory=list)
    final_decision: str = taxonomy.ASK
    reason: str = ""
    composition_rule: str = ""


@dataclass
class EnvWrapperParse:
    inner: list[str] | None = None
    risk_reason: str = ""
    unsupported: bool = False


def classify_command(command: str) -> ClassifyResult:
    """Main entry point: classify a bash command string."""
    result = ClassifyResult(command=command)

    if not command.strip():
        result.final_decision = taxonomy.ALLOW
        result.reason = "empty command"
        return result

    # --- FD-103: extract all substitutions before splitting ---
    # Substitutions can contain pipes that _split_on_operators would
    # incorrectly split on.  Extract first, replace with placeholders,
    # then classify inner commands separately.
    all_subs = _extract_substitutions(command)
    # Fail-closed: unbalanced substitution → block
    if any(s[3] == "failed" for s in all_subs):
        result.final_decision = taxonomy.BLOCK
        result.reason = "unbalanced substitution"
        return result
    active_subs = [s for s in all_subs if s[3] != "failed"]
    sanitized = _replace_substitutions(command, active_subs) if active_subs else command

    # Split on top-level shell operators while quoting context is available,
    # then shlex.split each stage independently (FD-095).
    try:
        raw_stages = _split_on_operators(sanitized)
    except ValueError as exc:
        result.final_decision = taxonomy.ASK
        detail = str(exc)
        result.reason = (
            f"unparseable command ({detail})"
            if detail == "unbalanced subshell group"
            else f"unparseable command (shlex error{': ' + detail if detail else ''})"
        )
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

    # --- FD-103: classify extracted substitution inners ---
    _kw = dict(global_table=global_table, builtin_table=builtin_table,
               project_table=project_table, user_actions=user_actions,
               profile=profile, trust_project=trust_project)
    inner_results_by_idx: dict[int, StageResult] = {}
    for sub_idx, (inner_cmd, _start, _end, _kind) in enumerate(active_subs):
        inner_cmd = inner_cmd.strip()
        if not inner_cmd:
            continue
        try:
            inner_raw = _split_on_operators(inner_cmd)
        except ValueError:
            inner_results_by_idx[sub_idx] = _obfuscated_result(
                [inner_cmd], "unparseable substitution", user_actions)
            continue
        inner_stages: list[Stage] = []
        _inner_ok = True
        for istage_str, iop in inner_raw:
            try:
                inner_stages.extend(_raw_stage_to_stages(istage_str, iop))
            except ValueError:
                inner_results_by_idx[sub_idx] = _obfuscated_result(
                    [inner_cmd], "unparseable substitution", user_actions)
                _inner_ok = False
                break
        if not _inner_ok:
            continue
        if inner_stages:
            outer_placeholder = Stage(tokens=[f"__nah_psub_{sub_idx}__"])
            inner_results_by_idx[sub_idx] = _classify_inner(
                inner_stages, outer_placeholder, 1, **_kw)

    # Decompose each raw stage into classified stages
    stages: list[Stage] = []
    for stage_str, op in raw_stages:
        stage_str = stage_str.strip()
        if not stage_str:
            continue
        try:
            stages.extend(_raw_stage_to_stages(stage_str, op))
        except ValueError as exc:
            result.final_decision = taxonomy.ASK
            detail = str(exc) or "shlex error"
            result.reason = (
                f"unparseable command ({detail})"
                if detail == "unbalanced subshell group"
                else f"unparseable command (shlex error{': ' + detail if detail else ''})"
            )
            return result

    if not stages:
        result.final_decision = taxonomy.ALLOW
        result.reason = "empty command"
        return result

    stages = _apply_trusted_script_vars(stages, active_subs)
    stages = _expand_intra_chain_vars(stages)

    # Classify each stage. Track shell-local state that can make a later
    # allowlisted python -m invocation resolve non-stdlib code.
    python_prior_env_risk = ""
    python_prior_cwd_risk = False
    for idx, stage in enumerate(stages):
        if python_prior_env_risk or python_prior_cwd_risk:
            stage = replace(
                stage,
                python_prior_env_risk=python_prior_env_risk,
                python_prior_cwd_risk=python_prior_cwd_risk,
            )
            stages[idx] = stage

        sr = _classify_stage(stage, **_kw)
        result.stages.append(sr)

        if stage.operator != "|":
            env_risk = _stage_python_env_update_risk(stage)
            if env_risk:
                python_prior_env_risk = env_risk
            if _stage_can_change_cwd(stage):
                python_prior_cwd_risk = True

    # --- FD-103: tighten outer results from inner process sub classifications ---
    if inner_results_by_idx:
        for i, sr in enumerate(result.stages):
            _tighten_from_inner(stages[i], sr, inner_results_by_idx)

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

        # Heredoc operator: << or <<- followed by a delimiter.
        # The body (up to the closing delimiter line) must not be split on
        # operators — consume it as part of the current stage.
        if c == '<' and i + 1 < n and command[i + 1] == '<' and not (i + 2 < n and command[i + 2] == '<'):
            # Consume << or <<-
            current.append(c)
            current.append(command[i + 1])
            j = i + 2
            if j < n and command[j] == '-':
                current.append(command[j])
                j += 1
            # Skip whitespace between operator and delimiter
            while j < n and command[j] in (' ', '\t'):
                current.append(command[j])
                j += 1
            # Extract delimiter (may be quoted: 'DELIM', "DELIM", or bare)
            delim_start = j
            if j < n and command[j] in ("'", '"'):
                quote_char = command[j]
                current.append(command[j])
                j += 1
                while j < n and command[j] != quote_char:
                    current.append(command[j])
                    j += 1
                if j < n:
                    current.append(command[j])
                    j += 1
                delim = command[delim_start + 1:j - 1]
            else:
                while j < n and command[j] not in (' ', '\t', '\n', ';', '|', '&', '<', '>'):
                    current.append(command[j])
                    j += 1
                delim = command[delim_start:j]
            # Consume everything through the closing delimiter line
            if delim:
                while j < n:
                    current.append(command[j])
                    if command[j] == '\n':
                        # Check if the next line is the closing delimiter
                        line_start = j + 1
                        line_end = line_start
                        while line_end < n and command[line_end] != '\n':
                            line_end += 1
                        line = command[line_start:line_end]
                        # <<- strips leading tabs
                        if line.lstrip('\t') == delim or line == delim:
                            # Consume the closing delimiter line
                            for k in range(line_start, line_end):
                                current.append(command[k])
                            j = line_end
                            break
                    j += 1
            i = j
            continue

        # Shell comment: # at word boundary → consume to end of line (nah-2zt)
        # Keeps content in stage string (heredoc-safe) but skips quote tracking.
        if c == '#':
            at_word_boundary = (i == 0 or command[i - 1] in (' ', '\t', '\n'))
            if at_word_boundary:
                while i < n and command[i] != '\n':
                    current.append(command[i])
                    i += 1
                continue

        # Leading subshell group: consume the balanced group as shell
        # structure so inner operators do not split the outer command.
        if c == '(' and ''.join(current).strip() == "":
            close = _match_parens(command, i)
            if close < 0:
                raise ValueError("unbalanced subshell group")
            current.append(command[i:close + 1])
            i = close + 1
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
        if c == '\n':
            stages.append((''.join(current), ';'))
            current = []
            i += 1
            continue

        current.append(c)
        i += 1

    # Last stage (no trailing operator)
    stages.append((''.join(current), ''))

    return stages


def _skip_heredoc(command: str, start: int) -> int:
    """Skip past a heredoc body that starts at *start*.

    *start* must point at the first ``<`` of a ``<<`` bigram. Returns the
    index of the first character after the terminator line, or ``len(command)``
    if no terminator is found (fail-open — caller treats the rest of the
    command as opaque body, matching shell behavior). Returns *start*
    unchanged if the bigram is not a heredoc operator (for example, ``<<<``
    here-strings, or a malformed marker), so the caller can fall through to
    normal character handling.

    Heredoc bodies are opaque literal content as far as the shell is
    concerned, so apostrophes, backticks, and unbalanced parens inside the
    body must not break nah's substitution parser.
    """
    n = len(command)
    if start + 1 >= n or command[start] != "<" or command[start + 1] != "<":
        return start
    # Here-string ``<<<`` is a different syntax with no body — bail.
    if start + 2 < n and command[start + 2] == "<":
        return start

    i = start + 2  # past the ``<<``

    # ``<<-`` strips leading tabs from the terminator.
    strip_tabs = False
    if i < n and command[i] == "-":
        strip_tabs = True
        i += 1

    # Skip whitespace between the operator and the marker word.
    while i < n and command[i] in " \t":
        i += 1

    if i >= n:
        return start

    # Read the marker word. It may be wrapped in matching ``'`` or ``"``
    # quotes; the quoting flavor controls parameter expansion inside the
    # body, which nah does not care about. Either way, the marker word
    # itself is the same.
    quote_char: str | None = None
    if command[i] in ("'", '"'):
        quote_char = command[i]
        i += 1
        marker_start = i
        while i < n and command[i] != quote_char:
            i += 1
        if i >= n:
            # Unclosed quote — let the caller fall through; the existing
            # quote-tracking code will surface the actual error.
            return start
        marker = command[marker_start:i]
        i += 1  # consume the closing quote
    else:
        marker_start = i
        # Marker word ends at any shell metacharacter or whitespace.
        while i < n and command[i] not in " \t;&|<>()\n":
            i += 1
        marker = command[marker_start:i]

    if not marker:
        return start

    # The body begins on the line after the operator. Find the next newline.
    nl = command.find("\n", i)
    if nl < 0:
        # No newline at all — there is no body. Treat the rest of the
        # command as opaque so apostrophes after the marker do not trip
        # the caller.
        return n

    # Walk line-by-line until we find the terminator line. The terminator
    # is a line that contains exactly the marker (with leading tabs
    # optionally stripped when ``<<-`` was used).
    pos = nl + 1
    while pos < n:
        line_end = command.find("\n", pos)
        if line_end < 0:
            line_end = n
        line = command[pos:line_end]
        if strip_tabs:
            line = line.lstrip("\t")
        if line == marker:
            # Return the position immediately after the terminator line,
            # including its trailing newline if present.
            return line_end + 1 if line_end < n else n
        pos = line_end + 1

    # No terminator found — fail-open to end of input. The shell would
    # error out, but nah only needs to avoid the false-block on
    # apostrophes inside the body.
    return n


def _match_parens(command: str, start: int) -> int:
    """Find the matching close-paren for an opening paren at *start*.

    Tracks nesting depth and respects single-quote, double-quote, and
    backslash escaping.  Returns the index of the matching ``)``, or
    ``-1`` if the parens are unbalanced (fail-closed).
    """
    depth = 1
    i = start + 1
    n = len(command)
    while i < n:
        c = command[i]
        # Heredoc bodies are opaque literal content; skip past them so
        # apostrophes, backticks, and unbalanced parens inside the body
        # do not corrupt depth tracking. Must come before the single-quote
        # branch below.
        if (
            c == "<"
            and i + 1 < n
            and command[i + 1] == "<"
            and (i + 2 >= n or command[i + 2] != "<")
        ):
            new_i = _skip_heredoc(command, i)
            if new_i > i:
                i = new_i
                continue
        if c == "'":
            # Skip single-quoted region (no escapes inside)
            j = command.find("'", i + 1)
            i = j + 1 if j >= 0 else n
            continue
        if c == '"':
            # Skip double-quoted region (backslash escapes apply)
            i += 1
            while i < n:
                if command[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if command[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _extract_substitutions(command: str) -> list[tuple[str, int, int, str]]:
    """Extract shell substitution syntax from *command*.

    Returns a list of ``(inner_command, start, end, kind)`` tuples where
    *kind* is one of ``"process_in"``, ``"process_out"``, ``"command"``,
    ``"backtick"``, or ``"failed"`` (unbalanced parens — fail-closed).
    Single-quoted regions are skipped (literal text).
    Arithmetic expansion ``$((...))`` is skipped (not a command).
    """
    results: list[tuple[str, int, int, str]] = []
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        # Heredoc bodies are opaque literal content. Skip past them before
        # the single-quote branch so an apostrophe inside the body does not
        # open a fake quoted region. Must come before the single-quote
        # skip below.
        if (
            c == "<"
            and i + 1 < n
            and command[i + 1] == "<"
            and (i + 2 >= n or command[i + 2] != "<")
        ):
            new_i = _skip_heredoc(command, i)
            if new_i > i:
                i = new_i
                continue
        # Skip single-quoted regions entirely
        if c == "'":
            j = command.find("'", i + 1)
            i = j + 1 if j >= 0 else n
            continue
        # Skip backslash-escaped characters
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        # $(...) command substitution — skip $((…)) arithmetic
        if c == "$" and i + 1 < n and command[i + 1] == "(":
            if i + 2 < n and command[i + 2] == "(":
                # Arithmetic expansion $((expr)) — skip past closing ))
                j = command.find("))", i + 3)
                i = j + 2 if j >= 0 else i + 3
                continue
            close = _match_parens(command, i + 1)
            if close >= 0:
                inner = command[i + 2 : close].strip()
                results.append((inner, i, close + 1, "command"))
                i = close + 1
                continue
            # Unbalanced — mark as failed so caller can fall back to block
            results.append(("", i, i + 2, "failed"))
            i += 2
            continue
        # <(...) or >(...) process substitution
        if c in "<>" and i + 1 < n and command[i + 1] == "(":
            kind = "process_in" if c == "<" else "process_out"
            close = _match_parens(command, i + 1)
            if close >= 0:
                inner = command[i + 2 : close].strip()
                results.append((inner, i, close + 1, kind))
                i = close + 1
                continue
            # Unbalanced — mark as failed so caller can fall back to block
            results.append(("", i, i + 2, "failed"))
            i += 2
            continue
        # `...` backtick substitution
        if c == "`":
            j = i + 1
            while j < n:
                if command[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if command[j] == "`":
                    inner = command[i + 1 : j]
                    results.append((inner, i, j + 1, "backtick"))
                    j += 1
                    break
                j += 1
            i = j
            continue
        i += 1
    return results


def _replace_substitutions(
    command: str,
    subs: list[tuple[str, int, int, str]],
) -> str:
    """Replace extracted substitution ranges with ``__nah_psub_N__`` placeholders.

    Processes in reverse offset order so earlier indices remain valid.
    """
    indexed = sorted(enumerate(subs), key=lambda t: t[1][1], reverse=True)
    result = command
    for idx, (_inner, start, end, _kind) in indexed:
        result = result[:start] + f"__nah_psub_{idx}__" + result[end:]
    return result


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


def _strip_heredoc_bodies(stage_str: str) -> str:
    """Remove heredoc bodies and terminators from a stage string.

    The heredoc operator and marker word are preserved on the first line
    so the post-shlex.split token-stripping logic in :func:`_decompose`
    still sees them. The body content (between the operator line and the
    terminator) plus the terminator line itself are removed so that
    :func:`shlex.split` can tokenize the result without choking on
    apostrophes, backticks, or other unescaped characters in the body
    that would otherwise be parsed as shell syntax.

    The body content is captured separately by :func:`_extract_heredoc_literal`
    upstream, so removing it here does not lose information that the
    classifier needs.

    Quote-aware: a ``<<`` sequence inside a single- or double-quoted
    region is not a heredoc operator and is left untouched. ``<<<``
    here-strings are also left untouched.
    """
    if "<<" not in stage_str:
        return stage_str
    n = len(stage_str)
    out: list[str] = []
    i = 0
    while i < n:
        c = stage_str[i]
        # Single-quoted region — copy literally; no heredoc detection inside.
        if c == "'":
            j = stage_str.find("'", i + 1)
            end = j + 1 if j >= 0 else n
            out.append(stage_str[i:end])
            i = end
            continue
        # Double-quoted region — copy literally (with backslash escapes).
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if stage_str[i] == "\\" and i + 1 < n:
                    out.append(stage_str[i : i + 2])
                    i += 2
                    continue
                if stage_str[i] == '"':
                    out.append(stage_str[i])
                    i += 1
                    break
                out.append(stage_str[i])
                i += 1
            continue
        # Backslash escape outside quotes
        if c == "\\" and i + 1 < n:
            out.append(stage_str[i : i + 2])
            i += 2
            continue
        # Heredoc detection — same guard as _skip_heredoc.
        if (
            c == "<"
            and i + 1 < n
            and stage_str[i + 1] == "<"
            and (i + 2 >= n or stage_str[i + 2] != "<")
        ):
            new_i = _skip_heredoc(stage_str, i)
            if new_i > i:
                # Keep the operator line up to and including its newline,
                # then jump past the body and the terminator line.
                first_nl = stage_str.find("\n", i)
                if 0 <= first_nl < new_i:
                    out.append(stage_str[i : first_nl + 1])
                    i = new_i
                    continue
                # No newline before the helper's stop position — copy
                # whatever the helper consumed and resume after it.
                out.append(stage_str[i:new_i])
                i = new_i
                continue
        # Default: copy character
        out.append(c)
        i += 1
    return "".join(out)


def _strip_shell_comments_for_split(stage_str: str) -> str:
    """Remove shell comments before shlex tokenization.

    Heredoc bodies must be stripped before this helper runs. Otherwise a line
    beginning with ``#`` inside heredoc content would be shell data, not a shell
    comment, and stripping it could hide content from later inspection.
    """
    if "#" not in stage_str:
        return stage_str

    out: list[str] = []
    i = 0
    n = len(stage_str)
    while i < n:
        c = stage_str[i]

        if c == "'":
            j = stage_str.find("'", i + 1)
            end = j + 1 if j >= 0 else n
            out.append(stage_str[i:end])
            i = end
            continue

        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if stage_str[i] == "\\" and i + 1 < n:
                    out.append(stage_str[i : i + 2])
                    i += 2
                    continue
                out.append(stage_str[i])
                if stage_str[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        if c == "\\" and i + 1 < n:
            out.append(stage_str[i : i + 2])
            i += 2
            continue

        if c == "#":
            at_word_boundary = i == 0 or stage_str[i - 1] in (" ", "\t", "\n")
            if at_word_boundary:
                while i < n and stage_str[i] != "\n":
                    i += 1
                if i < n and stage_str[i] == "\n":
                    out.append("\n")
                    i += 1
                else:
                    out.append(" ")
                continue

        out.append(c)
        i += 1

    return "".join(out)


def _extract_subshell_group(stage_str: str) -> tuple[str, str] | None:
    """Return ``(inner, suffix)`` for a leading ``(...)`` subshell group.

    Only leading groups are recognized. Parentheses that appear later in a
    normal argv word are left to the ordinary tokenizer.
    """
    start = len(stage_str) - len(stage_str.lstrip())
    if start >= len(stage_str) or stage_str[start] != "(":
        return None

    close = _match_parens(stage_str, start)
    if close < 0:
        raise ValueError("unbalanced subshell group")

    suffix = stage_str[close + 1:]
    if _parse_subshell_redirects(suffix) is None:
        return None

    return stage_str[start + 1:close], suffix


def _split_stage_tokens(stage_str: str) -> list[str]:
    """Split a raw stage with the same comment fallback used historically."""
    try:
        return shlex.split(stage_str)
    except ValueError as first_error:
        fixed = _fix_windows_quoted_trailing_backslash(stage_str, first_error)
        if fixed != stage_str:
            try:
                return shlex.split(fixed)
            except ValueError:
                pass
        try:
            return shlex.split(stage_str, comments=True)
        except ValueError:
            raise first_error


def _fix_windows_quoted_trailing_backslash(stage_str: str, error: ValueError) -> str:
    """Double a Windows path's final backslash when it escapes its closing quote."""
    if "No closing quotation" not in str(error):
        return stage_str
    return _WINDOWS_QUOTED_TRAILING_BACKSLASH_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}\\{m.group(1)}",
        stage_str,
    )


def _parse_subshell_redirects(suffix: str) -> list[tuple[str, bool, str]] | None:
    """Parse group-level output redirects, ignoring descriptor duplication.

    Returns ``None`` when *suffix* contains anything other than redirects and
    whitespace, allowing callers to fall back to conservative ordinary parsing.
    """
    if not suffix.strip():
        return []

    tokens = _split_stage_tokens(suffix)
    redirects: list[tuple[str, bool, str]] = []
    i = 0
    while i < len(tokens):
        parsed_redirect = _parse_output_redirect(tokens[i])
        if parsed_redirect is None:
            return None

        redirect_fd, redirect_append, target, needs_target, redirect_kind = parsed_redirect
        step = 1
        if needs_target:
            if i + 1 >= len(tokens):
                raise ValueError("unparseable subshell redirect")
            target = tokens[i + 1]
            step = 2
            if redirect_kind == "dup_or_file":
                if target == "-" or target.isdigit():
                    redirect_kind = "dup"
                else:
                    redirect_kind = "file"
                    if redirect_fd in ("", "1"):
                        redirect_fd = "&"

        if redirect_kind == "file":
            redirects.append((redirect_fd, redirect_append, target))
        i += step

    return redirects


def _apply_outer_operator(stages: list[Stage], op: str) -> None:
    """Attach an outer shell operator to the final stage in a flattened group."""
    if stages:
        stages[-1].operator = op


def _raw_stage_to_stages(
    stage_str: str,
    op: str,
    *,
    heredoc_literal: str = "",
) -> list[Stage]:
    """Convert one raw shell stage string into decomposed classifier stages."""
    stage_str = stage_str.strip()
    if not stage_str:
        return []

    group = _extract_subshell_group(stage_str)
    if group is not None:
        inner, suffix = group
        if op == "|":
            return [
                Stage(
                    tokens=["subshell"],
                    operator=op,
                    action_hint=taxonomy.UNKNOWN,
                    action_reason="subshell pipe pending",
                )
            ]

        raw_inner = _split_on_operators(inner)
        stages: list[Stage] = []
        for inner_stage, inner_op in raw_inner:
            stages.extend(_raw_stage_to_stages(inner_stage, inner_op))
        _apply_outer_operator(stages, op)

        redirects = _parse_subshell_redirects(suffix)
        if redirects is None:
            return []
        if redirects and stages:
            redirect_tokens = stages[-1].tokens
            for redirect_fd, redirect_append, target in redirects:
                stages.append(
                    Stage(
                        tokens=list(redirect_tokens),
                        redirect_fd=redirect_fd,
                        redirect_target=target,
                        redirect_append=redirect_append,
                    )
                )
        return stages

    heredoc_literal = heredoc_literal or _extract_heredoc_literal(stage_str)
    stage_for_split = _strip_heredoc_bodies(stage_str)
    stage_for_split = _strip_shell_comments_for_split(stage_for_split)
    tokens = _split_stage_tokens(stage_for_split)

    if not tokens:
        return []

    return _decompose(
        tokens,
        operator=op,
        heredoc_literal=heredoc_literal,
    )


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

        # Heredoc redirect: strip the << operator and delimiter token.
        # shlex.split doesn't understand heredocs, so the operator, delimiter,
        # and body all appear as flat tokens. The body is already captured in
        # heredoc_literal (extracted from the raw stage string upstream).
        # We only strip the operator + delimiter here — body tokens remain in
        # the token list but are harmless: for interpreter heredocs, the
        # _classify_stage bypass block returns before _check_extracted_paths;
        # for non-interpreter heredocs (cat), redirect detection still needs
        # to process tokens that may follow on the same first line.
        if tok in ("<<", "<<-"):
            i += 2  # skip operator + delimiter
            continue
        if tok.startswith("<<") and tok not in ("<<<",):
            # Glued form: <<DELIM, <<-DELIM, <<'DELIM', <<-'DELIM'
            i += 1  # skip the single glued token
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


_SHELL_FUNCTION_ENV_RE = re.compile(r"^\s*\(\)\s*\{")


def _env_var_risk_reason(value: str) -> str:
    """Return a reason when an env var value should fail closed."""
    if not value:
        return ""
    if _SHELL_FUNCTION_ENV_RE.search(value):
        return "env var shell function"
    try:
        tokens = shlex.split(value)
    except ValueError:
        return "env var parse error"
    if not tokens:
        return ""
    command = taxonomy._normalize_command_name(tokens[0])
    if taxonomy.is_exec_sink(tokens[0]):
        return f"env var exec sink: {command}"
    return ""


def _env_var_has_exec(value: str) -> bool:
    """Check if an env var value contains an execution risk."""
    return bool(_env_var_risk_reason(value))


def _classify_export_assignment(
    stage: Stage,
    user_actions: dict[str, str] | None,
) -> StageResult | None:
    """Classify benign ``export NAME=value`` shell-builtin stages."""
    tokens = stage.tokens
    if not tokens or taxonomy._normalize_command_name(tokens[0]) != "export" or len(tokens) == 1:
        return None

    for tok in tokens[1:]:
        if tok.startswith("-") or not _is_env_assignment(tok):
            return None

    action_type = taxonomy.FILESYSTEM_READ
    reason = "export assignment"
    for tok in tokens[1:]:
        _, value = tok.split("=", 1)
        risk_reason = _env_var_risk_reason(value)
        if risk_reason:
            action_type = taxonomy.LANG_EXEC
            reason = (
                "export assignment exec sink"
                if risk_reason.startswith("env var exec sink")
                else f"export assignment {risk_reason}"
            )
            break

    sr = StageResult(tokens=tokens)
    sr.action_type = action_type
    sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)
    _apply_policy(sr)
    sr.reason = reason
    return _apply_redirect_guard(stage, sr, user_actions=user_actions)


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
    python_risk_vars: list[str] = []
    for start, tok in enumerate(tokens):
        parts = _env_assignment_parts(tok)
        if parts is None:
            if "=" in tok and not tok.startswith(("-", "=")):
                _, value = tok.split("=", 1)
                risk_reason = _env_var_risk_reason(value)
                if risk_reason:
                    return Stage(
                        tokens=tokens, operator=operator,
                        action_hint=taxonomy.LANG_EXEC, action_reason=risk_reason,
                    )
            break
        name, value = parts
        if name in _PYTHON_ENV_RISK_VARS:
            python_risk_vars.append(name)
        risk_reason = _env_var_risk_reason(value)
        if risk_reason:
            return Stage(
                tokens=tokens, operator=operator,
                action_hint=taxonomy.LANG_EXEC, action_reason=risk_reason,
            )
    else:
        # All tokens were env assignments
        return Stage(tokens=tokens, operator=operator,
                     action_hint=taxonomy.FILESYSTEM_READ,
                     action_reason="env-only assignment")

    stage = Stage(tokens=tokens[start:], operator=operator,
                  action_hint=action_hint, action_reason=action_reason)
    if python_risk_vars:
        stage.python_env_risk = "python env assignment: " + ",".join(sorted(set(python_risk_vars)))
    return stage


_PSUB_PREFIX = "__nah_psub_"
_PSUB_SUFFIX = "__"
_CODEX_COMPANION_GLOB = "~/.claude/plugins/cache/openai-codex/codex/*/scripts/codex-companion.mjs"
_CODEX_COMPANION_SENTINEL = (
    "~/.claude/plugins/cache/openai-codex/codex/__nah_trusted__/scripts/codex-companion.mjs"
)
_SHELL_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _tighten_from_inner(
    stage: Stage,
    sr: StageResult,
    inner_results: dict[int, StageResult],
) -> None:
    """Escalate *sr* if an inner substitution result is stricter.

    Scans *stage.tokens* for ``__nah_psub_N__`` placeholders (which may be
    embedded inside larger tokens after shlex processing), looks up the
    corresponding inner ``StageResult``, and overwrites *sr* if the inner
    decision is more restrictive.  Never weakens.
    """
    worst: StageResult | None = None
    worst_s = -1
    for tok in stage.tokens:
        pos = 0
        while True:
            start = tok.find(_PSUB_PREFIX, pos)
            if start < 0:
                break
            end = tok.find(_PSUB_SUFFIX, start + len(_PSUB_PREFIX))
            if end < 0:
                break
            try:
                idx = int(tok[start + len(_PSUB_PREFIX) : end])
            except ValueError:
                pos = end + len(_PSUB_SUFFIX)
                continue
            ir = inner_results.get(idx)
            if ir is not None:
                s = taxonomy.STRICTNESS.get(ir.decision, 2)
                if s > worst_s:
                    worst_s = s
                    worst = ir
            pos = end + len(_PSUB_SUFFIX)
    if worst is None:
        return
    current_s = taxonomy.STRICTNESS.get(sr.decision, 0)
    if worst_s > current_s:
        sr.action_type = worst.action_type
        sr.default_policy = worst.default_policy
        sr.decision = worst.decision
        sr.reason = f"substitution: {worst.reason}"


def _env_assignment_parts(tok: str) -> tuple[str, str] | None:
    """Return ``(name, value)`` for shell-style env assignments."""
    if not _is_env_assignment(tok):
        return None
    return tok.split("=", 1)


def _safe_literal_var_value(value: str) -> bool:
    """True if *value* is a plain literal safe to propagate across chain stages.

    Rejects anything containing ``$`` (nested variable reference or
    unexpanded substitution), backticks, or a command-substitution
    placeholder. Propagating those would require real shell evaluation.
    """
    return "$" not in value and "`" not in value and _PSUB_PREFIX not in value


_INTRA_CHAIN_VAR_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


def _expand_token(token: str, var_map: dict[str, str]) -> str:
    """Substitute ``$NAME`` and ``${NAME}`` inside *token* using *var_map*.

    Leaves unknown names untouched. Skips tokens carrying a substitution
    placeholder so ``__nah_psub_N__`` sentinels are never second-pass
    expanded.
    """
    if not var_map or _PSUB_PREFIX in token:
        return token
    if "$" not in token:
        return token

    def _replace(match: "re.Match[str]") -> str:
        name = match.group(1) or match.group(2)
        if name in var_map:
            return var_map[name]
        return match.group(0)

    return _INTRA_CHAIN_VAR_RE.sub(_replace, token)


def _placeholder_sub_index(value: str) -> int | None:
    """Return the substitution index for an exact ``__nah_psub_N__`` value."""
    if not value.startswith(_PSUB_PREFIX) or not value.endswith(_PSUB_SUFFIX):
        return None
    raw_idx = value[len(_PSUB_PREFIX) : -len(_PSUB_SUFFIX)]
    if not raw_idx.isdigit():
        return None
    return int(raw_idx)


def _norm_shell_path(path: str) -> str:
    return path.replace("\\", "/")


def _trusted_codex_companion_globs() -> set[str]:
    return {
        _norm_shell_path(_CODEX_COMPANION_GLOB),
        _norm_shell_path(os.path.expanduser(_CODEX_COMPANION_GLOB)),
    }


def _is_stderr_devnull_redirect(tokens: list[str]) -> bool:
    """Return True for a single optional ``2>/dev/null`` redirect."""
    if not tokens:
        return True
    if len(tokens) > 2:
        return False

    parsed = _parse_output_redirect(tokens[0])
    if parsed is None:
        return False

    fd, append, target, needs_target, kind = parsed
    if needs_target:
        if len(tokens) != 2:
            return False
        target = tokens[1]
    elif len(tokens) != 1:
        return False

    return fd == "2" and not append and target == "/dev/null" and kind == "file"


def _is_trusted_codex_companion_discovery(inner_cmd: str) -> bool:
    """Recognize the narrow ``ls <companion-glob> [2>/dev/null] | head -1`` idiom."""
    try:
        raw_stages = [(s.strip(), op) for s, op in _split_on_operators(inner_cmd) if s.strip()]
    except ValueError:
        return False

    if len(raw_stages) != 2 or raw_stages[0][1] != "|" or raw_stages[1][1] != "":
        return False

    try:
        left = _split_stage_tokens(raw_stages[0][0])
        right = _split_stage_tokens(raw_stages[1][0])
    except ValueError:
        return False

    if len(left) < 2 or os.path.basename(left[0]) != "ls":
        return False
    if _norm_shell_path(left[1]) not in _trusted_codex_companion_globs():
        return False
    if not taxonomy.is_codex_companion_script(left[1]):
        return False
    if not _is_stderr_devnull_redirect(left[2:]):
        return False

    return len(right) == 2 and os.path.basename(right[0]) == "head" and right[1] == "-1"


def _trusted_script_var_binding(
    token: str,
    active_subs: list[tuple[str, int, int, str]],
) -> tuple[str, str] | None:
    """Return a trusted script variable binding from an env-only assignment token."""
    parts = _env_assignment_parts(token)
    if parts is None:
        return None

    name, value = parts
    sub_idx = _placeholder_sub_index(value)
    if sub_idx is None or sub_idx >= len(active_subs):
        return None

    inner_cmd, _start, _end, kind = active_subs[sub_idx]
    if kind != "command":
        return None
    if not _is_trusted_codex_companion_discovery(inner_cmd.strip()):
        return None
    return name, _CODEX_COMPANION_SENTINEL


def _variable_ref_name(token: str) -> str | None:
    """Return the variable name for ``$NAME`` or ``${NAME}`` tokens."""
    if token.startswith("${") and token.endswith("}"):
        name = token[2:-1]
    elif token.startswith("$"):
        name = token[1:]
    else:
        return None
    return name if _SHELL_VAR_RE.fullmatch(name) else None


def _rewrite_trusted_node_script(stage: Stage, trusted_script_vars: dict[str, str]) -> Stage:
    """Rewrite only ``node`` script argv when it references a trusted variable."""
    if len(stage.tokens) < 2 or os.path.basename(stage.tokens[0]) != "node":
        return stage

    var_name = _variable_ref_name(stage.tokens[1])
    if var_name is None or var_name not in trusted_script_vars:
        return stage

    tokens = list(stage.tokens)
    tokens[1] = trusted_script_vars[var_name]
    return replace(
        stage,
        tokens=tokens,
        action_reason=f"Codex companion delegation via trusted {stage.tokens[1]}",
    )


def _apply_trusted_script_vars(
    stages: list[Stage],
    active_subs: list[tuple[str, int, int, str]],
) -> list[Stage]:
    """Carry trusted same-command script variables into later stage classification.

    This intentionally recognizes only the Codex companion discovery pattern
    used by molds. It does not perform general shell evaluation.
    """
    trusted_script_vars: dict[str, str] = {}
    rewritten: list[Stage] = []

    for stage in stages:
        current = _rewrite_trusted_node_script(stage, trusted_script_vars)
        rewritten.append(current)

        if stage.action_hint == taxonomy.FILESYSTEM_READ and stage.action_reason == "env-only assignment":
            for token in stage.tokens:
                parts = _env_assignment_parts(token)
                if parts is None:
                    continue
                name, _value = parts
                binding = _trusted_script_var_binding(token, active_subs)
                if binding is None:
                    trusted_script_vars.pop(name, None)
                else:
                    trusted_script_vars[binding[0]] = binding[1]

        if stage.operator not in {"&&", ";"}:
            trusted_script_vars.clear()

    return rewritten


def _expand_intra_chain_vars(stages: list[Stage]) -> list[Stage]:
    """Propagate literal env assignments across ``&&`` / ``||`` / ``;`` stages.

    Mirrors ``_apply_trusted_script_vars`` but generalizes to any safe
    literal value. Closes the sensitive-path bypass where an earlier
    stage binds a variable and a later stage dereferences it:

        BAD=/etc/shadow && cat "$BAD"

    Two assignment shapes are recognized:

    * Form A: bare ``NAME=value`` stages tagged by ``_make_stage`` as
      ``FILESYSTEM_READ`` with reason ``"env-only assignment"``.
    * Form B: ``export NAME=value [NAME2=value2 ...]`` stages. These
      are not pre-tagged — ``_classify_export_assignment`` runs later
      inside ``_classify_stage`` — so we detect them structurally.

    The var map clears on pipe ``|`` (subshell semantics) and is
    preserved across ``&&``, ``||``, and ``;`` to match real bash.
    Only later consumer stages have their tokens rewritten; the
    executed command string stored on ``ClassifyResult`` is never
    touched.
    """
    var_map: dict[str, str] = {}
    rewritten: list[Stage] = []

    for stage in stages:
        assignment_tokens: list[str] | None = None

        if (
            stage.action_hint == taxonomy.FILESYSTEM_READ
            and stage.action_reason == "env-only assignment"
        ):
            assignment_tokens = list(stage.tokens)
        elif (
            len(stage.tokens) >= 2
            and taxonomy._normalize_command_name(stage.tokens[0]) == "export"
            and all(_is_env_assignment(t) for t in stage.tokens[1:])
        ):
            assignment_tokens = list(stage.tokens[1:])

        if assignment_tokens is not None:
            for tok in assignment_tokens:
                parts = _env_assignment_parts(tok)
                if parts is None:
                    continue
                name, value = parts
                if _safe_literal_var_value(value):
                    var_map[name] = value
                else:
                    var_map.pop(name, None)
            rewritten.append(stage)
        else:
            if var_map:
                new_tokens = [_expand_token(t, var_map) for t in stage.tokens]
                if new_tokens != list(stage.tokens):
                    rewritten.append(replace(stage, tokens=new_tokens))
                else:
                    rewritten.append(stage)
            else:
                rewritten.append(stage)

        if stage.operator == "|":
            var_map.clear()

    return rewritten


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

    export_assignment = _classify_export_assignment(stage, user_actions)
    if export_assignment is not None:
        return export_assignment

    # Shell unwrapping
    unwrapped = _unwrap_shell(stage, depth, global_table=global_table,
                              builtin_table=builtin_table, project_table=project_table,
                              user_actions=user_actions, profile=profile,
                              trust_project=trust_project)
    if unwrapped is not None:
        return _apply_redirect_guard(stage, unwrapped, user_actions=user_actions)

    # Heredoc-fed interpreter: python3 << EOF ... EOF
    # The heredoc body is already in stage.heredoc_literal (extracted upstream).
    # Bypass classify_tokens (which would see bare 'python3' as unknown) and
    # _apply_policy (which would call _resolve_context without the heredoc body).
    if stage.heredoc_literal and tokens:
        cmd = taxonomy._normalize_command_name(tokens[0])
        if cmd in taxonomy._SCRIPT_INTERPRETERS:
            sr.action_type = taxonomy.LANG_EXEC
            sr.default_policy = taxonomy.get_policy(taxonomy.LANG_EXEC, user_actions)
            if sr.default_policy == taxonomy.CONTEXT:
                sr.decision, sr.reason = context.resolve_context(
                    taxonomy.LANG_EXEC, tokens=tokens,
                    target_path=None, inline_code=stage.heredoc_literal)
            else:
                _apply_policy(sr)
            return _apply_redirect_guard(stage, sr, user_actions=user_actions)

    safe_python = _safe_python_module_result(stage, user_actions=user_actions, profile=profile)
    if safe_python is not None:
        return _apply_redirect_guard(stage, safe_python, user_actions=user_actions)

    find_exec = _classify_find_exec(
        stage,
        depth,
        global_table=global_table,
        builtin_table=builtin_table,
        project_table=project_table,
        user_actions=user_actions,
        profile=profile,
        trust_project=trust_project,
    )
    if find_exec is not None:
        return find_exec

    nah_cli = _classify_nah_cli(stage, user_actions=user_actions)
    if nah_cli is not None:
        return _apply_redirect_guard(stage, nah_cli, user_actions=user_actions)

    # Classify tokens
    sr.action_type = taxonomy.classify_tokens(tokens, global_table, builtin_table, project_table,
                                              profile=profile, trust_project=trust_project)
    sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)

    # Apply policy → decision
    _apply_policy(sr)
    if stage.action_reason and sr.action_type.startswith("agent_"):
        sr.reason = stage.action_reason

    # Path extraction + checking (regardless of policy)
    path_decision, path_reason = _check_extracted_paths(tokens)
    if path_decision == taxonomy.BLOCK or (path_decision == taxonomy.ASK and sr.decision == taxonomy.ALLOW):
        sr.decision = path_decision
        sr.reason = path_reason

    return _apply_redirect_guard(stage, sr, user_actions=user_actions)


_FIND_EXEC_PREDICATES = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_FIND_EXEC_TERMINATORS = frozenset({";", "+"})
_FIND_EXPRESSION_STARTERS = frozenset({"(", ")", "!", "not"})
_FIND_LEADING_FLAGS = frozenset({"-H", "-L", "-P"})
_FIND_LEADING_VALUE_FLAGS = frozenset({"-D", "-O"})


def _classify_nah_cli(
    stage: Stage,
    *,
    user_actions: dict[str, str] | None,
) -> StageResult | None:
    """Classify nah's own lifecycle commands without treating target names as paths."""
    tokens = stage.tokens
    if len(tokens) < 2 or taxonomy._normalize_command_name(tokens[0]) != "nah":
        return None

    subcommand = tokens[1]
    if subcommand not in {"install", "update", "uninstall"}:
        return None

    sr = StageResult(tokens=tokens)
    sr.action_type = taxonomy.FILESYSTEM_WRITE
    sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)
    if subcommand == "uninstall":
        sr.decision = taxonomy.ASK
        sr.reason = "nah uninstall removes nah protection"
        return sr

    sr.decision = taxonomy.ALLOW
    sr.reason = f"nah {subcommand} manages nah runtime files"
    return sr


def _apply_outer_path_guard(stage: Stage, sr: StageResult) -> StageResult:
    path_decision, path_reason = _check_extracted_paths(stage.tokens)
    if path_decision == taxonomy.BLOCK or (
        path_decision == taxonomy.ASK and sr.decision == taxonomy.ALLOW
    ):
        sr.decision = path_decision
        sr.reason = path_reason

    if (
        sr.decision == taxonomy.ALLOW
        and sr.action_type in (taxonomy.FILESYSTEM_WRITE, taxonomy.FILESYSTEM_DELETE)
    ):
        for root in _find_search_roots(stage.tokens):
            root_decision, root_reason = context.resolve_context(
                sr.action_type,
                tokens=stage.tokens,
                target_path=root,
            )
            if taxonomy.STRICTNESS.get(root_decision, 2) > taxonomy.STRICTNESS.get(sr.decision, 2):
                sr.decision = root_decision
                sr.reason = root_reason
    return sr


def _find_search_roots(tokens: list[str]) -> list[str]:
    roots: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            i += 1
            continue
        if not roots and tok in _FIND_LEADING_FLAGS:
            i += 1
            continue
        if not roots and tok in _FIND_LEADING_VALUE_FLAGS:
            i += 2
            continue
        if not roots and any(tok.startswith(flag) and len(tok) > len(flag) for flag in _FIND_LEADING_VALUE_FLAGS):
            i += 1
            continue
        if tok in _FIND_EXEC_PREDICATES or tok in _FIND_EXPRESSION_STARTERS or tok.startswith("-"):
            break
        roots.append(tok)
        i += 1
    return roots or ["."]


def _find_exec_payloads(tokens: list[str]) -> list[tuple[str, list[str], bool]]:
    payloads: list[tuple[str, list[str], bool]] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok not in _FIND_EXEC_PREDICATES:
            i += 1
            continue

        payload: list[str] = []
        j = i + 1
        while j < len(tokens) and tokens[j] not in _FIND_EXEC_TERMINATORS:
            payload.append(tokens[j])
            j += 1
        has_terminator = j < len(tokens) and tokens[j] in _FIND_EXEC_TERMINATORS
        payloads.append((tok, payload, has_terminator))
        i = j + 1 if has_terminator else len(tokens)
    return payloads


def _ask_find_exec_result(tokens: list[str], reason: str) -> StageResult:
    sr = StageResult(tokens=tokens)
    sr.action_type = taxonomy.UNKNOWN
    sr.default_policy = taxonomy.ASK
    sr.decision = taxonomy.ASK
    sr.reason = reason
    return sr


def _find_delete_result(stage: Stage, user_actions: dict[str, str] | None) -> StageResult:
    sr = StageResult(tokens=stage.tokens)
    sr.action_type = taxonomy.FILESYSTEM_DELETE
    sr.default_policy = taxonomy.get_policy(taxonomy.FILESYSTEM_DELETE, user_actions)
    _apply_policy(sr)
    return _apply_outer_path_guard(stage, sr)


def _classify_find_exec(
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
    tokens = stage.tokens
    if not tokens or taxonomy._normalize_command_name(tokens[0]) != "find":
        return None

    payloads = _find_exec_payloads(tokens)
    if not payloads:
        return None

    results: list[StageResult] = []
    if "-delete" in tokens:
        results.append(_find_delete_result(stage, user_actions))

    for predicate, payload, has_terminator in payloads:
        if not payload:
            sr = _ask_find_exec_result(tokens, f"malformed find {predicate}: missing command")
        elif not has_terminator:
            sr = _ask_find_exec_result(tokens, f"malformed find {predicate}: missing terminator")
        else:
            inner_stage = _make_stage(payload, stage.operator) or Stage(
                tokens=payload,
                operator=stage.operator,
            )
            inner_stage = _copy_python_metadata(inner_stage, stage)
            sr = _classify_stage(
                inner_stage,
                depth + 1,
                global_table=global_table,
                builtin_table=builtin_table,
                project_table=project_table,
                user_actions=user_actions,
                profile=profile,
                trust_project=trust_project,
            )
        results.append(_apply_outer_path_guard(stage, sr))

    worst = results[0]
    for sr in results[1:]:
        if taxonomy.STRICTNESS.get(sr.decision, 2) > taxonomy.STRICTNESS.get(worst.decision, 2):
            worst = sr
    return _apply_redirect_guard(stage, worst, user_actions=user_actions)


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



def _combine_python_risks(*risks: str) -> str:
    return "; ".join(risk for risk in risks if risk)


def _copy_python_metadata(inner_stage: Stage, outer_stage: Stage, *, env_risk: str = "") -> Stage:
    inner_stage.python_env_risk = _combine_python_risks(
        inner_stage.python_env_risk,
        outer_stage.python_env_risk,
        env_risk,
    )
    inner_stage.python_prior_env_risk = _combine_python_risks(
        inner_stage.python_prior_env_risk,
        outer_stage.python_prior_env_risk,
    )
    inner_stage.python_prior_cwd_risk = (
        inner_stage.python_prior_cwd_risk or outer_stage.python_prior_cwd_risk
    )
    return inner_stage


def _effective_command_tokens(stage: Stage) -> list[str]:
    """Return tokens after simple shell-builtin wrappers that keep shell state."""
    tokens = stage.tokens
    while tokens and os.path.basename(tokens[0]) in {"command", "builtin"}:
        if os.path.basename(tokens[0]) == "command":
            inner = _strip_command_builtin(tokens)
            if not inner:
                return tokens
            tokens = inner
            continue
        if len(tokens) <= 1:
            return tokens
        tokens = tokens[1:]
    return tokens


def _stage_can_change_cwd(stage: Stage) -> bool:
    tokens = _effective_command_tokens(stage)
    if not tokens:
        return False
    return os.path.basename(tokens[0]) in {"cd", "pushd", "popd"}


def _env_assignment_name(tok: str) -> str:
    if not _is_env_assignment(tok):
        return ""
    return tok.split("=", 1)[0]


def _stage_python_env_update_risk(stage: Stage) -> str:
    """Return a persistent shell-env risk introduced by an assignment/export stage."""
    tokens = _effective_command_tokens(stage)
    if not tokens:
        return ""

    if all(_is_env_assignment(tok) for tok in tokens):
        names = sorted({
            _env_assignment_name(tok)
            for tok in tokens
            if _env_assignment_name(tok) in _PYTHON_ENV_RISK_VARS
        })
        if names:
            return "python env assignment stage: " + ",".join(names)
        return ""

    if os.path.basename(tokens[0]) != "export":
        return ""

    names: set[str] = set()
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        name = _env_assignment_name(tok) or tok
        if name in _PYTHON_ENV_RISK_VARS:
            names.add(name)
    if names:
        return "exported python env: " + ",".join(sorted(names))
    return ""


def _env_wrapper_python_risk(tokens: list[str]) -> str:
    """Detect env(1) forms that alter Python command resolution/startup state."""
    if not tokens or os.path.basename(tokens[0]) != "env":
        return ""

    risks: set[str] = set()
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            break
        if _is_env_assignment(tok):
            name = tok.split("=", 1)[0]
            if name in _PYTHON_ENV_RISK_VARS:
                risks.add(name)
            i += 1
            continue
        if tok in _ENV_NOARG_FLAGS:
            risks.update(_PYTHON_ENV_RISK_VARS)
            i += 1
            continue
        if tok in {"-u", "--unset"}:
            if i + 1 < len(tokens) and tokens[i + 1] in _PYTHON_ENV_RISK_VARS:
                risks.add(tokens[i + 1])
            i += 2
            continue
        if tok.startswith("--unset="):
            name = tok.split("=", 1)[1]
            if name in _PYTHON_ENV_RISK_VARS:
                risks.add(name)
            i += 1
            continue
        if tok in {"-C", "--chdir"} or tok.startswith("--chdir="):
            risks.add("cwd")
            i += 2 if tok in {"-C", "--chdir"} else 1
            continue
        if tok in {"--argv0"}:
            i += 2
            continue
        if tok.startswith("--argv0="):
            i += 1
            continue
        if tok.startswith("-"):
            break
        break

    if risks:
        return "env wrapper alters python resolution: " + ",".join(sorted(risks))
    return ""


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


def _parse_env_wrapper(tokens: list[str]) -> EnvWrapperParse | None:
    """Parse env(1) wrapper operands without discarding risky assignments."""
    if not tokens or os.path.basename(tokens[0]) != "env":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        parts = _env_assignment_parts(tok)
        if parts is not None:
            _, value = parts
            risk_reason = _env_var_risk_reason(value)
            if risk_reason:
                return EnvWrapperParse(risk_reason=risk_reason)
            i += 1
            continue

        if "=" in tok and not tok.startswith(("-", "=")):
            _, value = tok.split("=", 1)
            risk_reason = _env_var_risk_reason(value)
            return EnvWrapperParse(
                risk_reason=risk_reason or "unsupported env assignment"
            )

        if tok in _ENV_NOARG_FLAGS:
            i += 1
            continue

        if tok in _ENV_ARG_FLAGS:
            if i + 1 >= n:
                return EnvWrapperParse(unsupported=True)
            i += 2
            continue

        if any(tok.startswith(prefix) for prefix in _ENV_ARG_FLAG_PREFIXES):
            i += 1
            continue

        if tok.startswith("-"):
            return EnvWrapperParse(unsupported=True)

        break

    inner = tokens[i:]
    return EnvWrapperParse(inner=inner if inner else None)


def _strip_env_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip safe env wrapper forms, returning inner command tokens."""
    parsed = _parse_env_wrapper(tokens)
    if parsed is None or parsed.risk_reason or parsed.unsupported:
        return None
    return parsed.inner


_SUDO_NOARG_SAFE = {
    "-A", "--askpass",
    "-B", "--bell",
    "-b", "--background",
    "-E", "--preserve-env",
    "-H", "--set-home",
    "-k", "--reset-timestamp",
    "-N", "--no-update",
    "-n", "--non-interactive",
    "-P", "--preserve-groups",
    "-S", "--stdin",
    "--",
}
_SUDO_VALUE_SAFE = {
    "-C", "--close-from",
    "-p", "--prompt",
    "-T", "--command-timeout",
}
_SUDO_FAIL_CLOSED = {
    "-e", "--edit",
    "-h", "--help",
    "--host",
    "-i", "--login",
    "-K", "--remove-timestamp",
    "-l", "--list",
    "-s", "--shell",
    "-V", "--version",
    "-v", "--validate",
    "-D", "--chdir",
    "-g", "--group",
    "-R", "--chroot",
    "-r", "--role",
    "-t", "--type",
    "-U", "--other-user",
    "-u", "--user",
}
_SUDO_SAFE_CLUSTER_FLAGS = frozenset("ABbEHkNnPS")
_SUDO_SAFE_VALUE_PREFIXES = (
    "--preserve-env=",
    "--close-from=",
    "--prompt=",
    "--command-timeout=",
)
_SUDO_FAIL_CLOSED_PREFIXES = (
    "--chdir=",
    "--group=",
    "--host=",
    "--chroot=",
    "--role=",
    "--type=",
    "--other-user=",
    "--user=",
)
_SUDO_FAIL_CLOSED_SHORT_VALUE_FLAGS = {"-D", "-g", "-h", "-R", "-r", "-t", "-U", "-u"}


def _strip_sudo_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip supported sudo wrapper flags, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "sudo":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if _is_env_assignment(tok):
            break

        if tok in _SUDO_NOARG_SAFE:
            i += 1
            continue

        if tok in _SUDO_FAIL_CLOSED or any(tok.startswith(prefix) for prefix in _SUDO_FAIL_CLOSED_PREFIXES):
            return None

        if any(tok.startswith(flag) and len(tok) > len(flag) for flag in _SUDO_FAIL_CLOSED_SHORT_VALUE_FLAGS):
            return None

        if tok in _SUDO_VALUE_SAFE:
            if i + 1 >= n:
                return None
            i += 2
            continue

        matched_safe_prefix = False
        for prefix in _SUDO_SAFE_VALUE_PREFIXES:
            if tok.startswith(prefix):
                if len(tok) == len(prefix):
                    return None
                i += 1
                matched_safe_prefix = True
                break
        if matched_safe_prefix:
            continue

        if any(tok.startswith(flag) and len(tok) > len(flag) for flag in {"-C", "-p", "-T"}):
            i += 1
            continue

        if tok.startswith("-") and len(tok) > 2 and not tok.startswith("--"):
            if set(tok[1:]) <= _SUDO_SAFE_CLUSTER_FLAGS:
                i += 1
                continue
            return None

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


def _strip_chrt_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip command-mode chrt wrapper, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "chrt":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in {"-a", "--all-tasks", "-m", "--max", "-p", "--pid", "-h", "--help", "-V", "--version"}:
            return None

        if tok in {"-b", "--batch", "-d", "--deadline", "-f", "--fifo", "-i", "--idle", "-o", "--other", "-r", "--rr", "-R", "--reset-on-fork", "-v", "--verbose"}:
            i += 1
            continue

        if tok in {"-T", "--sched-runtime", "-P", "--sched-period", "-D", "--sched-deadline"}:
            if i + 1 >= n:
                return None
            i += 2
            continue

        if tok.startswith(("--sched-runtime=", "--sched-period=", "--sched-deadline=")):
            i += 1
            continue

        if tok.startswith("-"):
            return None

        break

    if i >= n:
        return None

    i += 1  # priority
    if i < n and tokens[i] == "--":
        i += 1

    inner = tokens[i:]
    return inner if inner else None


_PRLIMIT_NOARG_FLAGS = {"--noheadings", "--raw", "--verbose"}
_PRLIMIT_ARG_FLAGS = {"-o", "--output"}
_PRLIMIT_PID_FLAGS = {"-p", "--pid"}
_PRLIMIT_RESOURCE_SHORT_FLAGS = {"-c", "-d", "-e", "-f", "-i", "-l", "-m", "-n", "-q", "-r", "-s", "-t", "-u", "-v", "-x", "-y"}
_PRLIMIT_RESOURCE_LONG_FLAGS = {
    "--core",
    "--data",
    "--nice",
    "--fsize",
    "--sigpending",
    "--memlock",
    "--rss",
    "--nofile",
    "--msgqueue",
    "--rtprio",
    "--stack",
    "--cpu",
    "--nproc",
    "--as",
    "--locks",
    "--rttime",
}


def _strip_prlimit_wrapper(tokens: list[str]) -> list[str] | None:
    """Strip command-mode prlimit wrapper, returning inner command tokens."""
    if not tokens or os.path.basename(tokens[0]) != "prlimit":
        return None

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]

        if tok == "--":
            i += 1
            break

        if tok in _PRLIMIT_NOARG_FLAGS:
            i += 1
            continue

        if tok in _PRLIMIT_PID_FLAGS or tok.startswith("--pid="):
            return None

        if tok in _PRLIMIT_ARG_FLAGS | _PRLIMIT_RESOURCE_SHORT_FLAGS | _PRLIMIT_RESOURCE_LONG_FLAGS:
            if i + 1 >= n:
                return None
            i += 2
            continue

        if tok.startswith("--output=") or any(
            tok.startswith(flag + "=") for flag in _PRLIMIT_RESOURCE_LONG_FLAGS
        ):
            i += 1
            continue

        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2:
            flag = tok[:2]
            if flag == "-p":
                return None
            if flag in _PRLIMIT_ARG_FLAGS | _PRLIMIT_RESOURCE_SHORT_FLAGS:
                i += 1
                continue
            return None

        if tok.startswith("-"):
            return None

        break

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
        or _strip_sudo_wrapper(tokens)
        or _strip_nice_wrapper(tokens)
        or _strip_time_wrapper(tokens)
        or _strip_nohup_wrapper(tokens)
        or _strip_stdbuf_wrapper(tokens)
        or _strip_setsid_wrapper(tokens)
        or _strip_timeout_wrapper(tokens)
        or _strip_ionice_wrapper(tokens)
        or _strip_taskset_wrapper(tokens)
        or _strip_chrt_wrapper(tokens)
        or _strip_prlimit_wrapper(tokens)
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
            inner_stage = _copy_python_metadata(Stage(tokens=inner, operator=stage.operator), stage)
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
            inner_stage = _copy_python_metadata(inner_stage, stage)
            return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                                   builtin_table=builtin_table, project_table=project_table,
                                   user_actions=user_actions, profile=profile,
                                   trust_project=trust_project)
        sr = StageResult(tokens=tokens)
        sr.action_type = taxonomy.UNKNOWN
        sr.default_policy = taxonomy.get_policy(taxonomy.UNKNOWN, user_actions)
        _apply_policy(sr)
        sr.reason = "unsupported time wrapper flags"
        return sr

    # sudo passthrough — dedicated branch so the reason can retain the
    # privilege boundary while still classifying the inner command.
    if tokens and os.path.basename(tokens[0]) == "sudo":
        inner_tokens = _strip_sudo_wrapper(tokens)
        if inner_tokens is None:
            return None
        inner_stage = _make_stage(inner_tokens, stage.operator) or Stage(
            tokens=inner_tokens, operator=stage.operator
        )
        inner_stage = _copy_python_metadata(inner_stage, stage)
        sr = _classify_stage(inner_stage, depth + 1, global_table=global_table,
                             builtin_table=builtin_table, project_table=project_table,
                             user_actions=user_actions, profile=profile,
                             trust_project=trust_project)
        if sr.reason and not sr.reason.startswith("sudo: "):
            sr.reason = f"sudo: {sr.reason}"
        return sr

    # env passthrough — dedicated branch so risky env assignments are not
    # discarded before classifying the inner command.
    if tokens and os.path.basename(tokens[0]) == "env":
        parsed_env = _parse_env_wrapper(tokens)
        if parsed_env is None or parsed_env.unsupported:
            return None
        if parsed_env.risk_reason:
            sr = StageResult(tokens=tokens)
            sr.action_type = taxonomy.LANG_EXEC
            sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)
            _apply_policy(sr)
            sr.reason = (
                f"env wrapper {parsed_env.risk_reason}: "
                f"{sr.action_type} → {sr.decision}"
            )
            return sr
        if parsed_env.inner is None:
            return None
        inner_stage = _make_stage(parsed_env.inner, stage.operator) or Stage(
            tokens=parsed_env.inner, operator=stage.operator
        )
        inner_stage = _copy_python_metadata(
            inner_stage, stage, env_risk=_env_wrapper_python_risk(tokens)
        )
        return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                               builtin_table=builtin_table, project_table=project_table,
                               user_actions=user_actions, profile=profile,
                               trust_project=trust_project)

    mise_inner = taxonomy._extract_mise_exec_inner(tokens)
    if mise_inner is not None:
        inner_stage = _make_stage(mise_inner, stage.operator) or Stage(
            tokens=mise_inner, operator=stage.operator
        )
        inner_stage = _copy_python_metadata(inner_stage, stage)
        sr = _classify_stage(inner_stage, depth + 1, global_table=global_table,
                             builtin_table=builtin_table, project_table=project_table,
                             user_actions=user_actions, profile=profile,
                             trust_project=trust_project)
        if sr.reason and not sr.reason.startswith("mise: "):
            sr.reason = f"mise: {sr.reason}"
        return sr

    # nice and other passthrough wrappers
    passthrough_tokens = _strip_passthrough_wrapper(tokens)
    if passthrough_tokens is not None:
        inner_stage = _make_stage(passthrough_tokens, stage.operator) or Stage(
            tokens=passthrough_tokens, operator=stage.operator
        )
        inner_stage = _copy_python_metadata(inner_stage, stage)
        return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                               builtin_table=builtin_table, project_table=project_table,
                               user_actions=user_actions, profile=profile,
                               trust_project=trust_project)

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
        inner_stage = _copy_python_metadata(Stage(tokens=inner_tokens, operator=stage.operator), stage)
        return _classify_stage(inner_stage, depth + 1, global_table=global_table,
                               builtin_table=builtin_table, project_table=project_table,
                               user_actions=user_actions, profile=profile,
                               trust_project=trust_project)

    is_wrapper, inner = taxonomy.is_shell_wrapper(tokens)
    if not is_wrapper or inner is None:
        return None

    # Check for $() or backticks in eval — obfuscated.
    # Also check for placeholders: top-level extraction already replaced
    # $(…) with __nah_psub_N__ before _unwrap_shell runs.
    if tokens[0] == "eval" and ("$(" in inner or "`" in inner or _PSUB_PREFIX in inner):
        return _obfuscated_result(tokens, "eval with command substitution", user_actions)

    # --- FD-103: extract all substitutions from inner before splitting ---
    inner_all_subs = _extract_substitutions(inner)
    if any(s[3] == "failed" for s in inner_all_subs):
        return _obfuscated_result(tokens, "unbalanced substitution", user_actions)
    inner_active = [s for s in inner_all_subs if s[3] != "failed"]
    inner_sanitized = _replace_substitutions(inner, inner_active) if inner_active else inner

    # Use _split_on_operators on the raw inner string to preserve quoting
    # context (FD-095), then shlex.split each stage independently.
    try:
        raw_stages = _split_on_operators(inner_sanitized)
    except ValueError:
        return _obfuscated_result(tokens, "unparseable inner command", user_actions)

    # Classify extracted substitution inners
    _ikw = dict(global_table=global_table, builtin_table=builtin_table,
                project_table=project_table, user_actions=user_actions,
                profile=profile, trust_project=trust_project)
    inner_sub_results: dict[int, StageResult] = {}
    for psub_idx, (psub_cmd, _ps, _pe, _pk) in enumerate(inner_active):
        psub_cmd = psub_cmd.strip()
        if not psub_cmd:
            continue
        try:
            psub_raw = _split_on_operators(psub_cmd)
        except ValueError:
            inner_sub_results[psub_idx] = _obfuscated_result(
                [psub_cmd], "unparseable substitution", user_actions)
            continue
        psub_stages: list[Stage] = []
        _psub_ok = True
        for pstage_str, pop in psub_raw:
            try:
                psub_stages.extend(_raw_stage_to_stages(pstage_str, pop))
            except ValueError:
                inner_sub_results[psub_idx] = _obfuscated_result(
                    [psub_cmd], "unparseable substitution", user_actions)
                _psub_ok = False
                break
        if not _psub_ok:
            continue
        if psub_stages:
            ph = Stage(tokens=[f"__nah_psub_{psub_idx}__"])
            inner_sub_results[psub_idx] = _classify_inner(
                psub_stages, ph, depth + 1, **_ikw)

    inner_stages: list[Stage] = []
    for stage_str, op in raw_stages:
        try:
            inner_stages.extend(_raw_stage_to_stages(stage_str, op))
        except ValueError as exc:
            detail = str(exc) or "shlex error"
            return _obfuscated_result(tokens, f"unparseable inner command ({detail})", user_actions)

    if inner_stages:
        inner_stages = [_copy_python_metadata(s, stage) for s in inner_stages]
        return _classify_inner(inner_stages, stage, depth + 1,
                               sub_results=inner_sub_results or None, **_ikw)

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
    sub_results: dict[int, StageResult] | None = None,
) -> StageResult:
    """Classify pre-decomposed inner stages."""
    kw = dict(global_table=global_table, builtin_table=builtin_table,
              project_table=project_table, user_actions=user_actions, profile=profile,
              trust_project=trust_project)

    if len(inner_stages) <= 1:
        # Simple case — single command, no operators
        s = inner_stages[0] if inner_stages else Stage(tokens=[])
        sr = _classify_stage(s, depth, **kw)
        if sub_results:
            _tighten_from_inner(s, sr, sub_results)
        return sr

    # Multiple stages — classify each, check composition, aggregate.
    # Mirror top-level Python resolution state tracking inside unwrapped shells.
    inner_results = []
    python_prior_env_risk = ""
    python_prior_cwd_risk = False
    for idx, s in enumerate(inner_stages):
        if python_prior_env_risk or python_prior_cwd_risk:
            s = replace(
                s,
                python_prior_env_risk=_combine_python_risks(
                    s.python_prior_env_risk, python_prior_env_risk
                ),
                python_prior_cwd_risk=s.python_prior_cwd_risk or python_prior_cwd_risk,
            )
            inner_stages[idx] = s

        sr = _classify_stage(s, depth, **kw)
        inner_results.append(sr)

        if s.operator != "|":
            env_risk = _stage_python_env_update_risk(s)
            if env_risk:
                python_prior_env_risk = env_risk
            if _stage_can_change_cwd(s):
                python_prior_cwd_risk = True

    # FD-103: tighten from inner process sub results before composition
    if sub_results:
        for i, sr in enumerate(inner_results):
            _tighten_from_inner(inner_stages[i], sr, sub_results)

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

    mise_inner = taxonomy._extract_mise_exec_inner(tokens)
    if mise_inner is not None:
        inner_stage = _make_stage(mise_inner, stage.operator) or Stage(
            tokens=mise_inner, operator=stage.operator
        )
        return _extract_redirect_literal(inner_stage)

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
    if _is_redirect_safe_sink(stage.redirect_target):
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
    if _is_redirect_safe_sink(target):
        return taxonomy.ALLOW, ""
    basic = paths.check_path_basic_raw(target)
    if basic:
        decision, reason = basic
        # reason is "targets X: detail" — rewrite as "redirect to X: detail"
        display = reason.replace("targets ", "", 1) if reason.startswith("targets ") else reason
        return decision, f"redirect to {display}"

    return context.resolve_filesystem_context(target)


def _is_redirect_safe_sink(target: str) -> bool:
    """Return True for redirect targets that are not filesystem writes."""
    normalized_target = target.rstrip(":").lower()
    return (
        target in _REDIRECT_SAFE_SINKS
        or target.startswith("/dev/fd/")
        or normalized_target in _WINDOWS_REDIRECT_SAFE_SINKS
    )


def _python_module_invocation(tokens: list[str]) -> tuple[str, list[str]] | None:
    """Return (module, args) for exact python/python3 -m invocations."""
    if len(tokens) < 3:
        return None
    cmd = taxonomy._normalize_interpreter(os.path.basename(tokens[0]))
    if cmd not in {"python", "python3"}:
        return None
    if tokens[1] != "-m":
        return None
    module = tokens[2]
    if not module or module.startswith("-"):
        return None
    return module, tokens[3:]


def _glued_input_redirect_target(tok: str) -> str:
    if tok.startswith("0<") and not tok.startswith("0<<") and len(tok) > 2:
        return tok[2:]
    if tok.startswith("<") and not tok.startswith("<<") and len(tok) > 1:
        return tok[1:]
    return ""


def _strip_input_redirect_args(args: list[str]) -> list[str] | None:
    """Remove stdin redirection tokens before parsing module argv."""
    stripped: list[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in {"<", "0<", "<<<"}:
            if i + 1 >= len(args):
                return None
            i += 2
            continue
        if _glued_input_redirect_target(tok) or tok.startswith("<<<"):
            i += 1
            continue
        stripped.append(tok)
        i += 1
    return stripped


def _parse_json_tool_args(args: list[str]) -> tuple[str, list[str], bool] | None:
    args = _strip_input_redirect_args(args)
    if args is None:
        return None
    no_arg_flags = {
        "--sort-keys", "--no-ensure-ascii", "--json-lines",
        "--compact", "--tab", "--no-indent",
    }
    positionals: list[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            positionals.extend(args[i + 1:])
            break
        if tok in no_arg_flags:
            i += 1
            continue
        if tok == "--indent":
            if i + 1 >= len(args) or not re.fullmatch(r"-?\d+", args[i + 1]):
                return None
            i += 2
            continue
        if tok.startswith("--indent="):
            if not re.fullmatch(r"-?\d+", tok.split("=", 1)[1]):
                return None
            i += 1
            continue
        if tok.startswith("-"):
            return None
        positionals.append(tok)
        i += 1

    if len(positionals) > 2:
        return None
    if len(positionals) == 2 and positionals[1] != "-":
        return taxonomy.FILESYSTEM_WRITE, [positionals[1]], False
    return taxonomy.FILESYSTEM_READ, [], True


def _parse_tokenize_args(args: list[str]) -> tuple[str, list[str], bool] | None:
    args = _strip_input_redirect_args(args)
    if args is None:
        return None
    positionals: list[str] = []
    for tok in args:
        if tok in {"-e", "--exact"}:
            continue
        if tok == "--":
            continue
        if tok.startswith("-"):
            return None
        positionals.append(tok)
    if len(positionals) > 1:
        return None
    return taxonomy.FILESYSTEM_READ, [], False


def _parse_tabnanny_args(args: list[str]) -> tuple[str, list[str], bool] | None:
    args = _strip_input_redirect_args(args)
    if args is None:
        return None
    after_double_dash = False
    for tok in args:
        if tok == "--":
            after_double_dash = True
            continue
        if not after_double_dash and tok in {"-v", "--verbose", "-q", "--quiet"}:
            continue
        if not after_double_dash and tok.startswith("-"):
            return None
    return taxonomy.FILESYSTEM_READ, [], False


def _parse_py_compile_args(args: list[str]) -> tuple[str, list[str], bool] | None:
    args = _strip_input_redirect_args(args)
    if args is None:
        return None
    targets: list[str] = []
    after_double_dash = False
    for tok in args:
        if tok == "--" and not after_double_dash:
            after_double_dash = True
            continue
        if not after_double_dash and tok in {"-q", "--quiet"}:
            continue
        if not after_double_dash and tok.startswith("-"):
            return None
        targets.append(tok)
    if not targets:
        return None
    return taxonomy.FILESYSTEM_WRITE, targets, False


def _parse_compileall_args(args: list[str]) -> tuple[str, list[str], bool] | None:
    args = _strip_input_redirect_args(args)
    if args is None:
        return None
    no_arg_flags = {"-f", "-q", "-b", "-l", "--force", "--quiet", "--legacy"}
    value_flags = {
        "-j", "-r", "-x", "-i", "-s", "-p", "-d",
        "--workers", "--recursion-limit", "--rx", "--input-file",
        "--stripdir", "--prependdir", "--ddir", "--invalidation-mode",
    }
    targets: list[str] = []
    i = 0
    after_double_dash = False
    while i < len(args):
        tok = args[i]
        if tok == "--" and not after_double_dash:
            after_double_dash = True
            i += 1
            continue
        if not after_double_dash and tok in no_arg_flags:
            i += 1
            continue
        if not after_double_dash and tok in value_flags:
            if i + 1 >= len(args):
                return None
            i += 2
            continue
        if not after_double_dash and any(tok.startswith(flag + "=") for flag in value_flags):
            i += 1
            continue
        if not after_double_dash and tok.startswith("-"):
            return None
        targets.append(tok)
        i += 1
    return taxonomy.FILESYSTEM_WRITE, targets or ["."], False


def _parse_safe_python_module_args(module: str, args: list[str]) -> tuple[str, list[str], bool] | None:
    if module == "json.tool":
        return _parse_json_tool_args(args)
    if module == "tokenize":
        return _parse_tokenize_args(args)
    if module == "tabnanny":
        return _parse_tabnanny_args(args)
    if module == "py_compile":
        return _parse_py_compile_args(args)
    if module == "compileall":
        return _parse_compileall_args(args)
    return None


def _python_module_shadow_exists(module: str) -> bool:
    top_level = module.split(".", 1)[0]
    roots = [os.getcwd()]
    project_root = paths.get_project_root()
    if project_root:
        roots.append(project_root)

    seen: set[str] = set()
    for root in roots:
        real_root = os.path.realpath(root)
        if real_root in seen:
            continue
        seen.add(real_root)
        module_file = os.path.join(real_root, top_level + ".py")
        package_init = os.path.join(real_root, top_level, "__init__.py")
        if os.path.isfile(module_file) or os.path.isfile(package_init):
            return True
    return False


def _safe_python_clean_risk(stage: Stage, module: str) -> str:
    if stage.python_env_risk:
        return stage.python_env_risk
    if stage.python_prior_env_risk:
        return stage.python_prior_env_risk
    if stage.python_prior_cwd_risk:
        return "python module resolution after cwd change"
    if os.environ.get("PYTHONPYCACHEPREFIX"):
        return "ambient PYTHONPYCACHEPREFIX"
    if _python_module_shadow_exists(module):
        return "python module shadow in cwd/project"
    return ""


def _resolve_filesystem_targets_context(targets: list[str]) -> tuple[str, str]:
    if not targets:
        return taxonomy.ALLOW, "filesystem_write: no target path"

    worst_decision = taxonomy.ALLOW
    worst_reason = ""
    for target in targets:
        decision, reason = context.resolve_filesystem_context(target)
        if taxonomy.STRICTNESS.get(decision, 0) > taxonomy.STRICTNESS.get(worst_decision, 0):
            worst_decision = decision
            worst_reason = reason
    return worst_decision, worst_reason


def _safe_python_module_result(
    stage: Stage,
    *,
    user_actions: dict[str, str] | None,
    profile: str = "full",
) -> StageResult | None:
    if profile == "none":
        return None

    invocation = _python_module_invocation(stage.tokens)
    if invocation is None:
        return None
    module, args = invocation
    if module not in _PYTHON_SAFE_MODULES:
        return None

    if _safe_python_clean_risk(stage, module):
        return None

    parsed = _parse_safe_python_module_args(module, args)
    if parsed is None:
        return None
    action_type, write_targets, transparent_formatter = parsed

    sr = StageResult(tokens=stage.tokens)
    sr.action_type = action_type
    sr.default_policy = taxonomy.get_policy(action_type, user_actions)
    sr.python_module = module
    sr.transparent_python_formatter = transparent_formatter

    if action_type == taxonomy.FILESYSTEM_WRITE and sr.default_policy == taxonomy.CONTEXT:
        sr.decision, sr.reason = _resolve_filesystem_targets_context(write_targets)
    else:
        _apply_policy(sr)

    path_decision, path_reason = _check_extracted_paths(stage.tokens)
    if path_decision == taxonomy.BLOCK or (path_decision == taxonomy.ASK and sr.decision == taxonomy.ALLOW):
        sr.decision = path_decision
        sr.reason = path_reason

    return sr


def _is_transparent_python_formatter(stage: Stage, sr: StageResult) -> bool:
    return (
        sr.transparent_python_formatter
        and sr.action_type == taxonomy.FILESYSTEM_READ
        and sr.decision == taxonomy.ALLOW
        and stage.redirect_target == ""
    )


def _resolve_context(action_type: str, tokens: list[str]) -> tuple[str, str]:
    """Resolve 'context' policy by checking filesystem or network context."""
    target_path = None
    inline_code = None
    if action_type in (taxonomy.FILESYSTEM_READ, taxonomy.FILESYSTEM_WRITE,
                       taxonomy.FILESYSTEM_DELETE):
        target_path = _extract_primary_target(tokens)
    elif action_type == taxonomy.LANG_EXEC:
        target_path = _resolve_script_path(tokens)
        if target_path is None:
            inline_code = _extract_inline_code(tokens)
    return context.resolve_context(action_type, tokens=tokens, target_path=target_path,
                                   inline_code=inline_code)


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


def _unwrap_lang_exec_wrapper(tokens: list[str]) -> list[str] | None:
    """Return canonical inner lang-exec-ish tokens for supported wrappers."""
    if not tokens:
        return None

    cmd = os.path.basename(tokens[0])
    if cmd in {"make", "gmake"}:
        return [cmd, *tokens[1:]] if cmd != tokens[0] else list(tokens)

    return taxonomy._extract_package_exec_inner(tokens)


def _resolve_makefile_path(tokens: list[str]) -> str | None:
    """Resolve the makefile path for make/gmake execution."""
    if not tokens:
        return None

    cmd = os.path.basename(tokens[0])
    if cmd not in {"make", "gmake"}:
        return None

    def _join(base_dir: str, value: str) -> str:
        if os.path.isabs(value):
            return value
        return os.path.join(base_dir, value)

    effective_dir = os.getcwd()
    makefiles: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in {"-E", "--eval"} or tok.startswith("--eval="):
            return None
        if tok == "-C":
            if i + 1 >= len(tokens):
                return None
            effective_dir = _join(effective_dir, tokens[i + 1])
            i += 2
            continue
        if tok.startswith("-C") and len(tok) > 2:
            effective_dir = _join(effective_dir, tok[2:])
            i += 1
            continue
        if tok == "--directory":
            if i + 1 >= len(tokens):
                return None
            effective_dir = _join(effective_dir, tokens[i + 1])
            i += 2
            continue
        if tok.startswith("--directory="):
            effective_dir = _join(effective_dir, tok.split("=", 1)[1])
            i += 1
            continue
        if tok in {"-f", "--file", "--makefile"}:
            if i + 1 >= len(tokens):
                return None
            makefiles.append(_join(effective_dir, tokens[i + 1]))
            i += 2
            continue
        if tok.startswith("-f") and len(tok) > 2:
            makefiles.append(_join(effective_dir, tok[2:]))
            i += 1
            continue
        if tok.startswith("--file=") or tok.startswith("--makefile="):
            makefiles.append(_join(effective_dir, tok.split("=", 1)[1]))
            i += 1
            continue
        i += 1

    if len(makefiles) > 1:
        return None
    if len(makefiles) == 1:
        return makefiles[0]

    for name in ("GNUmakefile", "makefile", "Makefile"):
        candidate = os.path.join(effective_dir, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _resolve_script_path(tokens: list[str]) -> str | None:
    """Extract script file path from interpreter command tokens.

    Returns resolved path (even if file doesn't exist) so context resolver
    can distinguish "file not found" from "inline execution" (None).
    Handles: python script.py, python -W ignore script.py, python -m module,
    ./script.py, etc. Returns None for inline code (python -c).
    """
    if not tokens:
        return None

    unwrapped = _unwrap_lang_exec_wrapper(tokens)
    if unwrapped is not None:
        tokens = unwrapped

    from nah.taxonomy import (
        _INLINE_FLAGS,
        _MODULE_FLAGS,
        _SCRIPT_EXTENSIONS,
        _SCRIPT_INTERPRETERS,
        _VALUE_FLAGS,
        _extract_source_operand,
        _normalize_command_name,
    )
    cmd = _normalize_command_name(tokens[0])

    if cmd in {"make", "gmake"}:
        return _resolve_makefile_path(tokens)

    if _windows_shell_inline_arg_index(tokens) is not None:
        return None

    sourced = _extract_source_operand(tokens)
    if sourced is not None:
        sourced = os.path.expanduser(sourced)
        if os.path.isabs(sourced):
            return sourced
        return os.path.join(os.getcwd(), sourced)

    raw = tokens[0]
    _, ext = os.path.splitext(cmd)
    # Only direct script-like commands own tokens[0]. Other table-driven
    # lang_exec commands (for example `gh api`) keep their existing operand scan.
    if (
        cmd not in _SCRIPT_INTERPRETERS
        and (ext in _SCRIPT_EXTENSIONS or "/" in raw or "\\" in raw)
    ):
        if os.path.isabs(raw):
            return raw
        if os.path.isfile(raw):
            return os.path.realpath(raw)
        return os.path.join(os.getcwd(), raw)

    inline = _INLINE_FLAGS.get(cmd, set())
    module = _MODULE_FLAGS.get(cmd, set())
    value_flags = _VALUE_FLAGS.get(cmd, set())

    skip_next = False
    for i, tok in enumerate(tokens[1:], 1):
        if skip_next:
            skip_next = False
            continue
        if tok in inline:
            return None  # inline code, no file
        if tok in module and i + 1 < len(tokens):
            return _resolve_module_path(tokens[i + 1])
        if tok in value_flags:
            skip_next = True  # skip flag + its value argument
            continue
        if tok.startswith("-"):
            continue
        # Return resolved path even if file doesn't exist — context resolver
        # distinguishes "file not found" from "inline execution" (None).
        if os.path.isabs(tok):
            return tok
        cwd = os.getcwd()
        return os.path.join(cwd, tok)

    return None


def _extract_inline_code(tokens: list[str]) -> str | None:
    """Extract inline code string from interpreter tokens (python -c '...', node -e '...').

    Returns the code string following an inline flag, or None if no inline
    flag found or no code argument follows it.
    """
    if not tokens or len(tokens) < 2:
        return None

    unwrapped = _unwrap_lang_exec_wrapper(tokens)
    if unwrapped is not None:
        tokens = unwrapped

    from nah.taxonomy import _INLINE_FLAGS, _VALUE_FLAGS, _normalize_command_name
    cmd = _normalize_command_name(tokens[0])

    if cmd in {"make", "gmake"}:
        return None

    windows_idx = _windows_shell_inline_arg_index(tokens)
    if windows_idx is not None:
        return " ".join(tokens[windows_idx:]) if windows_idx >= 0 else None

    inline = _INLINE_FLAGS.get(cmd, set())
    if not inline:
        return None
    value_flags = _VALUE_FLAGS.get(cmd, set())

    skip_next = False
    for i, tok in enumerate(tokens[1:], 1):
        if skip_next:
            skip_next = False
            continue
        if tok in value_flags:
            skip_next = True
            continue
        if tok in inline:
            if i + 1 < len(tokens):
                return tokens[i + 1]
            return None  # bare flag with no code argument
        if tok.startswith("-"):
            continue
    return None


def _windows_shell_inline_arg_index(tokens: list[str]) -> int | None:
    """Return inline payload index for Windows shells, -1 if opaque encoded."""
    if len(tokens) < 2:
        return None
    cmd = taxonomy._normalize_command_name(tokens[0])
    flag = tokens[1].lower()
    if cmd in {"powershell", "pwsh"}:
        if flag in {"-command", "-c"}:
            return 2 if len(tokens) > 2 else -1
        if flag == "-encodedcommand":
            return -1
    if cmd == "cmd" and flag in {"/c", "/k"}:
        return 2 if len(tokens) > 2 else -1
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
        check_tok = _glued_input_redirect_target(tok) or tok
        if check_tok.startswith("-"):
            continue
        if "/" in check_tok or check_tok.startswith("~") or check_tok.startswith("."):
            basic = paths.check_path_basic_raw(check_tok)
            if basic:
                decision, reason = basic
                # Check allow_paths exemption (same as check_path does for file tools)
                if is_path_allowed(check_tok, project_root):
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

        right_is_exec_sink = _is_exec_sink_stage(right)
        if right_is_exec_sink and _is_transparent_suffix_from(i + 1, stage_results, stages):
            continue

        # network | exec → block (remote code execution)
        if left.action_type in (taxonomy.NETWORK_OUTBOUND, taxonomy.NETWORK_WRITE) and right_is_exec_sink:
            return taxonomy.BLOCK, f"remote code execution: {right.tokens[0]} receives network input", "network | exec"

        # decode | exec → block (obfuscation)
        if taxonomy.is_decode_stage(left.tokens) and right_is_exec_sink:
            return taxonomy.BLOCK, f"obfuscated execution: {right.tokens[0]} receives decoded input", "decode | exec"

        # any_read | exec → ask
        if left.action_type == taxonomy.FILESYSTEM_READ and right_is_exec_sink:
            return taxonomy.ASK, f"local code execution: {right.tokens[0]} receives file input", "read | exec"

    return "", "", ""


def _is_transparent_suffix_from(
    start: int,
    stage_results: list[StageResult],
    stages: list[Stage],
) -> bool:
    if start >= len(stage_results):
        return False

    idx = start
    while idx < len(stage_results):
        if not _is_transparent_suffix_stage(stages[idx], stage_results[idx]):
            return False
        if idx >= len(stages) - 1 or stages[idx].operator != "|":
            return True
        idx += 1

    return True


def _is_transparent_suffix_stage(stage: Stage, sr: StageResult) -> bool:
    if sr.decision != taxonomy.ALLOW:
        return False
    if _is_transparent_python_formatter(stage, sr):
        return True
    if stage.redirect_target:
        return False
    if not sr.tokens:
        return False

    cmd = os.path.basename(sr.tokens[0])
    if cmd in {"tail", "head", "wc", "sort", "uniq"}:
        return sr.action_type == taxonomy.FILESYSTEM_READ
    if cmd == "tee":
        return _is_transparent_tee_stage(sr)
    return False


def _is_transparent_tee_stage(sr: StageResult) -> bool:
    if sr.action_type != taxonomy.FILESYSTEM_WRITE:
        return False

    targets: list[str] = []
    args = sr.tokens[1:]
    i = 0
    after_double_dash = False
    while i < len(args):
        tok = args[i]
        if tok == "--" and not after_double_dash:
            after_double_dash = True
            i += 1
            continue
        if not after_double_dash and tok in {"-a", "--append", "-i", "--ignore-interrupts", "-p"}:
            i += 1
            continue
        if not after_double_dash and tok == "--output-error":
            if i + 1 >= len(args):
                return False
            i += 2
            continue
        if not after_double_dash and tok.startswith("--output-error="):
            i += 1
            continue
        if not after_double_dash and tok.startswith("-"):
            return False
        targets.append(tok)
        i += 1

    if not targets:
        return True
    for target in targets:
        if _is_redirect_safe_sink(target):
            continue
        if paths.resolve_path(target).startswith(os.path.realpath("/tmp") + os.sep):
            continue
        decision, _reason = context.resolve_filesystem_context(target)
        if decision != taxonomy.ALLOW:
            return False
    return True


def _is_sensitive_read(sr: StageResult) -> bool:
    """Check if a stage reads from a sensitive path."""
    if sr.action_type != taxonomy.FILESYSTEM_READ:
        return False
    for tok in sr.tokens[1:]:
        check_tok = _glued_input_redirect_target(tok) or tok
        if check_tok.startswith("-"):
            continue
        basic = paths.check_path_basic_raw(check_tok)
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
