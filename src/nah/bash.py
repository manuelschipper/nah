"""Bash command classifier — tokenize, decompose, classify, compose."""

import shlex
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
    policy: str = "ask"
    decision: str = "ask"
    reason: str = ""


@dataclass
class ClassifyResult:
    command: str
    stages: list[StageResult] = field(default_factory=list)
    final_decision: str = "ask"
    reason: str = ""
    composition_rule: str = ""


def classify_command(command: str) -> ClassifyResult:
    """Main entry point: classify a bash command string."""
    result = ClassifyResult(command=command)

    if not command.strip():
        result.final_decision = "allow"
        result.reason = "empty command"
        return result

    # Tokenize
    try:
        tokens = shlex.split(command)
    except ValueError:
        result.final_decision = "ask"
        result.reason = "unparseable command (shlex error)"
        return result

    if not tokens:
        result.final_decision = "allow"
        result.reason = "empty command"
        return result

    # Load config for custom classify/actions
    merged_table = None
    user_actions = None
    try:
        from nah.config import get_config  # lazy import
        cfg = get_config()
        if cfg.classify:
            merged_table = taxonomy.build_merged_classify_table(cfg.classify)
        if cfg.actions:
            user_actions = cfg.actions
    except Exception:
        pass  # config unavailable — use defaults

    # Decompose into stages
    stages = _decompose(tokens)

    # Classify each stage
    for stage in stages:
        sr = _classify_stage(stage, merged_table=merged_table, user_actions=user_actions)
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

        # Handle glued semicolons: "ls;rm" → split into "ls", operator ";", "rm"
        # Only for tokens without spaces (spaces mean it came from a quoted string).
        if ";" in tok and tok != ";" and " " not in tok:
            parts = tok.split(";")
            for j, part in enumerate(parts):
                if part:
                    current_tokens.append(part)
                if j < len(parts) - 1:
                    stage = _make_stage(current_tokens, ";")
                    if stage:
                        stages.append(stage)
                    current_tokens = []
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
    merged_table: list | None = None,
    user_actions: dict[str, str] | None = None,
) -> StageResult:
    """Classify a single pipeline stage."""
    tokens = stage.tokens
    sr = StageResult(tokens=tokens)

    if not tokens:
        sr.action_type = taxonomy.UNKNOWN
        sr.policy = "ask"
        sr.decision = "ask"
        sr.reason = "empty stage"
        return sr

    # Shell unwrapping
    if depth < _MAX_UNWRAP_DEPTH:
        is_wrapper, inner = taxonomy.is_shell_wrapper(tokens)
        if is_wrapper and inner is not None:
            # Check for $() or backticks in eval — obfuscated
            if tokens[0] == "eval" and ("$(" in inner or "`" in inner):
                sr.action_type = taxonomy.OBFUSCATED
                sr.policy = taxonomy.get_policy(taxonomy.OBFUSCATED, user_actions)
                sr.decision = sr.policy
                sr.reason = "eval with command substitution"
                return sr
            try:
                inner_tokens = shlex.split(inner)
            except ValueError:
                sr.action_type = taxonomy.OBFUSCATED
                sr.policy = taxonomy.get_policy(taxonomy.OBFUSCATED, user_actions)
                sr.decision = sr.policy
                sr.reason = "unparseable inner command"
                return sr
            if inner_tokens:
                inner_stage = Stage(tokens=inner_tokens, operator=stage.operator)
                return _classify_stage(inner_stage, depth + 1, merged_table, user_actions)

    if depth >= _MAX_UNWRAP_DEPTH:
        sr.action_type = taxonomy.OBFUSCATED
        sr.policy = taxonomy.get_policy(taxonomy.OBFUSCATED, user_actions)
        sr.decision = sr.policy
        sr.reason = "excessive shell nesting"
        return sr

    # Classify tokens
    sr.action_type = taxonomy.classify_tokens(tokens, merged_table)
    sr.policy = taxonomy.get_policy(sr.action_type, user_actions)

    # Handle redirect target — treat as filesystem_write for the target path
    if stage.redirect_target:
        redir_decision, redir_reason = _check_redirect(stage.redirect_target)
        if redir_decision in ("block", "ask"):
            sr.decision = redir_decision
            sr.reason = f"redirect target: {redir_reason}"
            return sr

    # Apply policy
    if sr.policy == "allow":
        sr.decision = "allow"
        sr.reason = f"{sr.action_type} → allow"
    elif sr.policy == "block":
        sr.decision = "block"
        sr.reason = f"{sr.action_type} → block"
    elif sr.policy == "ask":
        sr.decision = "ask"
        sr.reason = f"{sr.action_type} → ask"
    elif sr.policy == "context":
        sr.decision, sr.reason = _resolve_context(sr.action_type, tokens)
    else:
        sr.decision = "ask"
        sr.reason = f"unknown policy: {sr.policy}"

    # Path extraction + checking (regardless of policy)
    path_decision, path_reason = _check_extracted_paths(tokens)
    if path_decision == "block" or (path_decision == "ask" and sr.decision == "allow"):
        sr.decision = path_decision
        sr.reason = path_reason

    return sr


def _check_redirect(target: str) -> tuple[str, str]:
    """Check redirect target as a filesystem write."""
    if not target:
        return "allow", ""
    resolved = paths.resolve_path(target)

    if paths.is_hook_path(resolved):
        return "ask", f"redirect to hook directory: {paths.friendly_path(resolved)}"

    matched, pattern, policy = paths.is_sensitive(resolved)
    if matched:
        if policy == "block":
            return "block", f"redirect to sensitive path: {pattern}"
        return "ask", f"redirect to sensitive path: {pattern}"

    return context.resolve_filesystem_context(target)


def _resolve_context(action_type: str, tokens: list[str]) -> tuple[str, str]:
    """Resolve 'context' policy by checking filesystem or network context."""
    if action_type == taxonomy.NETWORK_OUTBOUND:
        return context.resolve_network_context(tokens)

    # Filesystem actions — extract target paths
    target = _extract_primary_target(tokens)
    if target:
        return context.resolve_filesystem_context(target)

    # No path extracted — check action type default
    if action_type in (taxonomy.FILESYSTEM_DELETE, taxonomy.FILESYSTEM_WRITE):
        return "ask", f"{action_type}: no target path extracted"

    return "allow", f"{action_type}: no target path"


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
            if paths.is_hook_path(resolved):
                # Bash is not Write/Edit, so hook paths are ask (not block)
                if ask_result is None:
                    ask_result = ("ask", f"targets hook directory: {paths.friendly_path(resolved)}")
                continue
            matched, pattern, policy = paths.is_sensitive(resolved)
            if matched:
                if policy == "block":
                    block_result = ("block", f"targets sensitive path: {pattern}")
                elif ask_result is None:
                    ask_result = ("ask", f"targets sensitive path: {pattern}")

    if block_result:
        return block_result
    if ask_result:
        return ask_result
    return "allow", ""


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
        if _is_sensitive_read(left) and right.action_type == taxonomy.NETWORK_OUTBOUND:
            return "block", f"data exfiltration: {right.tokens[0]} receives sensitive input", "sensitive_read | network"

        # network | exec → block (remote code execution)
        if left.action_type == taxonomy.NETWORK_OUTBOUND and _is_exec_sink_stage(right):
            return "block", f"remote code execution: {right.tokens[0]} receives network input", "network | exec"

        # decode | exec → block (obfuscation)
        if taxonomy.is_decode_stage(left.tokens) and _is_exec_sink_stage(right):
            return "block", f"obfuscated execution: {right.tokens[0]} receives decoded input", "decode | exec"

        # any_read | exec → ask
        if left.action_type == taxonomy.FILESYSTEM_READ and _is_exec_sink_stage(right):
            return "ask", f"local code execution: {right.tokens[0]} receives file input", "read | exec"

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
        result.final_decision = "allow"
        result.reason = "no stages"
        return

    # Priority: block > ask > allow
    priority = {"block": 3, "ask": 2, "allow": 1}
    worst = result.stages[0]
    for sr in result.stages[1:]:
        if priority.get(sr.decision, 2) > priority.get(worst.decision, 2):
            worst = sr

    result.final_decision = worst.decision
    result.reason = worst.reason
