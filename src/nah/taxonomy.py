"""Action taxonomy — command classification table and policy defaults.

Classification data and policies are loaded from JSON files in data/.
"""

import json
from pathlib import Path

_DATA_DIR = Path(__file__).parent / "data"

# Action types
FILESYSTEM_READ = "filesystem_read"
FILESYSTEM_WRITE = "filesystem_write"
FILESYSTEM_DELETE = "filesystem_delete"
GIT_SAFE = "git_safe"
GIT_WRITE = "git_write"
GIT_DISCARD = "git_discard"
GIT_HISTORY_REWRITE = "git_history_rewrite"
NETWORK_OUTBOUND = "network_outbound"
PACKAGE_INSTALL = "package_install"
PACKAGE_RUN = "package_run"
PACKAGE_UNINSTALL = "package_uninstall"
LANG_EXEC = "lang_exec"
PROCESS_SIGNAL = "process_signal"
CONTAINER_DESTRUCTIVE = "container_destructive"
SQL_WRITE = "sql_write"
OBFUSCATED = "obfuscated"
UNKNOWN = "unknown"

# Decision constants
ALLOW = "allow"
ASK = "ask"
BLOCK = "block"
CONTEXT = "context"

# Strictness ordering — higher = more restrictive. Used for tighten-only merges.
STRICTNESS = {ALLOW: 0, CONTEXT: 1, ASK: 2, BLOCK: 3}


def _load_classify_table() -> list[tuple[tuple[str, ...], str]]:
    """Load classify table from data/classify/*.json files."""
    table: list[tuple[tuple[str, ...], str]] = []
    classify_dir = _DATA_DIR / "classify"
    for json_file in classify_dir.glob("*.json"):
        action_type = json_file.stem  # e.g. "git_safe" from "git_safe.json"
        with open(json_file) as f:
            prefixes = json.load(f)
        for prefix_str in prefixes:
            table.append((tuple(prefix_str.split()), action_type))
    table.sort(key=lambda entry: len(entry[0]), reverse=True)
    return table


def _load_policies() -> dict[str, str]:
    """Load default policies from data/policies.json."""
    with open(_DATA_DIR / "policies.json") as f:
        return json.load(f)


# Built at module load — one-time cost.
_CLASSIFY_TABLE = _load_classify_table()
_POLICIES = _load_policies()

# Shell wrappers that need unwrapping.
_SHELL_WRAPPERS = {"bash", "sh", "dash", "zsh"}

# Exec sinks for pipe composition.
EXEC_SINKS = {"bash", "sh", "dash", "zsh", "eval", "python", "python3", "node", "ruby", "perl", "php"}

# Decode commands for pipe composition (command, flag).
DECODE_COMMANDS: list[tuple[str, str | None]] = [
    ("base64", "-d"),
    ("base64", "--decode"),
    ("xxd", "-r"),
]


def build_merged_classify_table(user_classify: dict[str, list[str]]) -> list[tuple[tuple[str, ...], str]]:
    """Merge user classify entries with built-in table. Sorted longest-first."""
    merged = list(_CLASSIFY_TABLE)
    for action_type, prefixes in user_classify.items():
        for prefix_str in prefixes:
            prefix_tuple = tuple(prefix_str.split())
            merged.append((prefix_tuple, action_type))
    merged.sort(key=lambda entry: len(entry[0]), reverse=True)
    return merged


def classify_tokens(tokens: list[str], classify_table: list | None = None) -> str:
    """Classify command tokens by prefix match (longest wins). Returns action type."""
    if not tokens:
        return UNKNOWN

    # Special case: find
    action = _classify_find(tokens)
    if action is not None:
        return action

    # Strip git global flags so `git -C /dir rm` classifies as `git rm`.
    if tokens[0] == "git":
        tokens = _strip_git_global_flags(tokens)

    table = classify_table if classify_table is not None else _CLASSIFY_TABLE

    # Prefix match: iterate sorted table, first (longest) match wins.
    for prefix, action_type in table:
        if len(tokens) >= len(prefix) and tuple(tokens[:len(prefix)]) == prefix:
            return action_type

    return UNKNOWN


# Git global flags that take a value argument (must consume next token too).
_GIT_VALUE_FLAGS = {"-C", "--git-dir", "--work-tree", "--namespace", "-c"}

# Git global flags that are standalone (no value argument).
_GIT_BOOLEAN_FLAGS = {"--no-pager", "--no-replace-objects", "--bare", "--literal-pathspecs",
                      "--glob-pathspecs", "--noglob-pathspecs", "--no-optional-locks"}


def _strip_git_global_flags(tokens: list[str]) -> list[str]:
    """Strip git global flags (e.g. -C <dir>, --no-pager) from token list.

    Preserves 'git' as first token followed by the subcommand and its args.
    """
    result = [tokens[0]]  # keep "git"
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in _GIT_VALUE_FLAGS:
            i += 2  # skip flag + its value
        elif tok in _GIT_BOOLEAN_FLAGS:
            i += 1  # skip flag only
        else:
            # Reached the subcommand — append rest as-is.
            result.extend(tokens[i:])
            break
    return result


def _classify_find(tokens: list[str]) -> str | None:
    """Special classifier for find — flag-dependent action type."""
    if not tokens or tokens[0] != "find":
        return None
    for tok in tokens[1:]:
        if tok in ("-delete", "-exec", "-execdir", "-ok"):
            return FILESYSTEM_DELETE
    return FILESYSTEM_READ


def get_policy(action_type: str, user_actions: dict[str, str] | None = None) -> str:
    """Return policy for an action type. Checks user overrides first, then built-in."""
    if user_actions and action_type in user_actions:
        return user_actions[action_type]
    return _POLICIES.get(action_type, ASK)


def is_shell_wrapper(tokens: list[str]) -> tuple[bool, str | None]:
    """Detect bash -c, eval, source. Returns (is_wrapper, inner_command_or_None)."""
    if not tokens:
        return False, None

    cmd = tokens[0]

    # bash/sh/dash/zsh -c "inner"
    if cmd in _SHELL_WRAPPERS and len(tokens) >= 3 and tokens[1] == "-c":
        return True, tokens[2]

    # eval "string"
    if cmd == "eval" and len(tokens) >= 2:
        return True, " ".join(tokens[1:])

    # source / . (not unwrapped — classify as lang_exec)
    if cmd in ("source", "."):
        return False, None

    return False, None


def is_exec_sink(token: str) -> bool:
    """Check if a token is an exec sink (for pipe composition rules)."""
    return token in EXEC_SINKS


def is_decode_stage(tokens: list[str]) -> bool:
    """Check if tokens represent a decode command (base64 -d, xxd -r, etc.)."""
    if not tokens:
        return False
    for cmd, flag in DECODE_COMMANDS:
        if tokens[0] == cmd:
            if flag is None:
                return True
            if flag in tokens[1:]:
                return True
    return False
