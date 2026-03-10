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

# Valid profiles.
PROFILES = ("full", "minimal", "none")

# Strictness ordering — higher = more restrictive. Used for tighten-only merges.
STRICTNESS = {ALLOW: 0, CONTEXT: 1, ASK: 2, BLOCK: 3}


def _load_classify_table(profile: str = "full") -> list[tuple[tuple[str, ...], str]]:
    """Load classify table from JSON files for the given profile."""
    if profile == "none":
        return []
    subdir = "classify_minimal" if profile == "minimal" else "classify_full"
    classify_dir = _DATA_DIR / subdir
    table: list[tuple[tuple[str, ...], str]] = []
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


# Cached built-in tables keyed by profile name.
_BUILTIN_TABLES: dict[str, list[tuple[tuple[str, ...], str]]] = {}
_POLICIES = _load_policies()

# Pre-load full profile at module level (most common path).
_BUILTIN_TABLES["full"] = _load_classify_table("full")


def get_builtin_table(profile: str = "full") -> list[tuple[tuple[str, ...], str]]:
    """Get cached built-in classify table for a profile."""
    if profile not in _BUILTIN_TABLES:
        _BUILTIN_TABLES[profile] = _load_classify_table(profile)
    return _BUILTIN_TABLES[profile]


def build_user_table(user_classify: dict[str, list[str]]) -> list[tuple[tuple[str, ...], str]]:
    """Build a sorted classify table from user config entries."""
    table: list[tuple[tuple[str, ...], str]] = []
    for action_type, prefixes in user_classify.items():
        if not isinstance(prefixes, list):
            continue
        for prefix_str in prefixes:
            table.append((tuple(prefix_str.split()), action_type))
    table.sort(key=lambda entry: len(entry[0]), reverse=True)
    return table


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


def _prefix_match(tokens: list[str], table: list[tuple[tuple[str, ...], str]]) -> str:
    """First prefix match in a single sorted table. Returns action type or UNKNOWN."""
    for prefix, action_type in table:
        if len(tokens) >= len(prefix) and tuple(tokens[:len(prefix)]) == prefix:
            return action_type
    return UNKNOWN


def classify_tokens(
    tokens: list[str],
    global_table: list | None = None,
    builtin_table: list | None = None,
    project_table: list | None = None,
) -> str:
    """Classify command tokens via three-table priority lookup.

    Priority: global (trusted) → built-in (curated) → project (untrusted).
    First match wins with early return — project can only fill gaps.
    """
    if not tokens:
        return UNKNOWN

    # Special case: find
    action = _classify_find(tokens)
    if action is not None:
        return action

    # Strip git global flags so `git -C /dir rm` classifies as `git rm`.
    if tokens[0] == "git":
        tokens = _strip_git_global_flags(tokens)
        action = _classify_git(tokens)
        if action is not None:
            return action

    # Three-table lookup: global (trusted) → built-in → project (untrusted)
    for table in (global_table, builtin_table, project_table):
        if table:
            result = _prefix_match(tokens, table)
            if result != UNKNOWN:
                return result

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


def _classify_git(tokens: list[str]) -> str | None:
    """Flag-dependent classification for 12 git subcommands.

    Returns action type or None (fall through to prefix matching).
    Called after _strip_git_global_flags(), so tokens are clean.
    """
    if len(tokens) < 2 or tokens[0] != "git":
        return None

    sub = tokens[1]
    args = tokens[2:]

    if sub == "tag":
        return GIT_SAFE if not args else GIT_WRITE

    if sub == "branch":
        if not args:
            return GIT_SAFE
        for a in args:
            if a in ("-a", "-r", "--list", "-v", "-vv"):
                return GIT_SAFE
            if a == "-d":
                return GIT_DISCARD
            if a == "-D":
                return GIT_HISTORY_REWRITE
        return GIT_WRITE

    if sub == "config":
        for a in args:
            if a in ("--get", "--list", "--get-all", "--get-regexp"):
                return GIT_SAFE
            if a in ("--unset", "--unset-all", "--replace-all"):
                return GIT_WRITE
        # Count non-flag args: 0-1 = read (get), 2+ = write (set)
        non_flag = [a for a in args if not a.startswith("-")]
        return GIT_SAFE if len(non_flag) <= 1 else GIT_WRITE

    if sub == "reset":
        return GIT_DISCARD if "--hard" in args else GIT_WRITE

    if sub == "push":
        _FORCE_FLAGS = {"--force", "-f", "--force-with-lease", "--force-if-includes"}
        for a in args:
            if a in _FORCE_FLAGS:
                return GIT_HISTORY_REWRITE
            # +refspec means force push
            if a.startswith("+") and len(a) > 1:
                return GIT_HISTORY_REWRITE
        return GIT_WRITE

    if sub == "add":
        return GIT_SAFE if ("--dry-run" in args or "-n" in args) else GIT_WRITE

    if sub == "rm":
        return GIT_WRITE if "--cached" in args else GIT_DISCARD

    if sub == "clean":
        return GIT_SAFE if ("--dry-run" in args or "-n" in args) else GIT_HISTORY_REWRITE

    if sub == "reflog":
        if args and args[0] in ("delete", "expire"):
            return GIT_DISCARD
        return GIT_SAFE

    if sub == "checkout":
        _DISCARD = {".", "--", "HEAD", "--force", "-f", "--ours", "--theirs", "-B"}
        for a in args:
            if a in _DISCARD:
                return GIT_DISCARD
        return GIT_WRITE

    if sub == "switch":
        _DISCARD = {"--discard-changes", "--force", "-f"}
        for a in args:
            if a in _DISCARD:
                return GIT_DISCARD
        return GIT_WRITE

    if sub == "restore":
        return GIT_WRITE if "--staged" in args else GIT_DISCARD

    return None


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
