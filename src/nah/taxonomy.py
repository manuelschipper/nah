"""Action taxonomy — command classification table and policy defaults.

Classification data and policies are loaded from JSON files in data/.
"""

import json
import os
import sys
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
NETWORK_WRITE = "network_write"
NETWORK_DIAGNOSTIC = "network_diagnostic"
PACKAGE_INSTALL = "package_install"
PACKAGE_RUN = "package_run"
PACKAGE_UNINSTALL = "package_uninstall"
LANG_EXEC = "lang_exec"
PROCESS_SIGNAL = "process_signal"
CONTAINER_DESTRUCTIVE = "container_destructive"
DB_READ = "db_read"
DB_WRITE = "db_write"
BEADS_SAFE = "beads_safe"
BEADS_WRITE = "beads_write"
BEADS_DESTRUCTIVE = "beads_destructive"
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
            parts = prefix_str.split()
            if parts:
                parts[0] = os.path.basename(parts[0]) or parts[0]
            table.append((tuple(parts), action_type))
    table.sort(key=lambda entry: len(entry[0]), reverse=True)
    return table


def _load_policies() -> dict[str, str]:
    """Load default policies from data/policies.json."""
    with open(_DATA_DIR / "policies.json") as f:
        return json.load(f)


# Cached built-in tables keyed by profile name.
_BUILTIN_TABLES: dict[str, list[tuple[tuple[str, ...], str]]] = {}
_TYPE_DESCRIPTIONS: dict[str, str] | None = None
_POLICIES = _load_policies()
POLICIES = _POLICIES

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
            parts = prefix_str.split()
            if parts:
                parts[0] = os.path.basename(parts[0]) or parts[0]
            table.append((tuple(parts), action_type))
    table.sort(key=lambda entry: len(entry[0]), reverse=True)
    return table


# Commands with Phase 2 flag classifiers (flag-dependent classification).
_FLAG_CLASSIFIER_CMDS = {"find", "sed", "awk", "gawk", "mawk", "nawk",
                          "tar", "git", "curl", "wget",
                          "http", "https", "xh", "xhs",
                          "npm", "pnpm", "bun", "pip", "pip3", "cargo", "gem",
                          "python", "python3", "node", "ruby", "perl",
                          "bash", "sh", "dash", "zsh", "php", "tsx"}

# Global-install flags that escalate to unknown (ask).
_GLOBAL_INSTALL_FLAGS = {"-g", "--global", "--system", "--target", "--root"}
_GLOBAL_INSTALL_CMDS = {"npm", "pnpm", "bun", "pip", "pip3", "cargo", "gem"}


def find_table_shadows(
    user_table: list[tuple[tuple[str, ...], str]],
    builtin_table: list[tuple[tuple[str, ...], str]],
) -> dict[tuple[str, ...], list[tuple[str, ...]]]:
    """Return {user_prefix: [shadowed_builtin_prefixes]}.

    A user prefix u shadows builtin prefix b when:
    - b == u (exact override), OR
    - len(b) > len(u) AND b[:len(u)] == u (user is a proper prefix of builtin)
    """
    shadows: dict[tuple[str, ...], list[tuple[str, ...]]] = {}
    for u_prefix, _ in user_table:
        matched = []
        for b_prefix, _ in builtin_table:
            if b_prefix == u_prefix:
                matched.append(b_prefix)
            elif len(b_prefix) > len(u_prefix) and b_prefix[:len(u_prefix)] == u_prefix:
                matched.append(b_prefix)
        if matched:
            shadows[u_prefix] = matched
    return shadows


def find_flag_classifier_shadows(
    user_table: list[tuple[tuple[str, ...], str]],
) -> list[tuple[str, ...]]:
    """Return user prefixes that shadow a Phase 2 flag classifier."""
    return [u_prefix for u_prefix, _ in user_table
            if len(u_prefix) == 1 and u_prefix[0] in _FLAG_CLASSIFIER_CMDS]


# Shell wrappers that need unwrapping.
_SHELL_WRAPPERS = {"bash", "sh", "dash", "zsh"}

# Script execution detection — interpreters and their flags.
_SCRIPT_INTERPRETERS = {
    "python", "python3", "node", "ruby", "perl",
    "bash", "sh", "dash", "zsh", "php", "tsx",
}

# Flags that mean inline code (already classified as lang_exec via classify table).
_INLINE_FLAGS: dict[str, set[str]] = {
    "python": {"-c"}, "python3": {"-c"},
    "node": {"-e", "-p", "--eval", "--print"},
    "ruby": {"-e"},
    "perl": {"-e", "-E"},
    "php": {"-r"},
}

# Flags that mean module mode (still lang_exec, but different path resolution).
_MODULE_FLAGS: dict[str, set[str]] = {
    "python": {"-m"}, "python3": {"-m"},
}

# Script file extensions for shebang/extension detection.
_SCRIPT_EXTENSIONS = {".py", ".js", ".rb", ".sh", ".pl", ".ts", ".php", ".tsx"}

# Exec sinks for pipe composition.
_EXEC_SINKS_DEFAULTS = {"bash", "sh", "dash", "zsh", "eval", "python", "python3",
                         "node", "ruby", "perl", "php", "bun", "deno", "fish", "pwsh",
                         "env"}
EXEC_SINKS: set[str] = set(_EXEC_SINKS_DEFAULTS)
_exec_sinks_merged = False


def _ensure_exec_sinks_merged():
    """Lazy one-time merge of config exec_sinks into EXEC_SINKS."""
    global _exec_sinks_merged
    if _exec_sinks_merged:
        return
    _exec_sinks_merged = True
    try:
        from nah.config import get_config, _parse_add_remove
        cfg = get_config()
        if cfg.profile == "none":
            EXEC_SINKS.clear()
        add, remove = _parse_add_remove(cfg.exec_sinks)
        EXEC_SINKS.update(str(s) for s in add)
        if remove:
            sys.stderr.write("nah: warning: exec_sinks.remove weakens composition rules\n")
            EXEC_SINKS.difference_update(str(s) for s in remove)
    except Exception as exc:
        sys.stderr.write(f"nah: config: exec_sinks: {exc}\n")


def reset_exec_sinks():
    """Restore defaults and clear merge flag (for testing)."""
    global _exec_sinks_merged
    _exec_sinks_merged = False
    EXEC_SINKS.clear()
    EXEC_SINKS.update(_EXEC_SINKS_DEFAULTS)


# Decode commands for pipe composition (command, flag).
_DECODE_COMMANDS_DEFAULTS: list[tuple[str, str | None]] = [
    ("base64", "-d"),
    ("base64", "--decode"),
    ("xxd", "-r"),
    ("uudecode", None),
]
DECODE_COMMANDS: list[tuple[str, str | None]] = list(_DECODE_COMMANDS_DEFAULTS)
_decode_commands_merged = False


def _ensure_decode_commands_merged():
    """Lazy one-time merge of config decode_commands into DECODE_COMMANDS."""
    global _decode_commands_merged
    if _decode_commands_merged:
        return
    _decode_commands_merged = True
    try:
        from nah.config import get_config, _parse_add_remove
        cfg = get_config()
        if cfg.profile == "none":
            DECODE_COMMANDS.clear()
        add, remove = _parse_add_remove(cfg.decode_commands)
        # Remove by command name (all flag variants)
        if remove:
            sys.stderr.write("nah: warning: decode_commands.remove weakens composition rules\n")
            remove_cmds = {str(c) for c in remove}
            DECODE_COMMANDS[:] = [(c, f) for c, f in DECODE_COMMANDS if c not in remove_cmds]
        # Add: "command flag" or "command" (space-separated string)
        for entry in add:
            parts = str(entry).split(None, 1)
            if parts:
                cmd = parts[0]
                flag = parts[1] if len(parts) > 1 else None
                DECODE_COMMANDS.append((cmd, flag))
    except Exception as exc:
        sys.stderr.write(f"nah: config: decode_commands: {exc}\n")


def reset_decode_commands():
    """Restore defaults and clear merge flag (for testing)."""
    global _decode_commands_merged
    _decode_commands_merged = False
    DECODE_COMMANDS.clear()
    DECODE_COMMANDS.extend(_DECODE_COMMANDS_DEFAULTS)


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
    *,
    profile: str = "full",
    trust_project: bool = False,
) -> str:
    """Classify command tokens via three-phase lookup.

    Phase 1: Global table (trusted user config) — always runs.
    Phase 2: Flag classifiers (built-in opinions) — skipped when profile == "none".
    Phase 3: Remaining tables (project, builtin) — global already checked.
        When trust_project is True, project table wins over builtins even
        when it loosens policy (user explicitly opted in via
        trust_project_config in global config).
    """
    if not tokens:
        return UNKNOWN

    # Basename normalization — resolve /usr/bin/rm → rm (FD-065)
    base = os.path.basename(tokens[0])
    if base and base != tokens[0]:
        tokens = [base] + tokens[1:]

    # --- Phase 1: Global table override (trusted user config) ---
    # Non-git: check global table on raw tokens.
    if global_table and tokens[0] != "git":
        result = _prefix_match(tokens, global_table)
        if result != UNKNOWN:
            return result

    # Git: strip global flags first, then check global table on clean tokens.
    if tokens[0] == "git":
        tokens = _strip_git_global_flags(tokens)
        if global_table:
            result = _prefix_match(tokens, global_table)
            if result != UNKNOWN:
                return result

    # --- Phase 2: Flag classifiers (built-in opinions) ---
    # Skipped entirely when profile == "none".
    if profile != "none":
        action = _classify_find(
            tokens,
            global_table=global_table,
            builtin_table=builtin_table,
            project_table=project_table,
            profile=profile,
            trust_project=trust_project,
        )
        if action is not None:
            return action
        action = _classify_sed(tokens)
        if action is not None:
            return action
        action = _classify_awk(tokens)
        if action is not None:
            return action
        action = _classify_tar(tokens)
        if action is not None:
            return action
        if tokens[0] == "git":
            action = _classify_git(tokens)
            if action is not None:
                return action
        action = _classify_curl(tokens)
        if action is not None:
            return action
        action = _classify_wget(tokens)
        if action is not None:
            return action
        action = _classify_httpie(tokens)
        if action is not None:
            return action
        action = _classify_global_install(tokens)
        if action is not None:
            return action
        action = _classify_script_exec(tokens)
        if action is not None:
            return action

    # --- Phase 3: Remaining tables (project, builtin) ---
    # Project table may override built-ins only when it does not weaken policy,
    # unless trust_project is True (user opted in via trust_project_config).
    project_result = _prefix_match(tokens, project_table) if project_table else UNKNOWN
    builtin_result = _prefix_match(tokens, builtin_table) if builtin_table else UNKNOWN

    if project_result == UNKNOWN:
        return builtin_result
    if builtin_result == UNKNOWN:
        return project_result
    if project_result == builtin_result:
        return project_result

    # Trusted project: project wins unconditionally (user explicitly opted in).
    if trust_project:
        return project_result

    project_policy = get_policy(project_result)
    builtin_policy = get_policy(builtin_result)
    if STRICTNESS.get(project_policy, 0) >= STRICTNESS.get(builtin_policy, 0):
        return project_result
    return builtin_result


# Git global flags that take a value argument (must consume next token too).
_GIT_VALUE_FLAGS = {"-C", "--git-dir", "--work-tree", "--namespace", "-c", "--config-env"}
_GIT_VALUE_FLAG_PREFIXES = ("--git-dir=", "--work-tree=", "--namespace=", "--exec-path=", "--config-env=")

# Git global flags that are standalone (no value argument).
_GIT_BOOLEAN_FLAGS = {
    "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects",
    "--no-lazy-fetch", "--no-optional-locks", "--no-advice", "--bare",
    "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs",
    "--icase-pathspecs",
}


def _git_has_short_flag(args: list[str], flag: str) -> bool:
    """Return True if args contain a short git flag, including combined clusters."""
    needle = f"-{flag}"
    for arg in args:
        if arg == needle:
            return True
        if arg.startswith("-") and not arg.startswith("--") and flag in arg[1:]:
            return True
    return False


def _is_valid_git_config_key(name: str) -> bool:
    """Return True for plausible git config keys like section.name or section.sub.key."""
    section, dot, remainder = name.partition(".")
    return bool(dot and section and remainder and not remainder.startswith("."))


def _is_valid_git_config_arg(value: str) -> bool:
    """Return True for values accepted by `git -c`, including implicit boolean keys."""
    name = value.split("=", 1)[0]
    return _is_valid_git_config_key(name)


def _is_valid_git_config_env(value: str) -> bool:
    """Return True for NAME=ENVVAR values accepted by --config-env."""
    name, sep, env = value.partition("=")
    return bool(sep and env and _is_valid_git_config_key(name))


def _strip_git_global_flags(tokens: list[str]) -> list[str]:
    """Strip git global flags (e.g. -C <dir>, --no-pager) from token list.

    Preserves 'git' as first token followed by the subcommand and its args.
    Malformed value-taking flags stop stripping so classification fails closed.
    """
    result = [tokens[0]]  # keep "git"
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in _GIT_VALUE_FLAGS:
            if i + 1 >= len(tokens):
                result.extend(tokens[i:])
                break
            if tok == "-c" and not _is_valid_git_config_arg(tokens[i + 1]):
                result.extend(tokens[i:])
                break
            if tok == "--config-env" and not _is_valid_git_config_env(tokens[i + 1]):
                result.extend(tokens[i:])
                break
            i += 2  # skip flag + its value
        elif tok.startswith("--config-env="):
            if not _is_valid_git_config_env(tok.split("=", 1)[1]):
                result.extend(tokens[i:])
                break
            i += 1  # skip =joined config-env value flag
        elif any(tok.startswith(prefix) for prefix in _GIT_VALUE_FLAG_PREFIXES):
            i += 1  # skip =joined value flag
        elif tok in _GIT_BOOLEAN_FLAGS:
            i += 1  # skip flag only
        else:
            # Reached the subcommand — append rest as-is.
            result.extend(tokens[i:])
            break
    return result


def _classify_find(
    tokens: list[str],
    *,
    global_table: list | None = None,
    builtin_table: list | None = None,
    project_table: list | None = None,
    profile: str = "full",
    trust_project: bool = False,
) -> str | None:
    """Special classifier for find — inspect -exec payloads conservatively."""
    if not tokens or tokens[0] != "find":
        return None
    for i, tok in enumerate(tokens[1:], start=1):
        if tok == "-delete":
            return FILESYSTEM_DELETE
        if tok in ("-exec", "-execdir", "-ok", "-okdir"):
            inner_tokens = _extract_find_exec_tokens(tokens, i + 1)
            if not inner_tokens:
                return FILESYSTEM_DELETE
            inner_action = classify_tokens(
                inner_tokens,
                global_table=global_table,
                builtin_table=builtin_table,
                project_table=project_table,
                profile=profile,
                trust_project=trust_project,
            )
            return inner_action if inner_action != UNKNOWN else FILESYSTEM_DELETE
    return FILESYSTEM_READ


def _extract_find_exec_tokens(tokens: list[str], start: int) -> list[str]:
    """Extract the command payload following find -exec/-execdir/-ok until ; or +."""
    inner: list[str] = []
    for tok in tokens[start:]:
        if tok in (";", "+"):
            break
        inner.append(tok)
    return inner


def _classify_sed(tokens: list[str]) -> str | None:
    """Flag-dependent: sed -i/-I → filesystem_write; else → filesystem_read."""
    if not tokens or tokens[0] != "sed":
        return None
    for tok in tokens[1:]:
        # -i/-I or -i.bak/-I.bak (GNU lowercase, BSD uppercase)
        if tok == "-i" or tok.startswith("-i") or tok == "-I" or tok.startswith("-I"):
            return FILESYSTEM_WRITE
        # --in-place or --in-place=.bak (GNU long form)
        if tok.startswith("--in-place"):
            return FILESYSTEM_WRITE
        # Combined short flags: -ni, -nI, -ein, etc.
        if tok.startswith("-") and not tok.startswith("--") and ("i" in tok or "I" in tok):
            return FILESYSTEM_WRITE
    return FILESYSTEM_READ


def _classify_awk(tokens: list[str]) -> str | None:
    """Flag-dependent: awk with system()/getline/pipes → lang_exec."""
    if not tokens or tokens[0] not in ("awk", "gawk", "mawk", "nawk"):
        return None
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if any(p in tok for p in ("system(", "| getline", "|&", "| \"", "print >")):
            return LANG_EXEC
    return None


def _classify_tar(tokens: list[str]) -> str | None:
    """Flag-dependent: tar mode detection. Write takes precedence. Default: write."""
    if not tokens or tokens[0] != "tar":
        return None
    found_read = False
    found_write = False
    args = tokens[1:]
    if not args:
        return FILESYSTEM_WRITE  # Conservative default
    # Check if first arg is a bare mode string (no leading dash): tf, czf, xf
    first = args[0]
    if first and not first.startswith("-"):
        if any(c in first for c in "cxru"):
            found_write = True
        elif "t" in first:
            found_read = True
    # Check all flag arguments
    for tok in args:
        if tok.startswith("-") and len(tok) > 1 and tok[1] != "-":
            # Short flags: -tf, -czf, -xf, etc.
            letters = tok[1:]
            if "t" in letters:
                found_read = True
            if any(c in letters for c in "cxru"):
                found_write = True
        elif tok.startswith("--"):
            if tok == "--list":
                found_read = True
            if tok in ("--create", "--extract", "--append", "--update",
                       "--get", "--delete"):
                found_write = True
    if found_write:
        return FILESYSTEM_WRITE
    if found_read:
        return FILESYSTEM_READ
    return FILESYSTEM_WRITE  # Conservative default


_CURL_DATA_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "-F", "--form", "--form-string", "-T", "--upload-file", "--json",
}
_CURL_DATA_LONG_PREFIXES = (
    "--data=", "--data-raw=", "--data-binary=", "--data-urlencode=",
    "--form=", "--form-string=", "--upload-file=", "--json=",
)
_CURL_METHOD_FLAGS = {"-X", "--request"}
_WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _classify_curl(tokens: list[str]) -> str | None:
    """Flag-dependent: curl with write flags → network_write; else → network_outbound."""
    if not tokens or tokens[0] != "curl":
        return None

    has_data = False
    has_write_method = False

    i = 1
    while i < len(tokens):
        tok = tokens[i]

        # Standalone data flags
        if tok in _CURL_DATA_FLAGS:
            has_data = True
            i += 1
            continue

        # =joined long data flags
        if any(tok.startswith(p) for p in _CURL_DATA_LONG_PREFIXES):
            has_data = True
            i += 1
            continue

        # Method flags: -X METHOD, --request METHOD, --request=METHOD
        if tok in _CURL_METHOD_FLAGS:
            if i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                if method in _WRITE_METHODS:
                    has_write_method = True
            i += 2
            continue
        if tok.startswith("--request="):
            method = tok.split("=", 1)[1].upper()
            if method in _WRITE_METHODS:
                has_write_method = True
            i += 1
            continue

        # Combined short flags: -sXPOST, -XPOST, etc.
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            letters = tok[1:]
            if "X" in letters:
                x_idx = letters.index("X")
                rest = letters[x_idx + 1:]
                # Extract method: chars after X until non-alpha
                method_chars = []
                for c in rest:
                    if c.isalpha():
                        method_chars.append(c)
                    else:
                        break
                if method_chars:
                    method = "".join(method_chars).upper()
                    if method in _WRITE_METHODS:
                        has_write_method = True
                elif i + 1 < len(tokens):
                    # X is last char in combined flags, method is next token
                    method = tokens[i + 1].upper()
                    if method in _WRITE_METHODS:
                        has_write_method = True
                    i += 2
                    continue

        i += 1

    # Data flags take priority over method flags
    if has_data:
        return NETWORK_WRITE
    if has_write_method:
        return NETWORK_WRITE
    return NETWORK_OUTBOUND


def _classify_wget(tokens: list[str]) -> str | None:
    """Flag-dependent: wget with write flags → network_write; else → network_outbound."""
    if not tokens or tokens[0] != "wget":
        return None

    has_data = False
    has_write_method = False

    i = 1
    while i < len(tokens):
        tok = tokens[i]

        # --post-data, --post-file (standalone or =joined)
        if tok in ("--post-data", "--post-file"):
            has_data = True
            i += 2  # skip value
            continue
        if tok.startswith("--post-data=") or tok.startswith("--post-file="):
            has_data = True
            i += 1
            continue

        # --method METHOD or --method=METHOD
        if tok == "--method":
            if i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                if method in _WRITE_METHODS:
                    has_write_method = True
            i += 2
            continue
        if tok.startswith("--method="):
            method = tok.split("=", 1)[1].upper()
            if method in _WRITE_METHODS:
                has_write_method = True
            i += 1
            continue

        i += 1

    if has_data:
        return NETWORK_WRITE
    if has_write_method:
        return NETWORK_WRITE
    return NETWORK_OUTBOUND


_HTTPIE_CMDS = {"http", "https", "xh", "xhs"}
_HTTPIE_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _classify_httpie(tokens: list[str]) -> str | None:
    """Flag-dependent: httpie with write indicators → network_write; else → network_outbound."""
    if not tokens or tokens[0] not in _HTTPIE_CMDS:
        return None

    args = tokens[1:]
    has_form = False
    has_write_method = False
    has_data_item = False
    found_url = False

    for arg in args:
        # Check for --form / -f
        if arg == "--form" or arg == "-f":
            has_form = True
            continue

        # Skip other flags
        if arg.startswith("-"):
            continue

        # First non-flag arg: check if it's an uppercase method
        if not found_url and arg.upper() in _HTTPIE_METHODS:
            if arg.upper() in _WRITE_METHODS:
                has_write_method = True
            continue

        if not found_url:
            found_url = True
            continue

        # After URL: check for data item patterns (key=value, key:=value, key@file)
        if "=" in arg or ":=" in arg or "@" in arg:
            has_data_item = True

    if has_write_method:
        return NETWORK_WRITE
    if has_form:
        return NETWORK_WRITE
    if has_data_item:
        return NETWORK_WRITE
    return NETWORK_OUTBOUND


def _classify_global_install(tokens: list[str]) -> str | None:
    """Flag-dependent: global-install flags escalate to unknown (ask)."""
    if not tokens or tokens[0] not in _GLOBAL_INSTALL_CMDS:
        return None
    for tok in tokens[1:]:
        if tok in _GLOBAL_INSTALL_FLAGS:
            return UNKNOWN
        if tok.startswith(("--global=", "--system=", "--target=", "--root=")):
            return UNKNOWN
        if tokens[0] in {"pip", "pip3"} and tok == "-t":
            return UNKNOWN
    return None


def _classify_script_exec(tokens: list[str]) -> str | None:
    """Flag-dependent: detect interpreter + script file execution → lang_exec.

    Returns LANG_EXEC when a known interpreter is invoked with a script file.
    Returns None for bare REPL (python), inline code (python -c), and
    commands handled by the classify table or shell wrapper unwrapping.
    """
    if not tokens:
        return None

    cmd = tokens[0]

    # Shebang / extension detection: ./script.py, /path/to/script.sh
    # Note: classify_tokens() normalizes paths via basename before calling
    # flag classifiers, so ./script.py becomes script.py. Check extension
    # on the (possibly normalized) command name.
    if cmd not in _SCRIPT_INTERPRETERS:
        _, ext = os.path.splitext(cmd)
        if ext in _SCRIPT_EXTENSIONS:
            return LANG_EXEC
        return None

    if len(tokens) < 2:
        return None  # bare REPL (python, node) — fall through

    inline = _INLINE_FLAGS.get(cmd, set())
    module = _MODULE_FLAGS.get(cmd, set())

    # Inline code flags → fall through to classify table (already lang_exec)
    if tokens[1] in inline:
        return None

    # Module mode (python -m) → fall through to Phase 3 classify table.
    # Phase 3 has more specific prefixes (python -m pytest → package_run)
    # and python -m → lang_exec as a catch-all.
    if tokens[1] in module:
        return None

    # First non-flag argument = script file
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        return LANG_EXEC  # found script file argument

    return None  # all args are flags — fall through


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


def load_type_descriptions() -> dict[str, str]:
    """Load action type descriptions from types.json. Cached at module level."""
    global _TYPE_DESCRIPTIONS
    if _TYPE_DESCRIPTIONS is not None:
        return _TYPE_DESCRIPTIONS
    with open(_DATA_DIR / "types.json") as f:
        _TYPE_DESCRIPTIONS = json.load(f)
    return _TYPE_DESCRIPTIONS


def validate_action_type(name: str) -> tuple[bool, list[str]]:
    """Check if name is a valid action type. Returns (valid, close_matches)."""
    import difflib
    all_types = list(load_type_descriptions().keys())
    if name in all_types:
        return True, []
    matches = difflib.get_close_matches(name, all_types, n=3, cutoff=0.5)
    return False, matches


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

    # bash/sh/dash/zsh <<< "inner" (here-string)
    if cmd in _SHELL_WRAPPERS and len(tokens) >= 3 and tokens[1] == "<<<":
        return True, tokens[2]

    # source / . (not unwrapped — classify as lang_exec)
    if cmd in ("source", "."):
        return False, None

    return False, None


def is_exec_sink(token: str) -> bool:
    """Check if a token is an exec sink (for pipe composition rules)."""
    _ensure_exec_sinks_merged()
    return token in EXEC_SINKS


def is_decode_stage(tokens: list[str]) -> bool:
    """Check if tokens represent a decode command (base64 -d, xxd -r, etc.)."""
    _ensure_decode_commands_merged()
    if not tokens:
        return False
    for cmd, flag in DECODE_COMMANDS:
        if tokens[0] == cmd:
            if flag is None:
                return True
            if flag in tokens[1:]:
                return True
    return False
