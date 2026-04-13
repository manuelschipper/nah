"""Action taxonomy — command classification table and policy defaults.

Classification data and policies are loaded from JSON files in data/.
"""

import json
import os
import re
import sys
from pathlib import Path

_DATA_DIR = Path(__file__).parent / "data"

# Action types
FILESYSTEM_READ = "filesystem_read"
FILESYSTEM_WRITE = "filesystem_write"
FILESYSTEM_DELETE = "filesystem_delete"
GIT_SAFE = "git_safe"
GIT_WRITE = "git_write"
GIT_REMOTE_WRITE = "git_remote_write"
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
CONTAINER_READ = "container_read"
CONTAINER_WRITE = "container_write"
CONTAINER_EXEC = "container_exec"
CONTAINER_DESTRUCTIVE = "container_destructive"
SERVICE_READ = "service_read"
SERVICE_WRITE = "service_write"
SERVICE_DESTRUCTIVE = "service_destructive"
BROWSER_READ = "browser_read"
BROWSER_INTERACT = "browser_interact"
BROWSER_STATE = "browser_state"
BROWSER_NAVIGATE = "browser_navigate"
BROWSER_EXEC = "browser_exec"
BROWSER_FILE = "browser_file"
DB_READ = "db_read"
DB_WRITE = "db_write"
AGENT_READ = "agent_read"
AGENT_WRITE = "agent_write"
AGENT_EXEC_READ = "agent_exec_read"
AGENT_EXEC_WRITE = "agent_exec_write"
AGENT_EXEC_REMOTE = "agent_exec_remote"
AGENT_SERVER = "agent_server"
AGENT_EXEC_BYPASS = "agent_exec_bypass"
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
                parts[0] = _normalize_command_name(parts[0])
            table.append((tuple(parts), action_type))
    table.sort(key=lambda entry: len(entry[0]), reverse=True)
    return table


# Commands with Phase 2 flag classifiers (flag-dependent classification).
_FLAG_CLASSIFIER_CMDS = {"find", "sed", "awk", "gawk", "mawk", "nawk",
                          "tar", "git", "curl", "wget",
                          "http", "https", "xh", "xhs",
                          "codex",
                          "npm", "npx", "uv", "uvx", "pnpm", "bun", "pip",
                          "pip3", "cargo", "gem", "make", "gmake",
                          "python", "python3", "node", "ruby", "perl",
                          "bash", "sh", "dash", "zsh", "php", "tsx",
                          "powershell", "pwsh", "cmd"}

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
    "bash": {"-c"}, "sh": {"-c"}, "dash": {"-c"}, "zsh": {"-c"},
}

# Flags that mean module mode (still lang_exec, but different path resolution).
_MODULE_FLAGS: dict[str, set[str]] = {
    "python": {"-m"}, "python3": {"-m"},
}

# Interpreter flags that consume the next token as a value argument.
# Must be skipped (along with their value) when searching for the script file.
_VALUE_FLAGS: dict[str, set[str]] = {
    "python": {"-W", "-X"},
    "python3": {"-W", "-X"},
    "node": {"-r", "--require", "--loader"},
    "ruby": {"-I", "-r"},
    "perl": {"-I", "-M"},
}

# Script file extensions for shebang/extension detection.
_SCRIPT_EXTENSIONS = {".py", ".js", ".rb", ".sh", ".pl", ".ts", ".php", ".tsx"}
_SOURCE_COMMANDS = {"source", "."}


def _extract_source_operand(tokens: list[str]) -> str | None:
    """Return the sourced file operand for `source` / `.` commands."""
    if not tokens:
        return None

    cmd = os.path.basename(tokens[0]) or tokens[0]
    if cmd not in _SOURCE_COMMANDS:
        return None

    end_of_options = False
    for tok in tokens[1:]:
        if tok == "--" and not end_of_options:
            end_of_options = True
            continue
        if not end_of_options and tok.startswith("-"):
            continue
        return tok
    return None

_UV_RUN_VALUE_FLAGS = {
    "-w", "--with", "--with-editable", "--with-requirements", "--env-file",
    "--group", "--no-group", "--package", "--python", "--directory", "--project",
}
_UV_RUN_VALUE_FLAG_PREFIXES = (
    "--with=", "--with-editable=", "--with-requirements=", "--env-file=",
    "--group=", "--no-group=", "--package=", "--python=", "--directory=", "--project=",
)
_NPX_BOOL_FLAGS = {"-y", "--yes"}
_NPX_VALUE_FLAGS = {"-p", "--package"}
_NPX_VALUE_FLAG_PREFIXES = ("--package=",)
_NPX_UNSUPPORTED_FLAGS = {"-c", "--call"}

# Exec sinks for pipe composition.
_EXEC_SINKS_DEFAULTS = {"bash", "sh", "dash", "zsh", "eval", "python", "python3",
                         "node", "ruby", "perl", "php", "bun", "deno", "fish", "pwsh",
                         "powershell", "cmd",
                         "env", "lua", "R", "Rscript", "make", "julia", "swift"}
EXEC_SINKS: set[str] = set(_EXEC_SINKS_DEFAULTS)
_exec_sinks_merged = False

# Versioned interpreter normalization (nah-1o5).
# Canonical names, longest first to avoid prefix ambiguity.
_CANONICAL_INTERPRETERS = [
    "python3", "python", "pip3", "pip",
    "node", "ruby", "perl", "php", "deno", "bun",
    "powershell", "bash", "dash", "zsh", "sh", "fish", "pwsh", "cmd",
]
_VERSION_SUFFIX_RE = re.compile(r"^\.?[0-9]+(?:\.[0-9]+)*$")
_WINDOWS_CASE_INSENSITIVE_COMMANDS = {
    "cmd",
    "powershell",
    "pwsh",
    "dir",
    "findstr",
    "tasklist",
    "taskkill",
    "where",
    "wmic",
    "systeminfo",
}


def _command_basename(token: str) -> str:
    """Return a command basename for POSIX or Windows-style command paths."""
    return re.split(r"[\\/]", token)[-1] if token else token


def _strip_windows_exe_suffix(name: str) -> str:
    """Strip a case-insensitive Windows .exe command suffix."""
    return name[:-4] if name.lower().endswith(".exe") else name


def _normalize_command_name(name: str) -> str:
    """Normalize command identity without globally lowercasing Unix commands."""
    base = _strip_windows_exe_suffix(_command_basename(name) or name)
    lower = base.lower()
    if lower in _WINDOWS_CASE_INSENSITIVE_COMMANDS:
        base = lower
    return _normalize_interpreter(base)


def _normalize_interpreter(name: str) -> str:
    """Strip version suffix from interpreter basename.

    python3.12 → python3, node22 → node, bash5.2 → bash.
    Returns name unchanged if not a versioned interpreter.
    Uses longest-prefix-first matching to correctly handle python3 vs python.
    """
    for canonical in _CANONICAL_INTERPRETERS:
        if name.startswith(canonical):
            suffix = name[len(canonical):]
            if not suffix:
                return name
            if _VERSION_SUFFIX_RE.match(suffix):
                return canonical
            return name
    return name


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
        EXEC_SINKS.update(_normalize_command_name(str(s)) for s in add)
        if remove:
            sys.stderr.write("nah: warning: exec_sinks.remove weakens composition rules\n")
            EXEC_SINKS.difference_update(_normalize_command_name(str(s)) for s in remove)
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
    ("gzip", "-d"),
    ("gzip", "-dc"),
    ("zcat", None),
    ("bzip2", "-d"),
    ("bzcat", None),
    ("xz", "-d"),
    ("xzcat", None),
    ("openssl", "enc"),
    ("unzip", "-p"),
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

    # Command normalization — resolve /usr/bin/rm, C:\...\cmd.exe, python3.12.
    base = _normalize_command_name(tokens[0])
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
        action = _classify_codex(tokens)
        if action is not None:
            return action
        action = _classify_codex_companion(tokens)
        if action is not None:
            return action
        action = _classify_global_install(tokens)
        if action is not None:
            return action
        action = _classify_make(tokens)
        if action is not None:
            return action
        action = _classify_windows_shell(tokens)
        if action is not None:
            return action
        action = _classify_package_exec_wrapper(
            tokens,
            global_table=global_table,
            builtin_table=builtin_table,
            project_table=project_table,
            profile=profile,
            trust_project=trust_project,
        )
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


def _git_has_short_flag(args: list[str], flag: str) -> bool:
    """Return True if args contain a short git flag, including combined clusters."""
    needle = f"-{flag}"
    for arg in args:
        if arg == needle:
            return True
        if arg.startswith("-") and not arg.startswith("--") and flag in arg[1:]:
            return True
    return False


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


_CODEX_BYPASS_FLAG = "--dangerously-bypass-approvals-and-sandbox"
_CODEX_VALUE_FLAGS = {
    "-c", "--config", "--enable", "--disable", "--remote", "--remote-auth-token-env",
    "-i", "--image", "-m", "--model", "--local-provider", "-p", "--profile",
    "-s", "--sandbox", "-a", "--ask-for-approval", "-C", "--cd", "--add-dir",
}
_CODEX_LONG_VALUE_FLAGS = {flag for flag in _CODEX_VALUE_FLAGS if flag.startswith("--")}
_CODEX_TOP_LEVEL_INTERACTIVE_FLAGS = _CODEX_VALUE_FLAGS | {
    _CODEX_BYPASS_FLAG,
    "--full-auto",
}
_CODEX_TOP_LEVEL_READ_FLAGS = {"--help", "-h", "--version", "-V"}
_CODEX_READ_COMMANDS = {"completion"}
_CODEX_WRITE_COMMANDS = {"login", "logout", "apply", "a"}
_CODEX_AGENT_RUN_COMMANDS = {"exec", "e", "review", "resume", "fork"}


def _codex_has_bypass(tokens: list[str]) -> bool:
    """Return True if the Codex bypass flag appears anywhere in argv."""
    return _CODEX_BYPASS_FLAG in tokens


def _codex_flag_takes_value(tok: str) -> bool:
    """Return True for Codex flags whose value is expected as the next token."""
    if tok in _CODEX_VALUE_FLAGS:
        return True
    return False


def _codex_is_joined_value_flag(tok: str) -> bool:
    """Return True for --flag=value forms of known Codex value flags."""
    if not tok.startswith("--") or "=" not in tok:
        return False
    name = tok.split("=", 1)[0]
    return name in _CODEX_LONG_VALUE_FLAGS


def _codex_args_malformed(args: list[str]) -> bool:
    """Detect missing values for known Codex value-taking flags."""
    i = 0
    while i < len(args):
        tok = args[i]
        if _codex_is_joined_value_flag(tok):
            i += 1
            continue
        if _codex_flag_takes_value(tok):
            if i + 1 >= len(args) or args[i + 1].startswith("-"):
                return True
            i += 2
            continue
        i += 1
    return False


def _strip_codex_global_options(tokens: list[str]) -> tuple[list[str], bool]:
    """Strip Codex global options while finding the first subcommand.

    Returns (cleaned_tokens, malformed). Unknown boolean-looking options are
    skipped while searching for the subcommand because Codex adds flags more
    quickly than nah should need parser updates.
    """
    if not tokens:
        return [], False

    cleaned = [tokens[0]]
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            return cleaned + tokens[i + 1:], False
        if _codex_is_joined_value_flag(tok):
            i += 1
            continue
        if _codex_flag_takes_value(tok):
            if i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                return cleaned, True
            i += 2
            continue
        if tok in _CODEX_TOP_LEVEL_READ_FLAGS:
            return cleaned + tokens[i:], False
        if tok.startswith("-"):
            i += 1
            continue
        cleaned.extend(tokens[i:])
        return cleaned, False
    return cleaned, False


def _codex_option_value(args: list[str], names: set[str]) -> str | None:
    """Return the value for a Codex option, supporting --name value and --name=value."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in names:
            return args[i + 1] if i + 1 < len(args) else None
        if tok.startswith("--") and "=" in tok:
            name, value = tok.split("=", 1)
            if name in names:
                return value
        i += 1
    return None


def _codex_has_help_flag(args: list[str]) -> bool:
    """Return True when a subcommand is invoked for help only."""
    return "--help" in args or "-h" in args


def _codex_has_top_level_interactive_option(tokens: list[str]) -> bool:
    """Return True when a known top-level option makes following text a prompt."""
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            return False
        if _codex_is_joined_value_flag(tok):
            return tok.split("=", 1)[0] in _CODEX_TOP_LEVEL_INTERACTIVE_FLAGS
        if _codex_flag_takes_value(tok):
            return tok in _CODEX_TOP_LEVEL_INTERACTIVE_FLAGS
        if tok in _CODEX_TOP_LEVEL_INTERACTIVE_FLAGS:
            return True
        if tok.startswith("-"):
            i += 1
            continue
        return False
    return False


def _codex_prompt_arg_is_clear_prompt(arg: str) -> bool:
    """Return True for shell-quoted prompt text preserved as one token."""
    return any(ch.isspace() for ch in arg)


def _classify_codex_interactive(tokens: list[str]) -> str:
    """Classify Codex's top-level interactive prompt form."""
    if _codex_has_bypass(tokens):
        return AGENT_EXEC_BYPASS
    sandbox = _codex_option_value(tokens[1:], {"-s", "--sandbox"})
    if sandbox == "read-only":
        return AGENT_EXEC_READ
    return AGENT_EXEC_WRITE


def _classify_codex(tokens: list[str]) -> str | None:
    """Classify OpenAI Codex CLI invocations by agent safety class."""
    if not tokens or tokens[0] != "codex":
        return None

    if len(tokens) == 1:
        return AGENT_EXEC_WRITE

    if tokens[1] in _CODEX_TOP_LEVEL_READ_FLAGS or tokens[1] == "help":
        return AGENT_READ

    cleaned, malformed = _strip_codex_global_options(tokens)
    if malformed:
        return UNKNOWN
    if len(cleaned) < 2:
        return _classify_codex_interactive(tokens)

    sub = cleaned[1]
    args = cleaned[2:]

    if sub in _CODEX_TOP_LEVEL_READ_FLAGS or sub == "help":
        return AGENT_READ
    if _codex_args_malformed(args):
        return UNKNOWN
    if _codex_has_help_flag(args):
        return AGENT_READ

    if sub in _CODEX_READ_COMMANDS:
        return AGENT_READ

    if sub == "login":
        return AGENT_READ if args and args[0] == "status" else AGENT_WRITE
    if sub in _CODEX_WRITE_COMMANDS:
        return AGENT_WRITE

    if sub == "mcp":
        if not args:
            return UNKNOWN
        mcp_sub = args[0]
        if mcp_sub in {"list", "get"}:
            return AGENT_READ
        if mcp_sub in {"add", "remove", "login", "logout"}:
            return AGENT_WRITE
        return UNKNOWN

    if sub == "features":
        if not args:
            return UNKNOWN
        features_sub = args[0]
        if features_sub == "list":
            return AGENT_READ
        if features_sub in {"enable", "disable"}:
            return AGENT_WRITE
        return UNKNOWN

    if sub == "cloud":
        if not args:
            return UNKNOWN
        cloud_sub = args[0]
        cloud_args = args[1:]
        if _codex_has_help_flag(cloud_args):
            return AGENT_READ
        if cloud_sub in {"list", "status", "diff"}:
            return AGENT_READ
        if cloud_sub == "apply":
            return AGENT_WRITE
        if cloud_sub == "exec":
            return AGENT_EXEC_BYPASS if _codex_has_bypass(tokens) else AGENT_EXEC_REMOTE
        return UNKNOWN

    if sub in {"mcp-server", "app-server"}:
        return AGENT_SERVER
    if sub == "debug":
        return AGENT_SERVER if args and args[0] == "app-server" else UNKNOWN

    if sub == "sandbox":
        return UNKNOWN

    if sub in _CODEX_AGENT_RUN_COMMANDS:
        if _codex_has_bypass(tokens):
            return AGENT_EXEC_BYPASS
        if sub in {"exec", "e"}:
            sandbox = (
                _codex_option_value(args, {"-s", "--sandbox"})
                or _codex_option_value(tokens[1:], {"-s", "--sandbox"})
            )
            return AGENT_EXEC_READ if sandbox == "read-only" else AGENT_EXEC_WRITE
        if sub == "review":
            return AGENT_EXEC_READ
        return AGENT_EXEC_WRITE

    if (
        _codex_has_top_level_interactive_option(tokens)
        or _codex_prompt_arg_is_clear_prompt(sub)
    ):
        return _classify_codex_interactive(tokens)

    return UNKNOWN


def _is_codex_companion_script(path: str) -> bool:
    """Return True for installed OpenAI Codex plugin companion scripts."""
    return is_codex_companion_script(path)


def is_codex_companion_script(path: str) -> bool:
    """Return True for installed OpenAI Codex plugin companion scripts."""
    normalized = path.replace("\\", "/")
    return (
        os.path.basename(normalized) == "codex-companion.mjs"
        and "openai-codex/codex/" in normalized
    )


def _classify_codex_companion(tokens: list[str]) -> str | None:
    """Classify Codex plugin companion invocations before generic node script exec."""
    if len(tokens) < 3 or tokens[0] != "node":
        return None
    if not _is_codex_companion_script(tokens[1]):
        return None

    sub = tokens[2]
    args = tokens[3:]

    if sub == "setup":
        if "--enable-review-gate" in args or "--disable-review-gate" in args:
            return AGENT_WRITE
        return AGENT_READ
    if sub in {"review", "adversarial-review"}:
        return AGENT_EXEC_READ
    if sub == "task":
        return AGENT_EXEC_WRITE if "--write" in args else AGENT_EXEC_READ
    if sub == "task-worker":
        return AGENT_EXEC_WRITE
    if sub in {"status", "result", "task-resume-candidate"}:
        return AGENT_READ
    if sub == "cancel":
        return AGENT_WRITE
    return UNKNOWN


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


def _looks_like_script_path(token: str) -> bool:
    """Return True when a wrapper payload token is plausibly a local script path."""
    if not token or token == "-":
        return False
    if "/" in token or token.startswith(("~", ".")):
        return True
    _, ext = os.path.splitext(token)
    return ext in _SCRIPT_EXTENSIONS


def _canonicalize_wrapper_payload(payload: list[str]) -> list[str] | None:
    """Return inner tokens for wrapper payloads, or None when unsupported."""
    if not payload:
        return None

    if payload[0] == "ts-node":
        if len(payload) >= 2 and not payload[1].startswith("-"):
            return ["tsx", payload[1], *payload[2:]]
        return None

    return payload


def _extract_uv_run_inner(args: list[str]) -> list[str] | None:
    """Return canonical inner tokens for `uv run`, else None."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if tok == "-m":
            if i + 1 >= len(args):
                return None
            return ["python", "-m", args[i + 1]]
        if tok.startswith("-m") and len(tok) > 2:
            return ["python", "-m", tok[2:]]
        if tok == "--module":
            if i + 1 >= len(args):
                return None
            return ["python", "-m", args[i + 1]]
        if tok.startswith("--module="):
            return ["python", "-m", tok.split("=", 1)[1]]
        if tok == "-s":
            if i + 1 >= len(args):
                return None
            return ["python", args[i + 1], *args[i + 2:]]
        if tok.startswith("-s") and len(tok) > 2:
            return ["python", tok[2:], *args[i + 1:]]
        if tok == "--script":
            if i + 1 >= len(args):
                return None
            return ["python", args[i + 1], *args[i + 2:]]
        if tok.startswith("--script="):
            return ["python", tok.split("=", 1)[1], *args[i + 1:]]
        if tok in _UV_RUN_VALUE_FLAGS:
            if i + 1 >= len(args):
                return None
            i += 2
            continue
        if tok.startswith("-w") and len(tok) > 2:
            i += 1
            continue
        if any(tok.startswith(prefix) for prefix in _UV_RUN_VALUE_FLAG_PREFIXES):
            i += 1
            continue
        if tok.startswith("-"):
            return None
        break

    payload = args[i:]
    if not payload:
        return None
    if _looks_like_script_path(payload[0]):
        return ["python", *payload]
    return _canonicalize_wrapper_payload(payload)


def _extract_uv_tool_run_inner(args: list[str]) -> list[str] | None:
    """Return canonical inner tokens for `uv tool run`/`uvx`, else None."""
    if not args:
        return None
    if args[0] == "--":
        args = args[1:]
    if not args or args[0].startswith("-"):
        return None
    return _canonicalize_wrapper_payload(args)


def _extract_npx_inner(args: list[str]) -> list[str] | None:
    """Return canonical inner tokens for `npx`/`npm exec`, else None."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if tok in _NPX_UNSUPPORTED_FLAGS or any(tok.startswith(flag + "=") for flag in _NPX_UNSUPPORTED_FLAGS):
            return None
        if tok in _NPX_BOOL_FLAGS:
            i += 1
            continue
        if tok in _NPX_VALUE_FLAGS:
            if i + 1 >= len(args):
                return None
            i += 2
            continue
        if any(tok.startswith(prefix) for prefix in _NPX_VALUE_FLAG_PREFIXES):
            i += 1
            continue
        if tok.startswith("-"):
            return None
        break

    payload = args[i:]
    if not payload:
        return None
    return _canonicalize_wrapper_payload(payload)


def _extract_package_exec_inner(tokens: list[str]) -> list[str] | None:
    """Return canonical inner tokens for wrapper executors, else None."""
    if not tokens:
        return None

    cmd = os.path.basename(tokens[0])
    if cmd == "uv":
        if len(tokens) >= 3 and tokens[1:3] == ["tool", "run"]:
            return _extract_uv_tool_run_inner(tokens[3:])
        if len(tokens) >= 2 and tokens[1] == "run":
            return _extract_uv_run_inner(tokens[2:])
        return None
    if cmd == "uvx":
        return _extract_uv_tool_run_inner(tokens[1:])
    if cmd == "npx":
        return _extract_npx_inner(tokens[1:])
    if cmd == "npm" and len(tokens) >= 2 and tokens[1] == "exec":
        return _extract_npx_inner(tokens[2:])
    return None


def _classify_package_exec_wrapper(
    tokens: list[str],
    *,
    global_table: list | None = None,
    builtin_table: list | None = None,
    project_table: list | None = None,
    profile: str = "full",
    trust_project: bool = False,
) -> str | None:
    """Reclassify package wrappers only when the inner payload is lang_exec."""
    inner = _extract_package_exec_inner(tokens)
    if not inner:
        return None

    if inner[0] in {"uv", "uvx", "npx", "make", "gmake"}:
        return None
    if len(inner) >= 2 and inner[:2] == ["npm", "exec"]:
        return None

    inner_action = classify_tokens(
        inner,
        global_table=global_table,
        builtin_table=builtin_table,
        project_table=project_table,
        profile=profile,
        trust_project=trust_project,
    )
    if inner_action == LANG_EXEC:
        return LANG_EXEC
    return None


def _classify_make(tokens: list[str]) -> str | None:
    """Classify `make`/`gmake` read-only forms, else route to lang_exec."""
    if not tokens or tokens[0] not in {"make", "gmake"}:
        return None

    readonly_long = {
        "--dry-run", "--help", "--version", "--just-print",
        "--print-data-base", "--question",
    }
    for tok in tokens[1:]:
        if tok in readonly_long:
            return FILESYSTEM_READ
        if tok.startswith("-") and not tok.startswith("--"):
            letters = tok[1:]
            if any(flag in letters for flag in ("n", "p", "q")):
                return FILESYSTEM_READ
    return LANG_EXEC


def _classify_windows_shell(tokens: list[str]) -> str | None:
    """Flag-dependent classification for Windows shell inline execution."""
    if len(tokens) < 2:
        return None
    cmd = _normalize_command_name(tokens[0])
    first = tokens[1].lower()
    if cmd in {"powershell", "pwsh"} and first in {
        "-command",
        "-c",
        "-encodedcommand",
    }:
        return LANG_EXEC
    if cmd == "cmd" and first in {"/c", "/k"}:
        return LANG_EXEC
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

    if cmd in _SOURCE_COMMANDS:
        return LANG_EXEC if _extract_source_operand(tokens) is not None else None

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

    # First non-flag argument = script file.
    # Skip value-taking flags (e.g. -W ignore) and their arguments.
    value_flags = _VALUE_FLAGS.get(cmd, set())
    skip_next = False
    for tok in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok in value_flags:
            skip_next = True
            continue
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
        if not args:
            return GIT_SAFE
        has_force = "--force" in args or _git_has_short_flag(args, "f")
        has_delete = "--delete" in args or _git_has_short_flag(args, "d")
        if has_force:
            return GIT_HISTORY_REWRITE
        if has_delete:
            return GIT_DISCARD
        listing_flags = {"-l", "--list", "-v", "--verify", "--contains", "--no-contains",
                         "--merged", "--no-merged", "--points-at"}
        if any(a in listing_flags or a.startswith("-n") for a in args):
            return GIT_SAFE
        return GIT_WRITE

    if sub == "branch":
        if not args:
            return GIT_SAFE
        has_force = "--force" in args or _git_has_short_flag(args, "f")
        has_force_delete = _git_has_short_flag(args, "D")
        has_delete = "--delete" in args or _git_has_short_flag(args, "d")
        if has_force_delete or (has_delete and has_force):
            return GIT_HISTORY_REWRITE
        if has_delete:
            return GIT_DISCARD
        for a in args:
            if a in ("-a", "-r", "--list", "-v", "-vv"):
                return GIT_SAFE
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
        if "--mirror" in args or "--prune" in args:
            return GIT_HISTORY_REWRITE
        if _git_has_short_flag(args, "f") or _git_has_short_flag(args, "d"):
            return GIT_HISTORY_REWRITE
        for a in args:
            if a in _FORCE_FLAGS or a.startswith("--force-with-lease="):
                return GIT_HISTORY_REWRITE
            if a in ("--delete", "-d"):
                return GIT_HISTORY_REWRITE
            # +refspec means force push; :refspec deletes a remote ref.
            if (a.startswith("+") or a.startswith(":")) and len(a) > 1:
                return GIT_HISTORY_REWRITE
        return GIT_REMOTE_WRITE

    if sub == "add":
        return GIT_SAFE if ("--dry-run" in args or _git_has_short_flag(args, "n")) else GIT_WRITE

    if sub == "rm":
        return GIT_WRITE if "--cached" in args else GIT_DISCARD

    if sub == "clean":
        return GIT_SAFE if ("--dry-run" in args or _git_has_short_flag(args, "n")) else GIT_HISTORY_REWRITE

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
    """Detect shell-wrapper inner commands. Returns (is_wrapper, inner_command_or_None)."""
    if not tokens:
        return False, None

    cmd = _normalize_command_name(tokens[0])

    if cmd in _SHELL_WRAPPERS:
        # bash/sh/dash/zsh [flags...] -c "inner"
        for i in range(1, len(tokens) - 1):
            if tokens[i] == "-c":
                return True, tokens[i + 1]

        # Support the common short-option clusters that real shells accept as
        # equivalent to `-l -c` or `-c -l`. Keep attached payload forms like
        # `-cecho` fail-closed by only unwrapping the exact clustered flags.
        for i in range(1, len(tokens) - 1):
            if tokens[i] in {"-lc", "-cl"}:
                return True, tokens[i + 1]

        # bash/sh/dash/zsh [flags...] <<< "inner" (here-string)
        for i in range(1, len(tokens) - 1):
            if tokens[i] == "<<<":
                return True, tokens[i + 1]
            if tokens[i].startswith("<<<") and len(tokens[i]) > 3:
                return True, tokens[i][3:]

    # eval "string"
    if cmd == "eval" and len(tokens) >= 2:
        return True, " ".join(tokens[1:])

    # source / . execute a file in the current shell; classification and
    # context resolution handle them as lang_exec without shell unwrapping.
    if cmd in ("source", "."):
        return False, None

    return False, None


def is_exec_sink(token: str) -> bool:
    """Check if a token is an exec sink (for pipe composition rules)."""
    _ensure_exec_sinks_merged()
    return _normalize_command_name(token) in EXEC_SINKS


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
