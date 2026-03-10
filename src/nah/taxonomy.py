"""Action taxonomy — command classification table and policy defaults."""

# Action types
FILESYSTEM_READ = "filesystem_read"
FILESYSTEM_WRITE = "filesystem_write"
FILESYSTEM_DELETE = "filesystem_delete"
GIT_SAFE = "git_safe"
GIT_WRITE = "git_write"
GIT_HISTORY_REWRITE = "git_history_rewrite"
NETWORK_OUTBOUND = "network_outbound"
PACKAGE_INSTALL = "package_install"
PACKAGE_RUN = "package_run"
LANG_EXEC = "lang_exec"
OBFUSCATED = "obfuscated"
UNKNOWN = "unknown"

# (prefix_tuple, action_type) — sorted longest-first at module load.
# Prefix matching: iterate sorted list, first match wins.
_CLASSIFY_TABLE: list[tuple[tuple[str, ...], str]] = [
    # git — multi-token prefixes (longest first matters after sort)
    (("git", "reset", "--hard"), GIT_HISTORY_REWRITE),
    (("git", "push", "--force"), GIT_HISTORY_REWRITE),
    (("git", "push", "-f"), GIT_HISTORY_REWRITE),
    (("git", "stash", "list"), GIT_SAFE),
    (("git", "stash", "drop"), GIT_HISTORY_REWRITE),
    (("git", "stash", "clear"), GIT_HISTORY_REWRITE),
    (("git", "branch", "-D"), GIT_HISTORY_REWRITE),
    (("git", "remote", "-v"), GIT_SAFE),
    (("git", "status"), GIT_SAFE),
    (("git", "log"), GIT_SAFE),
    (("git", "diff"), GIT_SAFE),
    (("git", "show"), GIT_SAFE),
    (("git", "branch"), GIT_SAFE),
    (("git", "tag"), GIT_SAFE),
    (("git", "rebase"), GIT_HISTORY_REWRITE),
    (("git", "clean"), GIT_HISTORY_REWRITE),
    (("git", "add"), GIT_WRITE),
    (("git", "commit"), GIT_WRITE),
    (("git", "push"), GIT_WRITE),
    (("git", "pull"), GIT_WRITE),
    (("git", "fetch"), GIT_WRITE),
    (("git", "merge"), GIT_WRITE),
    (("git", "stash"), GIT_WRITE),
    (("git", "checkout"), GIT_WRITE),
    (("git", "switch"), GIT_WRITE),
    # package — multi-token
    (("npm", "install"), PACKAGE_INSTALL),
    (("npm", "test"), PACKAGE_RUN),
    (("npm", "run"), PACKAGE_RUN),
    (("pip", "install"), PACKAGE_INSTALL),
    (("pip3", "install"), PACKAGE_INSTALL),
    (("cargo", "build"), PACKAGE_INSTALL),
    (("cargo", "test"), PACKAGE_RUN),
    (("cargo", "run"), PACKAGE_RUN),
    (("brew", "install"), PACKAGE_INSTALL),
    (("apt", "install"), PACKAGE_INSTALL),
    (("gem", "install"), PACKAGE_INSTALL),
    (("go", "get"), PACKAGE_INSTALL),
    (("go", "test"), PACKAGE_RUN),
    (("go", "run"), PACKAGE_RUN),
    (("pnpm", "install"), PACKAGE_INSTALL),
    (("pnpm", "run"), PACKAGE_RUN),
    (("yarn", "add"), PACKAGE_INSTALL),
    (("yarn", "run"), PACKAGE_RUN),
    (("bun", "install"), PACKAGE_INSTALL),
    (("bun", "run"), PACKAGE_RUN),
    (("python", "-m", "pytest"), PACKAGE_RUN),
    # lang_exec — multi-token
    (("python", "-c"), LANG_EXEC),
    (("python3", "-c"), LANG_EXEC),
    (("node", "-e"), LANG_EXEC),
    (("ruby", "-e"), LANG_EXEC),
    (("perl", "-e"), LANG_EXEC),
    (("php", "-r"), LANG_EXEC),
    # filesystem_read — single token
    (("cat",), FILESYSTEM_READ),
    (("head",), FILESYSTEM_READ),
    (("tail",), FILESYSTEM_READ),
    (("less",), FILESYSTEM_READ),
    (("more",), FILESYSTEM_READ),
    (("file",), FILESYSTEM_READ),
    (("wc",), FILESYSTEM_READ),
    (("stat",), FILESYSTEM_READ),
    (("du",), FILESYSTEM_READ),
    (("df",), FILESYSTEM_READ),
    (("ls",), FILESYSTEM_READ),
    (("tree",), FILESYSTEM_READ),
    (("bat",), FILESYSTEM_READ),
    (("echo",), FILESYSTEM_READ),
    (("printf",), FILESYSTEM_READ),
    (("diff",), FILESYSTEM_READ),
    (("grep",), FILESYSTEM_READ),
    (("rg",), FILESYSTEM_READ),
    (("awk",), FILESYSTEM_READ),
    (("sed",), FILESYSTEM_READ),
    # filesystem_write — single token
    (("tee",), FILESYSTEM_WRITE),
    (("cp",), FILESYSTEM_WRITE),
    (("mv",), FILESYSTEM_WRITE),
    (("mkdir",), FILESYSTEM_WRITE),
    (("touch",), FILESYSTEM_WRITE),
    (("chmod",), FILESYSTEM_WRITE),
    (("chown",), FILESYSTEM_WRITE),
    (("ln",), FILESYSTEM_WRITE),
    (("install",), FILESYSTEM_WRITE),
    # filesystem_delete — single token
    (("rm",), FILESYSTEM_DELETE),
    (("rmdir",), FILESYSTEM_DELETE),
    (("unlink",), FILESYSTEM_DELETE),
    (("shred",), FILESYSTEM_DELETE),
    (("truncate",), FILESYSTEM_DELETE),
    # network_outbound — single token
    (("curl",), NETWORK_OUTBOUND),
    (("wget",), NETWORK_OUTBOUND),
    (("ssh",), NETWORK_OUTBOUND),
    (("scp",), NETWORK_OUTBOUND),
    (("rsync",), NETWORK_OUTBOUND),
    (("nc",), NETWORK_OUTBOUND),
    (("ncat",), NETWORK_OUTBOUND),
    (("telnet",), NETWORK_OUTBOUND),
    (("ftp",), NETWORK_OUTBOUND),
    (("sftp",), NETWORK_OUTBOUND),
    # package_run — single token
    (("npx",), PACKAGE_RUN),
    (("pytest",), PACKAGE_RUN),
    (("make",), PACKAGE_RUN),
    (("just",), PACKAGE_RUN),
    (("task",), PACKAGE_RUN),
]

# Sort longest prefix first — longest match wins.
_CLASSIFY_TABLE.sort(key=lambda entry: len(entry[0]), reverse=True)

# Default policies per action type.
_POLICIES: dict[str, str] = {
    FILESYSTEM_READ: "allow",
    FILESYSTEM_WRITE: "context",
    FILESYSTEM_DELETE: "context",
    GIT_SAFE: "allow",
    GIT_WRITE: "allow",
    GIT_HISTORY_REWRITE: "ask",
    NETWORK_OUTBOUND: "context",
    PACKAGE_INSTALL: "allow",
    PACKAGE_RUN: "allow",
    LANG_EXEC: "ask",
    OBFUSCATED: "block",
    UNKNOWN: "ask",
}

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


def classify_tokens(tokens: list[str]) -> str:
    """Classify command tokens by prefix match (longest wins). Returns action type."""
    if not tokens:
        return UNKNOWN

    # Special case: find
    action = _classify_find(tokens)
    if action is not None:
        return action

    # Prefix match: iterate sorted table, first (longest) match wins.
    for prefix, action_type in _CLASSIFY_TABLE:
        if len(tokens) >= len(prefix) and tuple(tokens[:len(prefix)]) == prefix:
            return action_type

    return UNKNOWN


def _classify_find(tokens: list[str]) -> str | None:
    """Special classifier for find — flag-dependent action type."""
    if not tokens or tokens[0] != "find":
        return None
    for tok in tokens[1:]:
        if tok in ("-delete", "-exec", "-execdir", "-ok"):
            return FILESYSTEM_DELETE
    return FILESYSTEM_READ


def get_policy(action_type: str) -> str:
    """Return policy for an action type. Falls back to 'ask' for unknown types."""
    return _POLICIES.get(action_type, "ask")


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
