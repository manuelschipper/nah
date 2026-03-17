"""Context resolution — filesystem and network context for 'context' policy decisions."""

import os
import sys
import urllib.parse

from nah import paths, taxonomy

# Known safe registries / hosts for network context.
_KNOWN_HOSTS_DEFAULTS: set[str] = {
    "npmjs.org", "www.npmjs.org", "registry.npmjs.org",
    "pypi.org", "files.pythonhosted.org",
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "crates.io",
    "rubygems.org",
    "packagist.org",
    "registry.yarnpkg.com",
    "registry.npmmirror.com",
    "dl.google.com",
    "repo.maven.apache.org",
    "pkg.go.dev", "proxy.golang.org",
    "hub.docker.com", "registry.hub.docker.com", "ghcr.io",
}
_known_hosts: set[str] = set(_KNOWN_HOSTS_DEFAULTS)
_known_hosts_merged = False


def _ensure_known_hosts_merged():
    """Lazy one-time merge of config known_registries into _known_hosts."""
    global _known_hosts_merged, _known_hosts
    if _known_hosts_merged:
        return
    _known_hosts_merged = True
    try:
        from nah.config import get_config, _parse_add_remove
        cfg = get_config()
        if cfg.profile == "none":
            _known_hosts.clear()
        add, remove = _parse_add_remove(cfg.known_registries)
        _known_hosts.update(str(h) for h in add)
        _known_hosts.difference_update(str(h) for h in remove)
    except Exception as exc:
        sys.stderr.write(f"nah: config: known_registries: {exc}\n")


def reset_known_hosts():
    """Restore defaults and clear merge flag (for testing)."""
    global _known_hosts_merged, _known_hosts
    _known_hosts_merged = False
    _known_hosts = set(_KNOWN_HOSTS_DEFAULTS)

# Localhost addresses.
_LOCALHOST: set[str] = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def resolve_context(
    action_type: str,
    *,
    tokens: list[str] | None = None,
    tool_input: dict | None = None,
    target_path: str | None = None,
) -> tuple[str, str]:
    """Dispatch context resolution by action type.

    Callers provide what they have:
    - bash.py: tokens + target_path (pre-extracted)
    - hook.py: tool_input (MCP structured input)
    """
    if action_type in (taxonomy.NETWORK_OUTBOUND, taxonomy.NETWORK_WRITE):
        if tokens:
            return resolve_network_context(tokens, action_type)
        return taxonomy.ASK, "unknown host"

    if action_type == taxonomy.DB_WRITE:
        return resolve_database_context(tokens, tool_input)

    if action_type in (taxonomy.FILESYSTEM_READ, taxonomy.FILESYSTEM_WRITE,
                       taxonomy.FILESYSTEM_DELETE):
        if target_path:
            return resolve_filesystem_context(target_path)
        if action_type in (taxonomy.FILESYSTEM_DELETE, taxonomy.FILESYSTEM_WRITE):
            return taxonomy.ASK, f"{action_type}: no target path extracted"
        return taxonomy.ALLOW, f"{action_type}: no target path"

    return taxonomy.ASK, f"{action_type}: no context resolver"


def resolve_filesystem_context(target_path: str) -> tuple[str, str]:
    """Resolve filesystem context for a target path.

    Returns (decision, reason).
    """
    if not target_path:
        return taxonomy.ALLOW, "no target path"

    # profile: none disables boundary check (defense in depth)
    from nah.config import get_config
    if get_config().profile == "none":
        return taxonomy.ALLOW, "profile: none (no boundary check)"

    resolved = paths.resolve_path(target_path)

    # Core path check (hook + sensitive)
    basic = paths.check_path_basic_raw(target_path)
    if basic:
        return basic

    # Trusted paths check — before project root so it works with no git root (FD-107)
    if paths.is_trusted_path(resolved):
        return taxonomy.ALLOW, f"trusted path: {paths.friendly_path(resolved)}"

    # Project root check
    project_root = paths.get_project_root()
    if project_root is None:
        return taxonomy.ASK, f"outside project (no git root): {paths.friendly_path(resolved)}"

    real_root = os.path.realpath(project_root)
    if resolved == real_root or resolved.startswith(real_root + os.sep):
        return taxonomy.ALLOW, f"inside project: {paths.friendly_path(resolved)}"

    return taxonomy.ASK, f"outside project: {paths.friendly_path(resolved)}"


def resolve_network_context(tokens: list[str], action_type: str = taxonomy.NETWORK_OUTBOUND) -> tuple[str, str]:
    """Resolve network context for outbound/write commands.

    Returns (decision, reason).
    """
    _ensure_known_hosts_merged()
    host = extract_host(tokens)
    if host is None:
        return taxonomy.ASK, "unknown host"

    # Strip port if present
    host_no_port = host.split(":")[0] if ":" in host else host

    # Localhost — allowed for reads, ask for writes (exfiltration risk)
    if host_no_port in _LOCALHOST:
        if action_type == taxonomy.NETWORK_WRITE:
            return taxonomy.ASK, f"network_write to localhost: {host}"
        return taxonomy.ALLOW, f"localhost: {host}"

    # Network writes always ask (known hosts only trusted for reads)
    if action_type == taxonomy.NETWORK_WRITE:
        return taxonomy.ASK, f"network_write → ask (host: {host_no_port})"

    # Known hosts (defaults + user config, merged)
    if host_no_port in _known_hosts:
        return taxonomy.ALLOW, f"known host: {host_no_port}"

    return taxonomy.ASK, f"unknown host: {host_no_port}"


def extract_host(tokens: list[str]) -> str | None:
    """Extract hostname from network command tokens.

    Handles curl/wget URLs, ssh user@host, nc/telnet host.
    """
    if not tokens:
        return None

    cmd = tokens[0]
    args = tokens[1:]

    if cmd in ("curl", "wget"):
        return _extract_url_host(args)
    if cmd in ("http", "https", "xh", "xhs"):
        return _extract_httpie_host(args)
    if cmd in ("ssh", "scp", "sftp"):
        return _extract_ssh_host(cmd, args)
    if cmd in ("nc", "ncat", "telnet"):
        return _extract_positional_host(args, {"-p", "-w", "-s"})

    # Fallback: try URL extraction
    return _extract_url_host(args)


_HTTPIE_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _extract_httpie_host(args: list[str]) -> str | None:
    """Extract host from httpie args. Skips flags, METHOD tokens, data items."""
    for arg in args:
        if arg.startswith("-"):
            continue
        # Skip method tokens
        if arg.upper() in _HTTPIE_METHODS:
            continue
        # Skip data items (key=value, key:=value, key@file)
        if "=" in arg or ":=" in arg or ("@" in arg and "://" not in arg):
            continue
        # This is the URL/host
        if "://" in arg:
            parsed = urllib.parse.urlparse(arg)
            if parsed.hostname:
                return parsed.hostname
        # Bare hostname
        if "." in arg or ":" in arg:
            part = arg.split("/")[0]
            if part:
                return part.split(":")[0] if ":" in part else part
        return arg
    return None


def _extract_url_host(args: list[str]) -> str | None:
    """Find URL-like argument and parse hostname."""
    for arg in args:
        if arg.startswith("-"):
            continue
        # Try parsing as URL
        if "://" in arg or arg.startswith("//"):
            parsed = urllib.parse.urlparse(arg)
            if parsed.hostname:
                return parsed.hostname
        # Bare hostname:port or hostname/path
        if "." in arg or ":" in arg:
            # Could be host:port or host/path
            part = arg.split("/")[0]
            if part and not part.startswith("-"):
                return part.split(":")[0] if ":" in part else part
    return None


def resolve_database_context(tokens: list[str], tool_input: dict | None) -> tuple[str, str]:
    """Resolve database context for db_write commands.

    Extracts database target from CLI flags, checks against configured db_targets.
    Returns (decision, reason).
    """
    target = _extract_db_target(tokens, tool_input)
    if target is None:
        return taxonomy.ASK, "unknown database target"

    database, schema = target
    # Normalize to uppercase for comparison
    database = database.upper() if database else None
    schema = schema.upper() if schema else None

    if not database:
        return taxonomy.ASK, "unknown database target"

    from nah.config import get_config
    cfg = get_config()

    if not cfg.db_targets:
        return taxonomy.ASK, "no db_targets configured"

    if _matches_db_targets(database, schema, cfg.db_targets):
        label = f"{database}.{schema}" if schema else database
        return taxonomy.ALLOW, f"allowed target: {label}"

    label = f"{database}.{schema}" if schema else database
    return taxonomy.ASK, f"unrecognized target: {label}"


def _extract_db_target(tokens: list[str] | None, tool_input: dict | None) -> tuple[str, str | None] | None:
    """Extract database target from CLI flags or tool input.

    Returns (database, schema) or None if not determinable.
    """
    # Phase 2 MCP path: tool_input has database/schema keys
    if tool_input:
        if "database" in tool_input or "schema" in tool_input:
            db = tool_input.get("database")
            sc = tool_input.get("schema")
            if db:
                return (db, sc)

    if not tokens:
        return None

    cmd = tokens[0]

    if cmd == "psql":
        return _extract_psql_target(tokens)
    if cmd == "snowsql":
        return _extract_snowsql_target(tokens)
    if cmd == "snow" and len(tokens) >= 2 and tokens[1] == "sql":
        return _extract_snow_sql_target(tokens)

    return None


def _extract_flag_value(tokens: list[str], short: str, long: str, start: int = 1) -> str | None:
    """Extract first occurrence of a flag value from tokens.

    Handles: -d VALUE, -dVALUE (glued), --dbname VALUE, --dbname=VALUE.
    """
    i = start
    while i < len(tokens):
        tok = tokens[i]
        # Long form: --flag=value or --flag value
        if tok == long:
            if i + 1 < len(tokens):
                return tokens[i + 1]
            return None
        if tok.startswith(long + "="):
            return tok[len(long) + 1:]
        # Short form: -d value or -dvalue (glued)
        if short:
            if tok == short:
                if i + 1 < len(tokens):
                    return tokens[i + 1]
                return None
            if tok.startswith(short) and len(tok) > len(short):
                return tok[len(short):]
        i += 1
    return None


def _extract_psql_target(tokens: list[str]) -> tuple[str, str | None] | None:
    """Extract database from psql flags or connection string."""
    # CLI flag takes priority
    db = _extract_flag_value(tokens, "-d", "--dbname")
    if db:
        return (db, None)

    # Check for connection string URL
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if tok.startswith("postgresql://") or tok.startswith("postgres://"):
            parsed = urllib.parse.urlparse(tok)
            # Only extract from path, not query params (fail-safe)
            if parsed.path and len(parsed.path) > 1:
                return (parsed.path.lstrip("/"), None)

    return None


def _extract_snowsql_target(tokens: list[str]) -> tuple[str, str | None] | None:
    """Extract database and schema from snowsql flags."""
    db = _extract_flag_value(tokens, "-d", "--dbname")
    if not db:
        return None
    schema = _extract_flag_value(tokens, "-s", "--schemaname")
    return (db, schema)


def _extract_snow_sql_target(tokens: list[str]) -> tuple[str, str | None] | None:
    """Extract database and schema from snow sql flags."""
    # snow sql --database X --schema Y (start at 2 to skip "snow sql")
    db = _extract_flag_value(tokens, "", "--database", start=2)
    if not db:
        return None
    schema = _extract_flag_value(tokens, "", "--schema", start=2)
    return (db, schema)


def _matches_db_targets(database: str, schema: str | None, db_targets: list[dict]) -> bool:
    """Check if database/schema matches any configured db_targets entry.

    Each entry has 'database' (required) and optional 'schema'.
    Wildcard '*' matches anything.
    """
    for entry in db_targets:
        entry_db = entry.get("database")
        if not entry_db:
            continue
        entry_db = entry_db.upper() if isinstance(entry_db, str) else entry_db

        # Database must match
        if entry_db != "*" and entry_db != database:
            continue

        # Schema: absent/None/"*" matches anything, otherwise must match
        entry_schema = entry.get("schema")
        if entry_schema is None or (isinstance(entry_schema, str) and entry_schema == "*"):
            return True
        entry_schema = entry_schema.upper() if isinstance(entry_schema, str) else entry_schema
        if schema is None or entry_schema == schema:
            return True

    return False


def _looks_like_local_path(arg: str) -> bool:
    """Check if an argument looks like a local file path rather than a hostname."""
    return arg.startswith(("/", "./", "../", "~"))


def _strip_host_from_colon_suffix(s: str) -> str:
    """Extract hostname from host:port or host:path, handling [IPv6] brackets."""
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            return s[1:end]
    return s.split(":")[0]


# ssh/scp/sftp valued flags — flags that consume the next argument.
# Comprehensive set to avoid misidentifying flag values as hostnames.
_SSH_VALUED_FLAGS = {
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L",
    "-l", "-m", "-O", "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w",
}


def _extract_ssh_host(cmd: str, args: list[str]) -> str | None:
    """Extract host from ssh/scp/sftp args.

    Two-pass approach:
    1. Prefer args with @ (user@host) — unambiguous.
    2. For scp, prefer args with : (host:path) — remote indicator.
    3. Fall back to first positional that doesn't look like a local path.
    """
    positionals = _collect_positionals(args, _SSH_VALUED_FLAGS)

    # Pass 1: look for user@host
    for arg in positionals:
        if "@" in arg:
            host_part = arg.split("@", 1)[1]
            return _strip_host_from_colon_suffix(host_part) if ":" in host_part else host_part

    # Pass 2 (scp/sftp): look for host:path (colon indicates remote)
    if cmd in ("scp", "sftp"):
        for arg in positionals:
            if ":" in arg:
                return _strip_host_from_colon_suffix(arg)

    # Pass 3: first positional that doesn't look like a local path
    for arg in positionals:
        if not _looks_like_local_path(arg):
            return arg

    return None


def _collect_positionals(args: list[str], valued_flags: set[str]) -> list[str]:
    """Collect positional (non-flag) args, skipping valued flags and their values."""
    positionals = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            if arg in valued_flags:
                skip_next = True
            continue
        positionals.append(arg)
    return positionals


def _extract_positional_host(args: list[str], valued_flags: set[str]) -> str | None:
    """Extract host from positional args, skipping valued flags. Handles user@host."""
    positionals = _collect_positionals(args, valued_flags)
    for arg in positionals:
        if "@" in arg:
            host_part = arg.split("@", 1)[1]
            return _strip_host_from_colon_suffix(host_part) if ":" in host_part else host_part
    # First positional that doesn't look like a local path
    for arg in positionals:
        if not _looks_like_local_path(arg):
            return arg
    # Last resort: first positional
    return positionals[0] if positionals else None
