"""Context resolution — filesystem and network context for 'context' policy decisions."""

import os
import urllib.parse

from nah import paths

# Known safe registries / hosts for network context.
_KNOWN_HOSTS: set[str] = {
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

# Localhost addresses.
_LOCALHOST: set[str] = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def resolve_filesystem_context(target_path: str) -> tuple[str, str]:
    """Resolve filesystem context for a target path.

    Returns (decision, reason).
    """
    if not target_path:
        return "allow", "no target path"

    resolved = paths.resolve_path(target_path)

    # Hook self-protection
    if paths.is_hook_path(resolved):
        return "ask", f"targets hook directory: {paths.friendly_path(resolved)}"

    # Sensitive path
    matched, pattern, policy = paths.is_sensitive(resolved)
    if matched:
        if policy == "block":
            return "block", f"targets sensitive path: {pattern}"
        return "ask", f"targets sensitive path: {pattern}"

    # Project root check
    project_root = paths.get_project_root()
    if project_root is None:
        return "ask", f"outside project (no git root): {paths.friendly_path(resolved)}"

    real_root = os.path.realpath(project_root)
    if resolved == real_root or resolved.startswith(real_root + os.sep):
        return "allow", f"inside project: {paths.friendly_path(resolved)}"

    return "ask", f"outside project: {paths.friendly_path(resolved)}"


def resolve_network_context(tokens: list[str]) -> tuple[str, str]:
    """Resolve network context for outbound commands.

    Returns (decision, reason).
    """
    host = extract_host(tokens)
    if host is None:
        return "ask", "unknown host"

    # Strip port if present
    host_no_port = host.split(":")[0] if ":" in host else host

    # Localhost
    if host_no_port in _LOCALHOST:
        return "allow", f"localhost: {host}"

    # Known registries
    if host_no_port in _KNOWN_HOSTS:
        return "allow", f"known host: {host_no_port}"

    return "ask", f"unknown host: {host_no_port}"


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
    if cmd in ("ssh", "scp", "sftp"):
        return _extract_ssh_host(args)
    if cmd in ("nc", "ncat", "telnet"):
        return _extract_nc_host(args)

    # Fallback: try URL extraction
    return _extract_url_host(args)


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


def _extract_ssh_host(args: list[str]) -> str | None:
    """Extract host from ssh/scp args (user@host or positional host)."""
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            # Flags that take a value
            if arg in ("-p", "-i", "-l", "-o", "-F", "-J", "-P"):
                skip_next = True
            continue
        # user@host
        if "@" in arg:
            host_part = arg.split("@", 1)[1]
            # scp: user@host:path
            return host_part.split(":")[0] if ":" in host_part else host_part
        # Bare host
        return arg
    return None


def _extract_nc_host(args: list[str]) -> str | None:
    """Extract host from nc/telnet — first non-flag argument."""
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            if arg in ("-p", "-w", "-s"):
                skip_next = True
            continue
        return arg
    return None
