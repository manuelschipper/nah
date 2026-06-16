"""Target registry for nah lifecycle and dry-run commands."""

from dataclasses import dataclass, field


CLAUDE = "claude"
CODEX = "codex"
BASH = "bash"
ZSH = "zsh"

AGENT = "agent"
SHELL = "shell"

# Lifecycle command vocabulary. A target supports a command only when the
# command name is in its ``commands`` set; everything else fails loudly via
# ``require_target`` instead of falling through silently.
INSTALL = "install"
UPDATE = "update"
UNINSTALL = "uninstall"
DOCTOR = "doctor"
STATUS = "status"
SETUP = "setup"


@dataclass(frozen=True)
class Target:
    key: str
    kind: str
    label: str
    description: str
    commands: frozenset[str] = field(default_factory=frozenset)


TARGETS: dict[str, Target] = {
    CLAUDE: Target(
        key=CLAUDE,
        kind=AGENT,
        label="Claude Code",
        description="protect Claude Code with direct hooks",
        # Claude Code diagnostics fold into `nah status claude`; there is no
        # separate `doctor` target.
        commands=frozenset({INSTALL, UPDATE, UNINSTALL, STATUS}),
    ),
    CODEX: Target(
        key=CODEX,
        kind=AGENT,
        label="OpenAI Codex",
        description="protect Codex with session hooks",
        # Codex protection is session-scoped (`nah run codex`); the persistent
        # surface is read-only status, mutating setup, and managed-file removal.
        commands=frozenset({STATUS, SETUP, UNINSTALL}),
    ),
    BASH: Target(
        key=BASH,
        kind=SHELL,
        label="bash",
        description="protect interactive bash",
        commands=frozenset({INSTALL, UPDATE, UNINSTALL, DOCTOR, STATUS}),
    ),
    ZSH: Target(
        key=ZSH,
        kind=SHELL,
        label="zsh",
        description="protect interactive zsh",
        commands=frozenset({INSTALL, UPDATE, UNINSTALL, DOCTOR, STATUS}),
    ),
}

SHELL_TARGETS = {BASH, ZSH}
AGENT_TARGETS = {CLAUDE, CODEX}

# Display order for guided target lists.
_HELP_ORDER = (CLAUDE, CODEX, BASH, ZSH)


def get_target(key: str | None) -> Target | None:
    """Return target metadata for ``key``."""
    if not key:
        return None
    return TARGETS.get(key)


def require_target(key: str | None, command: str) -> Target:
    """Return a target or raise ValueError with a product-facing message."""
    target = get_target(key)
    if target is not None:
        if command not in target.commands:
            raise ValueError(format_unsupported_target(command, target.key))
        return target
    if not key:
        raise ValueError(format_target_help(command))
    raise ValueError(
        f"nah {command}: unknown target '{key}'\n\n"
        + format_target_help(command)
    )


def format_unsupported_target(command: str, target_key: str) -> str:
    """Return a product-facing unsupported lifecycle target error."""
    if target_key == CODEX and command in (INSTALL, UPDATE):
        return (
            f"nah {command} codex: Codex has no persistent {command} target.\n\n"
            "Use `nah run codex` to launch a protected Codex session, and "
            "`nah setup codex` to refresh persistent Codex prompt rules.\n"
            "After upgrading the nah package, the next `nah run codex` uses the new version."
        )
    if command == DOCTOR and target_key == CODEX:
        return (
            "nah doctor codex: Codex diagnostics now live under `nah status codex`.\n\n"
            "Use `nah status codex` to inspect Codex preflight state."
        )
    if command == DOCTOR and target_key == CLAUDE:
        return (
            "nah doctor claude: Claude Code diagnostics now live under `nah status claude`.\n\n"
            "Use `nah status claude` to inspect Claude Code hook state."
        )
    if command == SETUP:
        return (
            f"nah setup {target_key}: setup is a Codex-only command.\n\n"
            + format_target_help(SETUP)
            + f"\n\nFor {target_key}, use `nah install {target_key}` / "
            f"`nah status {target_key}` instead."
        )
    return (
        f"nah {command}: target '{target_key}' does not support {command}\n\n"
        + format_target_help(command)
    )


def format_target_help(command: str) -> str:
    """Return the guided target list for lifecycle commands."""
    action = (
        f"what to {command}"
        if command in (INSTALL, UNINSTALL, UPDATE, SETUP)
        else "a target"
    )
    lines = [f"nah {command}: choose {action}", ""]
    for key in _HELP_ORDER:
        target = TARGETS[key]
        if command not in target.commands:
            continue
        verb = f"nah {command} {key}"
        lines.append(f"  {verb:<22} {target.description}")
    if command in (INSTALL, UPDATE):
        lines.extend([
            "",
            "Codex is session-scoped: use `nah run codex` to launch it, and "
            "`nah setup codex` for persistent Codex prompt rules.",
        ])
    return "\n".join(lines)
