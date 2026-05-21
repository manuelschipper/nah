"""Target registry for nah lifecycle and dry-run commands."""

from dataclasses import dataclass


CLAUDE = "claude"
CODEX = "codex"
BASH = "bash"
ZSH = "zsh"

AGENT = "agent"
SHELL = "shell"


@dataclass(frozen=True)
class Target:
    key: str
    kind: str
    label: str
    description: str
    can_install: bool = True
    can_update: bool = True
    can_uninstall: bool = True


TARGETS: dict[str, Target] = {
    CLAUDE: Target(
        key=CLAUDE,
        kind=AGENT,
        label="Claude Code",
        description="protect Claude Code with direct hooks",
    ),
    CODEX: Target(
        key=CODEX,
        kind=AGENT,
        label="OpenAI Codex",
        description="protect Codex with session hooks",
        can_install=False,
        can_update=False,
        can_uninstall=False,
    ),
    BASH: Target(
        key=BASH,
        kind=SHELL,
        label="bash",
        description="protect interactive bash",
    ),
    ZSH: Target(
        key=ZSH,
        kind=SHELL,
        label="zsh",
        description="protect interactive zsh",
    ),
}

SHELL_TARGETS = {BASH, ZSH}
AGENT_TARGETS = {CLAUDE, CODEX}


def get_target(key: str | None) -> Target | None:
    """Return target metadata for ``key``."""
    if not key:
        return None
    return TARGETS.get(key)


def require_target(key: str | None, command: str) -> Target:
    """Return a target or raise ValueError with a product-facing message."""
    if key == CODEX and command in ("install", "update", "uninstall"):
        raise ValueError(format_unsupported_target(command, CODEX))
    target = get_target(key)
    if target is not None:
        if not _target_supports_command(target, command):
            raise ValueError(format_unsupported_target(command, target.key))
        return target
    if not key:
        raise ValueError(format_target_help(command))
    raise ValueError(
        f"nah {command}: unknown target '{key}'\n\n"
        + format_target_help(command)
    )


def _target_supports_command(target: Target, command: str) -> bool:
    """Return whether a lifecycle command applies to target."""
    if command == "install":
        return target.can_install
    if command == "update":
        return target.can_update
    if command == "uninstall":
        return target.can_uninstall
    return True


def format_unsupported_target(command: str, target_key: str) -> str:
    """Return a product-facing unsupported lifecycle target error."""
    if target_key == CODEX and command in ("install", "update", "uninstall"):
        return (
            f"nah {command} codex: Codex has no persistent {command} target.\n\n"
            "Use `nah run codex` to launch a protected Codex session. "
            "After upgrading the nah package, the next `nah run codex` uses the new version."
        )
    return (
        f"nah {command}: target '{target_key}' does not support {command}\n\n"
        + format_target_help(command)
    )


def format_target_help(command: str) -> str:
    """Return the guided target list for lifecycle commands."""
    action = f"what to {command}" if command in ("install", "uninstall", "update") else "a target"
    lines = [f"nah {command}: choose {action}", ""]
    for key in (CLAUDE, BASH, ZSH):
        target = TARGETS[key]
        if command == "update" and not target.can_update:
            continue
        if command == "uninstall" and not target.can_uninstall:
            continue
        if command == "install" and not target.can_install:
            continue
        lines.append(f"  nah {command} {key:<10} {target.description}")
    if command in ("install", "update", "uninstall"):
        lines.extend([
            "",
            "Codex is session-scoped: use `nah run codex` instead of install/update/uninstall.",
        ])
    return "\n".join(lines)
