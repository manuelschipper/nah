"""Target registry for nah lifecycle and dry-run commands."""

from dataclasses import dataclass


CLAUDE = "claude"
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
AGENT_TARGETS = {CLAUDE}


def get_target(key: str | None) -> Target | None:
    """Return target metadata for ``key``."""
    if not key:
        return None
    return TARGETS.get(key)


def require_target(key: str | None, command: str) -> Target:
    """Return a target or raise ValueError with a product-facing message."""
    target = get_target(key)
    if target is not None:
        return target
    if not key:
        raise ValueError(format_target_help(command))
    raise ValueError(
        f"nah {command}: unknown target '{key}'\n\n"
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
    return "\n".join(lines)
