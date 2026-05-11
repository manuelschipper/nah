# Configuration Overview

nah works out of the box with zero config. When you want to tune it, configuration lives in two places.

## File locations

| Scope | Path | Purpose |
|-------|------|---------|
| **Global** | `~/.config/nah/config.yaml` | Your personal preferences, trusted paths, LLM setup |
| **Project** | Git root `.nah.yaml`; outside Git, current directory `.nah.yaml` | Project policy, tighten-only until trusted |

```bash
nah config path    # show both paths
nah config show    # display effective merged config
```

## Project config roots

Inside Git, the Git root is the project root. nah loads only the root
`.nah.yaml`, even when you run from a subdirectory.

```text
repo/
  .git/
  .nah.yaml          # loaded from anywhere inside repo
  app/.nah.yaml      # ignored
```

Outside Git, nah does not search parents. It loads `./.nah.yaml` only when the
current directory contains it.

```text
workspace/
  .nah.yaml          # loaded only when cwd is workspace/
  app/               # from here, parent .nah.yaml is not searched
```

`nah config path` shows the active project config path, root, and whether that
root is trusted.

## Global vs project scope

**Global config** can do everything -- override policies, add trusted paths, configure LLM, modify safety lists.

**Project config** can only **tighten** policy by default. It can:

- Escalate action policies (e.g., `git_write: ask`)
- Tighten content pattern policies (ask → block)
- Add target-scoped tightening under `targets.<target>`

It **cannot**:

- Relax any policy (lowering strictness is rejected)
- Contribute runtime `classify` entries before the project root is trusted
- Modify safety lists (`known_registries`, `exec_sinks`, etc.)
- Set `trusted_paths`, `allow_paths`, or `db_targets`
- Configure provider credentials or the global LLM provider cascade
- Change the taxonomy profile, UI, terminal settings, or non-policy target knobs

This is the **supply-chain safety** model: a malicious repo's `.nah.yaml` can't weaken your protections.

## Trusting project config

Trust is per exact project root. Use it when you trust that project's
`.nah.yaml` to loosen policy or define project-specific command
classifications:

```bash
nah trust-project          # trust the active project root, or cwd outside Git
nah trust-project /path/to/repo
nah untrust-project /path/to/repo
```

This writes `trusted_project_configs` to global config:

```yaml
trusted_project_configs:
  - /path/to/repo
```

Trust is exact-root after path resolution. Trusting `/work` does not trust
`/work/app` as a separate project root.

`trusted_project_configs` is different from `trusted_paths`: project-config
trust lets that root's `.nah.yaml` loosen nah policy; `trusted_paths` allows
filesystem operations in selected directories outside the project boundary.

## Merge rules

When both configs exist, nah merges them with these rules:

| Field | Merge behavior |
|-------|---------------|
| `profile` | Global only |
| `trusted_project_configs` | Global only; exact project roots whose `.nah.yaml` can loosen policy |
| `actions` | Tighten-only (project can only escalate strictness) |
| `classify` | Global entries are active first; project entries are active only for trusted project roots |
| `sensitive_paths` | Tighten-only; trusted project config can loosen |
| `sensitive_basenames` | Global only |
| `content_patterns` | Project can tighten policies only (add/suppress global-only) |
| `credential_patterns` | Global only |
| `known_registries` | Global only |
| `exec_sinks` | Global only |
| `decode_commands` | Global only |
| `trusted_paths` | Global only |
| `allow_paths` | Global only |
| `db_targets` | Global only |
| `llm` | Global only |
| `targets` | Global can override; project can only tighten until trusted |
| `log` | Global only |
| `active_allow` | Global only |

## Quick reference — all config keys

| Key | Type | Scope | Docs |
|-----|------|-------|------|
| `profile` | `full` / `none` | global | [Profiles](profiles.md) |
| `trusted_project_configs` | list of paths | global | This page |
| `classify` | dict of type → prefix list | global; trusted project roots | [Classification rules](classification-rules.md) |
| `actions` | dict of type → policy | both | [Action types](actions.md) |
| `sensitive_paths_default` | `ask` / `block` | both* | [Sensitive paths](sensitive-paths.md) |
| `sensitive_paths` | dict of path → policy | both | [Sensitive paths](sensitive-paths.md) |
| `allow_paths` | dict of path → project list | global | [Sensitive paths](sensitive-paths.md) |
| `trusted_paths` | list of paths | global | [Sensitive paths](sensitive-paths.md) |
| `known_registries` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `exec_sinks` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `sensitive_basenames` | dict of name → policy | global | [Safety lists](safety-lists.md) |
| `decode_commands` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `content_patterns` | dict (add/suppress) | both | [Content inspection (Claude Code)](content.md) |
| `credential_patterns` | dict (add/suppress) | global | [Content inspection (Claude Code)](content.md) |
| `llm` | dict (`mode`, providers, `eligible`, `context_chars`) | global | [LLM layer](llm.md) |
| `targets` | dict of target → overrides | both* | This page |
| `db_targets` | list of database/schema dicts | global | [Database targets](database.md) |
| `log` | dict (verbosity, etc.) | global | [CLI reference](../cli.md#nah-log) |
| `active_allow` | `true`, `false`, or list of tool names | global | [Claude Code](../runtimes/claude-code.md#prompt-behavior) |

*\* Project `sensitive_paths_default` can only tighten (ask → block) until the project root is trusted. Target-scoped project overrides can tighten policy by default; non-policy target settings require trusted project config.*

## Target overrides

Use `targets.<target>` when a runtime needs different policy from the shared
default. Supported config targets are `claude`, `codex`, `bash`, and `zsh`.
`codex` applies to sessions launched with `nah run codex`; it is not an
install target.

```yaml
# ~/.config/nah/config.yaml
actions:
  lang_exec: context
  git_remote_write: ask

llm:
  mode: on
  providers: [openrouter]
  openrouter:
    key_env: OPENROUTER_API_KEY
    model: google/gemini-3.1-flash-lite-preview

targets:
  claude:
    llm:
      mode: on
  codex:
    actions:
      network_outbound: ask
    llm:
      mode: on
  bash:
    actions:
      network_outbound: ask
    llm:
      mode: off
    terminal:
      bypass_env: NAH_TERMINAL_BYPASS
  zsh:
    actions:
      network_outbound: ask
    llm:
      mode: off
```

Global target overrides can set `actions`, `sensitive_paths_default`,
`sensitive_paths`, `content_patterns.policies`, `llm.mode`, `llm.eligible`, UI
settings, and shell `terminal` settings. Untrusted project target overrides can
tighten action, sensitive-path, and content policies only. Trusted project
config can loosen policy and change non-policy target settings for that exact
project root.

Codex sandbox and approval settings are fixed by `nah run codex`. Target config
can tune nah policies and LLM behavior for Codex, but it cannot change Codex
safety knobs.

Public `nah test --target` simulation currently supports `claude`, `bash`, and
`zsh`. Do not use `codex` there unless a later release adds that CLI target.

Bash and zsh are terminal-guard targets. They default to LLM mode off even
when global LLM mode is on. Enable terminal LLM review only with an explicit
target override such as
`targets.bash.llm.mode: on`.

Provider credentials and provider selection stay global-only. Configure LLM
providers directly in global config and store environment-variable names such
as `llm.openrouter.key_env`, not raw API keys. The secret value behind that
slot can live either in the current process environment or in the OS keychain
used by the optional `nah[keys]` extra on PyPI installs.

## YAML format

Both config files use standard YAML. If nah detects comments in a file before a CLI write operation (`nah allow`, `nah classify`, etc.), it warns you that comments will be removed and asks for confirmation.

Optional dependency: `pip install "nah[config]"` installs `pyyaml`. The default
install keeps nah's core hook/classifier stdlib-only for users who want the
smallest supply-chain surface. Install the config extra when you want YAML config
files or commands that write config (`nah allow`, `nah deny`, `nah classify`,
`nah trust`). With pipx, use `pipx inject nah pyyaml`.

Optional dependency: `pip install "nah[keys]"` installs keyring support for the
PyPI CLI so remote-provider secret values can live in your OS keychain instead
of exported env vars. If you want both YAML config support and key management,
use `pip install "nah[config,keys]"` or `pipx inject nah pyyaml keyring`.
