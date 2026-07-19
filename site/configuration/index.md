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
- Change UI, terminal settings, or non-policy target knobs

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
| `presets` | Global only; selected explicitly for one invocation/session |
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
| `presets` | dict of name → config overlay | global | [Presets](#presets) |
| `trusted_project_configs` | list of paths | global | This page |
| `classify` | dict of type → prefix list | global; trusted project roots | [Classification rules](classification-rules.md) |
| `actions` | dict of type → policy | both | [Action types](actions.md) |
| `sensitive_paths_default` | `ask` / `block` | both* | [Sensitive paths](sensitive-paths.md) |
| `sensitive_paths` | dict of path → policy | both | [Sensitive paths](sensitive-paths.md) |
| `allow_paths` | dict of path → project list | global | [Sensitive paths](sensitive-paths.md) |
| `trusted_paths` | list of paths | global | [Sensitive paths](sensitive-paths.md) |
| `trusted_containers` | list of container/compose identities | global; trusted project roots | [Action types](actions.md) |
| `known_registries` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `exec_sinks` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `sensitive_basenames` | dict of name → policy | global | [Safety lists](safety-lists.md) |
| `decode_commands` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `content_patterns` | dict (add/suppress) | both | [Content inspection (Claude Code)](content.md) |
| `credential_patterns` | dict (add/suppress) | global | [Content inspection (Claude Code)](content.md) |
| `llm` | dict (`mode`, providers, per-provider blocks) | global | [LLM layer](llm.md) |
| `targets` | dict of target → overrides | both* | This page |
| `db_targets` | list of database/schema dicts | global | [Database targets](database.md) |
| `log` | dict (verbosity, etc.) | global | [CLI reference](../cli.md#nah-log) |
| `active_allow` | `true`, `false`, or list of tool names | global | [Claude Code](../runtimes/claude-code.md#setup) |

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
`sensitive_paths`, `content_patterns.policies`, `llm.mode`,
`ask_fallback` (`allow`, `block`, or `native`), UI settings, and shell
`terminal` settings. Untrusted project target overrides can
tighten action, sensitive-path, and content policies only. Trusted project
config can loosen policy and change non-policy target settings for that exact
project root.

`ask_fallback: native` leaves unresolved asks to the interactive runtime's own
permission flow. For Claude Code, this allows Auto Mode to review only the
ambiguous remainder after nah's deterministic decisions. For interactive Codex,
it makes the default native behavior explicit. Headless Codex resolves `native`
to `block` because no native approval prompt is available.

Codex approval settings are owned by `nah run codex`. The launcher defaults to
Codex `danger-full-access` plus `untrusted` approvals; use
`nah run codex --sandbox workspace-write` or `--sandbox read-only` when you want
Codex's own sandbox too. Target config can tune nah policies and LLM behavior
for Codex, but it cannot change Codex safety knobs directly.

Public `nah test --target` simulation currently supports `claude`, `bash`, and
`zsh`. Do not use `codex` there unless a later release adds that CLI target.

Bash and zsh are terminal-guard targets and are deterministic-only: they do not
use the LLM. Their `llm.mode` knob is still accepted for backward compatibility
but has no effect on terminal decisions.

Provider credentials and provider selection stay global-only. Configure LLM
providers directly in global config and store environment-variable names such
as `llm.openrouter.key_env`, not raw API keys. The secret value behind that
slot can live either in the current process environment or in an OS
keychain/keyring when your CLI install includes keyring support.

## Presets

Presets are named global config overlays. Use them when you want a temporary
policy bundle for one workflow without editing your base config.

```yaml
# ~/.config/nah/config.yaml
actions:
  unknown: ask

presets:
  strict:
    actions:
      network_outbound: ask
      lang_exec: ask
      unknown: ask

  work:
    known_registries:
      - npm.company.test
    targets:
      codex:
        actions:
          filesystem_write: ask
```

Select a preset explicitly:

```bash
nah run claude --preset strict
nah run codex --preset work
nah test --preset strict "python3 script.py"
nah config show --preset work
NAH_PRESET=work claude
```

Inspect configured presets:

```bash
nah config presets          # list preset names
nah config presets strict   # show the raw global preset block
nah config show --preset strict
```

`nah config presets <name>` shows what you wrote in global config.
`nah config show --preset <name>` shows the final effective config after base
global config, the selected preset, project config safety rules, and target
overrides are applied.

Preset merge rules are intentionally simple:

- Dicts deep-merge, so `actions.network_outbound` can change without restating
  every action.
- Scalars replace.
- Lists replace. This applies to trust/scope lists such as
  `known_registries`, `trusted_paths`, `trusted_containers`, pattern lists, and
  `db_targets`.

Presets are global-only in this version. Project `.nah.yaml` files cannot
define or select presets. Unknown selected preset names fail closed.

## Legacy `profile` key

Older nah versions supported `profile: full`, `profile: minimal`, and
`profile: none`. That taxonomy-profile concept has been removed. nah now always
runs the full built-in taxonomy, classifiers, safety lists, sensitive path
checks, and content scanners.

Existing `profile` keys are accepted for compatibility but ignored. In
particular, `profile: none` no longer disables built-in safety checks. Use
presets for named policy bundles.

## YAML format

Both config files use standard YAML. If nah detects comments in a file before a CLI write operation (`nah allow`, `nah classify`, etc.), it warns you that comments will be removed and asks for confirmation.

Optional dependency: `pip install "nah[config]"` installs `pyyaml`. The default
install keeps nah's core hook/classifier stdlib-only for users who want the
smallest supply-chain surface. Install the config extra when you want YAML config
files or commands that write config (`nah allow`, `nah deny`, `nah classify`,
`nah trust`). With pipx, use `pipx inject nah pyyaml`.

Optional dependency: `pip install "nah[keys]"` installs keyring support for the
PyPI CLI so remote-provider secret values can live in your OS keychain/keyring
instead of exported env vars. The default Nix package also includes Python
keyring integration, but actual OS keychain/keyring availability depends on
the host backend. If you want both YAML config support and key management with
pip, use `pip install "nah[config,keys]"` or `pipx inject nah pyyaml keyring`.
