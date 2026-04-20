# Configuration Overview

nah works out of the box with zero config. When you want to tune it, configuration lives in two places.

## File locations

| Scope | Path | Purpose |
|-------|------|---------|
| **Global** | `~/.config/nah/config.yaml` | Your personal preferences, trusted paths, LLM setup |
| **Project** | `.nah.yaml` (in git root) | Per-project tightening, custom classifications |

```bash
nah config path    # show both paths
nah config show    # display effective merged config
```

## Global vs project scope

**Global config** can do everything -- override policies, add trusted paths, configure LLM, modify safety lists.

**Project config** can only **tighten** security by default. It can:

- Add classify entries (commands → action types)
- Escalate action policies (e.g., `git_write: ask`)
- Tighten content pattern policies (ask → block)
- Add target-scoped tightening under `targets.<target>`

It **cannot**:

- Relax any policy (lowering strictness is rejected)
- Modify safety lists (`known_registries`, `exec_sinks`, etc.)
- Set `trusted_paths`, `allow_paths`, or `db_targets`
- Configure provider credentials or the global LLM provider cascade
- Change the taxonomy profile

This is the **supply-chain safety** model: a malicious repo's `.nah.yaml` can't weaken your protections.

You can explicitly opt out of this model by setting `trust_project_config: true`
in global config. Only use that for repositories whose `.nah.yaml` you already
trust, because project config can then loosen policies.

## Merge rules

When both configs exist, nah merges them with these rules:

| Field | Merge behavior |
|-------|---------------|
| `profile` | Global only |
| `trust_project_config` | Global only; when true, project config can loosen policy |
| `actions` | Tighten-only (project can only escalate strictness) |
| `classify` | Kept separate (global = Phase 1, project = Phase 3 lookup; project can only tighten overlaps unless trusted) |
| `sensitive_paths` | Tighten-only unless project config is trusted |
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
| `targets` | Global can override; project can only tighten unless trusted |
| `log` | Global only |
| `active_allow` | Global only |

## Quick reference — all config keys

| Key | Type | Scope | Docs |
|-----|------|-------|------|
| `profile` | `full` / `minimal` / `none` | global | [Profiles](profiles.md) |
| `trust_project_config` | bool | global | This page |
| `classify` | dict of type → prefix list | both* | [Custom taxonomy](../guides/custom-taxonomy.md) |
| `actions` | dict of type → policy | both | [Action types](actions.md) |
| `sensitive_paths_default` | `ask` / `block` | both* | [Sensitive paths](sensitive-paths.md) |
| `sensitive_paths` | dict of path → policy | both | [Sensitive paths](sensitive-paths.md) |
| `allow_paths` | dict of path → project list | global | [Sensitive paths](sensitive-paths.md) |
| `trusted_paths` | list of paths | global | [Sensitive paths](sensitive-paths.md) |
| `known_registries` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `exec_sinks` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `sensitive_basenames` | dict of name → policy | global | [Safety lists](safety-lists.md) |
| `decode_commands` | list or dict (add/remove) | global | [Safety lists](safety-lists.md) |
| `content_patterns` | dict (add/suppress) | both | [Content inspection](content.md) |
| `credential_patterns` | dict (add/suppress) | global | [Content inspection](content.md) |
| `llm` | dict (`mode`, providers, `eligible`, `context_chars`) | global | [LLM layer](llm.md) |
| `targets` | dict of target → overrides | both* | This page |
| `db_targets` | list of database/schema dicts | global | [Database targets](database.md) |
| `log` | dict (verbosity, etc.) | global | [CLI reference](../cli.md#nah-log) |
| `active_allow` | `true`, `false`, or list of tool names | global | [Install](../install.md#active_allow) |

*\* `classify` entries in global config are Phase 1 (checked first, can override built-in). Project entries are Phase 3: they can add new commands and can tighten overlapping built-in classifications, but cannot weaken them unless `trust_project_config: true` is set globally. `sensitive_paths_default` in project config can only tighten (ask → block) unless project config is trusted. Target-scoped project overrides follow the same tighten-only rule.*

## Target overrides

Use `targets.<target>` when a runtime needs different policy from the shared
default. Supported targets are `claude`, `bash`, and `zsh`; `openrouter` is a
provider setup target, not a guarded runtime.

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

Target overrides can set `actions`, `sensitive_paths_default`,
`sensitive_paths`, `content_patterns.policies`, and `llm.mode` /
`llm.eligible`. Shell-specific options live under `targets.bash.terminal` and
`targets.zsh.terminal`.

Bash and zsh default to LLM mode off even when global LLM mode is on. Enable
terminal LLM review only with an explicit target override such as
`targets.bash.llm.mode: on`.

Provider credentials and provider selection stay global-only. `nah install
openrouter` writes global config, stores `llm.openrouter.key_env`, and never
writes a raw API key.

## YAML format

Both config files use standard YAML. If nah detects comments in a file before a CLI write operation (`nah allow`, `nah classify`, etc.), it warns you that comments will be removed and asks for confirmation.

Optional dependency: `pip install "nah[config]"` installs `pyyaml`. The default
install keeps nah's core hook/classifier stdlib-only for users who want the
smallest supply-chain surface. Install the config extra when you want YAML config
files or commands that write config (`nah allow`, `nah deny`, `nah classify`,
`nah trust`). With pipx, use `pipx inject nah pyyaml`.
