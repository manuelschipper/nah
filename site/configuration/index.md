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

**Project config** can only **tighten** security. It can:

- Add classify entries (commands → action types)
- Escalate action policies (e.g., `git_write: ask`)
- Tighten content pattern policies (ask → block)

It **cannot**:

- Relax any policy (lowering strictness is rejected)
- Modify safety lists (`known_registries`, `exec_sinks`, etc.)
- Set `trusted_paths`, `allow_paths`, or `db_targets`
- Configure the LLM layer
- Change the taxonomy profile

This is the **supply-chain safety** model: a malicious repo's `.nah.yaml` can't weaken your protections.

## Merge rules

When both configs exist, nah merges them with these rules:

| Field | Merge behavior |
|-------|---------------|
| `profile` | Global only |
| `actions` | Tighten-only (project can only escalate strictness) |
| `classify` | Kept separate (global = Phase 1, project = Phase 3 lookup) |
| `sensitive_paths` | Tighten-only |
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
| `log` | Global only |
| `active_allow` | Global only |

## Quick reference — all config keys

| Key | Type | Scope | Docs |
|-----|------|-------|------|
| `profile` | `full` / `minimal` / `none` | global | [Profiles](profiles.md) |
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
| `llm` | dict (providers, `max_decision`, `eligible`, `context_chars`) | global | [LLM layer](llm.md) |
| `db_targets` | list of database/schema dicts | global | [Database targets](database.md) |
| `log` | dict (verbosity, etc.) | global | [CLI reference](../cli.md#nah-log) |
| `active_allow` | `true`, `false`, or list of tool names | global | [Install](../install.md#active_allow) |

*\* `classify` entries in global config are Phase 1 (checked first, can override built-in). Project entries are Phase 3 (checked after built-in, can only add new commands). `sensitive_paths_default` in project config can only tighten (ask → block).*

## YAML format

Both config files use standard YAML. If nah detects comments in a file before a CLI write operation (`nah allow`, `nah classify`, etc.), it warns you that comments will be removed and asks for confirmation.

Optional dependency: `pip install nah[config]` installs `pyyaml`. Without it, config files are ignored (a stderr warning is printed).
