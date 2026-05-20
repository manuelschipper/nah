# Presets

Presets replaced the old taxonomy-profile setting.

nah now always loads the full built-in taxonomy, classifiers, safety lists,
sensitive path checks, and content scanners. Older config keys like
`profile: full`, `profile: minimal`, and `profile: none` are accepted for
compatibility, but ignored. In particular, `profile: none` no longer disables
built-in safety checks.

Use presets when you want a named policy bundle for a workflow:

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
    trusted_paths:
      - ~/work/scratch
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
nah config presets
nah config presets strict
nah config show --preset strict
```

Merge rules are intentionally simple:

- Dicts deep-merge.
- Scalars replace.
- Lists replace.

Presets are global-only in this version. Project `.nah.yaml` files cannot
define or select presets. Unknown selected preset names fail closed.
