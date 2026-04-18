# /nah-status — Show Current nah Configuration

Display active nah rules, action type policies, and config file locations.

______________________________________________________________________

## Execution

Run these in sequence:

**1. Custom rules (your overrides from defaults):**

```bash
nah status
```

**2. All 23 action types with current effective policies:**

```bash
nah types
```

**3. Full merged config (global + project):**

```bash
nah config show
```

**4. Config file locations:**

```bash
nah config path
```

______________________________________________________________________

## Output Format

Present results as:

```
## nah status

### Custom rules
[nah status output — what you've overridden from defaults]

### Action type policies (23 types)
allow:    filesystem_read, git_safe, package_run, ...
context:  filesystem_write, filesystem_delete, network_outbound, ...
ask:      git_history_rewrite, lang_exec, process_signal, ...
block:    obfuscated, ...

### Config files
Global:   ~/.config/nah/config.yaml  [present / not found]
Project:  .nah.yaml  [present / not found]
```

If no custom rules exist, print:

```
No custom rules — running on defaults (profile: full).
```

______________________________________________________________________

## Notes

- To reset a custom rule: `nah forget <action_type>`
- Project `.nah.yaml` can only tighten policies — it cannot grant permissions the global config doesn't allow
- Run this before `/nah-allow` or `/nah-classify` to establish the baseline
