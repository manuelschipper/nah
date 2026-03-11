# Custom Taxonomy

nah's classification is fully customizable. You can add commands to existing types, create new types, and control how the three-phase lookup works.

## Adding commands to existing types

Use the `classify` config key to map command prefixes to action types:

```yaml
# ~/.config/nah/config.yaml
classify:
  container_destructive:
    - "docker rm"
    - "docker system prune"
    - "kubectl delete"
  filesystem_delete:
    - "terraform destroy"
  db_write:
    - "psql -c DROP"
    - "mysql -e DROP"
```

Each entry is a **prefix** — `"docker rm"` matches `docker rm my-container`, `docker rm -f abc`, etc.

**CLI shortcut:**

```bash
nah classify "docker rm" container_destructive
nah classify "terraform destroy" filesystem_delete
```

## Creating custom action types

You can use any string as an action type — it doesn't have to be one of the 20 built-in types:

```bash
nah classify "terraform" infra_modify
nah deny infra_modify
```

nah will ask for confirmation since `infra_modify` is not a built-in type. Custom types default to `ask` policy.

## Three-phase lookup

Understanding the lookup order is key to effective customization:

### Phase 1: Global config (highest priority)

Your `classify:` entries in `~/.config/nah/config.yaml` are checked first. They override everything — built-in tables and flag classifiers.

```yaml
# Global config: this overrides the built-in curl flag classifier
classify:
  network_outbound:
    - curl    # all curl commands → network_outbound, even curl -X POST
```

!!! warning
    A single-token global entry like `curl` will shadow the built-in flag classifier that distinguishes `curl` (read) from `curl -X POST` (write). Use `nah status` to see shadow warnings.

### Phase 2: Flag classifiers (built-in)

Nine commands have flag-dependent classification (find, sed, awk, tar, git, curl, wget, httpie, global_install). These run after global config but before the built-in prefix tables.

Skipped entirely when `profile: none`.

### Phase 3: Built-in + Project

Built-in prefix tables (from the selected profile) are checked, followed by project `.nah.yaml` entries.

Project entries are Phase 3 — they can add new commands but cannot override built-in classification for the same prefix.

## Global vs project classify

| Aspect | Global | Project |
|--------|--------|---------|
| **Phase** | 1 (first) | 3 (last) |
| **Can override built-in** | Yes | No |
| **Can override flag classifiers** | Yes | No |
| **Use case** | Personal preferences, org standards | Project-specific commands |
| **Security** | Trusted (your machine) | Untrusted (supply-chain risk) |

## Example: project-specific rules

```yaml
# .nah.yaml (in project root)
classify:
  db_write:
    - "psql -c ALTER"
    - "psql -c DROP"
  filesystem_delete:
    - "make clean"

actions:
  db_write: block    # tighten: block all DB writes in this project
```

Project config can tighten `actions` (escalate `ask` → `block`) but cannot relax them.

## Checking your rules

```bash
# See all custom rules with shadow warnings
nah status

# See all types with override annotations
nah types

# Test a specific command
nah test "docker rm my-container"
```

`nah status` shows shadow warnings when your global classify entries override finer-grained built-in rules or flag classifiers. Use `nah forget <prefix>` to remove a shadow.
