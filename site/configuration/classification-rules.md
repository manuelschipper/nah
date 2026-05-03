# Classification Rules

Use classification rules when nah should recognize project-specific commands or
when your machine needs a personal override for a command prefix.

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

Each entry is a prefix. `"docker rm"` matches `docker rm my-container`,
`docker rm -f abc`, and similar commands.

**CLI shortcut:**

```bash
nah classify "docker rm" container_destructive
nah classify "terraform destroy" filesystem_delete
```

## Creating custom action types

You can use any string as an action type. It does not have to be one of the
built-in types:

```bash
nah classify "terraform" infra_modify
nah deny infra_modify
```

nah asks for confirmation because `infra_modify` is not a built-in type.
Custom types default to `ask` policy.

## Three-phase lookup

Global `classify:` entries are checked before built-in classifiers. They are
personal or organization-level overrides, so they can intentionally shadow
finer-grained built-in behavior.

```yaml
# Global config: this overrides the built-in curl flag classifier
classify:
  network_outbound:
    - curl    # all curl commands become network_outbound, even curl -X POST
```

!!! warning
    A single-token global entry like `curl` will shadow the built-in flag classifier that distinguishes `curl` (read) from `curl -X POST` (write). Use `nah status` to see shadow warnings.

Built-in classifiers and built-in prefix tables run after global overrides.
Project `.nah.yaml` entries run later: they can add new commands and tighten
overlapping built-in classifications, but cannot weaken built-in behavior unless
global config explicitly sets `trust_project_config: true`.

For the full lookup order, see
[How it works](../how-it-works.md#4-classify-three-phase-lookup).

## Global vs project classify

| Aspect | Global | Project |
|--------|--------|---------|
| **Phase** | 1 (first) | 3 (last) |
| **Can override built-in** | Yes | Only to tighten, unless `trust_project_config: true` |
| **Can override built-in classifier functions** | Yes | No |
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

Project config can tighten `actions` (for example, escalate `ask` to `block`)
but cannot relax them unless global config explicitly sets
`trust_project_config: true`.

## Checking your rules

```bash
# See all custom rules with shadow warnings
nah status

# See all types with override annotations
nah types

# Test a specific command
nah test "docker rm my-container"
```

`nah status` shows shadow warnings when your global classify entries override finer-grained built-in rules or classifier functions. Use `nah forget <prefix>` to remove a shadow.
