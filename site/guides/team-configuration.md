# Using nah as a team

nah works out of the box, but teams usually want a small amount of shared
policy per repo.

## Where settings should live

nah has two config files because teams need two kinds of rules.

Use the repo config for rules everyone on the project should share:

```text
my-app/
  .nah.yaml
```

Use your personal config for trust decisions that are specific to your machine:

```text
~/.config/nah/config.yaml
```

A good rule of thumb:

- Put project safety rules in `.nah.yaml`.
- Put your own trusted paths, company registries, database targets, and LLM
  provider setup in global config.
- Use presets when you want to temporarily run stricter or more autonomous
  sessions.

## Add shared project rules

Commit a `.nah.yaml` file at the repo root:

```yaml
# .nah.yaml
actions:
  git_history_rewrite: block
  git_remote_write: ask
  db_exec: block
  network_write: ask
  package_install: ask

sensitive_paths:
  .env: block
  .env.production: block
  terraform.tfvars: block
```

These rules apply to everyone who uses nah in the repo.

By default, repo config is only allowed to make policy stricter. That means a
malicious dependency or cloned repo cannot silently weaken your local
protection.

For example, this is accepted:

```yaml
actions:
  git_remote_write: block
```

But this kind of repo-owned relaxation is ignored unless you explicitly trust
the repo:

```yaml
actions:
  git_remote_write: allow
```

## Trust a repo after reviewing it

Some teams want the repo to define project-specific commands.

For example:

```yaml
# .nah.yaml
classify:
  db_exec:
    - "pnpm db:migrate"
  package_run:
    - "pnpm test"
  network_write:
    - "pnpm deploy"
```

Those command mappings only become active after you trust the project.

Run this from the repo root:

```bash
nah trust-project
```

Or pass a path explicitly:

```bash
nah trust-project /path/to/my-app
```

This records the exact project root in your global config:

```yaml
trusted_project_configs:
  - /path/to/my-app
```

Trust is exact. Trusting `/work` does not automatically trust `/work/my-app`.

Use `nah trust-project` when:

- You reviewed the repo's `.nah.yaml`.
- You want project-specific command classifications to apply.
- You are comfortable letting that repo loosen policy for that repo only.

Undo it with:

```bash
nah untrust-project /path/to/my-app
```

## Keep personal trust out of the repo

Do not commit machine-specific trust settings to `.nah.yaml`.

Put these in `~/.config/nah/config.yaml` instead:

```yaml
known_registries:
  - artifacts.company.com

trusted_paths:
  - ~/work/shared-scratch

db_targets:
  - host: localhost
    database: dev_app
    schemas:
      - public

llm:
  mode: on
  providers: [openrouter]
  openrouter:
    key_env: OPENROUTER_API_KEY
```

These settings depend on your machine, credentials, network, or organization.
They should not be inherited just because someone cloned a repo.

## Tune different runtimes

You can make Claude Code, Codex, and your terminal behave differently.

```yaml
# ~/.config/nah/config.yaml
targets:
  claude:
    actions:
      git_remote_write: ask

  codex:
    actions:
      network_outbound: ask
    ask_fallback: block

  bash:
    llm:
      mode: off
```

This is useful when one runtime is interactive and another is running
headless.

## Use presets for temporary modes

Presets are named config overlays in your global config.

```yaml
# ~/.config/nah/config.yaml
presets:
  strict:
    actions:
      network_outbound: ask
      lang_exec: ask
      unknown: ask

  sandboxed-build-agent:
    targets:
      codex:
        ask_fallback: block
      claude:
        ask_fallback: block
    actions:
      git_history_rewrite: block
      git_remote_write: block
      db_exec: block
      unknown: block
```

Run with a preset:

```bash
nah run claude --preset strict
nah run codex --preset sandboxed-build-agent
nah run codex --preset sandboxed-build-agent exec "work on the next issue"
```

Use presets when you want a mode for a session, not a permanent repo rule.
For a full unattended setup, see
[Running unsupervised agents](unsupervised-agents.md).

## Check what nah will use

Before rolling this out to a team, inspect the effective config:

```bash
nah config path
nah config show
nah config show --preset strict
```

Test individual commands:

```bash
nah test "git push --force"
nah test "pnpm db:migrate"
nah test "cat .env"
```

Inspect what happened during real sessions:

```bash
nah log
nah log --asks
nah log --blocks
```

## Suggested rollout

Start with a small `.nah.yaml`:

```yaml
actions:
  git_history_rewrite: block
  db_exec: ask
  network_write: ask

sensitive_paths:
  .env: ask
  .env.production: block
```

Then add project-specific command mappings once the team sees repeated asks.

For mature repos, review the `.nah.yaml`, run:

```bash
nah trust-project
```

Then move stable project commands into the repo config.

Keep broad trust decisions global. Keep repo rules narrow, readable, and easy
to review.
