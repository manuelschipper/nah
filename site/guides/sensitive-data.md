# Working with sensitive data

nah protects obvious sensitive access immediately. Taint tracking and session
provenance handle the harder cases: what happens after sensitive data was read,
and what happens after the agent wrote code or files.

Start in audit mode. It records what policy would have applied without changing
runtime decisions.

## Start with immediate protection

nah already checks sensitive paths, written content, and dangerous command
composition before a tool call runs.

For most teams, the first shared project rule is small:

```yaml
# .nah.yaml
sensitive_paths:
  .env: ask
  .env.production: block
  terraform.tfvars: block

actions:
  git_history_rewrite: block
  db_write: ask
  network_write: ask
```

This catches direct reads and writes. For example:

```bash
nah test "cat .env"
nah test "git push --force"
nah test --tool Read --path .env.production
```

Use [Sensitive paths](../configuration/sensitive-paths.md) for the full path
configuration reference, and [Content inspection](../configuration/content.md)
for write-content patterns.

## Enable audit mode

Taint and provenance are session-level layers. Enable them in your personal
global config first:

```yaml
# ~/.config/nah/config.yaml
taint:
  mode: audit

provenance:
  mode: audit
```

Then run normal guarded sessions:

```bash
nah run claude
nah run codex
```

Inspect what nah observed:

```bash
nah config show
nah log
nah log --asks
nah log --blocks
```

Audit mode is the right first step because it shows the real workflow and the
policies that would have applied before you add friction.

## Track sensitive reads with taint

Taint tracking remembers successful reads from sensitive sources. Later, if the
same session executes code, contacts a network, writes to a database, pushes to
git, opens browser state, or uses another boundary action, nah can add review.

Add labels for the data classes you actually care about:

```yaml
# ~/.config/nah/config.yaml
taint:
  mode: audit
  sources:
    - paths: [".env*", "secrets/**", "config/prod/**"]
      labels: [secret, prod_config]
    - paths: ["customers/**/*.csv"]
      labels: [customer_data]
  policies:
    default:
      activation: audit
      boundary: ask
      unknown: ask
    secret:
      activation: audit
      boundary: ask
      git_remote_write: block
    customer_data:
      activation: ask
      boundary: block
      unknown: ask
```

Use labels that match your operational language. `secret`, `prod_config`, and
`customer_data` are easier to review in logs than one generic sensitive bucket.

A blocked source access does not taint the session. nah only tracks sources
that were allowed and, for runtimes with post-tool hooks, confirmed as
executed.

See [Taint tracking](../configuration/taint-tracking.md) for propagation,
category, and policy details.

## Review agent-written code with provenance

Session provenance tracks files and repo state written during the guarded run.
It is useful for agent workflows where the risky moment is not the write, but
the later execution or externalization of what the agent wrote.

Start with context review for activation and selected boundary actions:

```yaml
# ~/.config/nah/config.yaml
provenance:
  mode: audit
  policies:
    activation: context
    boundary: ask
    lang_exec: context
    package_run: context
    git_remote_write: context
    git_history_rewrite: block
    network_write: block
    db_write: block
```

With that policy, a guarded run can write files normally in audit mode. When it
later tries to run the generated script, run a package command in the changed
repo, push to git, or perform a write-shaped network action, nah records the
provenance policy that would have applied.

`context` does not mean automatic allow. It means nah builds a bounded
same-session delta for review when provenance is enforcing. If the context is
incomplete, the reviewer is unavailable, or the reviewer is uncertain, the
decision remains a human review.

See [Session provenance](../configuration/provenance.md) for review limits,
LLM behavior, and runtime details.

## Choose activation and boundary policy

Use activation policy for actions that execute code or agent behavior inside
the current environment. Common examples are language execution, package
scripts, and local agent execution.

Use boundary policy for actions where data, code, state, or effects leave the
current controlled environment. Common examples are network writes, git remote
writes, database writes, service changes, containers, browser state, and remote
agent execution.

Good starting defaults:

```yaml
taint:
  mode: audit
  policies:
    default:
      activation: audit
      boundary: ask
      unknown: ask

provenance:
  mode: audit
  policies:
    activation: context
    boundary: ask
```

Then tighten specific labels or action types when the logs show a real risk:

```yaml
taint:
  policies:
    customer_data:
      boundary: block

provenance:
  policies:
    network_write: block
    db_write: block
```

## Keep trust in the right file

Use project config for rules everyone on the repo should share:

```yaml
# .nah.yaml
sensitive_paths:
  .env.production: block

actions:
  git_history_rewrite: block
  db_write: ask
```

Use global config for machine-specific trust and richer data-flow policy:

```yaml
# ~/.config/nah/config.yaml
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

taint:
  mode: audit

provenance:
  mode: audit
```

Project `.nah.yaml` files can tighten policy by default. Do not put personal
trusted paths, provider keys, registries, or local database targets in the repo.

If you want a repo to define richer project-specific policy, review it first
and then trust the project:

```bash
nah trust-project
```

See [Using nah as a team](team-configuration.md) for the full project vs
global config workflow.

## Move from audit to enforce

After a few real sessions, inspect the log:

```bash
nah log --asks
nah log --blocks
nah log --json
```

Move only the workflows you understand from audit mode to enforce mode:

```yaml
taint:
  mode: enforce
  policies:
    default:
      activation: audit
      boundary: ask
      unknown: ask
    customer_data:
      activation: ask
      boundary: block

provenance:
  mode: enforce
  policies:
    activation: context
    boundary: ask
    network_write: block
    db_write: block
```

For unattended agents, set an ask fallback so unresolved reviews fail closed:

```yaml
targets:
  codex:
    ask_fallback: block
  claude:
    ask_fallback: block
```

Use presets when you want a temporary stricter mode instead of a permanent
global default:

```yaml
presets:
  sensitive-work:
    taint:
      mode: enforce
    provenance:
      mode: enforce
    targets:
      codex:
        ask_fallback: block
```

Run with the preset:

```bash
nah run codex --preset sensitive-work
nah run claude --preset sensitive-work
```

## Verify the rollout

Check the effective config:

```bash
nah config path
nah config show
nah config show --preset sensitive-work
```

Run a few dry-run classifications for immediate policy:

```bash
nah test "cat .env"
nah test "git push origin main"
nah test --tool Read --path .env.production
```

Then verify session-level behavior from real guarded sessions:

```bash
nah log
nah log --asks
nah log --blocks
nah log --llm
```

For teams, start with audit mode and a small `.nah.yaml`. Add labels and
enforcement only after the log shows repeated, understandable patterns.

## Limitations

Taint tracking is not byte-level data-flow analysis. It records session labels,
target identities, propagation, and later sink actions.

Session provenance is not a proof that generated code is safe. It reviews the
bounded same-session delta before later activation or boundary actions.

Terminal Guard taint is audit-only in v1. Codex enforcement depends on the
local interactive hook surface. Claude Code and Codex both rely on the runtime
events they expose to nah.

Keep normal least-privilege practices in place. nah reduces accidental and
agent-driven unsafe flows; it does not replace secrets hygiene, scoped
credentials, test databases, or review of production deploy paths.
