# Start

nah is a guard that sits in your coding agent's hook path and reads tool calls
before they run. It blocks the calls it can prove are disasters and leaves
everything else to your runtime.

nah must be installed in the same execution environment as the coding agent
or agent gateway whose tool calls it evaluates.

nah runs on Windows, macOS, and Linux. Runtime integration support varies; see
`nah docs runtimes` for the qualified Windows matrix.

## Install

```sh
curl -fsSL https://nahguard.ai/install | sh
nah docs
```

## Inspect guards without installing a hook

`nah test` runs the real decision pipeline without executing the command:

```sh
nah test "git status"
nah test "git reset --hard"
nah guards
```

A completed decision has two verdicts. A `block` names the guard that fired. A
`delegate` leaves the choice to the agent runtime's normal approval or sandbox
path. An evaluation failure does not block by itself; other guards still
decide when evaluation can continue. Matching active custom guards run even
though the tested command does not. nah never approves a call.

## Connect one coding agent

Choose a supported runtime:

```sh
nah docs runtimes
nah hook codex install
nah hook codex status
nah docs runtime-codex
```

Restart or reload the runtime and complete any runtime-owned trust step. Hook
loading is not something nah can force, so inspect the active integration
using the runtime's own interface after installation.

Current installers create user-scoped wiring. While loaded, nah blocks
recognized in-session attempts to alter or bypass it, but the installation is
not tamper-proof against the same operating-system user or changes outside
intercepted tool calls. Read `nah docs threat-model` for the full boundary.

## Understand a decision

Every live decision receives an id. When its redacted audit record is
persisted, inspect it with:

```sh
nah log
nah why <id>
```

## Configure or extend

- `nah docs configuration` explains built-in guards and project trust.
- `nah docs extending` builds a custom guard.
- `nah docs security` states the enforcement boundaries.
