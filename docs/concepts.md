# Core concepts

## Effects and coverage

nah lowers calls into typed invocation, filesystem, Git, network, and
system-state effects. Observation resolves cwd, roots, paths, and environment.

Coverage reports only what the analyzer established. `full` means every
reported domain was fully modeled with no boundary left open. Unmodeled
programs, unresolved arguments, code, or fields, and environment-run code such
as Git hooks or package scripts make it `partial`.

Bash pipelines, control flow, subshells, and redirects become stages and
data-flow edges. Unresolved shell state makes coverage partial.

The engine analyzes visible shell, PowerShell, cmd, and language source without
running it. Exact child commands in source become nested calls. Unmodeled
dialects or language APIs and engine limits leave coverage partial rather than
inventing effects.

## Verdicts and failures

- `block` — an active guard or structural self-protection found definite danger.
- `delegate` — nothing blocked; the runtime keeps control.

Evaluation failure is diagnostic, not a third verdict. Nesting-limit refusals
block by default. For other failures, evidence suggesting an enabled guard
can block a failed analysis. `--fail-closed`
blocks all explicit failures/refusals, not ordinary
uncertainty. See `nah docs security`.

If guards never ran, any `.env` read can block on the error path, even one used
for counting, copying or Compose configuration. A late deadline preserves
completed guard exemptions; work exhaustion checks only the unfinished guards.
With no plan, a small screen covers plain-word `rm`, `cat`, curl file uploads,
and native `Read`, not quoting, shell syntax, wrappers or source files. Other
failures delegate with a `nah why <ID>` hint; rule disables and naps apply.

nah never approves. Delegation returns control to the runtime's permission or
execution behavior; nah is neither an approval UI nor a sandbox.

## Guards

Nine built-in guards, each named for what it protects (`work`, `machine`,
`secrets`, ...), hold rules. A rule blocks a narrow danger such as remote
content flowing into execution, a hard reset, or a private-key read. Each guard
is off, core, or strict, and `self` is always on. Rules compose by union: any
may block, matching one never suppresses another, and none may approve.

Definite evidence may block a partial stream; healthy uncertainty delegates.

Run `nah docs guards` for the catalog and tested examples.

## Save then run

Where nah can save (`nah docs runtimes`), `work` at core does not block a call
that would lose project work: it snapshots what it would lose, lets it run,
and reports the snapshot ID and `nah undo <id>`, in some runtimes only to the
user. Six rules save:

- `work/changes-discard`: hard resets, and checkouts or restores over edits.
- `work/untracked-clean`: forced `git clean`.
- `work/stash-drop`: stash drops and clears.
- `work/branch-delete`: local branch, tag, and ref deletes.
- `work/history-rewrite`: rewrites whose replaced commits no reflog or
  backup keeps.
- `work/files-delete`: recursive deletes inside the project.

A call Git shows can lose nothing runs at core without a save: a checkout of
unchanged files, a merged branch's delete, a rebase a reflog keeps, or a
delete Git can restore exactly. What nah cannot establish counts as a possible
loss.

nah blocks instead, saying why, when the save fails or times out, or
when it cannot save the call: it would lose a secret file, ignored files over
1 MB each or 20 MB in all, or a nested repository or submodule; it exceeds the
save budget; or the call also runs a step nah cannot follow, such as
`sudo`, `eval`, or a build or test, or changes the project in another step.
At strict nothing is saved, and a call that could lose work blocks. Where the
runtime cannot save, `work` at core blocks only what 1.x blocked.

`nah snapshots` lists the project's snapshots, newest first. `nah undo <id>`
restores a snapshot's files, staged state, and deleted refs and stash entries
in place, and a rewrite's old commits under `refs/nah/<id>/`. It first saves
what it replaces, so an undo can be undone, and leaves each path edited since,
naming it. `--into DIR` recovers a snapshot of files into an empty folder
instead; one of commits (a stash drop, ref delete, or rewrite) restores only
in place. Undo leaves the current branch and commit in place. Snapshots live
under `~/.nah/`, never in the project's repository, and expire after 14 days,
oldest first past 2 GB per project; the operator's `nah snapshots prune`
removes them sooner. Agents may list and undo.

## Session memory

Where it works (`nah docs runtimes`), nah remembers what earlier calls in the
session wrote, fetched, and labelled. Each mechanism blocks under the rule
that owns the loss, so settings, overrides, and naps apply.

1. Content a rule flags when written blocks under that rule when it later
   reaches an interpreter by any route.
2. A pending launch blocks flagged content written where it runs. A crontab
   entry or launch agent also blocks any content nah cannot read; a launch in
   the session, content no one has read, such as a download or a decode. A
   launch left running in the background waits only while a process that
   names its file runs.
3. A file secret bytes flowed into, and files derived from it, are labelled
   secret: reading it back blocks under `secrets/env-files-read`, uploading,
   staging, or committing it under `exfiltration/secret-upload`, and
   snapshots leave it out.
4. At strict, running code fetched this session, such as a download or a
   clone, blocks under `untrusted-code/remote-script-run`.
5. Where nah saves, the rolling copy keeps the last copy of uncommitted files
   a call deletes.

Once the post-call hook reports, a denied call or failed file tool stops
counting; a failed shell command keeps only what the disk shows it did, such
as a written file or a launch still running.
`nah session [ID]` prints a session's ledger, or the latest ledger without an
ID.

Unsupported: session memory across `--fork-session`. A forked Claude Code
session starts with empty memory, since Claude Code's hooks do not name the
session it came from (`nah docs runtime-claude`).

## Self-protection and naps

Settings are per user; nothing in a repository changes what nah enforces. nah
blocks understood intercepted attempts to change its own settings or disable
active wiring.

`nah nap` starts a 10-minute, user-global maintenance window: plain nap pauses
self-protection; `nah nap all` pauses every non-permanent layer; `nah nap
<guard|guard/rule>...` pauses only those. Nap-state protection remains. See `nah docs configuration` and `nah docs security`.

## Audit records

Live decisions attempt a redacted audit append; failure does not change the
verdict. Records name the runtime (`unknown` for `nah decide`). `nah why <id>`
explains one; `nah log` lists recent decisions, `--blocked` lists blocks, and
`--json` emits JSON Lines.
