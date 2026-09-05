# Agent instructions

## Built-in guard design

Build guards around a concrete loss or exposure that Nah can establish from
modeled evidence. State what the guard catches, which legitimate workflows it
interrupts, and what context Nah cannot determine.

### Factory defaults

Ship on when a human handoff is justified by proven broad loss of working
state, destruction of recovery paths, raw credential exposure, or bypassing
checks that prevent substantial loss.

Ship off when the same operation is routine legitimate work and its danger
depends on context Nah cannot establish. Whole-stack teardown, for example,
may be ordinary cleanup of a disposable environment.

Judge the interruption when the guard matches. Users who never invoke the
affected operation are not a reason to ship it off. Conversely, severity alone
does not justify default-on: examine realistic legitimate uses and recovery.

### Granularity

One guard should represent a protection a user can meaningfully choose.

Extend an existing guard when the new behavior protects against the same
kind of loss. Split only when a concrete workflow needs independent controls
or different defaults. Separate commands, providers, or internal effect codes
do not by themselves justify separate guards.

Prefer the fewest controls that preserve useful choices. Keep applicable
protections independent: matching one guard must not suppress another.

### Review

Before adding or widening a guard, explain:

- The consequential mistake it prevents.
- A realistic legitimate workflow it could interrupt.
- Why its scope and factory default fit those cases.
- Why an existing guard can or cannot own the behavior.

Keep the full guard inventory in the README accurate. Keep contributor
reasoning here; command behavior and options belong in help and product docs.

## Documentation scope

Keep documentation changes proportional. Edit the README or homepage only when
a change makes them inaccurate, and then make the smallest factual correction.
Do not expand surrounding copy or refresh demos and recordings unless requested.

## Keep the changelog curated

`CHANGELOG.md` is the public news feed on nahguard.ai, not a development log.
Add an entry only when an existing user might change how they use or upgrade
Nah, or a prospective user would care that the capability exists.

- Keep one concise `Unreleased` bullet per user outcome, with a bold label and
  plain technical summary. Fold related follow-up work into that bullet.
- Omit docs and copy edits, site polish, internal work, tests, and minor edge
  case or message fixes.
- Keep newest releases first and never rewrite shipped entries.
