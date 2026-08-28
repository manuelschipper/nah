# Agent instructions

## Documentation scope

Keep documentation changes proportional. Edit the README or homepage only when
a change makes them inaccurate, and then make the smallest factual correction.
Do not expand surrounding copy or refresh demos and recordings unless requested.

## Keep the changelog current

`CHANGELOG.md` doubles as the news feed on nahguard.ai, so it is part of the
product. Whenever you land a user-visible change — a guard added or changed,
CLI or TUI behavior, a runtime adapter, a docs topic, a changed decision or
message — add its entry in the same change.

```markdown
## nah 1.1.0 — Aug 12, 2026

- **Kiro adapter** — `nah hook kiro install` wires Kiro's native hook path.
- **`fs-home` covers `find ~ -delete`** — the home guard now blocks
  find-based deletion selecting the home root.
```

Rules:

- Newest release first. Work that has not shipped collects under an
  `## Unreleased` heading at the top; cutting a release renames that heading
  to `## nah X.Y.Z — Mon DD, YYYY`.
- One bullet per change: a bold label naming the change, then a plain
  description of what changed and why a user would care. Technical voice, no
  marketing language.
- User-visible changes only. Internal refactors stay out unless they change a
  verdict, a message, or performance.
- Do not rewrite entries for releases that have shipped.
