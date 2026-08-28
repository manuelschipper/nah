# Corpus triage ledger

Every corpus case is in exactly one implementation state:

- **green** — passes against the current pipeline (the default; not listed here).
- **expected-fail** — not implemented yet; listed below with the phase that owns it.

Design-level changes also go to the relevant public documentation topic and
`CHANGELOG.md`.

CI gate: zero unexpected failures; the expected-fail list only shrinks.

## Expected-fail

None.
