# Official Marketplace Submission Notes

These notes are for submitting nah to Anthropic's official Claude Code plugin
marketplace. Do not claim official marketplace availability until Anthropic has
approved and listed the plugin.

## Submission URLs

- Claude.ai: https://claude.ai/settings/plugins/submit
- Console: https://platform.claude.com/plugins/submit

## Plugin Identity

- Name: `nah`
- Description: Context-aware safety guard for Claude Code.
- Category: Security
- Repository: https://github.com/manuelschipper/nah
- Privacy policy: https://schipper.ai/nah/privacy/
- License: MIT
- Author: Manuel Schipper

## Source To Submit

Preferred reviewer source is the generated plugin artifact, not the source
template:

- Repository: `manuelschipper/nah`
- Branch fallback: `claude-marketplace`
- Immutable release tag format: `claude-plugin-vX.Y.Z`
- Plugin path inside that ref: `plugins/nah`

The source template lives at `plugins/claude-code/nah` on `main`, but the
generated artifact adds the vendored stdlib-only runtime under `lib/nah` and
injects the release version into `.claude-plugin/plugin.json`.

## What nah Does

nah runs before Claude Code tool calls and classifies the requested operation
with deterministic local rules. It guards Bash, Read, Write, Edit, MultiEdit,
NotebookEdit, Glob, Grep, and MCP tools.

Typical decisions:

- Allow safe operations such as `git status` or project-local reads.
- Ask for ambiguous operations such as force pushes or sensitive file access.
- Deny deterministic threats such as decode-to-shell or remote-code pipes.

## Runtime And Commands

The plugin registers PreToolUse hooks and a SessionStart diagnostic hook. Hook
commands run scripts bundled in the plugin directory via
`${CLAUDE_PLUGIN_ROOT}`.

The plugin requires Python 3.10 or newer on `PATH`. If Python is missing, the
hook fails closed to an `ask` decision rather than allowing silently.

The plugin does not run package managers, does not bootstrap dependencies, and
does not fetch code at enable time.

## Data Handling

The deterministic guard runs locally and does not send tool input off-device by
default.

nah supports an optional LLM refinement layer only when the user configures an
LLM provider in nah config. If enabled, requests go to the user-selected
provider and model. nah applies best-effort redaction for known secret patterns
in transcript and write/edit content before prompt enrichment, but users should
still treat external LLM providers as receiving security-sensitive context. The
plugin itself does not configure an LLM provider or enable network calls.

Decision logs are written to the user's local nah config/log directory.

## User Control

Plugin mode is opt-in through Claude Code's plugin manager. Users can disable
or uninstall the plugin with Claude Code plugin commands. Users who previously
installed direct nah hooks can run `nah uninstall` before enabling the plugin
to avoid duplicate hook execution.

## Validation Before Submission

Run from the repository root before submitting a release artifact:

```bash
pytest tests/test_plugin_distribution.py tests/test_release_automation.py
python3 scripts/build_claude_plugin.py --marketplace-out dist/claude-marketplace
python3 scripts/build_claude_plugin.py --check --marketplace-out dist/claude-marketplace
claude plugin validate dist/claude-marketplace
```

Inspect generated metadata:

```bash
python3 -m json.tool dist/claude-marketplace/plugins/nah/.claude-plugin/plugin.json
python3 -m json.tool dist/claude-marketplace/.claude-plugin/marketplace.json
```

## After Approval

After Anthropic lists `nah` in `claude-plugins-official`, add the CLI plugin
hint:

```text
<claude-code-hint v="1" type="plugin" value="nah@claude-plugins-official" />
```

Gate hint emission on `CLAUDECODE=1` and write it to stderr on its own line.
