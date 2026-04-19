# nah Claude Code Plugin

This is a local Claude Code plugin scaffold for nah. It is not a marketplace
release.

Build the local artifact from the repository root:

```bash
python3 scripts/build_claude_plugin.py
```

The generated plugin lives at `dist/claude-plugin/nah` and bundles the `nah`
package from `src/nah` into `lib/nah`. The hook uses that bundled stdlib-only
runtime directly. It does not install PyYAML, pip packages, or any network
bootstrap code.

Use Claude Code's local plugin install flow against the generated
`dist/claude-plugin/nah` directory when testing. If you already have direct
`nah install` hooks in Claude settings, run `nah uninstall` before enabling the
plugin to avoid mixed direct/plugin behavior.
