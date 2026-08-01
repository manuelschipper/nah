# GitHub Copilot

## Install

```text
nah hook copilot install
nah hook copilot status
```

Restart Copilot CLI or reload VS Code after installation. Remove only nah's
owned file with:

```text
nah hook copilot uninstall
```

## What nah installs

nah writes `~/.copilot/hooks/nah.json`. The file registers one lower-camel
`preToolUse` command hook that invokes `nah hook copilot run`. Copilot CLI
loads that format directly, and current VS Code agent hooks load the same user
hook directory and compatible format. Existing files beside `nah.json` are
untouched. A pre-existing unowned `nah.json`, symlinked hook path, or custom
`COPILOT_HOME` is rejected.

Blocks return branded `nah - ...` feedback. On VS Code, the same guidance is
also added to the model context because that surface documents the decision
reason as user-visible. Every other call delegates to Copilot's normal
permission flow. The adapter lowers documented shell, read, create, replace,
grep, and glob tools. Unknown and extension-contributed tools remain opaque
and delegate.

## Boundaries

- This integration covers local Copilot CLI and the local VS Code Copilot
  agent. Copilot cloud agent supports repository hooks, but it runs in an
  ephemeral remote sandbox without this local user installation; nah does not
  install a repository hook.
- Copilot CLI command-hook crashes and nonzero exits fail closed, but hook
  timeouts always fail open into Copilot's permission flow. This is runtime
  behavior; nah cannot strengthen it. nah itself delegates evaluation failure:
  CLI receives a progress message and VS Code receives a `systemMessage`.
- Copilot's `--yolo` and `--allow-all` modes remove its normal permission
  prompts but do not document disabling hooks. A nah block still applies if
  the hook runs; delegated calls may execute immediately. `disableAllHooks`
  can disable this non-policy user hook, while organization policy hooks are
  unaffected.
- VS Code agent hooks are currently preview functionality. Loading,
  organization policy, workspace trust, user settings, runtime updates, and
  tools that do not emit `PreToolUse` remain runtime-owned.
- UI changes and settings that prevent the hook from loading remain Copilot
  or user policy.
- Copilot plugins and extensions can contribute executable hooks. Unrelated
  plugin and extension installation remains runtime-owned; nah does not protect
  those directories or commands.
While active, this adapter blocks visible lifecycle commands, mutations to its
`nah.json` or user `settings.json`, explicit plugin removal or disable commands
naming nah, and child launches with an alternate `COPILOT_HOME`. Other plugin
and project settings remain user-owned. The agent is told not to retry; an
operator can use `nah nap` from another terminal.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream documentation linked below,
inspect the loaded hook, and test it before relying on nah. See GitHub's
[Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
and VS Code's
[agent hooks documentation](https://code.visualstudio.com/docs/agent-customization/hooks).
