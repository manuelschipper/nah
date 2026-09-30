# Prime Agent

## Install

```sh
nah hook prime-agent install
```

To deny explicit evaluation failures and bounded analysis refusals, install
with `--fail-closed`. Ordinary unknown or opaque calls still delegate.
`--fail-open` restores the default; flagless reinstall preserves a recognized
mode. Fail-closed wiring also blocks when its nah subprocess is missing, times
out, or returns invalid output. The guarantee still requires the extension
handler to run; disabled hooks, runtime process termination, and bypass remain
outside it.

Run `/reload` in Prime Agent. Remove only nah's extension with:

```sh
nah hook prime-agent uninstall
```

The installer writes one dependency-free extension at
`~/.prime/agent/extensions/nah.js`. If
`PRIME_AGENT_CODING_AGENT_DIR` selects an absolute or `~/` agent directory,
nah installs, inspects, removes, and protects the extension there instead.

## Behavior

The extension invokes nah without a shell before each tool executes. A
provenance-verified built-in `ipython` call with a nonblank string `code` field
uses the Python side of nah's bounded effect interpreter in a Prime Agent
kernel profile. The cell runs as plain Python, not IPython; `!cmd` and magics
fail to parse. An extension override named `ipython` stays opaque. The pinned
Prime CLI registers no other built-in tool. Every custom, SDK, or future tool
uses one Prime-specific opaque identity, including tools named `bash`, `Read`,
`Write`, or `Edit`, so a native-looking name cannot select Nah's unrelated tool schemas.

Current-cell constants, control flow, definitions, reviewed builtins, and
imports use normal Python semantics. Visible rebinding, mutation, or escape
removes affected ownership. Earlier hidden changes do not erase definite
current-cell evidence. Extra fields make coverage partial; missing or
non-string code stays opaque.

The tool-call event omits prior bindings, heap state, and kernel cwd. Imports
not re-established in the current cell and relative paths therefore stay
unknown; absolute paths remain actionable. nah does not execute the cell to
discover hidden state.

## Shell boundary

Prime Agent 0.9.6 (live-verified 2026-09-27) runs shell commands through the
`bash(command)` helper its kernel injects, which emits no hook event.

A direct `bash(<command>)` or `await bash(<command>)` call with one
positional argument is analyzed like `os.system`: a literal command reaches
the shell guards; a computed one stays partial. The name is the helper only if every
NFKC-normalized reference to `bash` calls it, and the cell has no star import,
no name or import (even aliased) of `globals`, `locals`, `vars`, `exec`,
`eval`, `compile`, `getattr`, `setattr`, `delattr`, `__import__`, `builtins`,
`__builtins__`, or `__main__`, no `__dict__`, `__globals__`,
`__getattribute__`, `__setattr__`, `__delattr__`, or frame-namespace
attribute, no three-argument `type()`, and no class with class keywords or a
base other than a class defined in the cell. Otherwise nah claims no shell
effect; aliased (`run = bash`) and keyword calls are not covered.

An earlier cell or imported module can rebind `bash` unseen, so a guarded
command may block without a shell. Coverage stays partial. Prime Agent's
`commandPrefix`, the kernel's cwd and environment, and changes to its
`PRIME_AGENT_BASH_*` variables are not in the hook input.

The package also exports Bash and edit tool factories, but the pinned CLI does
not register them as base tools. SDK `baseToolsOverride` can supply arbitrary
implementations and give them synthetic built-in provenance. Those tools remain
opaque even when their reported path resembles `<builtin:bash>`.

## Boundaries

Blocks stop the call. Every other call delegates to Prime Agent and any later
extension handlers. Earlier handlers may mutate input before nah sees it;
later handlers may mutate it after nah delegates, with no subsequent nah
decision. Parallel sibling calls are preflighted sequentially before allowed
siblings execute concurrently.

Prime Agent has no approval prompt behind this extension, so delegates normally
execute unless another extension blocks them. `--no-extensions` disables the
global hook. Nah's self-protection policy still applies to effects the admitted
cell analysis proves, but opaque tools and hidden kernel state do not produce
guessed file or shell effects. An operator can use `nah nap` from another
terminal.

A handler error natively blocks the tool, but the default nah wiring catches
adapter failure, delegates, and requests a UI warning when Prime Agent exposes
one. Disabled or unloaded extensions, trusted extensions that act directly,
and changes invisible to the tool-call event remain outside nah.

SDK runtimes using `baseToolsOverride` are outside this adapter's admitted CLI
contract.

This integration is best effort: runtime APIs and hook behavior can change.
After upgrades, verify the latest official upstream
[extension documentation](https://github.com/PrimeIntellect-ai/prime-agent/blob/main/packages/coding-agent/docs/extensions.md),
inspect the loaded hook, and test it before relying on nah.
