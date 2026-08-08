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
uses the shared Python effect frontend in a persistent-kernel profile. An
extension override named `ipython` stays opaque. The pinned Prime CLI registers
no other built-in tool. Every custom, SDK, or future tool uses one Prime-specific
opaque identity, including tools named `bash`, `Read`, `Write`, or `Edit`, so a
native-looking name cannot select Nah's unrelated tool schemas.

Current-cell constants, control flow, and local definitions are still analyzed,
but imported modules and builtins remain unowned: earlier cells can replace
`sys.modules`, import hooks, module attributes, and builtin callables. Nah
therefore does not emit effects for those calls without a future kernel
provenance contract. Additional fields make coverage partial without hiding the
built-in code string. A missing or non-string code field stays opaque.

Prime Agent can retain Python bindings, mutate imported modules and builtins,
and change the kernel working directory between cells, but its tool-call event
does not expose that state. Prior bare names, imported callables, and relative
paths therefore remain unknown. nah does not execute a cell or reconstruct the
full Python runtime to discover them.

## Shell boundary

At Prime Agent commit `b817a089`, the `tool_call` hook receives raw IPython
code before the runtime rewrites a `%%bash` cell with configured shell
settings. The extension context does not expose the resolved settings or
kernel environment. Consequently raw `%%bash`, `!`, and `!!` syntax remains
partial and opaque: nah will not assume Bash or analyze bytes that may differ
from execution. Moving Prime Agent's shell rewrite into argument preparation,
before validation and `tool_call`, would provide an exact boundary that nah
could safely consume.

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
IPython analysis proves, but opaque tools and hidden kernel state do not produce
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
