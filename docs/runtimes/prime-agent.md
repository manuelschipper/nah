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

At Prime Agent commit `b817a089`, `tool_call` receives raw IPython before
configured shell settings apply. Nah owns IPython's
syntactic boundary: `!`, `!!`, `%%bash`, and `%%sh` lower to shell effects
without trusting spoofable runtime method names. Exact simple `$name` and
`{name}` interpolation is resolved from current-cell values; unresolved
interpolation makes the affected shell execution partial. `%%capture`, `%time`,
and `%%time` preserve effects from the code they execute; `%%capture` contains
IPython-routed output; inherited child stdout remains visible. Bare escapes use
the hook process's observed `SHELL`; unsupported shells stay partial.

The visible body of a Bash or sh cell is analyzed. Prime Agent's configured
`commandPrefix`, final shell-path rewrite, and prior in-kernel environment
mutations are not present in the hook input and remain outside the adapter
contract. IPython state-changing or file-loading forms such as `%cd`, `%run`,
and `%%writefile` also remain outside the current effect contract.

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
