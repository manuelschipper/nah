# Guard reference

A guard is one built-in protection against a specific kind of loss or
exposure. Nah analyzes each shell command, script, or native tool call before
the agent's runtime executes it, without running anything. When an enabled
guard matches, Nah blocks the call and tells the agent why. Otherwise the call
**delegates**: Nah hands it back unchanged to the runtime's own permission
prompt, sandbox, or approval flow. Nah never approves a call, so a delegated
call has not been judged safe.

Guards block only on definite evidence. When Nah cannot establish what a call
would do, for example because a target sits in an unset variable, a program is
not modeled, or a server chooses the file name, the guard does not match and
the call delegates. Some guards also record a coverage gap on the decision,
which `nah why <id>` shows. Filesystem guards trust a program run by a
`/`-spelled path only from a standard executable directory, the list
custom-guard selectors use; `/usr/local` and Homebrew directories are not
trusted when the path or PATH entry reaches them through `..`. A lookalike
such as `/tmp/chmod` delegates with a
`model-identity-unestablished` gap. Windows drive-qualified paths stay trusted.
Each section below names the limits that matter most for that guard.

Every guard ships on or off. Guards that ship on protect against broad loss of
working state, destroyed recovery paths, or raw credential exposure. Guards
that ship off cover operations that are dangerous in some settings and routine
in others; enable one when that operation should always go through a human. A
human changes a guard with `nah guard enable <name>`, `nah guard disable
<name>`, or `nah guard reset <name>`, or in `nah tui`. Disabling a guard
removes only that rule, and another guard may still block the same call.

`nah guards` shows live state, `nah docs guards` lists every guard with tested
examples, and `nah docs guards <name>` prints one section of this page. Check a
command with `nah test '<command>'`; do not run the examples below.
