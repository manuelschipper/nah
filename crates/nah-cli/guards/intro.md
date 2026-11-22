# Guard reference

Nah has nine guards, each named for what it protects, and each guard is made
of rules. Nah analyzes each shell command, script, or native tool call before
the agent's runtime executes it, without running anything. When a rule that
is on matches, Nah blocks the call and tells the agent what is at risk and to
ask the operator. Otherwise the call **delegates**: Nah hands it back
unchanged to the runtime's own permission prompt, sandbox, or approval flow.
Nah never approves a call, so a delegated call has not been judged safe.

Rules block only on definite evidence. When Nah cannot establish what a call
would do, for example because a target sits in an unset variable, a program is
not modeled, or a server chooses the file name, the rule does not match and
the call delegates. Some rules also record a coverage gap on the decision,
which `nah why <id>` shows. Filesystem rules trust a program run by a
`/`-spelled path only from a standard executable directory;
`/usr/local` and Homebrew directories are not
trusted when the path or PATH entry reaches them through `..`. A lookalike
such as `/tmp/chmod` delegates with a
`model-identity-unestablished` gap. Windows drive-qualified paths stay trusted.
Each rule's section names the limits that matter most for it.

Each guard except `self` is off, core (the default), or strict. Rules that
apply at core protect against broad loss of working state, destroyed recovery
paths, or raw credential exposure. Rules, or parts of rules, that apply only
at strict cover operations that are dangerous in some settings and routine in
others. A human sets a guard with `nah guard set <guard> off|core|strict` or
`nah guard reset <guard>`, runs or stops one rule whatever its guard says with
`nah rule enable <guard/rule>` or `nah rule disable <guard/rule>`, undoes that
with `nah rule reset <guard/rule>`, or does any of these in `nah tui`. An
enabled rule runs all of its parts, including those that apply at strict.
Disabling a rule removes only that rule, and another rule may still block the
same call. `self` has no setting and cannot be turned off.

Each rule's section says which nah 1.x guards it replaces. nah 2.0 imports a
1.x configuration once, as `nah docs configuration` describes; after that,
only the 2.0 names are accepted.

`nah guards` shows live state, `nah docs guards` lists every rule with tested
examples, `nah docs guards <guard>` prints one guard with its rules'
summaries, and `nah docs guards <guard/rule>` prints one rule's section of
this page. Check a command with `nah test '<command>'`; do not run the
examples below.
