# Security

A call nah fails to block is usually a coverage gap, not a vulnerability:
nah never approves, so an uncaught call falls through to your runtime's
normal approval flow, exactly as it would without nah. Coverage gaps are
welcome as public issues.

An opt-in `nah hook <runtime> install --fail-closed` mode denies explicit
evaluation failures and security-relevant analysis refusals while continuing to
delegate ordinary uncertainty. Its guarantee begins only once the installed nah
process is running; missing/unloaded hooks, process termination, runtime
timeouts or bypass, and broken output pipes remain runtime-owned boundaries.

If there's something you think needs to be reported privately, please contact me at:

- Email [security@nahguard.ai](mailto:security@nahguard.ai), or
- use [GitHub's private advisory form](https://github.com/manuelschipper/nah/security/advisories/new).

Include the affected nah version, runtime, operating system, a
reproduction, and the expected impact.
