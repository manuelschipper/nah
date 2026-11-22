//! Shared subprocess bridges for JavaScript runtime plugins: the decision
//! before a call and the report after it.

use crate::runtime::FailurePolicy;

/// Expects a JSON-encoded executable; installers own encoding and runtime event handlers.
pub(super) fn javascript_decision_bridge(
    executable: &str,
    runtime: &str,
    policy: FailurePolicy,
) -> String {
    let failure_arg = if policy == FailurePolicy::Block {
        r#", "--fail-closed""#
    } else {
        ""
    };
    format!(
        r#"const nahExecutable = {executable};
const maxOutputBytes = 65536;

function decide(input) {{
  return new Promise((resolve, reject) => {{
    const child = spawn(nahExecutable, ["hook", "{runtime}", "run"{failure_arg}], {{
      stdio: ["pipe", "pipe", "pipe"],
    }});
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer;
    const cleanup = () => clearTimeout(timer);
    const fail = (error) => {{
      if (settled) return;
      settled = true;
      cleanup();
      child.kill();
      reject(error);
    }};
    const append = (current, chunk) => {{
      const next = current + chunk.toString();
      if (Buffer.byteLength(next) > maxOutputBytes) {{
        fail(new Error("nah output limit exceeded"));
      }}
      return next;
    }};
    timer = setTimeout(() => fail(new Error("nah decision timed out")), 5000);
    child.on("error", fail);
    child.stdout.on("data", (chunk) => {{ stdout = append(stdout, chunk); }});
    child.stderr.on("data", (chunk) => {{ stderr = append(stderr, chunk); }});
    child.on("close", (code) => {{
      if (settled) return;
      settled = true;
      cleanup();
      if (code !== 0) return reject(new Error("nah decision failed"));
      try {{
        const result = JSON.parse(stdout);
        if (typeof result.block !== "boolean") throw new Error("invalid nah decision");
        if (typeof result.evaluation_failed !== "boolean") throw new Error("invalid nah failure state");
        if ((result.block || result.evaluation_failed) && typeof result.reason !== "string") throw new Error("invalid nah reason");
        resolve(result);
      }} catch (error) {{
        reject(error);
      }}
    }});
    child.stdin.on("error", fail);
    child.stdin.end(JSON.stringify(input));
  }});
}}
"#
    )
}

/// The JavaScript `report(input)` of a plugin that reports finished calls to
/// `nah hook <runtime> run`, which answers nothing. It resolves once Nah has
/// recorded the call, or after ten seconds, and never rejects: a call whose
/// end goes unreported keeps counting as run. Expects a JSON-encoded
/// executable, as `javascript_decision_bridge` does.
pub(super) fn javascript_report_bridge(executable: &str, runtime: &str) -> String {
    format!(
        r#"function report(input) {{
  return new Promise((resolve) => {{
    let child;
    try {{
      child = spawn({executable}, ["hook", "{runtime}", "run"], {{
        stdio: ["pipe", "ignore", "ignore"],
      }});
    }} catch {{
      return resolve();
    }}
    const timer = setTimeout(() => {{ child.kill(); resolve(); }}, 10000);
    const done = () => {{ clearTimeout(timer); resolve(); }};
    child.on("error", done);
    child.on("close", done);
    child.stdin.on("error", () => {{}});
    child.stdin.end(JSON.stringify(input));
  }});
}}
"#
    )
}
