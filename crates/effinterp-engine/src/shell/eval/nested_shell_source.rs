//! Nested shell source: shell text this shell reads as a nested invocation of
//! its own, such as `eval` and `source` text, an alias expansion, a `trap`
//! action or a command substitution body. `NestedShellMode` says whether the
//! text's changes persist in the caller, stay in a child environment, or stay
//! in a child whose standard output is captured.

use effinterp_proto::{ExecutionNodeRef, Subject};

use crate::builder::PlanBuilder;
use crate::nest::Transition;
use crate::shell::lex::ShellSpan;
use crate::shell::shell_env::ShellEnv;
use crate::shell::{Shell, analyze_shell_at, analyze_shell_with_env};

impl Shell<'_> {
    /// Analyze `source` as a nested shell invocation under `mode`, returning its
    /// execution. A structurally saturated walk only recovers command heads from
    /// it and returns `None`.
    pub(super) fn nested_shell_source(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        source: &str,
        span: ShellSpan,
        mode: NestedShellMode,
    ) -> Option<ExecutionNodeRef> {
        let span_node = self.span_node(builder, span);
        if self.structural_saturated(builder, env) {
            // Retaining heads after saturation still recurses into the
            // substitution body, so the execution depth bound applies here
            // exactly as it does to a charged nested transition.
            if self.depth + 1 >= self.nest.limits.max_execution_depth {
                if !env.saturated_substitution_recorded {
                    env.saturated_substitution_recorded = true;
                    self.nest.record_refused_nested_with_cwd(
                        builder,
                        Subject::Shell {
                            source: source.to_string(),
                            cwd: env.cwd.clone(),
                            context: Default::default(),
                        },
                        &[span_node],
                        self.depth,
                        env.cwd_resource.clone(),
                        env.cwd_node,
                    );
                }
                return None;
            }
            let scope = if self.nest.budget.exhausted() || builder.execution_saturated() {
                if env.saturated_substitution_recorded {
                    Some(span_node)
                } else {
                    env.saturated_substitution_recorded = true;
                    self.nest.record_refused_nested_with_cwd(
                        builder,
                        Subject::Shell {
                            source: source.to_string(),
                            cwd: env.cwd.clone(),
                            context: Default::default(),
                        },
                        &[span_node],
                        self.depth,
                        env.cwd_resource.clone(),
                        env.cwd_node,
                    )
                }
            } else {
                Some(span_node)
            };
            if let Some(scope) = scope {
                let mut child = self.saturated_substitution_env(env, source)?;
                if matches!(mode, NestedShellMode::Capture) {
                    child.capture_stdout();
                }
                analyze_shell_at(
                    builder,
                    self.nest,
                    source,
                    child,
                    Some(scope),
                    self.depth + 1,
                );
            }
            return None;
        }
        let frame = self.nest.begin(
            builder,
            Transition::file(Subject::Shell {
                source: source.to_string(),
                cwd: env.cwd.clone(),
                context: Default::default(),
            })
            .cwd(env.cwd_resource.clone(), env.cwd_node)
            .streams({
                let mut streams = builder.inherited_execution_streams();
                if matches!(mode, NestedShellMode::Capture) {
                    streams.stdout = None;
                }
                streams
            }),
            &[span_node],
            self.depth,
        )?;
        let nested_scope = frame.scope;
        let nested_execution = builder.current_execution();
        if matches!(mode, NestedShellMode::Persist) {
            let aliases = env.aliases.clone();
            analyze_shell_with_env(
                builder,
                self.nest,
                source,
                env,
                Some(nested_scope),
                self.depth + 1,
            );
            env.anchor_new_aliases(&aliases, span.end);
        } else {
            let mut child = self.child_env(env);
            if matches!(mode, NestedShellMode::Capture) {
                child.capture_stdout();
            }
            analyze_shell_with_env(
                builder,
                self.nest,
                source,
                &mut child,
                Some(nested_scope),
                self.depth + 1,
            );
        }
        frame.end(builder);
        Some(nested_execution)
    }
}

/// How a nested shell source relates to the shell reading it: `Persist` runs
/// it in the caller's environment, `Child` in a child environment, and
/// `Capture` in a child whose standard output is captured.
pub(super) enum NestedShellMode {
    Persist,
    Child,
    Capture,
}
