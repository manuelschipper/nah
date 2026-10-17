//! Path binding dispatch: a command name that `if`/`case` arms or an
//! `&&`/`||` operand left bound to different functions, aliases or hashed
//! paths is dispatched once per path binding, each under its path's condition.

use std::rc::Rc;

use effinterp_proto::ExecutionNodeRef;

use crate::builder::PlanBuilder;
use crate::control_flow::SiteFacts;
use crate::models::StdinValue;
use crate::shell::name_tables::{FunctionBinding, PathBindings};
use crate::shell::parse::Simple;
use crate::shell::shell_env::ShellEnv;
use crate::shell::{Converted, Shell, Termination};

use super::conditional_shell_state::ConditionalShellState;

impl Shell<'_> {
    /// Run a command whose name earlier branch paths bound differently once
    /// per path, under that path's condition. Alias expansion comes first,
    /// then functions, then `hash -p`; each dispatch resolves the next table.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub(super) fn dispatch_path_bindings(
        &self,
        builder: &mut PlanBuilder,
        env: &mut ShellEnv,
        cmd: &Simple,
        converted: &[Converted],
        name: &str,
        first_retained_token: Option<usize>,
        stdin: Option<&StdinValue>,
        persist: bool,
        guarded: bool,
    ) -> Option<(
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    )> {
        let mut dispatch = |builder: &mut PlanBuilder, env: &mut ShellEnv| {
            self.dispatch_argv(
                builder,
                env,
                cmd,
                converted,
                Some(name),
                first_retained_token,
                stdin,
                persist,
                true,
                guarded,
            )
        };
        if let Some(bindings) = env.alias_alternatives.remove(name) {
            let saved = env.aliases.get(name).cloned();
            let dispatched = for_each_path_binding(
                builder,
                env,
                &bindings,
                persist,
                &mut dispatch,
                |env, alias| {
                    match alias {
                        Some(alias) => env.aliases.insert(name.to_string(), alias.clone()),
                        None => env.aliases.remove(name),
                    };
                },
            );
            match saved {
                Some(alias) => env.aliases.insert(name.to_string(), alias),
                None => env.aliases.remove(name),
            };
            env.alias_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        if let Some(bindings) = env.function_alternatives.remove(name) {
            // A path that leaves the name unbound runs what the name resolves
            // to without the function. A name nothing else resolves to would
            // only fail there, so that path adds no command.
            let resolves =
                crate::shell::shell_builtin(name) || self.nest.catalog.find(name).is_some();
            let mut paths = bindings
                .iter()
                .filter(|((function, _), _)| resolves || function.is_some())
                .cloned()
                .collect::<Vec<_>>();
            if paths.is_empty() {
                paths.clone_from(&bindings);
            }
            let saved = (
                env.functions.get(name).cloned(),
                env.readonly_functions.contains(name),
            );
            let install = |env: &mut ShellEnv, (function, readonly): &FunctionBinding| {
                match function {
                    Some(function) => env.functions.insert(name.to_string(), Rc::clone(function)),
                    None => env.functions.remove(name),
                };
                if *readonly {
                    env.readonly_functions.insert(name.to_string());
                } else {
                    env.readonly_functions.remove(name);
                }
            };
            let dispatched =
                for_each_path_binding(builder, env, &paths, persist, &mut dispatch, install);
            install(env, &saved);
            env.function_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        if let Some(bindings) = env.hash_alternatives.remove(name) {
            let saved = env.hashed.get(name).cloned();
            let install = |env: &mut ShellEnv, path: &Option<String>| {
                match path {
                    Some(path) => env.hashed.insert(name.to_string(), path.clone()),
                    None => env.hashed.remove(name),
                };
            };
            let dispatched =
                for_each_path_binding(builder, env, &bindings, persist, &mut dispatch, install);
            install(env, &saved);
            env.hash_alternatives.insert(name.to_string(), bindings);
            return Some(dispatched);
        }
        None
    }
}

/// Dispatch once per path binding, each under its path's condition. Shell
/// state the paths change joins as for conditionally defined functions.
fn for_each_path_binding<T>(
    builder: &mut PlanBuilder,
    env: &mut ShellEnv,
    bindings: &PathBindings<T>,
    persist: bool,
    dispatch: &mut impl FnMut(
        &mut PlanBuilder,
        &mut ShellEnv,
    ) -> (
        Option<ExecutionNodeRef>,
        Option<Termination>,
        SiteFacts,
        bool,
    ),
    install: impl Fn(&mut ShellEnv, &T),
) -> (
    Option<ExecutionNodeRef>,
    Option<Termination>,
    SiteFacts,
    bool,
) {
    let mut state = persist.then(|| ConditionalShellState::new(env));
    let mut execution = None;
    let mut termination = None;
    let mut all_terminate = true;
    let mut facts: Option<SiteFacts> = None;
    for (binding, condition) in bindings {
        if let Some(state) = &state {
            state.reset(env);
        }
        install(env, binding);
        if let Some(condition) = condition {
            builder.push_bound_condition(condition.clone());
        }
        let (path_execution, path_termination, path_facts, _) = dispatch(builder, env);
        if condition.is_some() {
            builder.pop_condition();
        }
        if let Some(state) = &mut state {
            state.observe(env);
        }
        execution = path_execution.or(execution);
        all_terminate &= path_termination.is_some();
        termination = path_termination;
        match &mut facts {
            Some(facts) => facts.merge(&path_facts),
            None => facts = Some(path_facts),
        }
    }
    if let Some(state) = state {
        state.merge(env, false);
    }
    (
        execution,
        termination.filter(|_| all_terminate),
        facts.unwrap_or_else(SiteFacts::unknown),
        false,
    )
}
