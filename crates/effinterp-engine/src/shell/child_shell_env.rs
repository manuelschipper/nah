//! Child shell environments: the state a subshell, command substitution or
//! pipeline stage starts from. It inherits the parent's values and working
//! directory, and its own mutations do not escape.

use std::collections::BTreeSet;
use std::rc::Rc;

use super::referenced_inputs::{
    expanded_referenced_inputs_bounded, referenced_inputs_with_substitutions,
};
use super::shell_env::{ShellEnv, VarEntry};
use super::{Converted, MAX_SATURATED_FUNCTION_STEPS, MAX_WALK_DEPTH, Shell, lex, parse};

impl Shell<'_> {
    /// A child environment inheriting literal values and cwd; its own
    /// mutations do not escape (subshells, command substitutions).
    pub(super) fn child_env(&self, env: &ShellEnv) -> ShellEnv {
        self.child_env_with_inputs(env, None, None, env.positional.clone())
    }

    /// `child_env` with the inherited state narrowed: when `variables` or
    /// `functions` is given, only those names are carried over, which keeps a
    /// saturated walk from copying source-sized tables per call. `positional`
    /// becomes the child's positional parameters.
    pub(super) fn child_env_with_inputs(
        &self,
        env: &ShellEnv,
        variables: Option<&BTreeSet<String>>,
        functions: Option<&BTreeSet<String>>,
        positional: Option<Vec<Converted>>,
    ) -> ShellEnv {
        // Saturated callers provide small reachable-name sets. Look them up
        // directly so unrelated source-sized maps are not scanned per call.
        let copy_var = |entry: &VarEntry| VarEntry {
            nameref: entry.nameref,
            branches: entry.branches.clone(),
            value: entry.value.clone(),
            may: entry.may.clone(),
            unresolved_default_override: entry.unresolved_default_override,
            word: entry.word.clone(),
            word_condition: entry.word_condition.clone(),
            saturation_key: entry.saturation_key,
            span: entry.span,
            node: entry.node,
            antecedents: entry.antecedents.clone(),
            producers: entry.producers.clone(),
            producers_condition: entry.producers_condition.clone(),
            earlier_producers: entry.earlier_producers.clone(),
            script_set: entry.script_set,
            script_may_set: entry.script_may_set,
            captured_name_hidden: entry.captured_name_hidden,
            transparent_writes: entry.transparent_writes.clone(),
        };
        ShellEnv {
            stdout_consumed: true,
            loop_reads: env.loop_reads.clone(),
            loop_carry_pass: env.loop_carry_pass,
            loop_continues: env.loop_continues.clone(),
            chain_held: env.chain_held.clone(),
            chain_alias: env.chain_alias.clone(),
            captured_values: env.captured_values.clone(),
            filed_values: env.filed_values.clone(),
            captured_operands: env.captured_operands.clone(),
            vars: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.vars
                            .get(name)
                            .map(|entry| (name.clone(), copy_var(entry)))
                    })
                    .collect(),
                None => env
                    .vars
                    .iter()
                    .map(|(name, entry)| (name.clone(), copy_var(entry)))
                    .collect(),
            },
            arrays: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.arrays
                            .get(name)
                            .map(|entry| (name.clone(), entry.clone()))
                    })
                    .collect(),
                None => env.arrays.clone(),
            },
            exported: env.exported.clone(),
            unexported: env.unexported.clone(),
            readonly: env.readonly.clone(),
            attributed: env.attributed.clone(),
            attribute_frames: env.attribute_frames.clone(),
            value_attributes: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.value_attributes
                            .get(name)
                            .map(|attributes| (name.clone(), *attributes))
                    })
                    .collect(),
                None => env.value_attributes.clone(),
            },
            readonly_functions: env.readonly_functions.clone(),
            hashed: env.hashed.clone(),
            uncertain_bindings: env.uncertain_bindings.clone(),
            disabled_builtins: env.disabled_builtins.clone(),
            aliases: env.aliases.clone(),
            unread_aliases: env.unread_aliases.clone(),
            unread_alias_names: env.unread_alias_names,
            expand_aliases: env.expand_aliases,
            bash: env.bash,
            alias_alternatives: env.alias_alternatives.clone(),
            hash_alternatives: env.hash_alternatives.clone(),
            function_alternatives: env.function_alternatives.clone(),
            nocaseglob: env.nocaseglob,
            lastpipe: env.lastpipe,
            unset: env.unset.clone(),
            startup_may_set: env.startup_may_set.clone(),
            unexported_nodes: env.unexported_nodes.clone(),
            positional,
            positional_set_changed: Some(false),
            positional_discard_revision: 0,
            argv0: env.argv0.clone(),
            script_source: env.script_source.clone(),
            source_condition: env.source_condition.clone(),
            reads: match variables {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.reads
                            .get(name)
                            .cloned()
                            .map(|producer| (name.clone(), producer))
                    })
                    .collect(),
                None => env.reads.clone(),
            },
            cwd: env.cwd.clone(),
            cwd_resource: env.cwd_resource.clone(),
            captured_cwd: env.captured_cwd,
            physical_cd: env.physical_cd,
            allexport: env.allexport,
            observes_later_bindings: env.observes_later_bindings,
            pwd_is_cwd: env.pwd_is_cwd,
            physical_depth: env.physical_depth,
            cwd_node: env.cwd_node,
            socket_fds: env.socket_fds.clone(),
            descriptors: env.descriptors.clone(),
            descriptor_values: env.descriptor_values.clone(),
            coprocess_fds: env.coprocess_fds.clone(),
            redirections: env.redirections.clone(),
            deferred: Vec::new(),
            channel_bytes: Rc::clone(&env.channel_bytes),
            channel_selections: Rc::clone(&env.channel_selections),
            stdout_channel: env.stdout_channel,
            stdin: None,
            compound_stdin: None,
            dispatch_stdin: Box::default(),
            source_cwd: env.source_cwd.clone(),
            source_uses_runtime_cwd: env.source_uses_runtime_cwd,
            runtime_cwd: env.runtime_cwd.clone(),
            cwd_known: env.cwd_known,
            functions: match functions {
                Some(names) => names
                    .iter()
                    .filter_map(|name| {
                        env.functions
                            .get(name)
                            .map(|entry| (name.clone(), Rc::clone(entry)))
                    })
                    .collect(),
                None => env.functions.clone(),
            },
            exported_functions: env.exported_functions.clone(),
            exported_function_nodes: env.exported_function_nodes.clone(),
            unexported_function_nodes: env.unexported_function_nodes.clone(),
            active: env.active.clone(),
            background_depth: env.background_depth,
            call_redirects: None,
            command_redirects: Vec::new(),
            pid_is_own: false,
            status: None,
            sourced: env.sourced,
            sourced_assignments: env.sourced_assignments.clone(),
            local_frames: env.local_frames.clone(),
            function_heads_only: env.function_heads_only,
            saturated_substitution_recorded: env.saturated_substitution_recorded,
            saturation_memos: Rc::clone(&env.saturation_memos),
            script: Rc::clone(&env.script),
        }
    }

    /// The child environment for a command substitution body once the walk is
    /// structurally saturated: only the bindings the body, or a function it can
    /// reach, may expand. `None` when the saturated parse or function step budget
    /// (`MAX_SATURATED_FUNCTION_STEPS`) is spent.
    pub(super) fn saturated_substitution_env(
        &self,
        env: &ShellEnv,
        source: &str,
    ) -> Option<ShellEnv> {
        // Only head recovery runs on this path, so carry the bindings the
        // substitution or a reachable function can actually expand.
        // Charge body bytes before lexing because repeated call sites can
        // otherwise reparse the same wide substitution without a bound.
        let mut memos = env.saturation_memos.borrow_mut();
        if source.len()
            > MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.substitution_parse_steps)
        {
            return None;
        }
        memos.substitution_parse_steps += source.len();
        drop(memos);
        let lexed = lex::lex(source);
        let items = parse::parse_shell_items(&lexed.toks, source.len() as u32);
        let refs = referenced_inputs_with_substitutions(
            &items,
            self.nest
                .limits
                .max_execution_depth
                .saturating_sub(self.depth + 1)
                .min(MAX_WALK_DEPTH as u64) as u32,
        );
        let mut memos = env.saturation_memos.borrow_mut();
        let Some((variables, functions, work)) = expanded_referenced_inputs_bounded(
            &refs.vars,
            &refs.calls,
            &refs.command_vars,
            &refs.command_head_patterns,
            env,
            self.nest
                .limits
                .max_shell_function_depth
                .saturating_sub(env.active.len() as u64),
            MAX_SATURATED_FUNCTION_STEPS.saturating_sub(memos.function_steps),
        ) else {
            memos.function_steps = MAX_SATURATED_FUNCTION_STEPS;
            return None;
        };
        memos.function_steps += work;
        drop(memos);
        Some(self.child_env_with_inputs(
            env,
            Some(&variables),
            Some(&functions),
            env.positional.clone(),
        ))
    }
}
