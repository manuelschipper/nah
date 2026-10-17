//! Conditional shell state: the variable bindings and working directory a
//! sourced file or conditionally bound function body shares with the shell
//! that runs it. Each possible body starts from the same state, and a value
//! the bodies leave different is widened afterwards.

use std::collections::HashMap;

use effinterp_proto::{ProvenanceRef, ResourceExpr};

use crate::shell::saturation_memos::variable_saturation_key;
use crate::shell::shell_env::{ShellEnv, VarEntry};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

// Sources and conditional function calls share the shell's bindings and cwd.
// Evaluate each possible body from the same state, then widen changed values.
/// Every cwd field a conditional body starts from, in `ShellEnv` declaration order.
type CwdState = (
    Option<String>,
    Option<ResourceExpr>,
    bool,
    Option<ProvenanceRef>,
    Option<String>,
    Option<String>,
    bool,
);

pub(super) struct ConditionalShellState {
    initial_vars: HashMap<String, VarEntry>,
    initial_cwd: CwdState,
    uncertain_vars: HashMap<String, VarEntry>,
    uncertain_cwd: bool,
}

impl ConditionalShellState {
    pub(super) fn new(env: &ShellEnv) -> Self {
        Self {
            initial_vars: env.vars.clone(),
            initial_cwd: (
                env.cwd.clone(),
                env.cwd_resource.clone(),
                env.captured_cwd,
                env.cwd_node,
                env.source_cwd.clone(),
                env.runtime_cwd.clone(),
                env.cwd_known,
            ),
            uncertain_vars: HashMap::new(),
            uncertain_cwd: false,
        }
    }

    pub(super) fn reset(&self, env: &mut ShellEnv) {
        env.vars = self.initial_vars.clone();
        (
            env.cwd,
            env.cwd_resource,
            env.captured_cwd,
            env.cwd_node,
            env.source_cwd,
            env.runtime_cwd,
            env.cwd_known,
        ) = self.initial_cwd.clone();
    }

    pub(super) fn observe(&mut self, env: &ShellEnv) {
        for (name, entry) in self.initial_vars.iter().chain(env.vars.iter()) {
            if self
                .initial_vars
                .get(name)
                .map(|entry| entry.saturation_key)
                != env.vars.get(name).map(|entry| entry.saturation_key)
            {
                let script_set = self
                    .initial_vars
                    .get(name)
                    .is_some_and(|entry| entry.script_set)
                    && env.vars.get(name).is_some_and(|entry| entry.script_set)
                    && self
                        .uncertain_vars
                        .get(name)
                        .is_none_or(|entry| entry.script_set);
                let mut entry = entry.clone();
                entry.script_set = script_set;
                // The value may be the one an earlier body left.
                if let Some(earlier) = self.uncertain_vars.get(name) {
                    entry.producers.extend(earlier.producers.iter().cloned());
                }
                self.uncertain_vars.insert(name.clone(), entry);
            }
        }
        self.uncertain_cwd |= (
            &env.cwd,
            &env.cwd_resource,
            env.captured_cwd,
            env.cwd_node,
            &env.source_cwd,
            &env.runtime_cwd,
            env.cwd_known,
        ) != (
            &self.initial_cwd.0,
            &self.initial_cwd.1,
            self.initial_cwd.2,
            self.initial_cwd.3,
            &self.initial_cwd.4,
            &self.initial_cwd.5,
            self.initial_cwd.6,
        );
    }

    /// Widen every value the bodies left different. `keep_producers` leaves
    /// a widened value the pending flow values the bodies bound it with, for
    /// bodies whose bindings must stay tied to what they read.
    pub(super) fn merge(self, env: &mut ShellEnv, keep_producers: bool) {
        env.vars = self.initial_vars;
        for (name, mut entry) in self.uncertain_vars {
            entry.value = None;
            entry.branches.clear();
            entry.transparent_writes.clear();
            entry.may.clear();
            entry.word = Some(Word::new(vec![WordPart::Unknown]));
            entry.word_condition = None;
            if !keep_producers {
                entry.producers.clear();
            }
            entry.producers_condition = None;
            entry.earlier_producers.clear();
            entry.script_may_set = true;
            entry.saturation_key = variable_saturation_key(
                None,
                &entry.may,
                entry.word.as_ref(),
                true,
                entry.unresolved_default_override,
            );
            env.vars.insert(name, entry);
        }
        if self.uncertain_cwd {
            env.cwd = None;
            env.cwd_resource = Some(unresolved_resource("filesystem"));
            env.captured_cwd = false;
            env.cwd_node = None;
            env.source_cwd = None;
            env.runtime_cwd = None;
            env.cwd_known = false;
        }
    }
}
