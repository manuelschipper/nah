//! Preserves visible and sourced shell payloads while coordinating bounded reparsing.

use std::collections::BTreeSet;

use nah_parse::{Statement, Syntax, Word};

use super::positionals::syntax_sets_positionals;
use super::{AssignmentUpdate, Lowered, Lowerer, VisibleExecutionState, VisibleStdin};
use crate::bash_flow::add_artifact_flows;
use crate::bash_model::{InvocationDraft, ProgramDraft, StdoutDraft, VariableValue};
use crate::bash_state::{BindingAttribute, Cwd};

fn is_return_statement(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Command {
            name,
            name_substitutions,
            ..
        } if name == "return" && name_substitutions.is_empty()
    )
}

impl Lowerer {
    pub(super) fn visible_pipeline_output(&self, lowered: &Lowered) -> Option<VisibleStdin> {
        let [stage] = lowered.outputs.as_slice() else {
            return None;
        };
        let StdoutDraft::Exact(value) = &self.stages[*stage].stdout else {
            return None;
        };
        Some(VisibleStdin {
            value: value.clone(),
            origins: vec![*stage],
        })
    }

    pub(super) fn lower_visible_programs(&mut self) {
        let mut seen = self.prelowered_visible_stages.clone();
        loop {
            add_artifact_flows(&self.stages, &mut self.flows, self.platform);
            let payloads = crate::bash_content::visible_payloads(&self.stages, &self.flows, &seen);
            if payloads.is_empty() {
                break;
            }
            for (sink, payload) in payloads {
                seen.insert(sink);
                let shell_payload = matches!(
                    &self.stages[sink].invocation,
                    InvocationDraft::CodeExecution { source, .. }
                        if source.as_str().starts_with("shell-")
                );
                if !shell_payload {
                    if let InvocationDraft::CodeExecution { code, .. } =
                        &mut self.stages[sink].invocation
                    {
                        *code = Some(payload);
                    }
                    crate::bash_self_protection::reclassify_inline(
                        &mut self.stages[sink].invocation,
                        &self.home,
                        &self.critical_paths,
                        self.platform,
                        &self.runtime_variables,
                    );
                    continue;
                }
                let cwd = self.stages[sink].invocation_cwd.clone();
                let parent_depth = self.payload_depth;
                self.payload_depth = self.stages[sink].payload_depth;
                if !self.enter_payload(payload.len()) {
                    self.payload_depth = parent_depth;
                    continue;
                }
                let syntax = match nah_parse::normalize(&payload) {
                    Ok(syntax) => syntax,
                    Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                        self.complete = false;
                        self.analysis_refused = true;
                        self.payload_depth = parent_depth;
                        continue;
                    }
                    Err(_) => {
                        self.complete = false;
                        self.payload_depth = parent_depth;
                        continue;
                    }
                };
                let state = self.state.clone();
                let ambient_variables = self.ambient_variables.clone();
                let lookup_mode = self.next_lookup_mode;
                if let Some(visible) = self
                    .visible_execution_states
                    .iter()
                    .find(|visible| visible.stage == sink)
                    .cloned()
                {
                    self.state = visible.state;
                    self.ambient_variables = visible.ambient_variables;
                } else {
                    self.prepare_isolated_environment(&ProgramDraft::Unresolved, &[], &[], &[]);
                    self.state.functions.clear();
                    self.state.cwd = cwd.map(Cwd::Known).unwrap_or(Cwd::Unknown);
                }
                self.next_lookup_mode = None;
                self.lower_syntax(&syntax);
                self.next_lookup_mode = lookup_mode;
                self.state = state;
                self.ambient_variables = ambient_variables;
                self.payload_depth = parent_depth;
            }
        }
        if crate::bash_content::has_unresolved_execution(&self.stages, &self.flows, &seen) {
            self.complete = false;
        }
        if self
            .unresolved_current_shell_stages
            .iter()
            .any(|stage| seen.contains(stage))
        {
            self.analysis_refused = true;
        }
        if self.tracked_execution_stream_stages.iter().any(|stage| {
            !seen.contains(stage)
                && !crate::bash_content::guarded_unknown_source(*stage, &self.stages, &self.flows)
        }) {
            self.analysis_refused = true;
        }
    }

    pub(super) fn lower_visible_execution_now(&mut self, sink: usize) -> Lowered {
        let Some(payload) = self.visible_execution_payload(sink) else {
            return Lowered::default();
        };
        self.prelowered_visible_stages.insert(sink);
        self.lower_current_shell_payload(&payload)
    }

    pub(super) fn visible_execution_payload(&mut self, sink: usize) -> Option<String> {
        add_artifact_flows(&self.stages, &mut self.flows, self.platform);
        crate::bash_content::visible_payloads(&self.stages, &self.flows, &BTreeSet::new())
            .into_iter()
            .find_map(|(candidate, payload)| (candidate == sink).then_some(payload))
    }

    pub(super) fn lower_current_shell_payload(&mut self, payload: &str) -> Lowered {
        if !self.enter_payload(payload.len()) {
            return Lowered::default();
        }
        let lowered = match nah_parse::normalize(payload) {
            Ok(syntax) => self.lower_syntax(&syntax),
            Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                self.complete = false;
                self.analysis_refused = true;
                Lowered::default()
            }
            Err(_) => {
                self.complete = false;
                Lowered::default()
            }
        };
        self.payload_depth -= 1;
        lowered
    }

    pub(super) fn lower_source_payload(
        &mut self,
        sink: usize,
        payload: &str,
        assignments: &[(String, Word)],
        assignment_updates: &[AssignmentUpdate],
        arguments: &[Word],
        argument_origins: &[Vec<usize>],
    ) -> Lowered {
        self.prelowered_visible_stages.insert(sink);
        if !self.enter_payload(payload.len()) {
            return Lowered::default();
        }
        let syntax = match nah_parse::normalize(payload) {
            Ok(syntax) => syntax,
            Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                self.complete = false;
                self.analysis_refused = true;
                self.payload_depth -= 1;
                return Lowered::default();
            }
            Err(_) => {
                self.complete = false;
                self.analysis_refused = true;
                self.payload_depth -= 1;
                return Lowered::default();
            }
        };

        let entry = self.state.clone();
        self.apply_assignment_updates(assignments, assignment_updates.to_vec(), false);
        let has_source_arguments = arguments.len() > 1;
        if has_source_arguments {
            self.state.positionals = self.function_positional_values(
                &arguments[1..],
                argument_origins.get(1..).unwrap_or_default(),
            );
            if syntax_sets_positionals(&syntax) {
                self.complete = false;
                self.analysis_refused = true;
            }
        }
        let lowered = self.lower_source_syntax(&syntax);
        if has_source_arguments {
            self.state.positionals.clone_from(&entry.positionals);
        }
        self.restore_function_assignment_scope(&entry, assignments);
        self.payload_depth -= 1;
        lowered
    }

    pub(super) fn lower_source_syntax(&mut self, syntax: &Syntax) -> Lowered {
        self.detected_fork_bomb |= syntax.fork_bomb();
        let parent_aliases = self.active_aliases.clone();
        let parent_eligible = self.next_alias_eligible;
        let mut lowered = Lowered::default();
        for unit in syntax.parse_units() {
            self.active_aliases = Some(self.state.lookup.alias_snapshot());
            self.next_alias_eligible = Some(true);
            let end = unit
                .iter()
                .position(is_return_statement)
                .map_or(unit.len(), |index| index + 1);
            lowered.extend(self.lower_statements(&unit[..end]));
            if end < unit.len() || unit.last().is_some_and(is_return_statement) {
                break;
            }
        }
        self.active_aliases = parent_aliases;
        self.next_alias_eligible = parent_eligible;
        lowered
    }

    pub(super) fn invalidate_unknown_current_shell_code(&mut self, stage: usize) {
        self.visible_execution_states.push(VisibleExecutionState {
            stage,
            state: self.state.clone(),
            ambient_variables: self.ambient_variables.clone(),
        });
        self.unresolved_current_shell_stages.insert(stage);
        self.complete = false;
        self.state.cwd = Cwd::Unknown;
        self.state.unknown_variables = true;
        for binding in &mut self.state.variables {
            if binding.readonly != BindingAttribute::Yes {
                binding.value = VariableValue::Unknown;
                binding.origins.clear();
            }
        }
        self.state.tar_options.assign(None);
        for binding in &mut self.state.functions {
            if binding.readonly != BindingAttribute::Yes {
                binding.name_definite = false;
            }
        }
        self.set_positionals_unknown(&[]);
        self.state.lastpipe = BindingAttribute::Unknown;
        self.state.lookup.invalidate_all();
    }

    pub(super) fn enter_payload(&mut self, bytes: usize) -> bool {
        const MAX_PAYLOAD_DEPTH: usize = 32;
        if self.payload_depth >= MAX_PAYLOAD_DEPTH || bytes > crate::INVOCATION_EVIDENCE_CAP {
            self.complete = false;
            return false;
        }
        self.payload_depth += 1;
        true
    }
}
