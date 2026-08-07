//! Preserves visible and sourced shell payloads while coordinating bounded reparsing.

use std::collections::BTreeSet;

use nah_inline::{EnvironmentValue, LanguageDraft, NestedExecution};
use nah_parse::{Statement, Syntax, Word};
use nah_proto::action::InvocationInput;

use super::positionals::syntax_sets_positionals;
use super::{
    AssignmentUpdate, CommandContext, InjectedOrigins, Lowered, Lowerer, VisibleExecutionState,
    VisibleStdin,
};
use crate::bash_flow::add_artifact_flows;
use crate::bash_lookup::LookupMode;
use crate::bash_model::{InvocationDraft, ProgramDraft, StdoutDraft, VariableValue};
use crate::bash_state::{BindingAttribute, Cwd, current_pwd, known_cwd};
use crate::language::{LanguageDraftTarget, LanguageExecution};

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

fn requires_ipython_shell(draft: &LanguageDraft) -> bool {
    draft.calls().iter().any(|call| {
        let InvocationInput::Native { value, .. } = call.input() else {
            return false;
        };
        matches!(
            value.get("callable").and_then(|value| value.as_str()),
            Some("ipython.system" | "ipython.getoutput")
        )
    })
}

impl Lowerer {
    pub(super) fn resolve_visible_execution_at_boundary(&mut self, sink: usize) {
        let payload = self.visible_execution_payload(sink);
        let Some(payload) = payload else {
            let mut flows = self.flows.clone();
            add_artifact_flows(&self.stages, &mut flows, self.platform);
            if crate::bash_content::guarded_unknown_source(sink, &self.stages, &flows) {
                return;
            }
            let stream_source = matches!(
                &self.stages[sink].invocation,
                InvocationDraft::CodeExecution { source, .. }
                    if source == &nah_proto::action::SemanticCode::SHELL_STDIN
                        || source == &nah_proto::action::SemanticCode::INTERPRETER_STDIN
            );
            if stream_source {
                return;
            }
            self.prelowered_visible_stages.insert(sink);
            self.complete = false;
            return;
        };
        self.prelowered_visible_stages.insert(sink);
        let shell_payload = matches!(
            &self.stages[sink].invocation,
            InvocationDraft::CodeExecution { source, .. }
                if source.as_str().starts_with("shell-")
        );
        if !shell_payload {
            if let InvocationDraft::CodeExecution { code, .. } = &mut self.stages[sink].invocation {
                *code = Some(payload);
            }
            return;
        }
        self.lower_visible_shell_stage(sink, &payload);
    }

    fn lower_visible_shell_stage(&mut self, sink: usize, payload: &str) {
        let cwd = self.stages[sink].invocation_cwd.clone();
        let parent_depth = self.payload_depth;
        self.payload_depth = self.stages[sink].payload_depth;
        if !self.enter_payload(payload.len()) {
            self.payload_depth = parent_depth;
            return;
        }
        let syntax = match nah_parse::normalize(payload) {
            Ok(syntax) => syntax,
            Err(nah_parse::ParseError::ExceedsLimit(_)) => {
                self.complete = false;
                self.analysis_refused = true;
                self.payload_depth = parent_depth;
                return;
            }
            Err(_) => {
                self.complete = false;
                self.payload_depth = parent_depth;
                return;
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
                    continue;
                }
                self.lower_visible_shell_stage(sink, &payload);
            }
        }
        self.prelowered_visible_stages.clone_from(&seen);
        let mut outer_resolved = seen.clone();
        outer_resolved.extend(self.inline_child_stages.iter().copied());
        if crate::bash_content::has_unresolved_execution(&self.stages, &self.flows, &outer_resolved)
        {
            self.complete = false;
        }
        if self
            .unresolved_current_shell_stages
            .iter()
            .any(|stage| !self.inline_child_stages.contains(stage) && seen.contains(stage))
        {
            self.analysis_refused = true;
        }
        if self.tracked_execution_stream_stages.iter().any(|stage| {
            !self.inline_child_stages.contains(stage)
                && !seen.contains(stage)
                && !crate::bash_content::guarded_unknown_source(*stage, &self.stages, &self.flows)
        }) {
            self.analysis_refused = true;
        }
    }

    pub(super) fn analyze_inline_stage(&mut self, execution: VisibleExecutionState) {
        let Some((program, code, argv)) =
            self.stages
                .get(execution.stage)
                .and_then(|stage| match &stage.invocation {
                    InvocationDraft::CodeExecution {
                        program,
                        code: Some(code),
                        argv,
                        ..
                    } => Some((program.clone(), code.clone(), argv.clone())),
                    InvocationDraft::Opaque { .. }
                    | InvocationDraft::Known { .. }
                    | InvocationDraft::Native { .. }
                    | InvocationDraft::CodeExecution { code: None, .. } => None,
                })
        else {
            return;
        };
        let analysis_program =
            crate::bash_execution::inline_language_program(&program, argv.as_deref());
        self.analyze_language_stage(execution, &analysis_program, &program, &code, true, false);
    }

    pub(super) fn analyze_direct_inline_stage(
        &mut self,
        execution: VisibleExecutionState,
        program: &str,
        code: &str,
        persistent_ipython: bool,
    ) {
        self.analyze_language_stage(execution, program, program, code, false, persistent_ipython);
    }

    fn analyze_language_stage(
        &mut self,
        execution: VisibleExecutionState,
        analysis_program: &str,
        evidence_program: &str,
        code: &str,
        cwd_authoritative: bool,
        persistent_ipython: bool,
    ) {
        let environment = if persistent_ipython {
            Vec::new()
        } else {
            inline_environment(&execution)
        };
        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let input = nah_inline::InlineInput {
                program: analysis_program,
                code,
                home: &self.home,
                platform: self.platform,
            };
            let protection = nah_inline::ProtectionInput {
                critical_paths: &self.critical_paths,
                ambient_variables: &environment,
            };
            if persistent_ipython {
                nah_inline::analyze_persistent_ipython_with_language_effects(input, protection)
            } else {
                nah_inline::analyze_with_language_effects(input, protection)
            }
        }));
        let Ok(analysis) = report else {
            self.inline_failed = true;
            return;
        };
        let (report, language_draft) = analysis.into_parts();
        if !persistent_ipython
            && requires_ipython_shell(&language_draft)
            && !execution
                .state
                .variables
                .iter()
                .any(|binding| binding.name == "SHELL")
        {
            self.env_key("SHELL");
        }
        let nested = report.nested_executions().to_vec();
        self.inline_report.extend(report);
        let (cwd, pwd) = if cwd_authoritative {
            (known_cwd(&execution.state), current_pwd(&execution.state))
        } else {
            (None, None)
        };
        LanguageDraftTarget {
            complete: &mut self.complete,
            stages: &mut self.stages,
            flows: &mut self.flows,
            queries: &mut self.queries,
            home: &self.home,
            platform: self.platform,
        }
        .append(
            LanguageExecution {
                stage: execution.stage,
                program: evidence_program,
                cwd,
                pwd,
            },
            &language_draft,
        );
        for child in nested {
            if self.reserve_inline_child(&child) {
                self.lower_inline_child(&execution, child);
            }
        }
    }

    fn reserve_inline_child(&mut self, child: &NestedExecution) -> bool {
        const MAX_INLINE_CHILDREN: usize = 64;
        const MAX_INLINE_CHILD_BYTES: usize = crate::INVOCATION_EVIDENCE_CAP;
        let bytes = match child {
            NestedExecution::Shell { program, code, .. } => {
                program.len().saturating_add(code.len())
            }
            NestedExecution::Command { argv, .. } => argv.iter().map(String::len).sum(),
        };
        if self.inline_child_count >= MAX_INLINE_CHILDREN {
            self.inline_report
                .refuse(nah_inline::InlineRefusal::NestedExecutionLimit);
            return false;
        }
        if self.inline_child_bytes.saturating_add(bytes) > MAX_INLINE_CHILD_BYTES {
            self.inline_report
                .refuse(nah_inline::InlineRefusal::EvidenceLimit);
            return false;
        }
        self.inline_child_count += 1;
        self.inline_child_bytes += bytes;
        true
    }

    fn lower_inline_child(&mut self, execution: &VisibleExecutionState, child: NestedExecution) {
        let parent_state = self.state.clone();
        let parent_ambient_variables = self.ambient_variables.clone();
        let parent_lookup_mode = self.next_lookup_mode;
        let parent_aliases = self.active_aliases.clone();
        let parent_alias_eligible = self.next_alias_eligible;
        let parent_visible_stdin = self.visible_stdin.take();
        let parent_pending_visible_child_state = self.pending_visible_child_state.take();
        let parent_suppress_bash_startup = self.suppress_bash_startup;
        let parent_asynchronous_depth = self.asynchronous_depth;
        let parent_payload_depth = self.payload_depth;
        let parent_conditional_depth = self.conditional_depth;
        let parent_complete = self.complete;
        let parent_analysis_refused = self.analysis_refused;
        let parent_fork_bomb = self.detected_fork_bomb;
        let child_stage = self.stages.len();

        self.state = execution.state.clone();
        self.state.cwd = Cwd::Unknown;
        self.state.unknown_variables = true;
        for binding in &mut self.state.variables {
            if binding.readonly != BindingAttribute::Yes {
                binding.value = VariableValue::Unknown;
                binding.origins.clear();
            }
        }
        self.ambient_variables = execution
            .ambient_variables
            .iter()
            .map(|(name, _)| (name.clone(), VariableValue::Unknown))
            .collect();
        self.next_lookup_mode = None;
        self.active_aliases = None;
        self.next_alias_eligible = None;
        self.suppress_bash_startup = false;
        self.asynchronous_depth = 0;
        self.payload_depth = self.stages[execution.stage].payload_depth;
        self.conditional_depth = self.stages[execution.stage].conditional_depth;

        let (lowered, stdout_inherited) = match child {
            NestedExecution::Shell {
                code,
                stdout_inherited,
                ..
            } => (self.lower_inline_shell_payload(&code), stdout_inherited),
            NestedExecution::Command {
                argv,
                stdout_inherited,
            } => {
                if let Some((program, arguments)) = argv.split_first() {
                    let arguments = arguments
                        .iter()
                        .map(|argument| Word::from_literal(argument))
                        .collect::<Vec<_>>();
                    self.next_lookup_mode = Some(LookupMode::External);
                    (
                        self.lower_command(
                            program,
                            &[],
                            &[],
                            &arguments,
                            &[],
                            CommandContext {
                                injected_origins: &InjectedOrigins::default(),
                                exact_target: None,
                                builtin_target: false,
                            },
                        ),
                        stdout_inherited,
                    )
                } else {
                    (Lowered::default(), stdout_inherited)
                }
            }
        };
        if stdout_inherited {
            self.flows.extend(
                lowered
                    .outputs
                    .iter()
                    .map(|output| (*output, execution.stage)),
            );
        }

        let child_end = self.stages.len();
        self.inline_child_stages.extend(child_stage..child_end);
        let nested_fork_bomb = self.detected_fork_bomb && !parent_fork_bomb;
        self.state = parent_state;
        self.ambient_variables = parent_ambient_variables;
        self.next_lookup_mode = parent_lookup_mode;
        self.active_aliases = parent_aliases;
        self.next_alias_eligible = parent_alias_eligible;
        self.visible_stdin = parent_visible_stdin;
        self.pending_visible_child_state = parent_pending_visible_child_state;
        self.suppress_bash_startup = parent_suppress_bash_startup;
        self.asynchronous_depth = parent_asynchronous_depth;
        self.payload_depth = parent_payload_depth;
        self.conditional_depth = parent_conditional_depth;
        self.complete = parent_complete;
        self.analysis_refused = parent_analysis_refused;
        self.detected_fork_bomb = parent_fork_bomb;

        let fork_bomb_stage = if child_stage < child_end {
            child_stage
        } else {
            execution.stage
        };
        if nested_fork_bomb
            && let Some(stage) = self.stages.get_mut(fork_bomb_stage)
            && !stage
                .system_states
                .contains(&nah_proto::action::SemanticCode::FORK_BOMB)
        {
            stage
                .system_states
                .push(nah_proto::action::SemanticCode::FORK_BOMB);
        }
    }

    fn lower_inline_shell_payload(&mut self, payload: &str) -> Lowered {
        if !self.enter_payload(payload.len()) {
            return Lowered::default();
        }
        let mut lowered = Lowered::default();
        if let Ok(syntax) = nah_parse::normalize(payload) {
            self.detected_fork_bomb |= syntax.fork_bomb();
            if syntax.complete() {
                lowered = self.lower_syntax(&syntax);
            }
        }
        self.payload_depth -= 1;
        lowered
    }

    pub(super) fn lower_visible_execution_now(&mut self, sink: usize) -> Lowered {
        let Some(payload) = self.visible_execution_payload(sink) else {
            return Lowered::default();
        };
        self.prelowered_visible_stages.insert(sink);
        self.lower_current_shell_payload(&payload)
    }

    pub(super) fn visible_execution_payload(&mut self, sink: usize) -> Option<String> {
        let mut flows = self.flows.clone();
        add_artifact_flows(&self.stages, &mut flows, self.platform);
        crate::bash_content::visible_payloads(&self.stages, &flows, &BTreeSet::new())
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
            self.analysis_refused = true;
            return false;
        }
        self.payload_depth += 1;
        true
    }
}

fn inline_environment(execution: &VisibleExecutionState) -> Vec<(String, EnvironmentValue)> {
    let mut environment = execution
        .ambient_variables
        .iter()
        .map(|(name, value)| (name.clone(), inline_environment_value(value)))
        .collect::<Vec<_>>();
    for binding in &execution.state.variables {
        let value = inline_environment_value(&binding.value);
        if let Some((_, existing)) = environment
            .iter_mut()
            .find(|(name, _)| name == &binding.name)
        {
            *existing = value;
        } else {
            environment.push((binding.name.clone(), value));
        }
    }
    environment
}

fn inline_environment_value(value: &VariableValue) -> EnvironmentValue {
    match value {
        VariableValue::Unset => EnvironmentValue::Unset,
        VariableValue::Static(value) => EnvironmentValue::Static(value.clone()),
        VariableValue::Unknown => EnvironmentValue::Unknown,
    }
}
