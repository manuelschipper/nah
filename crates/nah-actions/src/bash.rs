//! Coordinates parsed Bash lowering; it does not observe the host or decide policy.

use std::collections::BTreeSet;

use nah_parse::{LoopControlKind, Redirect, Statement, Substitution, Syntax, Word};
use nah_proto::action::{InvocationInput, SemanticCode};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::observation::ObservationQuery;

use crate::bash_descendants::add_recursive_descendant_inspections;
use crate::bash_descriptor_state::{DescriptorFacts, SymbolicDescriptorId};
use crate::bash_flow::{add_artifact_flows, add_artifact_identities};
use crate::bash_lookup::{AliasSnapshot, LookupMode};
use crate::bash_model::{
    ChildCwdDraft, Draft, InvocationDraft, ProgramDraft, StageDraft, StdoutDraft, VariableValue,
};
use crate::bash_state::{
    BindingAttribute, Cwd, FunctionBody, PositionalValue, ShellState, known_cwd, merge_states,
};
use crate::bash_tar::TarOptionsState;
use crate::shell_word::{arithmetic_possibly_mutated_names, definite_parameter_assignments};

mod assignments;
mod child_shell;
mod command;
mod command_builtins;
mod command_classification;
mod command_commit;
mod command_descriptors;
mod command_effects;
mod command_payload;
mod command_preparation;
mod command_resources;
mod control_flow;
mod filesystem;
mod function_state;
mod invocation_flow;
mod payload;
mod positionals;
mod tar_state;
mod variables;
mod word_resolution;
mod words;

struct Lowerer {
    complete: bool,
    stages: Vec<StageDraft>,
    flows: Vec<(usize, usize)>,
    queries: Vec<ObservationQuery>,
    state: ShellState,
    ambient_variables: Vec<(String, VariableValue)>,
    runtime_variables: Vec<(String, VariableValue)>,
    initial_cwd: String,
    loop_depth: usize,
    home: String,
    critical_paths: Vec<AbsolutePath>,
    platform: Platform,
    payload_depth: usize,
    conditional_depth: usize,
    analysis_refused: bool,
    function_bodies: Vec<FunctionBody>,
    active_function_calls: Vec<usize>,
    function_local_scopes: Vec<Vec<String>>,
    next_lookup_mode: Option<LookupMode>,
    active_aliases: Option<AliasSnapshot>,
    next_alias_eligible: Option<bool>,
    active_alias_expansions: Vec<String>,
    alias_expansions: usize,
    function_expansions: usize,
    asynchronous_depth: usize,
    detected_fork_bomb: bool,
    visible_stdin: Option<VisibleStdin>,
    visible_execution_states: Vec<VisibleExecutionState>,
    inline_child_stages: BTreeSet<usize>,
    inline_child_cwds: Vec<ChildCwdDraft>,
    inline_report: nah_inline::InlineReport,
    inline_failed: bool,
    inline_child_count: usize,
    inline_child_bytes: usize,
    prelowered_visible_stages: BTreeSet<usize>,
    unresolved_current_shell_stages: BTreeSet<usize>,
    tracked_execution_stream_stages: BTreeSet<usize>,
    pending_visible_child_state: Option<VisibleExecutionState>,
    suppress_bash_startup: bool,
    next_descriptor_id: usize,
    // Set while lowering arguments that only might be a command, so the same
    // question is not asked again about their own arguments.
    speculative: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VisibleStdin {
    value: String,
    origins: Vec<usize>,
}

#[derive(Clone)]
struct VisibleExecutionState {
    stage: usize,
    state: ShellState,
    ambient_variables: Vec<(String, VariableValue)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssignmentUpdate {
    value: Option<String>,
    origins: Vec<usize>,
}

#[derive(Default)]
struct InjectedOrigins {
    name: Vec<usize>,
    arguments: Vec<Vec<usize>>,
}

struct AliasInvocation<'a> {
    name: &'a str,
    name_substitutions: &'a [Substitution],
    assignments: &'a [(String, Word)],
    arguments: &'a [Word],
    redirects: &'a [Redirect],
    injected_origins: &'a InjectedOrigins,
}

#[derive(Clone, Copy)]
struct CommandContext<'a> {
    injected_origins: &'a InjectedOrigins,
    exact_target: Option<&'a str>,
    builtin_target: bool,
}

struct PositionalCommand {
    name: String,
    arguments: Vec<Word>,
    origins: InjectedOrigins,
}

enum PositionalExpansion {
    NotPositional,
    Exact(Vec<PositionalValue>),
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PayloadExecution {
    CurrentShell,
    CurrentShellCommand,
    CurrentShellDefaultPath,
    CurrentShellBuiltin,
    Isolated,
    IsolatedWithFunctions,
}

impl PayloadExecution {
    const fn lookup_mode(self) -> Option<LookupMode> {
        match self {
            Self::CurrentShellCommand => Some(LookupMode::Command),
            Self::CurrentShellDefaultPath => Some(LookupMode::CommandDefaultPath),
            Self::CurrentShellBuiltin => Some(LookupMode::BuiltinOnly),
            Self::CurrentShell | Self::Isolated | Self::IsolatedWithFunctions => None,
        }
    }

    const fn persists_state(self) -> bool {
        matches!(
            self,
            Self::CurrentShell
                | Self::CurrentShellCommand
                | Self::CurrentShellDefaultPath
                | Self::CurrentShellBuiltin
        )
    }
}

#[derive(Clone, Default)]
struct Lowered {
    stages: Vec<usize>,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
}

impl Lowered {
    fn extend(&mut self, other: Self) {
        self.stages.extend(other.stages);
        self.inputs.extend(other.inputs);
        self.outputs.extend(other.outputs);
    }
}

pub(crate) fn draft(
    syntax: &Syntax,
    requested_cwd: &AbsolutePath,
    home: &AbsolutePath,
    platform: Platform,
    ambient_variables: &[(String, VariableValue)],
    critical_paths: &[AbsolutePath],
) -> (
    Draft,
    Draft,
    Vec<ObservationQuery>,
    nah_inline::InlineReport,
    bool,
) {
    let mut lowerer = Lowerer::new(
        syntax.complete(),
        requested_cwd,
        home,
        platform,
        ambient_variables,
        critical_paths,
    );
    lowerer.lower_syntax(syntax);
    lowerer.finish()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn visible_language_draft(
    outer_program: &str,
    interpreter: &str,
    analysis_program: &str,
    source: &str,
    input: InvocationInput,
    requested_cwd: &AbsolutePath,
    home: &AbsolutePath,
    platform: Platform,
    ambient_variables: &[(String, VariableValue)],
    critical_paths: &[AbsolutePath],
) -> (
    Draft,
    Draft,
    Vec<ObservationQuery>,
    nah_inline::InlineReport,
    bool,
) {
    visible_language_draft_with_profile(
        outer_program,
        interpreter,
        analysis_program,
        source,
        input,
        requested_cwd,
        home,
        platform,
        ambient_variables,
        critical_paths,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn visible_ipython_draft(
    outer_program: &str,
    source: &str,
    input: InvocationInput,
    requested_cwd: &AbsolutePath,
    home: &AbsolutePath,
    platform: Platform,
    ambient_variables: &[(String, VariableValue)],
    critical_paths: &[AbsolutePath],
) -> (
    Draft,
    Draft,
    Vec<ObservationQuery>,
    nah_inline::InlineReport,
    bool,
) {
    visible_language_draft_with_profile(
        outer_program,
        "ipython",
        "ipython",
        source,
        input,
        requested_cwd,
        home,
        platform,
        ambient_variables,
        critical_paths,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn visible_language_draft_with_profile(
    outer_program: &str,
    interpreter: &str,
    analysis_program: &str,
    source: &str,
    input: InvocationInput,
    requested_cwd: &AbsolutePath,
    home: &AbsolutePath,
    platform: Platform,
    ambient_variables: &[(String, VariableValue)],
    critical_paths: &[AbsolutePath],
    persistent_ipython: bool,
) -> (
    Draft,
    Draft,
    Vec<ObservationQuery>,
    nah_inline::InlineReport,
    bool,
) {
    let complete = input.complete();
    let mut lowerer = Lowerer::new(
        complete,
        requested_cwd,
        home,
        platform,
        ambient_variables,
        critical_paths,
    );
    lowerer.stages.push(StageDraft {
        invocation: InvocationDraft::CodeExecution {
            program: outer_program.to_owned(),
            interpreter: Some(interpreter.to_owned()),
            source: SemanticCode::INTERPRETER_INLINE,
            code: Some(source.to_owned()),
            input: Some(input),
            words: Vec::new(),
            argv: None,
        },
        invocation_cwd: None,
        child_cwd_keys: Vec::new(),
        filesystems: Vec::new(),
        git_operations: Vec::new(),
        git_project_scoped: false,
        network_outbound: false,
        network_endpoints: Vec::new(),
        system_states: Vec::new(),
        fifo_creations: Vec::new(),
        stdout: StdoutDraft::Unknown,
        content_writes: Vec::new(),
        payload_depth: 0,
        conditional_depth: 0,
        execution_dominators: Vec::new(),
    });
    let mut state = lowerer.state.clone();
    state.cwd = Cwd::Unknown;
    if let Some(pwd) = state
        .variables
        .iter_mut()
        .find(|binding| binding.name == "PWD")
    {
        pwd.value = VariableValue::Unknown;
        pwd.origins.clear();
    }
    lowerer.analyze_direct_inline_stage(
        VisibleExecutionState {
            stage: 0,
            state,
            ambient_variables: lowerer.ambient_variables.clone(),
        },
        analysis_program,
        source,
        persistent_ipython,
    );
    lowerer.finish()
}

impl Lowerer {
    #[allow(clippy::too_many_arguments)]
    fn new(
        complete: bool,
        requested_cwd: &AbsolutePath,
        home: &AbsolutePath,
        platform: Platform,
        ambient_variables: &[(String, VariableValue)],
        critical_paths: &[AbsolutePath],
    ) -> Self {
        Self {
            complete,
            stages: Vec::new(),
            flows: Vec::new(),
            queries: Vec::new(),
            state: ShellState::initial(requested_cwd.as_str(), home.as_str()),
            ambient_variables: ambient_variables.to_vec(),
            runtime_variables: ambient_variables.to_vec(),
            initial_cwd: requested_cwd.as_str().to_owned(),
            loop_depth: 0,
            home: home.as_str().to_owned(),
            critical_paths: critical_paths.to_vec(),
            platform,
            payload_depth: 0,
            conditional_depth: 0,
            analysis_refused: false,
            function_bodies: Vec::new(),
            active_function_calls: Vec::new(),
            function_local_scopes: Vec::new(),
            next_lookup_mode: None,
            active_aliases: None,
            next_alias_eligible: None,
            active_alias_expansions: Vec::new(),
            alias_expansions: 0,
            function_expansions: 0,
            asynchronous_depth: 0,
            detected_fork_bomb: false,
            visible_stdin: None,
            visible_execution_states: Vec::new(),
            inline_child_stages: BTreeSet::new(),
            inline_child_cwds: Vec::new(),
            inline_report: nah_inline::InlineReport::default(),
            inline_failed: false,
            inline_child_count: 0,
            inline_child_bytes: 0,
            prelowered_visible_stages: BTreeSet::new(),
            unresolved_current_shell_stages: BTreeSet::new(),
            tracked_execution_stream_stages: BTreeSet::new(),
            pending_visible_child_state: None,
            suppress_bash_startup: false,
            next_descriptor_id: 0,
            speculative: false,
        }
    }

    fn finish(
        mut self,
    ) -> (
        Draft,
        Draft,
        Vec<ObservationQuery>,
        nah_inline::InlineReport,
        bool,
    ) {
        self.lower_visible_programs();
        self.attach_fork_bomb();
        self.ensure_analysis_refusal_stage();
        let mut coverage_draft = self.coverage_draft();
        add_artifact_flows(&self.stages, &mut self.flows, self.platform);
        add_artifact_identities(&mut self.stages, self.platform);
        add_recursive_descendant_inspections(
            &mut self.stages,
            &self.flows,
            &mut self.queries,
            self.platform,
        );
        add_artifact_flows(
            &coverage_draft.stages,
            &mut coverage_draft.flows,
            self.platform,
        );
        add_artifact_identities(&mut coverage_draft.stages, self.platform);
        add_recursive_descendant_inspections(
            &mut coverage_draft.stages,
            &coverage_draft.flows,
            &mut self.queries,
            self.platform,
        );
        let draft = Draft {
            complete: self.complete,
            analysis_refused: self.analysis_refused,
            child_cwds: self.inline_child_cwds,
            stages: self.stages,
            flows: self.flows,
        };
        (
            draft,
            coverage_draft,
            self.queries,
            self.inline_report,
            self.inline_failed,
        )
    }

    fn coverage_draft(&self) -> Draft {
        let mut old_to_new = vec![None; self.stages.len()];
        let mut stages = Vec::new();
        for (old, stage) in self.stages.iter().enumerate() {
            if self.inline_child_stages.contains(&old) {
                continue;
            }
            old_to_new[old] = Some(stages.len());
            stages.push(stage.clone());
        }
        for stage in &mut stages {
            stage.execution_dominators = stage
                .execution_dominators
                .iter()
                .filter_map(|old| old_to_new.get(*old).copied().flatten())
                .collect();
        }
        let flows = self
            .flows
            .iter()
            .filter_map(|(from, to)| {
                Some((
                    old_to_new.get(*from).copied().flatten()?,
                    old_to_new.get(*to).copied().flatten()?,
                ))
            })
            .collect();
        Draft {
            complete: self.complete,
            analysis_refused: self.analysis_refused,
            child_cwds: self.inline_child_cwds.clone(),
            stages,
            flows,
        }
    }

    fn merged_state(&mut self, states: &[ShellState]) -> ShellState {
        let (state, origins_saturated) = merge_states(states, &self.function_bodies);
        if origins_saturated {
            self.complete = false;
            self.analysis_refused = true;
        }
        state
    }

    fn lower_syntax(&mut self, syntax: &Syntax) -> Lowered {
        self.detected_fork_bomb |= syntax.fork_bomb();
        let parent_aliases = self.active_aliases.clone();
        let parent_eligible = self.next_alias_eligible;
        let mut lowered = Lowered::default();
        for unit in syntax.parse_units() {
            self.active_aliases = Some(self.state.lookup.alias_snapshot());
            self.next_alias_eligible = Some(true);
            lowered.extend(self.lower_statements(unit));
        }
        self.active_aliases = parent_aliases;
        self.next_alias_eligible = parent_eligible;
        lowered
    }

    fn attach_fork_bomb(&mut self) {
        if !self.detected_fork_bomb {
            return;
        }
        self.complete = false;
        if let Some(stage) = self.stages.first_mut() {
            if !stage.system_states.contains(&SemanticCode::FORK_BOMB) {
                stage.system_states.push(SemanticCode::FORK_BOMB);
            }
            return;
        }
        self.stages.push(StageDraft {
            invocation: InvocationDraft::Opaque {
                program: ProgramDraft::Static("bash".into()),
                words: vec!["bash".into()],
                argv: None,
            },
            invocation_cwd: known_cwd(&self.state).map(str::to_owned),
            child_cwd_keys: Vec::new(),
            filesystems: Vec::new(),
            git_operations: Vec::new(),
            git_project_scoped: false,
            network_outbound: false,
            network_endpoints: Vec::new(),
            system_states: vec![SemanticCode::FORK_BOMB],
            fifo_creations: Vec::new(),
            stdout: StdoutDraft::Unknown,
            content_writes: Vec::new(),
            payload_depth: self.payload_depth,
            conditional_depth: self.conditional_depth,
            execution_dominators: Vec::new(),
        });
    }

    fn ensure_analysis_refusal_stage(&mut self) {
        if !self.analysis_refused || !self.stages.is_empty() {
            return;
        }
        self.stages.push(StageDraft {
            invocation: InvocationDraft::Opaque {
                program: ProgramDraft::Static("bash".into()),
                words: vec!["bash".into()],
                argv: None,
            },
            invocation_cwd: known_cwd(&self.state).map(str::to_owned),
            child_cwd_keys: Vec::new(),
            filesystems: Vec::new(),
            git_operations: Vec::new(),
            git_project_scoped: false,
            network_outbound: false,
            network_endpoints: Vec::new(),
            system_states: Vec::new(),
            fifo_creations: Vec::new(),
            stdout: StdoutDraft::Unknown,
            content_writes: Vec::new(),
            payload_depth: self.payload_depth,
            conditional_depth: self.conditional_depth,
            execution_dominators: Vec::new(),
        });
    }

    fn lower_statements(&mut self, statements: &[Statement]) -> Lowered {
        let mut lowered = Lowered::default();
        let mut states = vec![self.state.clone()];
        for (index, statement) in statements.iter().enumerate() {
            let mut exits = Vec::new();
            for entry in std::mem::take(&mut states) {
                self.state.clone_from(&entry);
                lowered.extend(self.lower_statement(statement));
                let success = self.state.clone();
                if !exits.contains(&success) {
                    exits.push(success.clone());
                }
                if index + 1 < statements.len()
                    && success.cwd != entry.cwd
                    && matches!(success.cwd, Cwd::Known(_))
                    && !exits.contains(&entry)
                {
                    // A semicolon or newline runs the next statement whether
                    // a state-changing command succeeded or failed. Keep both
                    // states so relative paths and explicit PWD values remain
                    // visible on either path.
                    exits.push(entry);
                }
            }
            const MAX_SEQUENCE_STATES: usize = 16;
            if exits.len() > MAX_SEQUENCE_STATES {
                self.complete = false;
                self.analysis_refused = true;
                exits = vec![self.merged_state(&exits)];
            } else if exits.len() > 1 {
                self.complete = false;
            }
            states = exits;
        }
        self.state = self.merged_state(&states);
        lowered
    }

    fn lower_optional_statement(&mut self, statement: &Statement) -> Lowered {
        self.conditional_depth += 1;
        let lowered = self.lower_statement(statement);
        self.conditional_depth -= 1;
        lowered
    }

    fn lower_optional_statements(&mut self, statements: &[Statement]) -> Lowered {
        self.conditional_depth += 1;
        let lowered = self.lower_statements(statements);
        self.conditional_depth -= 1;
        lowered
    }

    fn lower_statement(&mut self, statement: &Statement) -> Lowered {
        match statement {
            Statement::Command {
                name,
                name_substitutions,
                assignments,
                unmodeled_assignments,
                arguments,
                redirects,
            } => {
                let mut lowered =
                    self.lower_unmodeled_command_assignments(assignments, unmodeled_assignments);
                let invocation = if let Some(positional) =
                    self.positional_command(name, name_substitutions, arguments)
                {
                    self.lower_invocation(
                        &positional.name,
                        &[],
                        assignments,
                        &positional.arguments,
                        redirects,
                        &positional.origins,
                    )
                } else {
                    self.lower_invocation(
                        name,
                        name_substitutions,
                        assignments,
                        arguments,
                        redirects,
                        &InjectedOrigins::default(),
                    )
                };
                lowered.extend(invocation);
                lowered
            }
            Statement::Assignments {
                bindings,
                unmodeled,
            } => self.lower_assignments(bindings, unmodeled),
            Statement::Redirected { body, redirects } => self.lower_redirected(body, redirects),
            Statement::RedirectOnly {
                redirects,
                produces_stdout,
            } => self.lower_redirect_only(redirects, *produces_stdout),
            Statement::Pipeline { operators, stages } => {
                let pipeline_state = self.state.clone();
                let mut lowered = Vec::with_capacity(stages.len());
                let mut visible_stdin = None;
                let mut final_state = pipeline_state.clone();
                for (index, pipeline_stage) in stages.iter().enumerate() {
                    self.state.clone_from(&pipeline_state);
                    self.visible_stdin = visible_stdin;
                    let stage = self.lower_optional_statement(pipeline_stage);
                    visible_stdin = self.visible_pipeline_output(&stage);
                    if index + 1 == stages.len() {
                        final_state = self.state.clone();
                    }
                    lowered.push(stage);
                }
                self.visible_stdin = None;
                self.state = match pipeline_state.lastpipe {
                    BindingAttribute::No => pipeline_state,
                    BindingAttribute::Yes => final_state,
                    BindingAttribute::Unknown => {
                        self.complete = false;
                        self.merged_state(&[pipeline_state, final_state])
                    }
                };
                if lowered.iter().any(|stage| stage.stages.is_empty())
                    || lowered.len().saturating_sub(1) != operators.len()
                    || operators
                        .iter()
                        .any(|operator| !matches!(operator.as_str(), "|" | "|&"))
                {
                    self.complete = false;
                }
                for pair in lowered.windows(2) {
                    for from in &pair[0].outputs {
                        for to in &pair[1].inputs {
                            self.flows.push((*from, *to));
                        }
                    }
                }
                let inputs = lowered
                    .first()
                    .map(|stage| stage.inputs.clone())
                    .unwrap_or_default();
                let outputs = lowered
                    .last()
                    .map(|stage| stage.outputs.clone())
                    .unwrap_or_default();
                Lowered {
                    stages: lowered.into_iter().flat_map(|stage| stage.stages).collect(),
                    inputs,
                    outputs,
                }
            }
            Statement::Chain { operators, items } => {
                if items.len().saturating_sub(1) != operators.len()
                    || operators
                        .iter()
                        .any(|operator| !matches!(operator.as_str(), "&&" | "||"))
                {
                    self.complete = false;
                }
                let chain_state = self.state.clone();
                let mut reachable_tar_options = vec![chain_state.tar_options.clone()];
                let mut reachable_states = vec![chain_state.clone()];
                let mut state_changed = false;
                let mut lowered = Lowered::default();
                let mut previous_item_stages: Vec<usize> = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    let item_state = self.state.clone();
                    let item_conditional_depth = self.conditional_depth + usize::from(index > 0);
                    let item = if index == 0 {
                        self.lower_statement(item)
                    } else {
                        self.lower_optional_statement(item)
                    };
                    if index > 0
                        && (index == 1 || operators.get(index - 1) == operators.get(index - 2))
                    {
                        let mut dominators = previous_item_stages.clone();
                        for stage in &previous_item_stages {
                            dominators
                                .extend(self.stages[*stage].execution_dominators.iter().copied());
                        }
                        dominators.sort_unstable();
                        dominators.dedup();
                        for stage in &item.stages {
                            self.stages[*stage]
                                .execution_dominators
                                .extend(dominators.iter().copied());
                        }
                    }
                    previous_item_stages = item
                        .stages
                        .iter()
                        .copied()
                        .filter(|stage| {
                            self.stages[*stage].conditional_depth == item_conditional_depth
                        })
                        .collect();
                    lowered.extend(item);
                    state_changed |= self.state != item_state;
                    reachable_tar_options.push(self.state.tar_options.clone());
                    reachable_states.push(self.state.clone());
                    if operators
                        .get(index)
                        .is_some_and(|operator| operator == "||")
                    {
                        self.state = item_state;
                    }
                }
                if !operators.is_empty() && state_changed {
                    self.state = self.merged_state(&reachable_states);
                    self.state.tar_options = TarOptionsState::merge(reachable_tar_options);
                }
                lowered
            }
            Statement::Subshell { statements } => {
                let state = self.state.clone();
                let lowered = self.lower_statements(statements);
                self.state = state;
                lowered
            }
            Statement::Group { statements } => self.lower_statements(statements),
            Statement::If {
                branches,
                else_body,
            } => self.lower_if(branches, else_body),
            Statement::Loop {
                kind,
                condition,
                body,
            } => self.lower_loop(*kind, condition, body),
            Statement::For {
                variable,
                values,
                body,
            } => self.lower_for(variable, values, body),
            Statement::FunctionDefinition {
                name,
                body,
                redirects,
            } => {
                self.define_function(name, body, redirects);
                Lowered::default()
            }
            Statement::Coprocess { name, body } => {
                self.complete = false;
                let state = self.state.clone();
                self.asynchronous_depth += 1;
                let lowered = self.lower_optional_statement(body);
                self.asynchronous_depth -= 1;
                self.state = state;
                let producer = SymbolicDescriptorId::new(self.next_descriptor_id);
                let consumer = SymbolicDescriptorId::new(self.next_descriptor_id.saturating_add(1));
                self.next_descriptor_id = self.next_descriptor_id.saturating_add(2);
                let producer_facts =
                    DescriptorFacts::try_new(Vec::new(), lowered.outputs.clone(), Vec::new());
                let consumer_facts =
                    DescriptorFacts::try_new(Vec::new(), Vec::new(), lowered.inputs.clone());
                let coprocess = name.as_deref().unwrap_or("COPROC");
                let mut descriptors = self.state.descriptors.clone();
                let update = producer_facts
                    .and_then(|facts| descriptors.rebind_symbolic(producer, facts))
                    .and_then(|_| {
                        consumer_facts
                            .and_then(|facts| descriptors.rebind_symbolic(consumer, facts))
                    })
                    .and_then(|_| descriptors.set_coprocess_aliases(coprocess, producer, consumer));
                if update.is_err() {
                    self.analysis_refused = true;
                } else {
                    self.state.descriptors = descriptors;
                    self.set_local_variable_preserving_descriptor_alias(
                        coprocess,
                        VariableValue::Unknown,
                        Vec::new(),
                    );
                }
                lowered
            }
            Statement::LoopControl {
                kind,
                arguments,
                redirects,
            } => {
                let program = match kind {
                    LoopControlKind::Break => "break",
                    LoopControlKind::Continue => "continue",
                };
                let lowered = self.lower_command(
                    program,
                    &[],
                    &[],
                    arguments,
                    redirects,
                    CommandContext {
                        injected_origins: &InjectedOrigins::default(),
                        exact_target: None,
                        builtin_target: true,
                    },
                );
                if self.loop_depth == 0 {
                    self.complete = false;
                }
                lowered
            }
            Statement::Case { value, arms } => self.lower_case(value, arms),
            Statement::UnmodeledStateMutation {
                word, statements, ..
            } => {
                self.complete = false;
                let assignments =
                    definite_parameter_assignments(word.raw(), &self.visible_variables());
                self.refuse_parameter_assignment_words(std::iter::once(word.raw()));
                let (mut lowered, _) = self.lower_word_with_origins(word);
                let Some(names) = arithmetic_possibly_mutated_names(word.raw()) else {
                    self.refuse_parameter_assignment_state_with(assignments);
                    lowered.extend(self.lower_optional_statements(statements));
                    return lowered;
                };
                for name in names {
                    if name == "PATH" {
                        self.state.lookup.invalidate_all();
                    }
                    if name == "TAR_OPTIONS"
                        || self
                            .state
                            .possible_tar_options_aliases
                            .iter()
                            .chain(&self.state.definite_tar_options_aliases)
                            .any(|alias| alias == &name)
                    {
                        self.state.tar_options.assign(None);
                    }
                    self.mark_local_variable_unknown_with_origins(&name, Vec::new());
                }
                lowered.extend(self.lower_optional_statements(statements));
                lowered
            }
            Statement::Unsupported { statements, .. } => {
                self.complete = false;
                let state = self.state.clone();
                let lowered = self.lower_optional_statements(statements);
                self.state = state;
                lowered
            }
        }
    }
}
