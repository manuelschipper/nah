//! Coordinates redirect and filesystem observation planning for Bash lowering.

use nah_parse::{Redirect, Statement, Substitution, Word};
use nah_proto::action::{FilesystemOperation, SemanticCode};
use nah_proto::observation::{ObservationQuery, SymlinkTraversal};

use super::assignments::valid_variable_name;
use super::{Lowered, Lowerer};
use crate::bash_content::{exact_redirect_input, redirect_content_target};
use crate::bash_descriptor_paths::{
    descriptor_alias_fd, descriptor_reference_path_from_cwd, is_fd_target, shell_network_host,
};
use crate::bash_descriptor_state::{
    DescriptorFacts, DescriptorFlow, DescriptorState, NetworkEndpoint, SymbolicDescriptorId,
};
use crate::bash_descriptors::{
    DescriptorRedirectPlan, RedirectProvenance, compound_descriptor_effects,
    descriptor_file_write_target, exact_descriptor_alias_name, filesystem_descriptor_effects,
    shell_descriptor_redirects, standard_descriptor_effects,
};
use crate::bash_filesystem::command_filesystems;
use crate::bash_flow::{redirects_stdin, redirects_stdout};
use crate::bash_model::{FilesystemDraft, InvocationDraft, StageDraft, StdoutDraft};
use crate::bash_state::{current_pwd, known_cwd};
use crate::bash_symlinks::has_dynamic_target;
use crate::paths::{cwd_relative, resolve_from_cwd};
use crate::shell_word::{
    contains_unquoted_pattern, referenced_env_names, static_filesystem_word, static_word,
};

pub(super) fn allocated_descriptor_variable(fd: Option<&str>) -> Option<&str> {
    let name = fd?.strip_prefix('{')?.strip_suffix('}')?;
    valid_variable_name(name).then_some(name)
}

pub(super) fn exact_redirect_process_substitution(redirect: &Redirect) -> Option<&Substitution> {
    let [substitution] = redirect.target_substitutions() else {
        return None;
    };
    let raw = redirect.target()?;
    match substitution {
        Substitution::ProcessInput { .. } if raw.starts_with("<(") && raw.ends_with(')') => {
            Some(substitution)
        }
        Substitution::ProcessOutput { .. } if raw.starts_with(">(") && raw.ends_with(')') => {
            Some(substitution)
        }
        Substitution::Command { .. }
        | Substitution::Backtick { .. }
        | Substitution::ProcessInput { .. }
        | Substitution::ProcessOutput { .. } => None,
    }
}

pub(super) fn redirect_operations(
    fd: Option<&str>,
    operator: &str,
    target: Option<&str>,
) -> Option<Vec<FilesystemOperation>> {
    match operator {
        "<" => Some(vec![FilesystemOperation::Read]),
        ">" | ">>" | ">|" | "&>" | "&>>" => Some(vec![FilesystemOperation::Write]),
        "<>" => Some(vec![FilesystemOperation::Read, FilesystemOperation::Write]),
        ">&" if fd.is_none() && target.is_some_and(|target| !is_fd_target(target)) => {
            Some(vec![FilesystemOperation::Write])
        }
        "<<" | "<<-" | "<<<" => Some(vec![]),
        // Descriptor duplication changes stream routing in an order-sensitive
        // way the v1 effect schema cannot encode.
        ">&" | "<&" => None,
        _ => None,
    }
}

pub(super) fn unresolved_read(requested: &str) -> FilesystemDraft {
    FilesystemDraft {
        key: None,
        descendant_key: None,
        requested: requested.to_owned(),
        cwd_relative: false,
        operation: FilesystemOperation::Read,
        git_guard: None,
        recursive: false,
        symlink_traversal: SymlinkTraversal::None,
        network_bound: false,
        unresolved_selection: true,
        content_access: true,
        identity: None,
        identity_key: None,
        identity_follows_final_symlink: false,
        identity_requirements: Vec::new(),
        protects_descendants: false,
        follows_final_symlink: true,
        read_if_existing_file: false,
        pattern: false,
    }
}

impl Lowerer {
    pub(super) fn resolve_requested(&mut self, target: &str) -> Option<String> {
        let expand_tilde = target.starts_with('~');
        let requested = resolve_from_cwd(
            known_cwd(&self.state),
            current_pwd(&self.state),
            target,
            &self.home,
            self.platform,
            expand_tilde,
        );
        if requested.is_none() {
            self.complete = false;
        }
        requested
    }

    pub(super) fn redirect_provenance(
        &mut self,
        redirects: &[Redirect],
        lowered_substitutions: &[(&Substitution, Lowered)],
    ) -> Vec<RedirectProvenance> {
        redirects
            .iter()
            .map(|redirect| {
                let allocation = allocated_descriptor_variable(redirect.fd()).map(|_| {
                    let id = SymbolicDescriptorId::new(self.next_descriptor_id);
                    self.next_descriptor_id = self.next_descriptor_id.saturating_add(1);
                    id
                });
                let process_substitution =
                    exact_redirect_process_substitution(redirect).and_then(|substitution| {
                        let nested =
                            lowered_substitutions
                                .iter()
                                .find_map(|(candidate, lowered)| {
                                    std::ptr::eq(*candidate, substitution).then_some(lowered)
                                })?;
                        let facts = match substitution {
                            Substitution::ProcessInput { .. } => {
                                let facts = DescriptorFacts::try_new(
                                    Vec::new(),
                                    nested.outputs.clone(),
                                    Vec::new(),
                                );
                                match (facts, self.visible_pipeline_output(nested)) {
                                    (Ok(facts), Some(visible)) => {
                                        facts.try_with_exact_content(visible.value)
                                    }
                                    (facts, None) => facts,
                                    (Err(error), Some(_)) => Err(error),
                                }
                            }
                            Substitution::ProcessOutput { .. } => DescriptorFacts::try_new(
                                Vec::new(),
                                Vec::new(),
                                nested.inputs.clone(),
                            )
                            .and_then(|facts| facts.try_with_exact_content(String::new())),
                            Substitution::Command { .. } | Substitution::Backtick { .. } => {
                                return None;
                            }
                        };
                        match facts {
                            Ok(facts) => Some(facts),
                            Err(_) => {
                                self.complete = false;
                                self.analysis_refused = true;
                                None
                            }
                        }
                    });
                let exact_input = exact_redirect_input(redirect);
                RedirectProvenance {
                    allocation,
                    process_substitution,
                    file_stage: None,
                    file_target: None,
                    exact_input,
                }
            })
            .collect()
    }

    pub(super) fn descriptor_redirect_plan(
        &mut self,
        redirects: &[Redirect],
        provenance: &[RedirectProvenance],
        file_stage: usize,
    ) -> DescriptorRedirectPlan {
        let mut provenance = provenance.to_vec();
        for (redirect, provenance) in redirects.iter().zip(&mut provenance) {
            provenance.file_stage = Some(file_stage);
            provenance.file_target = descriptor_file_write_target(redirect)
                .and_then(|target| self.resolve_requested(&target));
        }
        match shell_descriptor_redirects(
            redirects,
            &self.state.descriptors,
            &self.visible_variables(),
            &provenance,
        ) {
            Ok(plan) => {
                self.complete &= plan.complete;
                plan
            }
            Err(_) => {
                self.complete = false;
                self.analysis_refused = true;
                DescriptorRedirectPlan {
                    command: self.state.descriptors.clone(),
                    persistent: self.state.descriptors.clone(),
                    persists: false,
                    complete: false,
                }
            }
        }
    }

    pub(super) fn descriptor_filesystem_effects(
        &mut self,
        filesystems: &[FilesystemDraft],
        descriptors: &DescriptorState,
        stage: usize,
    ) -> (Vec<NetworkEndpoint>, Vec<DescriptorFlow>) {
        let variables = self.visible_variables();
        let cwd = known_cwd(&self.state);
        match filesystem_descriptor_effects(filesystems, descriptors, &variables, cwd, stage) {
            Ok((endpoints, flows, complete)) => {
                self.complete &= complete;
                (endpoints, flows)
            }
            Err(_) => {
                self.complete = false;
                self.analysis_refused = true;
                (Vec::new(), Vec::new())
            }
        }
    }

    pub(super) fn conservative_descriptor_effects(
        &mut self,
        descriptors: &DescriptorState,
        stage: usize,
    ) -> (Vec<NetworkEndpoint>, Vec<DescriptorFlow>) {
        match crate::bash_descriptors::possible_descriptor_effects(descriptors, stage) {
            Ok(effects) => effects,
            Err(_) => {
                self.complete = false;
                self.analysis_refused = true;
                (Vec::new(), Vec::new())
            }
        }
    }

    pub(super) fn lower_redirected(&mut self, body: &Statement, redirects: &[Redirect]) -> Lowered {
        self.refuse_redirect_parameter_assignments(redirects);
        let mut lowered_substitutions = Vec::new();
        let mut redirect_origins = Vec::new();
        for redirect in redirects {
            for raw in [redirect.target(), redirect.body()].into_iter().flatten() {
                for name in referenced_env_names(raw) {
                    self.prepare_variable_reference(&name);
                }
                redirect_origins.extend(self.variable_origins(raw));
            }
            for substitution in redirect
                .target_substitutions()
                .iter()
                .chain(redirect.body_substitutions())
            {
                let state = self.state.clone();
                let nested = self.lower_statements(substitution.statements());
                self.state = state;
                if matches!(
                    substitution,
                    Substitution::Command { .. } | Substitution::Backtick { .. }
                ) {
                    redirect_origins.extend(nested.outputs.iter().copied());
                }
                lowered_substitutions.push((substitution, nested));
            }
        }
        let redirect_origins = self.bounded_origins(redirect_origins);
        let provenance = self.redirect_provenance(redirects, &lowered_substitutions);
        // Compound-command redirects are opened before the body runs, so
        // resolve their paths against the entry state rather than a `cd`
        // performed inside the group.
        let resolved_redirects = self.resolved_redirects(redirects);
        let redirects = resolved_redirects.as_slice();
        let mut filesystem_drafts = Vec::new();
        let descriptor_plan =
            self.descriptor_redirect_plan(redirects, &provenance, self.stages.len());
        for redirect in redirects {
            self.lower_redirect(redirect, &mut filesystem_drafts);
        }
        let mut lowered = self.lower_statement(body);
        let Some(stage) = lowered.stages.last().copied() else {
            self.complete = false;
            let mut substitutions = Lowered::default();
            for (_, nested) in lowered_substitutions {
                substitutions.extend(nested);
            }
            substitutions.extend(lowered);
            return substitutions;
        };
        let (routed_endpoints, mut descriptor_flows) = compound_descriptor_effects(
            &descriptor_plan.command,
            &lowered.inputs,
            &lowered.outputs,
            stage,
        );
        let (filesystem_endpoints, filesystem_flows) =
            self.descriptor_filesystem_effects(&filesystem_drafts, &descriptor_plan.command, stage);
        descriptor_flows.extend(filesystem_flows);
        self.stages[stage].filesystems.extend(filesystem_drafts);
        self.stages[stage]
            .network_endpoints
            .extend(filesystem_endpoints);
        for (target, endpoint) in routed_endpoints {
            self.stages[target].network_endpoints.push(endpoint);
        }
        self.stages[stage].network_endpoints.sort();
        self.stages[stage].network_endpoints.dedup();
        for target in lowered
            .inputs
            .iter()
            .chain(&lowered.outputs)
            .copied()
            .filter(|target| *target != stage)
        {
            self.stages[target].network_endpoints.sort();
            self.stages[target].network_endpoints.dedup();
        }
        for origin in redirect_origins {
            self.flows.push((origin, stage));
        }
        self.flows.extend(descriptor_flows);
        if descriptor_plan.persists {
            self.state.descriptors = descriptor_plan.persistent;
        }
        if redirects_stdin(redirects) {
            lowered.inputs.clear();
        }
        if redirects_stdout(redirects) {
            lowered.outputs.clear();
        }
        let mut substitutions = Lowered::default();
        for (_, nested) in lowered_substitutions {
            substitutions.extend(nested);
        }
        substitutions.extend(lowered);
        substitutions
    }

    pub(super) fn lower_redirect_only(
        &mut self,
        redirects: &[Redirect],
        produces_stdout: bool,
    ) -> Lowered {
        self.refuse_redirect_parameter_assignments(redirects);
        let mut lowered = Lowered::default();
        let mut lowered_substitutions = Vec::new();
        let mut redirect_origins = Vec::new();
        for redirect in redirects {
            for raw in [redirect.target(), redirect.body()].into_iter().flatten() {
                for name in referenced_env_names(raw) {
                    self.prepare_variable_reference(&name);
                }
                redirect_origins.extend(self.variable_origins(raw));
            }
            for substitution in redirect
                .target_substitutions()
                .iter()
                .chain(redirect.body_substitutions())
            {
                let state = self.state.clone();
                let nested = self.lower_statements(substitution.statements());
                self.state = state;
                if matches!(
                    substitution,
                    Substitution::Command { .. } | Substitution::Backtick { .. }
                ) {
                    redirect_origins.extend(nested.outputs.iter().copied());
                }
                lowered_substitutions.push((substitution, nested.clone()));
                lowered.extend(nested);
            }
        }
        let redirect_origins = self.bounded_origins(redirect_origins);
        let provenance = self.redirect_provenance(redirects, &lowered_substitutions);

        let resolved_redirects = self.resolved_redirects(redirects);
        let redirects = resolved_redirects.as_slice();
        let mut filesystems = Vec::new();
        let stage = self.stages.len();
        let descriptor_plan = self.descriptor_redirect_plan(redirects, &provenance, stage);
        for redirect in redirects {
            self.lower_redirect(redirect, &mut filesystems);
        }
        let mut content_writes = redirect_content_target(redirects)
            .and_then(|target| self.resolve_requested(&target))
            .into_iter()
            .collect::<Vec<_>>();
        content_writes.sort();
        content_writes.dedup();

        let (mut network_endpoints, mut descriptor_flows) =
            standard_descriptor_effects(&descriptor_plan.command, stage);
        let (filesystem_endpoints, filesystem_flows) =
            self.descriptor_filesystem_effects(&filesystems, &descriptor_plan.command, stage);
        network_endpoints.extend(filesystem_endpoints);
        descriptor_flows.extend(filesystem_flows);
        self.stages.push(StageDraft {
            invocation: InvocationDraft::Known {
                program: "bash".into(),
                operation: SemanticCode::NULL_COMMAND,
                words: vec!["bash".into()],
                argv: Some(vec!["bash".into()]),
            },
            invocation_cwd: known_cwd(&self.state).map(str::to_owned),
            child_cwd_keys: Vec::new(),
            filesystems,
            git_operations: Vec::new(),
            git_project_scoped: false,
            network_outbound: false,
            network_endpoints,
            system_states: Vec::new(),
            fifo_creations: Vec::new(),
            stdout: if produces_stdout {
                StdoutDraft::Unknown
            } else {
                StdoutDraft::Exact(String::new())
            },
            content_writes,
            payload_depth: self.payload_depth,
            conditional_depth: self.conditional_depth,
            execution_dominators: Vec::new(),
        });
        for origin in redirect_origins {
            self.flows.push((origin, stage));
        }
        self.flows.extend(descriptor_flows);
        if descriptor_plan.persists {
            self.state.descriptors = descriptor_plan.persistent;
        }
        lowered.stages.push(stage);
        if produces_stdout {
            lowered.outputs.push(stage);
        }
        lowered
    }

    pub(super) fn lower_redirect(&mut self, redirect: &Redirect, out: &mut Vec<FilesystemDraft>) {
        if exact_redirect_process_substitution(redirect).is_some() {
            return;
        }
        if matches!(redirect.operator(), ">&" | "<&")
            && redirect.target().is_some_and(|target| {
                exact_descriptor_alias_name(target.trim_end_matches('-')).is_some()
            })
        {
            return;
        }
        if matches!(redirect.operator(), ">&" | "<&")
            && redirect
                .target()
                .and_then(|target| static_word(target, redirect.target_substitutions().is_empty()))
                .is_some_and(|target| is_fd_target(&target))
        {
            return;
        }
        let Some(operations) =
            redirect_operations(redirect.fd(), redirect.operator(), redirect.target())
        else {
            self.complete = false;
            return;
        };
        if operations.is_empty() {
            return;
        }
        let Some(raw) = redirect
            .target()
            .filter(|_| redirect.target_substitutions().is_empty())
        else {
            self.complete = false;
            return;
        };
        let Some(target) = static_filesystem_word(raw, true) else {
            self.complete = false;
            return;
        };
        if target.is_empty() {
            self.complete = false;
            return;
        }
        if shell_network_host(&target).is_some()
            || target.starts_with("/dev/tcp/")
            || target.starts_with("/dev/udp/")
        {
            return;
        }
        if descriptor_alias_fd(&target).is_some() {
            return;
        }
        // The shell expands a redirect target too, so the effect stays bounded
        // by its literal prefix rather than being dropped.
        let pattern = contains_unquoted_pattern(raw);
        let Some(requested) = self.resolve_requested(&target) else {
            return;
        };
        for operation in operations {
            self.add_filesystem_with_requirement(
                &requested,
                operation,
                false,
                false,
                pattern,
                cwd_relative(&target, self.platform),
                out,
            );
        }
    }

    pub(super) fn lower_command_filesystems(
        &mut self,
        program: &str,
        arguments: &[Word],
        patterns: &[String],
        out: &mut Vec<FilesystemDraft>,
    ) {
        let Some(specs) = command_filesystems(program, arguments) else {
            return;
        };
        if has_dynamic_target(arguments) {
            self.complete = false;
        }
        if !specs.is_empty() {
            self.complete = false;
        }
        let first = out.len();
        self.lower_filesystem_specs(&specs, patterns, out);
        if matches!(
            program,
            "chmod" | "chown" | "chgrp" | "setfacl" | "chattr" | "touch" | "mkfifo" | "mknod"
        ) {
            for filesystem in &mut out[first..] {
                filesystem.content_access = false;
            }
        } else if matches!(program, "ln" | "link") {
            for filesystem in &mut out[first..] {
                if filesystem.operation == FilesystemOperation::Read {
                    filesystem.content_access = false;
                }
            }
        }
    }

    pub(super) fn lower_filesystem_specs(
        &mut self,
        specs: &[(String, FilesystemOperation, bool)],
        patterns: &[String],
        out: &mut Vec<FilesystemDraft>,
    ) {
        for (target, operation, recursive) in specs {
            if target.is_empty() {
                self.complete = false;
                continue;
            }
            let pattern = patterns.iter().any(|pattern| {
                pattern == target
                    || target
                        .strip_suffix(pattern)
                        .is_some_and(|prefix| prefix.ends_with(['/', '\\']))
            });
            let Some(requested) = self.resolve_requested(target) else {
                continue;
            };
            self.add_filesystem_with_requirement(
                &requested,
                *operation,
                *recursive,
                false,
                pattern,
                cwd_relative(target, self.platform),
                out,
            );
        }
    }

    pub(super) fn add_filesystem(
        &mut self,
        requested: &str,
        operation: FilesystemOperation,
        recursive: bool,
        cwd_relative: bool,
        out: &mut Vec<FilesystemDraft>,
    ) {
        self.add_filesystem_with_requirement(
            requested,
            operation,
            recursive,
            false,
            false,
            cwd_relative,
            out,
        );
    }

    pub(super) fn add_existing_file(
        &mut self,
        requested: &str,
        cwd_relative: bool,
        out: &mut Vec<FilesystemDraft>,
    ) {
        self.add_filesystem_with_requirement(
            requested,
            FilesystemOperation::Read,
            false,
            true,
            false,
            cwd_relative,
            out,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn add_filesystem_with_requirement(
        &mut self,
        requested: &str,
        operation: FilesystemOperation,
        recursive: bool,
        read_if_existing_file: bool,
        pattern: bool,
        cwd_relative: bool,
        out: &mut Vec<FilesystemDraft>,
    ) {
        // The shell expands a pattern before any path exists to observe, so the
        // effect stays unresolved and coverage drops instead.
        let key = (!pattern
            && descriptor_reference_path_from_cwd(requested, known_cwd(&self.state)).is_none())
        .then(|| {
            let path_count = self
                .queries
                .iter()
                .filter(|query| matches!(query, ObservationQuery::Path { .. }))
                .count();
            let key = format!("path-{path_count}");
            self.queries.push(ObservationQuery::Path {
                key: key.clone(),
                requested: requested.into(),
                cwd_key: "cwd".into(),
                inspect_descendants: false,
                symlink_traversal: SymlinkTraversal::None,
            });
            key
        });
        out.push(FilesystemDraft {
            key,
            descendant_key: None,
            requested: requested.into(),
            cwd_relative,
            operation,
            git_guard: None,
            recursive,
            symlink_traversal: SymlinkTraversal::None,
            network_bound: false,
            unresolved_selection: false,
            content_access: true,
            identity: None,
            identity_key: None,
            identity_follows_final_symlink: false,
            identity_requirements: Vec::new(),
            protects_descendants: false,
            follows_final_symlink: true,
            read_if_existing_file,
            pattern,
        });
    }
}
