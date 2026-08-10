//! Applies command redirects and descriptor-backed input/output effects.

use nah_parse::{Redirect, Word};
use nah_proto::action::FilesystemOperation;

use super::Lowerer;
use crate::bash_content::{Producer, mapfile_descriptor};
use crate::bash_descriptor_state::{DescriptorFlow, NetworkEndpoint};
use crate::bash_descriptors::{
    DescriptorReadEffects, DescriptorRedirectPlan, RedirectProvenance, descriptor_read_effects,
    standard_descriptor_effects,
};
use crate::bash_model::{FilesystemDraft, ProgramDraft, StdoutDraft};
use crate::shell_word::static_word;

pub(super) struct CommandDescriptorEffects {
    pub(super) producer: Producer,
    pub(super) content_writes: Vec<String>,
    pub(super) plan: DescriptorRedirectPlan,
    pub(super) filesystems: Vec<FilesystemDraft>,
    pub(super) network_endpoints: Vec<NetworkEndpoint>,
    pub(super) flows: Vec<DescriptorFlow>,
    pub(super) read: Option<DescriptorReadEffects>,
}

fn content_read_descriptor(program: &str, arguments: &[Word]) -> Option<String> {
    if !matches!(program, "read" | "mapfile" | "readarray") {
        return None;
    }
    if matches!(program, "mapfile" | "readarray") {
        return mapfile_descriptor(arguments);
    }
    let mut index = 0;
    while index < arguments.len() {
        let raw = arguments[index].raw();
        let static_value = static_word(raw, arguments[index].substitutions().is_empty());
        if static_value.as_deref() == Some("--") {
            break;
        }
        if static_value.as_deref() == Some("-u") {
            return arguments.get(index + 1).map(|word| word.raw().to_owned());
        }
        let unquoted = raw
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(raw);
        if let Some(descriptor) = unquoted
            .strip_prefix("-u")
            .filter(|value| !value.is_empty())
        {
            return Some(descriptor.to_owned());
        }
        index += 1;
    }
    Some("0".to_owned())
}

impl Lowerer {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn lower_command_descriptors(
        &mut self,
        program: &ProgramDraft,
        arguments: &[Word],
        redirects: &[Redirect],
        redirect_provenance: &[RedirectProvenance],
        builtin_target: bool,
        stage: usize,
        mut producer: Producer,
        mut content_writes: Vec<String>,
    ) -> CommandDescriptorEffects {
        let mut filesystems = Vec::new();
        let plan = self.descriptor_redirect_plan(redirects, redirect_provenance, stage);
        let redirected = &plan.command;
        let (mut network_endpoints, mut flows) = standard_descriptor_effects(redirected, stage);
        for redirect in redirects {
            self.lower_redirect(redirect, &mut filesystems);
        }
        if let Some(stdout) = redirected.binding("1").cloned()
            && stdout.tracks_content()
            && (!stdout.write_targets().is_empty() || !stdout.consumer_sinks().is_empty())
        {
            let exact_content = match &producer.stdout {
                StdoutDraft::Exact(output) => match stdout.appended_exact_output(output) {
                    Ok(content) => content,
                    Err(_) => {
                        self.complete = false;
                        self.analysis_refused = true;
                        None
                    }
                },
                StdoutDraft::Unknown | StdoutDraft::Stdin => None,
            };
            if self
                .state
                .descriptors
                .record_output(&stdout, exact_content.clone())
                .is_err()
            {
                self.complete = false;
                self.analysis_refused = true;
            }
            if stdout.write_targets().is_empty() {
                self.tracked_execution_stream_stages
                    .extend(stdout.consumer_sinks().iter().copied());
                if self.conditional_depth == 0 {
                    self.flows.retain(|(_, target)| {
                        !stdout.consumer_sinks().iter().any(|sink| sink == target)
                    });
                }
            }
            for target in stdout.write_targets() {
                if !filesystems.iter().any(|filesystem| {
                    filesystem.operation == FilesystemOperation::Write
                        && filesystem.requested == *target
                }) {
                    let inherited = stdout.consumer_sinks().iter().find_map(|sink| {
                        self.stages.get(*sink).and_then(|stage| {
                            stage.filesystems.iter().find(|filesystem| {
                                filesystem.operation == FilesystemOperation::Write
                                    && filesystem.requested == *target
                            })
                        })
                    });
                    if let Some(filesystem) = inherited {
                        filesystems.push(filesystem.clone());
                    } else {
                        self.complete = false;
                        self.analysis_refused = true;
                    }
                }
                if exact_content.is_some() {
                    content_writes.push(target.clone());
                }
            }
            if let Some(exact_content) = exact_content {
                producer.stdout = StdoutDraft::Exact(exact_content);
                content_writes.sort();
                content_writes.dedup();
            }
        }
        let read = if builtin_target {
            match program {
                ProgramDraft::Static(program)
                    if matches!(program.as_str(), "read" | "mapfile" | "readarray") =>
                {
                    content_read_descriptor(program, arguments).and_then(|descriptor| {
                        match descriptor_read_effects(
                            redirected,
                            &descriptor,
                            &self.visible_variables(),
                            stage,
                        ) {
                            Ok(effects) => effects,
                            Err(_) => {
                                self.complete = false;
                                self.analysis_refused = true;
                                None
                            }
                        }
                    })
                }
                ProgramDraft::Static(_) | ProgramDraft::Env { .. } | ProgramDraft::Unresolved => {
                    None
                }
            }
        } else {
            None
        };
        if let Some(read) = &read {
            self.complete &= read.complete;
            network_endpoints.extend(read.endpoints.iter().cloned());
            flows.extend(read.flows.iter().copied());
        }
        if matches!(program, ProgramDraft::Static(program)
            if matches!(program.as_str(), "chmod" | "chown" | "chgrp" | "setfacl" | "stat" | "touch"))
        {
            for filesystem in &mut filesystems {
                if filesystem.operation == FilesystemOperation::Read {
                    filesystem.content_access = false;
                }
            }
        }
        CommandDescriptorEffects {
            producer,
            content_writes,
            plan,
            filesystems,
            network_endpoints,
            flows,
            read,
        }
    }
}
