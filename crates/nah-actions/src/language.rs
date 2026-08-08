//! Composes language-analysis drafts into shared action stages.

use nah_inline::{LanguageCallKind, LanguageDraft};
use nah_proto::action::{FilesystemOperation, NetworkDirection, SemanticCode};
use nah_proto::ctx::Platform;
use nah_proto::observation::{ObservationQuery, SymlinkTraversal};

use crate::bash_model::{FilesystemDraft, InvocationDraft, StageDraft, StdoutDraft};
use crate::paths::resolve_from_cwd;

pub(crate) struct LanguageExecution<'a> {
    pub(crate) stage: usize,
    pub(crate) program: &'a str,
    pub(crate) cwd: Option<&'a str>,
    pub(crate) pwd: Option<&'a str>,
}

pub(crate) struct LanguageDraftTarget<'a> {
    pub(crate) complete: &'a mut bool,
    pub(crate) stages: &'a mut Vec<StageDraft>,
    pub(crate) flows: &'a mut Vec<(usize, usize)>,
    pub(crate) queries: &'a mut Vec<ObservationQuery>,
    pub(crate) home: &'a str,
    pub(crate) platform: Platform,
}

impl LanguageDraftTarget<'_> {
    pub(crate) fn append(&mut self, execution: LanguageExecution<'_>, draft: &LanguageDraft) {
        *self.complete &= draft.complete();
        let first_stage = self.stages.len();
        let stage_ordinals = (0..draft.calls().len())
            .map(|ordinal| first_stage + ordinal)
            .collect::<Vec<_>>();
        let outer = &self.stages[execution.stage];
        let outer_payload_depth = outer.payload_depth;
        let outer_conditional_depth = outer.conditional_depth;
        let outer_dominators = outer.execution_dominators.clone();
        for (call_ordinal, call) in draft.calls().iter().enumerate() {
            let mut filesystems = Vec::new();
            for (filesystem_ordinal, filesystem) in call.filesystems().iter().enumerate() {
                let resolved = filesystem.requested().and_then(|requested| {
                    resolve_from_cwd(
                        execution.cwd,
                        execution.pwd,
                        requested,
                        self.home,
                        self.platform,
                        false,
                    )
                });
                let (key, descendant_key, requested, unresolved_selection) = match resolved {
                    Some(requested) => {
                        let key = format!(
                            "language-{:04}-path-{call_ordinal:04}-{filesystem_ordinal:02}",
                            execution.stage
                        );
                        debug_assert!(!self.queries.iter().any(|query| query.key() == key));
                        let inspect_descendants = filesystem.recursive()
                            && filesystem.operation() == FilesystemOperation::Read;
                        self.queries.push(ObservationQuery::Path {
                            key: key.clone(),
                            requested: requested.clone(),
                            cwd_key: crate::CWD_KEY.into(),
                            inspect_descendants,
                            symlink_traversal: SymlinkTraversal::None,
                        });
                        (
                            Some(key.clone()),
                            inspect_descendants.then_some(key),
                            requested,
                            false,
                        )
                    }
                    None => {
                        *self.complete = false;
                        (None, None, String::new(), true)
                    }
                };
                let identity = filesystem.identity_path().and_then(|identity| {
                    resolve_from_cwd(
                        execution.cwd,
                        execution.pwd,
                        identity,
                        self.home,
                        self.platform,
                        false,
                    )
                });
                if filesystem.identity_path().is_some() && identity.is_none() {
                    *self.complete = false;
                }
                let identity_key = if filesystem.identity_observed() {
                    identity.as_ref().map(|identity| {
                        let key = format!(
                            "language-{:04}-identity-{call_ordinal:04}-{filesystem_ordinal:02}",
                            execution.stage
                        );
                        debug_assert!(!self.queries.iter().any(|query| query.key() == key));
                        self.queries.push(ObservationQuery::Path {
                            key: key.clone(),
                            requested: identity.clone(),
                            cwd_key: crate::CWD_KEY.into(),
                            inspect_descendants: false,
                            symlink_traversal: SymlinkTraversal::None,
                        });
                        key
                    })
                } else {
                    None
                };
                let identity_requirements =
                    if identity.is_some() && filesystem.identity_requires_missing_target() {
                        key.clone().into_iter().collect()
                    } else {
                        Vec::new()
                    };
                filesystems.push(FilesystemDraft {
                    key,
                    descendant_key,
                    requested,
                    operation: filesystem.operation(),
                    git_guard: None,
                    recursive: filesystem.recursive(),
                    symlink_traversal: SymlinkTraversal::None,
                    network_bound: false,
                    unresolved_selection,
                    content_access: filesystem.content_access(),
                    identity,
                    identity_key,
                    identity_follows_final_symlink: filesystem.identity_follows_final_symlink(),
                    identity_requirements,
                    protects_descendants: filesystem.descendant_protection(),
                    follows_final_symlink: filesystem.follows_final_symlink(),
                    read_if_existing_file: false,
                    pattern: false,
                });
            }
            let operation = match call.kind() {
                LanguageCallKind::DirectFile => SemanticCode::DIRECT_FILE,
                LanguageCallKind::EvaluatedShell => SemanticCode::EVALUATED_SHELL,
                LanguageCallKind::LocalUtility => SemanticCode::LOCAL_UTILITY,
                LanguageCallKind::NetworkTransfer => SemanticCode::NETWORK_TRANSFER,
            };
            let mut network_outbound = false;
            let mut network_endpoints = Vec::new();
            if call.kind() == LanguageCallKind::NetworkTransfer {
                match call.endpoint().and_then(outbound_host) {
                    Some(host) => network_endpoints.push((NetworkDirection::Outbound, host)),
                    None => {
                        network_outbound = true;
                        *self.complete = false;
                    }
                }
            }
            let mut execution_dominators = outer_dominators.clone();
            execution_dominators.extend(
                call.execution_dominators()
                    .iter()
                    .filter_map(|ordinal| stage_ordinals.get(*ordinal).copied()),
            );
            execution_dominators.sort_unstable();
            execution_dominators.dedup();
            self.stages.push(StageDraft {
                invocation: InvocationDraft::Native {
                    program: execution.program.to_owned(),
                    operation,
                    input: call.input().clone(),
                },
                invocation_cwd: execution.cwd.map(str::to_owned),
                filesystems,
                root_move_destination_key: None,
                git_operations: Vec::new(),
                git_project_scoped: false,
                network_outbound,
                network_endpoints,
                system_states: Vec::new(),
                fifo_creations: Vec::new(),
                stdout: StdoutDraft::Unknown,
                content_writes: Vec::new(),
                payload_depth: outer_payload_depth,
                conditional_depth: outer_conditional_depth + call.conditional_depth(),
                execution_dominators,
            });
        }
        self.flows.extend(draft.flows().iter().filter_map(|flow| {
            Some((
                *stage_ordinals.get(flow.from())?,
                *stage_ordinals.get(flow.to())?,
            ))
        }));
    }
}

fn outbound_host(endpoint: &str) -> Option<String> {
    let endpoint = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))?;
    let authority = endpoint.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority.get(..=end)?;
        let suffix = authority.get(end + 1..)?;
        return (host.is_ascii()
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)))
        .then(|| host.to_owned());
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || !host.is_ascii()
        || host.contains(':')
        || port.is_some_and(|port| !valid_port(port))
    {
        None
    } else {
        Some(host.to_owned())
    }
}

fn valid_port(port: &str) -> bool {
    port.parse::<u16>().is_ok()
}
