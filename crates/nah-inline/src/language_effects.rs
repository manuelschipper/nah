//! Owns language-effect interpretation results and their bounded public contracts.

use nah_proto::action::{FilesystemOperation, InvocationInput};

use crate::{InlineRefusal, InlineReport};

const MAX_PUBLIC_LANGUAGE_CALLS: usize = 64;
const MAX_LANGUAGE_SAFETY_CALLS: usize = 256;
const MAX_LANGUAGE_SAFETY_FLOWS: usize = 4_096;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LanguageAnalysis {
    report: InlineReport,
    draft: LanguageDraft,
}

impl LanguageAnalysis {
    pub(crate) fn new(mut report: InlineReport, draft: LanguageDraft) -> Self {
        for refusal in draft.refusals() {
            report.refuse(*refusal);
        }
        Self { report, draft }
    }

    pub(crate) fn refused(refusal: InlineRefusal) -> Self {
        Self::new(InlineReport::refused(refusal), LanguageDraft::partial())
    }

    pub fn report(&self) -> &InlineReport {
        &self.report
    }

    pub fn draft(&self) -> &LanguageDraft {
        &self.draft
    }

    pub fn into_report(self) -> InlineReport {
        self.report
    }

    pub fn into_parts(self) -> (InlineReport, LanguageDraft) {
        (self.report, self.draft)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageDraft {
    complete: bool,
    calls: Vec<LanguageCall>,
    flows: Vec<LanguageFlow>,
    language_safety_flows: Vec<LanguageFlow>,
    refusals: Vec<InlineRefusal>,
}

impl Default for LanguageDraft {
    fn default() -> Self {
        Self {
            complete: true,
            calls: Vec::new(),
            flows: Vec::new(),
            language_safety_flows: Vec::new(),
            refusals: Vec::new(),
        }
    }
}

impl LanguageDraft {
    pub(crate) fn partial() -> Self {
        Self {
            complete: false,
            ..Self::default()
        }
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn calls(&self) -> &[LanguageCall] {
        &self.calls[..self.calls.len().min(MAX_PUBLIC_LANGUAGE_CALLS)]
    }

    pub fn language_safety_calls(&self) -> &[LanguageCall] {
        &self.calls
    }

    pub fn flows(&self) -> &[LanguageFlow] {
        &self.flows
    }

    pub fn language_safety_flows(&self) -> &[LanguageFlow] {
        &self.language_safety_flows
    }

    pub(crate) fn refusals(&self) -> &[InlineRefusal] {
        &self.refusals
    }

    pub(crate) fn set_partial(&mut self) {
        self.complete = false;
    }

    pub(crate) fn extend(&mut self, other: Self) {
        let first = self.calls.len();
        self.complete &= other.complete;
        for call in other.calls {
            self.push_call(call);
        }
        for flow in other.language_safety_flows {
            self.push_flow(first + flow.from, first + flow.to);
        }
        for refusal in other.refusals {
            self.refuse(refusal);
        }
    }

    pub(crate) fn push_call(&mut self, call: LanguageCall) -> Option<usize> {
        if self.calls.len() >= MAX_PUBLIC_LANGUAGE_CALLS {
            self.complete = false;
            self.refuse(InlineRefusal::LanguageCallLimit);
        }
        if self.calls.len() >= MAX_LANGUAGE_SAFETY_CALLS {
            self.refuse(InlineRefusal::LanguageSafetyLimit);
            return None;
        }
        let ordinal = self.calls.len();
        self.calls.push(call);
        Some(ordinal)
    }

    pub(crate) fn push_flow(&mut self, from: usize, to: usize) {
        let flow = LanguageFlow { from, to };
        if from != to && !self.language_safety_flows.contains(&flow) {
            if self.language_safety_flows.len() >= MAX_LANGUAGE_SAFETY_FLOWS {
                self.complete = false;
                self.refuse(InlineRefusal::LanguageSafetyLimit);
                return;
            }
            self.language_safety_flows.push(flow);
            self.language_safety_flows.sort_unstable();
            if from < MAX_PUBLIC_LANGUAGE_CALLS && to < MAX_PUBLIC_LANGUAGE_CALLS {
                self.flows.push(flow);
                self.flows.sort_unstable();
            }
        }
    }

    pub(crate) fn refuse(&mut self, refusal: InlineRefusal) {
        if !self.refusals.contains(&refusal) {
            self.refusals.push(refusal);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanguageCallKind {
    DirectFile,
    EvaluatedShell,
    HostPower,
    LocalUtility,
    NetworkTransfer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageCall {
    kind: LanguageCallKind,
    input: InvocationInput,
    filesystems: Vec<LanguageFilesystem>,
    endpoint: Option<String>,
    conditional_depth: usize,
    execution_dominators: Vec<usize>,
}

impl LanguageCall {
    pub(crate) fn new(
        kind: LanguageCallKind,
        input: InvocationInput,
        filesystems: Vec<LanguageFilesystem>,
        endpoint: Option<String>,
        conditional_depth: usize,
        execution_dominators: Vec<usize>,
    ) -> Self {
        Self {
            kind,
            input,
            filesystems,
            endpoint,
            conditional_depth,
            execution_dominators,
        }
    }

    pub const fn kind(&self) -> LanguageCallKind {
        self.kind
    }

    pub const fn input(&self) -> &InvocationInput {
        &self.input
    }

    pub fn filesystems(&self) -> &[LanguageFilesystem] {
        &self.filesystems
    }

    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    pub const fn conditional_depth(&self) -> usize {
        self.conditional_depth
    }

    pub fn execution_dominators(&self) -> &[usize] {
        &self.execution_dominators
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageFilesystem {
    requested: Option<String>,
    operation: FilesystemOperation,
    recursive: bool,
    pattern: bool,
    file_only: bool,
    content_access: bool,
    identity: Option<String>,
    identity_requires_missing_target: bool,
    identity_observed: bool,
    identity_follows_final_symlink: bool,
    protects_descendants: bool,
    follows_final_symlink: bool,
}

impl LanguageFilesystem {
    pub(crate) fn new(
        requested: Option<String>,
        operation: FilesystemOperation,
        recursive: bool,
    ) -> Self {
        Self {
            requested,
            operation,
            recursive,
            pattern: false,
            file_only: false,
            content_access: true,
            identity: None,
            identity_requires_missing_target: false,
            identity_observed: false,
            identity_follows_final_symlink: false,
            protects_descendants: false,
            follows_final_symlink: true,
        }
    }

    pub(crate) fn metadata(mut self) -> Self {
        self.content_access = false;
        self
    }

    pub(crate) fn pattern_if(mut self, pattern: bool) -> Self {
        self.pattern = pattern;
        self
    }

    pub(crate) fn file_only(mut self) -> Self {
        self.file_only = true;
        self
    }

    pub(crate) fn metadata_if(self, metadata: bool) -> Self {
        if metadata { self.metadata() } else { self }
    }

    pub(crate) fn without_requested(mut self) -> Self {
        self.requested = None;
        self
    }

    pub(crate) fn with_requested(mut self, requested: String) -> Self {
        self.requested = Some(requested);
        self
    }

    pub(crate) fn identity(mut self, identity: Option<String>, requires_missing: bool) -> Self {
        self.identity = identity;
        self.identity_requires_missing_target = requires_missing;
        self
    }

    pub(crate) fn observed_identity(
        mut self,
        identity: Option<String>,
        requires_missing: bool,
        follows_final_symlink: bool,
    ) -> Self {
        self.identity = identity;
        self.identity_requires_missing_target = requires_missing;
        self.identity_observed = self.identity.is_some();
        self.identity_follows_final_symlink = follows_final_symlink;
        self
    }

    pub(crate) fn without_identity(mut self) -> Self {
        self.identity = None;
        self.identity_requires_missing_target = false;
        self.identity_observed = false;
        self.identity_follows_final_symlink = false;
        self
    }

    pub(crate) fn with_identity(mut self, identity: String) -> Self {
        self.identity = Some(identity);
        self
    }

    pub(crate) fn protects_descendants(mut self) -> Self {
        self.protects_descendants = true;
        self
    }

    pub(crate) fn protects_descendants_if(self, protects: bool) -> Self {
        if protects {
            self.protects_descendants()
        } else {
            self
        }
    }

    pub(crate) fn without_final_symlink_follow(mut self) -> Self {
        self.follows_final_symlink = false;
        self
    }

    pub(crate) fn without_final_symlink_follow_if(self, no_follow: bool) -> Self {
        if no_follow {
            self.without_final_symlink_follow()
        } else {
            self
        }
    }

    pub fn requested(&self) -> Option<&str> {
        self.requested.as_deref()
    }

    pub const fn operation(&self) -> FilesystemOperation {
        self.operation
    }

    pub const fn recursive(&self) -> bool {
        self.recursive
    }

    pub const fn pattern(&self) -> bool {
        self.pattern
    }

    pub const fn file_only_target(&self) -> bool {
        self.file_only
    }

    pub const fn content_access(&self) -> bool {
        self.content_access
    }

    pub fn identity_path(&self) -> Option<&str> {
        self.identity.as_deref()
    }

    pub const fn identity_requires_missing_target(&self) -> bool {
        self.identity_requires_missing_target
    }

    pub const fn identity_observed(&self) -> bool {
        self.identity_observed
    }

    pub const fn identity_follows_final_symlink(&self) -> bool {
        self.identity_follows_final_symlink
    }

    pub const fn descendant_protection(&self) -> bool {
        self.protects_descendants
    }

    pub const fn follows_final_symlink(&self) -> bool {
        self.follows_final_symlink
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LanguageFlow {
    from: usize,
    to: usize,
}

impl LanguageFlow {
    pub const fn from(self) -> usize {
        self.from
    }

    pub const fn to(self) -> usize {
        self.to
    }
}
