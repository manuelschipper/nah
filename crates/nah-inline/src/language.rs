use nah_proto::action::{FilesystemOperation, InvocationInput};

use crate::{InlineRefusal, InlineReport};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LanguageAnalysis {
    report: InlineReport,
    draft: LanguageDraft,
}

impl LanguageAnalysis {
    pub(crate) fn new(report: InlineReport, draft: LanguageDraft) -> Self {
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
}

impl Default for LanguageDraft {
    fn default() -> Self {
        Self {
            complete: true,
            calls: Vec::new(),
            flows: Vec::new(),
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
        &self.calls
    }

    pub fn flows(&self) -> &[LanguageFlow] {
        &self.flows
    }

    pub(crate) fn set_partial(&mut self) {
        self.complete = false;
    }

    pub(crate) fn push_call(&mut self, call: LanguageCall) -> Option<usize> {
        const MAX_CALLS: usize = 64;
        if self.calls.len() >= MAX_CALLS {
            self.complete = false;
            return None;
        }
        let ordinal = self.calls.len();
        self.calls.push(call);
        Some(ordinal)
    }

    pub(crate) fn push_flow(&mut self, from: usize, to: usize) {
        if from != to && !self.flows.contains(&LanguageFlow { from, to }) {
            self.flows.push(LanguageFlow { from, to });
            self.flows.sort_unstable();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LanguageCallKind {
    DirectFile,
    EvaluatedShell,
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
}

impl LanguageCall {
    pub(crate) fn new(
        kind: LanguageCallKind,
        input: InvocationInput,
        filesystems: Vec<LanguageFilesystem>,
        endpoint: Option<String>,
        conditional_depth: usize,
    ) -> Self {
        Self {
            kind,
            input,
            filesystems,
            endpoint,
            conditional_depth,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageFilesystem {
    requested: Option<String>,
    operation: FilesystemOperation,
    recursive: bool,
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
