use nah_proto::ctx::Platform;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingKind {
    RootDestruction,
    HomeDestruction,
    DecodedExecution,
    NahTampering,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NestedExecutionCwd {
    Inherited,
    Path(String),
    Unknown,
}

impl NestedExecutionCwd {
    pub(crate) fn changed(&self, path: &str, platform: Platform) -> Self {
        if nested_path_is_drive_relative(path, platform) {
            return Self::Unknown;
        }
        if nested_path_is_absolute(path, platform) {
            Self::Path(path.to_owned())
        } else {
            self.resolve(path, platform)
                .map_or(Self::Unknown, Self::Path)
        }
    }

    pub(crate) fn resolve(&self, path: &str, platform: Platform) -> Option<String> {
        if nested_path_is_drive_relative(path, platform) {
            return None;
        }
        if nested_path_is_absolute(path, platform) {
            return Some(path.to_owned());
        }
        match self {
            Self::Inherited => Some(path.to_owned()),
            Self::Path(cwd) => {
                let separator = if platform == Platform::Windows {
                    '\\'
                } else {
                    '/'
                };
                Some(format!(
                    "{}{separator}{path}",
                    cwd.trim_end_matches(['/', '\\'])
                ))
            }
            Self::Unknown => None,
        }
    }
}

fn nested_path_is_drive_relative(path: &str, platform: Platform) -> bool {
    let bytes = path.as_bytes();
    platform == Platform::Windows
        && bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && !bytes
            .get(2)
            .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
}

fn nested_path_is_absolute(path: &str, platform: Platform) -> bool {
    if platform == Platform::Windows {
        path.starts_with(['/', '\\'])
            || path.as_bytes().get(1) == Some(&b':')
                && path
                    .as_bytes()
                    .get(2)
                    .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
    } else {
        path.starts_with('/')
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NestedExecution {
    Shell {
        program: String,
        code: String,
        cwd: NestedExecutionCwd,
        stdout_inherited: bool,
    },
    Command {
        argv: Vec<String>,
        cwd: NestedExecutionCwd,
        stdout_inherited: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Evidence {
    Exact,
    Conservative,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InlineRefusal {
    SourceLimit,
    RecursionLimit,
    StructureIncomplete,
    StructureMismatch,
    DelimiterLimit,
    WorkLimit,
    NestedExecutionLimit,
    EvidenceLimit,
}

impl InlineRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceLimit => "source-limit",
            Self::RecursionLimit => "recursion-limit",
            Self::StructureIncomplete => "structure-incomplete",
            Self::StructureMismatch => "structure-mismatch",
            Self::DelimiterLimit => "delimiter-limit",
            Self::WorkLimit => "work-limit",
            Self::NestedExecutionLimit => "nested-execution-limit",
            Self::EvidenceLimit => "evidence-limit",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Finding {
    kind: FindingKind,
    evidence: Evidence,
}

impl Finding {
    pub const fn exact(kind: FindingKind) -> Self {
        Self {
            kind,
            evidence: Evidence::Exact,
        }
    }

    pub const fn conservative(kind: FindingKind) -> Self {
        Self {
            kind,
            evidence: Evidence::Conservative,
        }
    }

    pub const fn kind(self) -> FindingKind {
        self.kind
    }

    pub const fn evidence(self) -> Evidence {
        self.evidence
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InlineReport {
    findings: Vec<Finding>,
    nested_executions: Vec<NestedExecution>,
    refusals: Vec<InlineRefusal>,
}

impl InlineReport {
    pub fn push(&mut self, finding: Finding) {
        if !self.findings.contains(&finding) {
            self.findings.push(finding);
            self.findings.sort_unstable();
        }
    }

    pub fn extend(&mut self, other: Self) {
        for finding in other.findings {
            self.push(finding);
        }
        for execution in other.nested_executions {
            self.push_nested_execution(execution);
        }
        for refusal in other.refusals {
            self.refuse(refusal);
        }
    }

    pub fn contains_exact(&self, kind: FindingKind) -> bool {
        self.findings.contains(&Finding::exact(kind))
    }

    pub fn contains_conservative(&self, kind: FindingKind) -> bool {
        self.findings.contains(&Finding::conservative(kind))
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn push_nested_execution(&mut self, execution: NestedExecution) {
        if self.nested_executions.len() < 64 {
            self.nested_executions.push(execution);
        } else {
            self.refuse(InlineRefusal::NestedExecutionLimit);
        }
    }

    pub fn nested_executions(&self) -> &[NestedExecution] {
        &self.nested_executions
    }

    pub fn refuse(&mut self, refusal: InlineRefusal) {
        if !self.refusals.contains(&refusal) {
            self.refusals.push(refusal);
            self.refusals.sort_unstable();
        }
    }

    pub fn refused(refusal: InlineRefusal) -> Self {
        let mut report = Self::default();
        report.refuse(refusal);
        report
    }

    pub fn refusals(&self) -> &[InlineRefusal] {
        &self.refusals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_deduplicates_findings() {
        let mut report = InlineReport::default();
        report.push(Finding::exact(FindingKind::RootDestruction));
        report.push(Finding::exact(FindingKind::RootDestruction));

        assert_eq!(report.findings().len(), 1);
        assert!(report.contains_exact(FindingKind::RootDestruction));
    }

    #[test]
    fn report_preserves_nested_execution_order_and_repetition() {
        let first = NestedExecution::Command {
            argv: vec!["first".into()],
            cwd: NestedExecutionCwd::Inherited,
            stdout_inherited: false,
        };
        let second = NestedExecution::Command {
            argv: vec!["second".into()],
            cwd: NestedExecutionCwd::Inherited,
            stdout_inherited: false,
        };
        let mut report = InlineReport::default();
        report.push_nested_execution(first.clone());
        report.push_nested_execution(second.clone());
        report.push_nested_execution(first.clone());

        assert_eq!(report.nested_executions(), [first.clone(), second, first]);
    }

    #[test]
    fn report_merges_and_deduplicates_refusals() {
        let mut report = InlineReport::refused(InlineRefusal::WorkLimit);
        report.extend(InlineReport::refused(InlineRefusal::WorkLimit));
        report.extend(InlineReport::refused(InlineRefusal::EvidenceLimit));

        assert_eq!(
            report.refusals(),
            [InlineRefusal::WorkLimit, InlineRefusal::EvidenceLimit]
        );
    }

    #[test]
    fn nested_execution_cap_is_a_sticky_refusal() {
        let child = NestedExecution::Command {
            argv: vec!["echo".into()],
            cwd: NestedExecutionCwd::Inherited,
            stdout_inherited: false,
        };
        let mut report = InlineReport::default();
        for _ in 0..65 {
            report.push_nested_execution(child.clone());
        }

        assert_eq!(report.nested_executions().len(), 64);
        assert_eq!(report.refusals(), [InlineRefusal::NestedExecutionLimit]);
    }
}
