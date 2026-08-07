use crate::{InlineInput, InlineReport, LanguageAnalysis, ProtectionInput};

mod engine;
mod parser;

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    analyze_language(program, input, protection, depth).into_report()
}

pub(super) fn analyze_language(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    engine::analyze(program, input, protection, depth)
}
