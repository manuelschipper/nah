use crate::{InlineInput, InlineReport, LanguageAnalysis, ProtectionInput};

mod engine;
mod parser;

#[derive(Clone, Copy)]
pub(super) enum InitialState {
    Fresh,
    Persistent,
}

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
    analyze_language_with_state(program, input, protection, depth, InitialState::Fresh)
}

pub(super) fn analyze_language_with_state(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
    initial_state: InitialState,
) -> LanguageAnalysis {
    engine::analyze(program, input, protection, depth, initial_state)
}
