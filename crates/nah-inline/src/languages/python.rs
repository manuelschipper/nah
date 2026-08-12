use crate::{InlineInput, InlineReport, LanguageAnalysis, ProtectionInput};

mod engine;
mod parser;

pub(super) const IPYTHON_CELL_INTRINSIC: &str = "__nah_ipython_cell_7f19__";
pub(super) const IPYTHON_GETOUTPUT_INTRINSIC: &str = "__nah_ipython_getoutput_7f19__";
pub(super) const IPYTHON_SYSTEM_INTRINSIC: &str = "__nah_ipython_system_7f19__";

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
    interpret_effects(program, input, protection, depth).into_report()
}

pub(super) fn interpret_effects(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    interpret_effects_with_state(
        program,
        input,
        protection,
        depth,
        InitialState::Fresh,
        false,
    )
}

pub(super) fn interpret_effects_with_state(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
    initial_state: InitialState,
    capture_ipython_output: bool,
) -> LanguageAnalysis {
    engine::interpret(
        program,
        input,
        protection,
        depth,
        initial_state,
        false,
        capture_ipython_output,
    )
}

pub(super) fn interpret_ipython_syntax_with_state(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
    initial_state: InitialState,
    capture_ipython_output: bool,
) -> LanguageAnalysis {
    engine::interpret(
        program,
        input,
        protection,
        depth,
        initial_state,
        true,
        capture_ipython_output,
    )
}
