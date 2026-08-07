use crate::{InlineInput, InlineReport, ProtectionInput};

mod engine;
mod parser;

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    engine::analyze(program, input, protection, depth)
}
