use crate::{InlineInput, LanguageAnalysis, ProtectionInput};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    super::python::analyze_language(program, input, protection, depth)
}
