use crate::syntax::{lexical_code_cased, static_call_arguments_cased};
use crate::{InlineInput, InlineReport, ProtectionInput};

use super::common::{
    DefinitionStyle, add_destructive_target, named_boolean, observe_shadow, ordered_active_segments,
};

pub(super) fn analyze(
    program: &str,
    input: &InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
) -> InlineReport {
    let mut report = InlineReport::default();
    let mut rm_shadowed = false;
    let code = super::deferred::mask(input.code, program);
    for segment in ordered_active_segments(&code, program, DefinitionStyle::End, &mut report) {
        if segment.executable && !rm_shadowed {
            let (outside, strings, offsets, static_strings, _) =
                lexical_code_cased(segment.source, program);
            let call_outside = outside.replace(';', ",");
            for arguments in static_call_arguments_cased(
                &call_outside,
                &call_outside,
                &strings,
                &offsets,
                &static_strings,
                "rm",
                true,
            ) {
                if matches!(arguments.as_slice(), [_, recursive]
                    if named_boolean(
                        recursive,
                        "recursive",
                        &["true"],
                        &["false"]
                    ) == Some(true))
                {
                    add_destructive_target(
                        &mut report,
                        arguments.first(),
                        input.home,
                        input.platform,
                    );
                }
            }
        }
        observe_shadow(&mut rm_shadowed, segment.source, program, "rm");
    }
    super::common::with_protection(report, program, input, protection)
}
