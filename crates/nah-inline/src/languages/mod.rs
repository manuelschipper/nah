//! Dispatches admitted language profiles to effect interpreters or narrower detectors.

mod common;
mod deferred;
mod ipython;
mod javascript;
mod julia;
mod lua;
mod perl;
mod php;
mod powershell;
mod python;
mod r;
mod ruby;
mod swift;

use crate::{
    InlineInput, InlineReport, LanguageAnalysis, LanguageDraft, ProtectionInput,
    is_ipython_interpreter, is_python_interpreter, normalized_program,
};

pub(crate) fn supports(program: &str) -> bool {
    let program = normalized_program(program);
    is_python_interpreter(&program)
        || javascript::profile(&program).is_some()
        || common::protection::is_perl_interpreter(&program)
        || matches!(
            program.as_str(),
            "ruby"
                | "php"
                | "lua"
                | "luajit"
                | "r"
                | "rscript"
                | "julia"
                | "swift"
                | "powershell"
                | "pwsh"
                | "cmd"
        )
}

pub(crate) fn has_javascript_profile(program: &str) -> bool {
    javascript::profile(&normalized_program(program)).is_some()
}

pub(crate) fn interpret_python_effects(
    input: InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    python::interpret_effects(
        &crate::normalized_program(input.program),
        &input,
        protection,
        depth,
    )
}

pub(crate) fn interpret_ipython_effects(
    input: InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    ipython::interpret_effects(
        &crate::normalized_program(input.program),
        &input,
        protection,
        depth,
    )
}

pub(crate) fn interpret_persistent_ipython_effects(
    input: InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    ipython::interpret_persistent_effects(
        &crate::normalized_program(input.program),
        &input,
        protection,
        depth,
    )
}

pub(crate) fn analyze(
    input: InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    let program = normalized_program(input.program);
    if is_ipython_interpreter(&program) {
        ipython::interpret_effects(&program, &input, protection, depth).into_report()
    } else if is_python_interpreter(&program) {
        python::analyze(&program, &input, protection, depth)
    } else if common::protection::is_perl_interpreter(&program) {
        perl::analyze("perl", &input, protection)
    } else {
        match program.as_str() {
            "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "deno-run-js"
            | "deno-run-typescript"
            | "deno-run-tsx"
            | "deno-eval-js"
            | "deno-eval-typescript"
            | "deno-eval-tsx"
            | "deno-checked-eval-js"
            | "deno-checked-eval-typescript"
            | "deno-checked-eval-tsx"
            | "bun-js"
            | "bun-typescript"
            | "bun-tsx"
            | "bun-shell"
            | "tsx"
            | "javascript"
            | "typescript"
            | "openclaw-javascript"
            | "openclaw-typescript" => javascript::analyze(&program, &input, protection, depth),
            "ruby" => ruby::analyze(&program, &input, protection),
            "php" => php::analyze(&program, &input, protection),
            "lua" | "luajit" => lua::analyze(&program, &input, protection),
            "r" | "rscript" => r::analyze(&program, &input, protection),
            "julia" => julia::analyze(&program, &input, protection),
            "swift" => swift::analyze(&program, &input, protection),
            "powershell" | "pwsh" | "cmd" => {
                powershell::analyze(&program, &input, protection, depth)
            }
            _ => InlineReport::default(),
        }
    }
}

pub(crate) fn interpret_effects(
    input: InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    let program = normalized_program(input.program);
    if is_ipython_interpreter(&program) {
        return ipython::interpret_effects(&program, &input, protection, depth);
    }
    if is_python_interpreter(&program) {
        return python::interpret_effects(&program, &input, protection, depth);
    }
    if javascript::profile(&program).is_some() {
        return javascript::interpret_effects(&program, &input, protection, depth);
    }
    LanguageAnalysis::new(analyze(input, protection, depth), LanguageDraft::default())
}
