mod common;
mod deferred;
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
    InlineInput, InlineReport, ProtectionInput, is_python_interpreter, normalized_program,
};

pub(crate) fn supports(program: &str) -> bool {
    let program = normalized_program(program);
    is_python_interpreter(&program)
        || common::protection::is_perl_interpreter(&program)
        || matches!(
            program.as_str(),
            "node"
                | "nodejs"
                | "deno"
                | "bun"
                | "ruby"
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

pub(crate) fn analyze_python(
    input: InlineInput<'_>,
    protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> InlineReport {
    python::analyze(
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
    if is_python_interpreter(&program) {
        python::analyze(&program, &input, protection, depth)
    } else if common::protection::is_perl_interpreter(&program) {
        perl::analyze("perl", &input, protection)
    } else {
        match program.as_str() {
            "node" | "nodejs" => javascript::analyze(&program, &input, protection, depth),
            "deno" | "bun" => InlineReport::default(),
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
