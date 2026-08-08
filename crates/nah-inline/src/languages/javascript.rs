use crate::{InlineInput, InlineReport, LanguageAnalysis, ProtectionInput};

mod engine;
mod parser;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SyntaxProfile {
    JavaScript,
    TypeScript,
    Tsx,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeOwnership {
    Node,
    DenoEval,
    DenoCheckedEval,
    Bun,
    OpenClaw,
    Unowned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceContext {
    Module,
    FunctionBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Profile {
    pub(super) syntax: SyntaxProfile,
    pub(super) ownership: RuntimeOwnership,
    pub(super) context: SourceContext,
}

pub(super) fn profile(program: &str) -> Option<Profile> {
    let profile = match program {
        "node" | "nodejs" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::Node,
            context: SourceContext::Module,
        },
        "tsx" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::Node,
            context: SourceContext::Module,
        },
        "javascript" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::FunctionBody,
        },
        "typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::FunctionBody,
        },
        "deno" => Profile {
            syntax: SyntaxProfile::Ambiguous,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "bun" => Profile {
            syntax: SyntaxProfile::Ambiguous,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "deno-run-js" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "deno-run-typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "deno-run-tsx" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "deno-eval-js" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::DenoEval,
            context: SourceContext::Module,
        },
        "deno-eval-typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::DenoEval,
            context: SourceContext::Module,
        },
        "deno-eval-tsx" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::DenoEval,
            context: SourceContext::Module,
        },
        "deno-checked-eval-js" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::DenoCheckedEval,
            context: SourceContext::Module,
        },
        "deno-checked-eval-typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::DenoCheckedEval,
            context: SourceContext::Module,
        },
        "deno-checked-eval-tsx" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::DenoCheckedEval,
            context: SourceContext::Module,
        },
        "bun-js" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::Bun,
            context: SourceContext::Module,
        },
        "bun-typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::Bun,
            context: SourceContext::Module,
        },
        "bun-tsx" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::Bun,
            context: SourceContext::Module,
        },
        "bun-shell" => Profile {
            syntax: SyntaxProfile::Ambiguous,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "openclaw-javascript" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::OpenClaw,
            context: SourceContext::FunctionBody,
        },
        "openclaw-typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::OpenClaw,
            context: SourceContext::FunctionBody,
        },
        _ => return None,
    };
    Some(profile)
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
    _protection: Option<&ProtectionInput<'_>>,
    depth: usize,
) -> LanguageAnalysis {
    let profile = profile(program).expect("JavaScript analysis requires an admitted profile");
    engine::analyze(profile, input, depth)
}
