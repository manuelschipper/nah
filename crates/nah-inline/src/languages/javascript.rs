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
        "deno-js" => Profile {
            syntax: SyntaxProfile::JavaScript,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "deno-typescript" => Profile {
            syntax: SyntaxProfile::TypeScript,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "deno-tsx" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
        },
        "bun" => Profile {
            syntax: SyntaxProfile::Tsx,
            ownership: RuntimeOwnership::Unowned,
            context: SourceContext::Module,
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
