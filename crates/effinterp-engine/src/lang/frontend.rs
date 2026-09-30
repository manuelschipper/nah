use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceRef,
};

use crate::ScopeKey;
use crate::builder::{KNOWN_DOMAINS, PlanBuilder};
use crate::module_summary::ModuleSummary;
use crate::nest::Nest;

/// The arguments a printf-style format prints verbatim: for each `%s`
/// conversion without a precision, the index of the argument it consumes,
/// counting from the first argument after the format. A `*` width consumes
/// the argument before the value. A `numeric` conversion prints a number or a
/// character, never the argument's text. `None` when the format uses anything
/// else: a precision, which may cut the text, another conversion, a named
/// reference, or a `*` in a positional conversion.
pub(crate) fn format_text_arguments(format: &str, numeric: &[char]) -> Option<Vec<usize>> {
    let mut characters = format.chars();
    let mut next = 0;
    let mut arguments = Vec::new();
    while let Some(character) = characters.next() {
        if character != '%' {
            continue;
        }
        let mut spec = String::new();
        let conversion = loop {
            match characters.next()? {
                '%' if spec.is_empty() => break '%',
                '<' | '{' => return None,
                // PHP's `'c` names a padding character.
                '\'' => {
                    characters.next()?;
                }
                letter if letter.is_ascii_alphabetic() => break letter,
                other => spec.push(other),
            }
        };
        if conversion == '%' {
            continue;
        }
        let stars = spec.matches('*').count();
        let index = match spec.split_once('$') {
            Some(_) if stars > 0 => return None,
            Some((position, _)) => position.parse::<usize>().ok()?.checked_sub(1)?,
            None => {
                next += stars + 1;
                next - 1
            }
        };
        match conversion {
            's' if !spec.contains('.') => arguments.push(index),
            _ if numeric.contains(&conversion) => {}
            _ => return None,
        }
    }
    Some(arguments)
}

/// Recursive statement nesting stays below the native thread stack limit.
pub(crate) const MAX_WALK_DEPTH: u32 = 256;
pub(crate) const MAX_CALLBACK_VALUES: usize = 16;

pub(crate) struct FrontendInput<'a> {
    pub source: &'a str,
    pub source_cwd: Option<&'a str>,
    pub runtime_cwd: Option<&'a str>,
    pub cwd_node: Option<ProvenanceRef>,
    pub scope: Option<ProvenanceRef>,
    pub depth: u64,
}

/// Parsers may retain a recovered AST alongside a syntax diagnostic.
pub(crate) struct ParseOutcome<A> {
    pub ast: Option<A>,
    pub failure: Option<ParseFailure>,
}

pub(crate) struct ParseFailure {
    pub detail: String,
}

#[derive(Default)]
pub(crate) struct WalkOutcome {
    /// Callables left unentered when execution produced no effects.
    pub declared_callables: Vec<String>,
}

pub(crate) trait Frontend {
    const LANGUAGE: &'static str;
    const DOMAINS: &'static [&'static str];
    // Oxc's program borrows both the frontend's arena and the source.
    type Ast<'a>
    where
        Self: 'a;

    fn parse<'a>(&'a self, source: &'a str) -> ParseOutcome<Self::Ast<'a>>;

    fn parse_summary<'a>(&'a self, source: &'a str) -> Option<Self::Ast<'a>> {
        self.parse(source).ast
    }

    /// Whether the source nests deeper than the walk limit. Frontends whose
    /// parser descends recursively (JS/TS, Ruby) override this so [`run`] and
    /// [`summarize`] refuse the source before the parser overflows the native
    /// stack; the default assumes an iterative or already-bounded parser.
    fn nesting_exceeds(&self, _source: &str) -> bool {
        false
    }

    fn parse_failure(
        &self,
        builder: &mut PlanBuilder,
        scope: Option<ProvenanceRef>,
        failure: &ParseFailure,
    ) {
        let domains = match Self::LANGUAGE {
            "go" => Self::DOMAINS,
            "ruby" | "java" | "php" => KNOWN_DOMAINS.as_slice(),
            _ => unreachable!("frontend overrides parse failure coverage"),
        };
        builder.boundary_with_coverage(
            Boundary {
                reason: BoundaryReason::PARSE_ERROR,
                class: BoundaryClass::ParseFailure,
                scope: BoundaryScope::Invocation,
                affected_resource: None,
                callee: None,
                domains: domains.iter().map(|d| Domain::new(*d)).collect(),
                provenance: scope.as_slice().to_vec(),
                limit: None,
                detail: Some(failure.detail.clone()),
            },
            CoverageLevel::None,
        );
    }

    fn walk<'a>(
        &'a self,
        builder: &mut PlanBuilder,
        nest: &Nest,
        input: &FrontendInput,
        ast: &Self::Ast<'a>,
    ) -> WalkOutcome;

    fn summarize<'a>(
        &'a self,
        source: &str,
        ast: &Self::Ast<'a>,
        file: &str,
        scope: ScopeKey,
        value_limits: crate::ValueLimits,
    ) -> ModuleSummary;
}

/// One prologue for root sources and recursively loaded source files.
pub(crate) fn run<F: Frontend>(
    frontend: &F,
    builder: &mut PlanBuilder,
    nest: &Nest,
    input: FrontendInput<'_>,
) {
    if input.source.len() as u64 > nest.limits.max_source_bytes {
        let domains = if F::LANGUAGE == "python" {
            F::DOMAINS
        } else {
            &KNOWN_DOMAINS
        };
        let detail = match F::LANGUAGE {
            "python" => None,
            "go" => Some("go source too large"),
            "java" => Some("java source too large"),
            "php" => Some("php source too large"),
            "ruby" => Some("ruby source too large"),
            "rust" => Some("rust source too large"),
            "js" => Some("js source too large"),
            _ => unreachable!(),
        };
        builder.boundary(Boundary {
            reason: BoundaryReason::LIMIT_SATURATED,
            class: BoundaryClass::Limit,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: input.scope.as_slice().to_vec(),
            limit: Some("max_source_bytes".to_string()),
            detail: detail.map(str::to_string),
        });
        for domain in domains {
            builder.declare_coverage(Domain::new(*domain), CoverageLevel::None);
        }
        return;
    }
    if frontend.nesting_exceeds(input.source) {
        let domains = if F::LANGUAGE == "python" {
            F::DOMAINS
        } else {
            &KNOWN_DOMAINS
        };
        // The same partial-analysis boundary the walkers raise at the walk
        // limit: a structural stop, not budget exhaustion, so downstream reads
        // it as partial coverage and the rest of the command still analyzes.
        builder.boundary(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: domains.iter().map(|d| Domain::new(*d)).collect(),
            provenance: input.scope.as_slice().to_vec(),
            limit: None,
            detail: Some(format!(
                "{} source nesting exceeds the walk limit",
                F::LANGUAGE
            )),
        });
        for domain in domains {
            builder.declare_coverage(Domain::new(*domain), CoverageLevel::Partial);
        }
        return;
    }
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    let parsed = frontend.parse(input.source);
    if nest.budget.timed_out() {
        builder.note_deadline();
        return;
    }
    if let Some(failure) = parsed.failure {
        frontend.parse_failure(builder, input.scope, &failure);
    }
    let Some(ast) = parsed.ast else { return };
    let outcome = frontend.walk(builder, nest, &input, &ast);
    if !(outcome.declared_callables.is_empty()
        || builder.current_execution_is_dependency()
        || (nest.registration.is_some() && builder.execution_depth() == 1))
    {
        builder.no_entry_point(&outcome.declared_callables, F::DOMAINS, input.scope);
    }
}

pub(crate) fn summarize<F: Frontend>(
    frontend: &F,
    source: &str,
    file: &str,
    scope: ScopeKey,
    value_limits: crate::ValueLimits,
) -> ModuleSummary {
    if frontend.nesting_exceeds(source) {
        let mut summary = ModuleSummary::default();
        summary.module_boundaries.push(Boundary {
            reason: BoundaryReason::PARTIAL_ANALYSIS,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: KNOWN_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: Vec::new(),
            limit: None,
            detail: Some(format!(
                "{} source nesting exceeds the walk limit",
                F::LANGUAGE
            )),
        });
        return summary;
    }
    frontend
        .parse_summary(source)
        .as_ref()
        .map(|ast| frontend.summarize(source, ast, file, scope, value_limits))
        .unwrap_or_default()
}
