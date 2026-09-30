//! Shell operand perturbation for symbolic-operand tests: locate an authored
//! operand in a subject, replace it with an unset environment variable, and
//! check that the plan still cites that operand.

use effinterp_proto::{Plan, ProvenanceKind, ProvenanceRef, Subject};

use crate::shell::lex;

/// The environment variable name a perturbed operand is replaced with; no
/// subject defines it, so the engine can only keep it symbolic.
pub const SYMBOLIC_OPERAND: &str = "EFFINTERP_SYMBOLIC_OPERAND";

/// Quote one argv element without interpreting shell metacharacters.
pub fn quote_shell_operand(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Adapt exec argv to one quoted shell command; preserve other subjects.
pub fn shell_operand_subject(subject: &Subject) -> Subject {
    match subject {
        Subject::Exec { argv, cwd, context } => Subject::Shell {
            source: argv
                .iter()
                .map(|value| quote_shell_operand(value))
                .collect::<Vec<_>>()
                .join(" "),
            cwd: cwd.clone(),
            context: context.clone(),
        },
        _ => subject.clone(),
    }
}

/// Locate an authored operand in a single command, excluding the command head.
pub fn shell_operand_slot(subject: &Subject, index: usize) -> Result<(u32, u32), &'static str> {
    let Subject::Shell { source, .. } = subject else {
        return Err("not shell");
    };
    if source.contains(SYMBOLIC_OPERAND) {
        return Err("local variable collision");
    }
    let parsed = lex::lex(source);
    if parsed.error.is_some() {
        return Err("invalid source");
    }
    if parsed
        .toks
        .iter()
        .any(|token| !matches!(token, lex::Tok::Word(_)))
    {
        return Err("operators require a separately authored transform");
    }
    let token = parsed.toks.get(index).ok_or("missing argument")?;
    match token {
        lex::Tok::Word(word) if index > 0 => Ok((word.span.start, word.span.end)),
        _ => Err("operator or command head is not an operand"),
    }
}

/// Match exact source evidence or root-exec argument evidence in a valid plan.
pub fn operand_cites(plan: &Plan, roots: &[ProvenanceRef], span: (u32, u32)) -> bool {
    let index = match &plan.subject {
        Subject::Shell { source, .. } => lex::lex(source).toks.iter().position(|token|
            matches!(token, lex::Tok::Word(word) if (word.span.start, word.span.end) == span)),
        _ => None,
    };
    let mut pending = roots.to_vec();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference) {
            continue;
        }
        let node = &plan.provenance[reference.0 as usize];
        if matches!(node.kind, ProvenanceKind::SourceSpan { start, end } if (start, end) == span) {
            return true;
        }
        if matches!(node.kind, ProvenanceKind::Argument { index: argument }
            if Some(argument as usize) == index)
            && node.antecedents.iter().any(|reference| {
                let ProvenanceKind::Execution { node } = plan.provenance[reference.0 as usize].kind
                else {
                    return false;
                };
                plan.execution_graph
                    .edges
                    .iter()
                    .any(|edge| edge.from == plan.execution_graph.entry && edge.to.0 == node)
            })
        {
            return true;
        }
        pending.extend(&node.antecedents);
    }
    false
}

/// Literal operand spans in a single command; operators and embedded assignments
/// require a separately validated transform.
pub fn literal_shell_operand_spans(subject: &Subject) -> Result<Vec<(u32, u32)>, &'static str> {
    let Subject::Shell { source, .. } = subject else {
        return Err("not_shell");
    };
    if source.contains('=') {
        return Err("shell_embedded_operands_unsupported");
    }
    let parsed = lex::lex(source);
    if parsed.error.is_some() {
        return Err("invalid_source");
    }
    if parsed.toks.iter().any(|t| !matches!(t, lex::Tok::Word(_))) {
        return Err("shell_operators_unsupported");
    }
    let mut spans = Vec::new();
    for (index, token) in parsed.toks.iter().enumerate().skip(1) {
        let lex::Tok::Word(word) = token else {
            unreachable!();
        };
        if !word
            .segs
            .iter()
            .all(|s| matches!(s, lex::Seg::Literal { .. }))
        {
            continue;
        }
        if word
            .segs
            .first()
            .is_some_and(|s| matches!(s, lex::Seg::Literal { text, .. } if text.starts_with('-')))
        {
            continue;
        }
        spans.push(shell_operand_slot(subject, index)?);
    }
    Ok(spans)
}

/// Recover literal bytes from an operand span already validated by the tokenizer.
pub fn shell_operand_literal(subject: &Subject, span: (u32, u32)) -> Option<String> {
    let Subject::Shell { source, .. } = subject else {
        return None;
    };
    lex::lex(source).toks.into_iter().find_map(|token| {
        let lex::Tok::Word(word) = token else {
            return None;
        };
        if (word.span.start, word.span.end) != span {
            return None;
        }
        word.segs
            .into_iter()
            .map(|seg| match seg {
                lex::Seg::Literal { text, .. } => Some(text),
                _ => None,
            })
            .collect::<Option<String>>()
    })
}
