use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Syntax {
    pub complete: bool,
    pub statements: Vec<Statement>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum Statement {
    Command {
        name: String,
        name_substitutions: Vec<Substitution>,
        arguments: Vec<Word>,
        redirects: Vec<Redirect>,
    },
    Pipeline {
        operators: Vec<String>,
        stages: Vec<Statement>,
    },
    Chain {
        operators: Vec<String>,
        items: Vec<Statement>,
    },
    Unsupported {
        construct: String,
    },
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Word {
    pub raw: String,
    pub substitutions: Vec<Substitution>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum Substitution {
    Command { statements: Vec<Statement> },
    Backtick { statements: Vec<Statement> },
    ProcessInput { statements: Vec<Statement> },
    ProcessOutput { statements: Vec<Statement> },
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<String>,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_substitutions: Vec<Substitution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_substitutions: Vec<Substitution>,
}

pub fn syntax_is_clean(source: &str) -> Result<bool, String> {
    Ok(normalize(source)?.complete)
}

pub fn normalize(source: &str) -> Result<Syntax, String> {
    let tree = parse(source)?;
    let mut complete = tree_is_clean(&tree, source);
    let statements = statement_children(tree.root_node(), source, &mut complete);
    Ok(Syntax {
        complete,
        statements,
    })
}

fn parse(source: &str) -> Result<Tree, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|error| format!("load Bash grammar: {error}"))?;
    parser
        .parse(source, None)
        .ok_or_else(|| "tree-sitter returned no tree".to_string())
}

fn tree_is_clean(tree: &Tree, source: &str) -> bool {
    let root = tree.root_node();
    !root.has_error() && !contains_error_or_missing(root) && source_bytes_are_covered(root, source)
}

fn contains_error_or_missing(node: Node<'_>) -> bool {
    if node.is_error() || node.is_missing() {
        return true;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor).any(contains_error_or_missing)
}

fn source_bytes_are_covered(root: Node<'_>, source: &str) -> bool {
    fn mark_leaves(node: Node<'_>, covered: &mut [bool]) {
        if node.child_count() == 0 {
            for byte in node.byte_range() {
                covered[byte] = true;
            }
            return;
        }
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                mark_leaves(child, covered);
            }
        }
    }

    let mut covered = vec![false; source.len()];
    mark_leaves(root, &mut covered);
    source
        .bytes()
        .zip(covered)
        .all(|(byte, is_covered)| is_covered || byte.is_ascii_whitespace())
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn statement_children(node: Node<'_>, source: &str, complete: &mut bool) -> Vec<Statement> {
    let mut statements = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if child.is_named() {
            if child.kind() != "comment" {
                statements.push(statement(child, source, complete));
            }
        } else if !matches!(
            (node.kind(), child.kind()),
            ("command_substitution", "$(" | "`" | ")")
                | ("process_substitution", "<(" | ">(" | ")")
        ) {
            *complete = false;
        }
    }
    statements
}

fn statement(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    match node.kind() {
        "command" => command(node, source, complete),
        "pipeline" => pipeline(node, source, complete),
        "list" => chain(node, source, complete),
        "redirected_statement" => redirected(node, source, complete),
        other => {
            *complete = false;
            Statement::Unsupported {
                construct: other.to_string(),
            }
        }
    }
}

fn word(node: Node<'_>, source: &str, complete: &mut bool) -> Word {
    let mut substitutions = Vec::new();
    collect_substitutions(node, source, complete, &mut substitutions);
    Word {
        raw: text(node, source).to_string(),
        substitutions,
    }
}

fn command(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(name_node) = node.child_by_field_name("name") else {
        *complete = false;
        return Statement::Unsupported {
            construct: "command-without-name".to_string(),
        };
    };
    let mut name_substitutions = Vec::new();
    collect_substitutions(name_node, source, complete, &mut name_substitutions);
    let mut arguments = Vec::new();
    let mut redirects = Vec::new();

    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        match node.field_name_for_child(index as u32) {
            Some("name") => {}
            Some("argument") => arguments.push(word(child, source, complete)),
            Some("redirect") => redirects.push(redirect(child, source, complete)),
            _ if child.kind() == "comment" => {}
            _ => *complete = false,
        }
    }

    Statement::Command {
        name: text(name_node, source).to_string(),
        name_substitutions,
        arguments,
        redirects,
    }
}

fn collect_substitutions(
    node: Node<'_>,
    source: &str,
    complete: &mut bool,
    out: &mut Vec<Substitution>,
) {
    match node.kind() {
        "command_substitution" => {
            let statements = statement_children(node, source, complete);
            if matches!(text(node, source).as_bytes(), [b'`', ..] | [b'$', b'`', ..]) {
                out.push(Substitution::Backtick { statements });
            } else {
                out.push(Substitution::Command { statements });
            }
            return;
        }
        "process_substitution" => {
            let statements = statement_children(node, source, complete);
            if text(node, source).starts_with("<(") {
                out.push(Substitution::ProcessInput { statements });
            } else if text(node, source).starts_with(">(") {
                out.push(Substitution::ProcessOutput { statements });
            } else {
                *complete = false;
            }
            return;
        }
        _ => {}
    }
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        collect_substitutions(child, source, complete, out);
    }
}

fn pipeline(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let mut operators = Vec::new();
    let mut stages = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if matches!(child.kind(), "|" | "|&") {
            operators.push(text(child, source).to_string());
        } else if child.is_named() && child.kind() != "comment" {
            stages.push(statement(child, source, complete));
        } else if child.kind() != "comment" {
            *complete = false;
        }
    }
    if stages.len().saturating_sub(1) != operators.len() {
        *complete = false;
    }
    Statement::Pipeline { operators, stages }
}

fn chain(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let mut operators = Vec::new();
    let mut items = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if matches!(child.kind(), "&&" | "||") {
            operators.push(text(child, source).to_string());
        } else if child.kind() == "list" {
            match chain(child, source, complete) {
                Statement::Chain {
                    operators: inner_operators,
                    items: inner_items,
                } => {
                    operators.extend(inner_operators);
                    items.extend(inner_items);
                }
                _ => unreachable!("a list normalizes to a chain"),
            }
        } else if child.is_named() && child.kind() != "comment" {
            items.push(statement(child, source, complete));
        } else if child.kind() != "comment" {
            *complete = false;
        }
    }
    if items.len().saturating_sub(1) != operators.len() {
        *complete = false;
    }
    Statement::Chain { operators, items }
}

fn redirected(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(body_node) = node.child_by_field_name("body") else {
        *complete = false;
        return Statement::Unsupported {
            construct: "redirect-without-body".to_string(),
        };
    };
    let mut body = statement(body_node, source, complete);
    let mut redirects = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        match node.field_name_for_child(index as u32) {
            Some("body") => {}
            Some("redirect") => redirects.push(redirect(child, source, complete)),
            _ if child.kind() == "comment" => {}
            _ => *complete = false,
        }
    }
    match &mut body {
        Statement::Command {
            redirects: body_redirects,
            ..
        } => {
            body_redirects.extend(redirects);
            body
        }
        _ => {
            *complete = false;
            Statement::Unsupported {
                construct: "non-command-redirect-scope".to_string(),
            }
        }
    }
}

fn redirect(node: Node<'_>, source: &str, complete: &mut bool) -> Redirect {
    let mut fd = None;
    let mut operator = None;
    let mut target_node = None;
    let mut body_node = None;

    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        match node.field_name_for_child(index as u32) {
            Some("descriptor") if fd.is_none() => fd = Some(text(child, source).to_string()),
            Some("descriptor") => *complete = false,
            Some("destination") if target_node.is_none() => target_node = Some(child),
            Some("destination") => *complete = false,
            _ if !child.is_named() && is_redirect_operator(child.kind()) => {
                if operator.is_none() {
                    operator = Some(text(child, source).to_string());
                } else {
                    *complete = false;
                }
            }
            _ if child.kind() == "heredoc_start" && target_node.is_none() => {
                target_node = Some(child)
            }
            _ if child.kind() == "heredoc_body" && body_node.is_none() => body_node = Some(child),
            _ if child.kind() == "heredoc_end" => {}
            _ if node.kind() == "herestring_redirect" && target_node.is_none() => {
                target_node = Some(child)
            }
            _ => *complete = false,
        }
    }

    let operator = operator.unwrap_or_else(|| {
        *complete = false;
        String::new()
    });
    let mut target_substitutions = Vec::new();
    if let Some(target) = target_node {
        collect_substitutions(target, source, complete, &mut target_substitutions);
    }
    let mut body_substitutions = Vec::new();
    if let Some(body) = body_node {
        collect_substitutions(body, source, complete, &mut body_substitutions);
    }
    if node.kind() == "heredoc_redirect"
        && target_node.is_some_and(|target| delimiter_is_unquoted(text(target, source)))
        && body_node.is_some_and(|body| contains_unescaped_backtick(text(body, source)))
    {
        // tree-sitter-bash 0.25 treats legacy backticks in an expanding
        // heredoc as plain content. Preserve the body, but do not call the
        // structure complete when executable syntax was not decomposed.
        *complete = false;
    }
    Redirect {
        fd,
        operator,
        target: target_node.map(|node| text(node, source).to_string()),
        body: body_node.map(|node| text(node, source).to_string()),
        target_substitutions,
        body_substitutions,
    }
}

fn is_redirect_operator(kind: &str) -> bool {
    matches!(
        kind,
        "<" | ">" | ">>" | ">|" | "<>" | ">&" | "<&" | "&>" | "&>>" | "<<<" | "<<" | "<<-"
    )
}

fn delimiter_is_unquoted(delimiter: &str) -> bool {
    !delimiter
        .bytes()
        .any(|byte| matches!(byte, b'\'' | b'"' | b'\\'))
}

fn contains_unescaped_backtick(body: &str) -> bool {
    let mut preceding_backslashes = 0;
    for byte in body.bytes() {
        if byte == b'`' && preceding_backslashes % 2 == 0 {
            return true;
        }
        if byte == b'\\' {
            preceding_backslashes += 1;
        } else {
            preceding_backslashes = 0;
        }
    }
    false
}
