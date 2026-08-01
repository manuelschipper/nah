//! Adapts tree-sitter Bash into the owned syntax model; it does not lower effects.

use tree_sitter::{Node, Parser, Tree};

mod fork_bomb;

use crate::model::word;
use crate::{
    CaseArm, CaseTermination, ConditionalBranch, LoopControlKind, LoopKind, Redirect, Statement,
    Substitution, Syntax, UnmodeledStateExpansion, Word,
};

/// Largest command nah will parse. Larger input returns a bounded parse error
/// without walking the command.
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// Deepest semantically nested syntax nah will analyse. Shell scripts nest a
/// few dozen levels; deeper input is refused with a verdict.
pub const MAX_SYNTAX_DEPTH: usize = 512;

/// Largest concrete syntax tree nah will analyse. This bounds wide generated
/// commands whose later policy work can otherwise dominate a runtime hook.
const MAX_SYNTAX_NODES: usize = 25_000;

const TOO_LARGE: &str = "command is larger than nah can analyse (1 MiB limit)";
const TOO_DEEP: &str = "command nests too deeply for nah to analyse (512 level limit)";
const TOO_COMPLEX: &str = "command is too complex for nah to analyse (25000 syntax node limit)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The command is past a documented bound, so nah refused to walk it.
    ExceedsLimit(&'static str),
    /// The Bash grammar itself was unusable.
    Grammar(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExceedsLimit(reason) => formatter.write_str(reason),
            Self::Grammar(error) => formatter.write_str(error),
        }
    }
}

pub fn syntax_is_clean(source: &str) -> Result<bool, ParseError> {
    Ok(normalize(source)?.complete())
}

pub fn normalize(source: &str) -> Result<Syntax, ParseError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(ParseError::ExceedsLimit(TOO_LARGE));
    }
    let tree = parse(source)?;
    if let Some(reason) = syntax_limit(&tree) {
        return Err(ParseError::ExceedsLimit(reason));
    }
    let mut complete = tree_is_clean(&tree, source);
    let (fork_bomb, fork_bomb_uncertain) = fork_bomb::detect(tree.root_node(), source);
    complete &= !fork_bomb_uncertain;
    let parsed = statement_children_with_units(tree.root_node(), source, &mut complete);
    Ok(Syntax::new(
        complete,
        fork_bomb,
        parsed.statements,
        parsed.parse_unit_starts,
    ))
}

fn parse(source: &str) -> Result<Tree, ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|error| ParseError::Grammar(format!("load Bash grammar: {error}")))?;
    parser
        .parse(source, None)
        .ok_or_else(|| ParseError::Grammar("tree-sitter returned no tree".to_owned()))
}

/// Measures semantic nesting without charging tree-sitter's left-nested
/// representation of a flat `&&`/`||` chain.
fn syntax_limit(tree: &Tree) -> Option<&'static str> {
    let root = tree.root_node();
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0;
    while let Some((node, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_SYNTAX_NODES {
            return Some(TOO_COMPLEX);
        }
        let mut cursor = node.walk();
        let mut children = node.children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        for child in children {
            let child_depth =
                depth + usize::from(!(node.kind() == "list" && child.kind() == "list"));
            if child_depth > MAX_SYNTAX_DEPTH {
                return Some(TOO_DEEP);
            }
            stack.push((child, child_depth));
        }
    }
    None
}

fn tree_is_clean(tree: &Tree, source: &str) -> bool {
    let root = tree.root_node();
    !contains_error_or_missing(root, source) && source_bytes_are_covered(root, source)
}

fn contains_error_or_missing(node: Node<'_>, source: &str) -> bool {
    walk_nodes(node, false, |_| false).into_iter().any(|node| {
        !recognized_multi_digit_redirect_artifact(node, source)
            && (node.is_missing() || node.is_error() && !recognized_extglob_error(node, source))
    })
}

fn recognized_multi_digit_redirect_artifact(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node
        .parent()
        .filter(|parent| parent.kind() == "file_redirect")
    else {
        return false;
    };
    let raw = text(parent, source);
    let digits = raw.bytes().take_while(u8::is_ascii_digit).count();
    let operator_end = raw[digits..]
        .bytes()
        .take_while(|byte| matches!(byte, b'<' | b'>' | b'&' | b'|'))
        .count();
    if digits < 2 || !is_redirect_operator(&raw[digits..digits + operator_end]) {
        return false;
    }
    node.kind() == "ERROR" && text(node, source) == &raw[..digits]
        || node.kind() == "file_descriptor"
            && node.start_byte() == parent.start_byte()
            && node.end_byte() == node.start_byte()
}

fn recognized_extglob_error(node: Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let Some(index) = (0..parent.child_count()).find(|index| parent.child(*index) == Some(node))
    else {
        return false;
    };
    let Some(next) = parent.child(index + 1) else {
        return false;
    };
    node.end_byte() == next.start_byte()
        && next.kind() == "subshell"
        && text(node, source)
            .bytes()
            .next_back()
            .is_some_and(|byte| matches!(byte, b'@' | b'+' | b'!' | b'?' | b'*'))
}

fn source_bytes_are_covered(root: Node<'_>, source: &str) -> bool {
    let mut covered = vec![false; source.len()];
    for node in walk_nodes(root, false, |_| false) {
        if node.child_count() == 0 {
            for byte in node.byte_range() {
                covered[byte] = true;
            }
        }
    }
    source
        .bytes()
        .zip(covered)
        .all(|(byte, covered)| covered || byte.is_ascii_whitespace())
}

fn walk_nodes<'tree>(
    root: Node<'tree>,
    named_only: bool,
    prune: impl FnMut(Node<'tree>) -> bool,
) -> impl Iterator<Item = Node<'tree>> {
    NodeWalk {
        stack: vec![root],
        named_only,
        prune,
    }
}

struct NodeWalk<'tree, P> {
    stack: Vec<Node<'tree>>,
    named_only: bool,
    prune: P,
}

impl<'tree, P> Iterator for NodeWalk<'tree, P>
where
    P: FnMut(Node<'tree>) -> bool,
{
    type Item = Node<'tree>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        if (self.prune)(node) {
            return Some(node);
        }
        let mut cursor = node.walk();
        let mut children = if self.named_only {
            node.named_children(&mut cursor).collect::<Vec<_>>()
        } else {
            node.children(&mut cursor).collect::<Vec<_>>()
        };
        children.reverse();
        self.stack.extend(children);
        Some(node)
    }
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

struct ParsedStatements {
    statements: Vec<Statement>,
    parse_unit_starts: Vec<usize>,
}

fn statement_children_with_units(
    node: Node<'_>,
    source: &str,
    complete: &mut bool,
) -> ParsedStatements {
    let mut statements = Vec::new();
    let mut parse_unit_starts = Vec::new();
    let mut previous_end = None;
    let mut cursor = node.walk();
    let children = node.children(&mut cursor).collect::<Vec<_>>();
    let mut index = 0;
    while index < children.len() {
        let child = children[index];
        if let Some((coprocess, end)) = compound_coprocess(child, source, complete) {
            record_parse_unit_start(
                &mut parse_unit_starts,
                statements.len(),
                previous_end,
                child.start_byte(),
                source,
            );
            statements.push(coprocess);
            previous_end = Some(end);
            index += 1;
            while index < children.len() && children[index].start_byte() < end {
                index += 1;
            }
            continue;
        }
        if child.is_named() {
            if child.kind() != "comment" {
                record_parse_unit_start(
                    &mut parse_unit_starts,
                    statements.len(),
                    previous_end,
                    child.start_byte(),
                    source,
                );
                statements.push(statement(child, source, complete));
                previous_end = Some(child.end_byte());
            }
        } else if child.kind() != ";"
            && !matches!(
                (node.kind(), child.kind()),
                ("command_substitution", "$(" | "`" | ")")
                    | ("process_substitution", "<(" | ">(" | ")")
            )
        {
            *complete = false;
        }
        index += 1;
    }
    ParsedStatements {
        statements,
        parse_unit_starts,
    }
}

fn statement_children(node: Node<'_>, source: &str, complete: &mut bool) -> Vec<Statement> {
    statement_children_with_units(node, source, complete).statements
}

fn record_parse_unit_start(
    starts: &mut Vec<usize>,
    statement: usize,
    previous_end: Option<usize>,
    next_start: usize,
    source: &str,
) {
    if statement == 0
        || previous_end.is_some_and(|previous_end| {
            contains_terminating_newline(&source[previous_end..next_start])
        })
    {
        starts.push(statement);
    }
}

fn contains_terminating_newline(source: &str) -> bool {
    let bytes = source.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != b'\n' {
            return false;
        }
        let preceding_backslashes = bytes[..index]
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\\')
            .count();
        preceding_backslashes % 2 == 0
    })
}

fn statement(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    match node.kind() {
        "command" => command_or_coprocess(node, source, complete),
        "declaration_command" => declaration_command(node, source, complete),
        "unset_command" => simple_builtin_command(node, source, complete),
        "variable_assignment" => assignments(std::slice::from_ref(&node), source, complete),
        "variable_assignments" => {
            let nodes = (0..node.child_count())
                .filter_map(|index| node.child(index))
                .filter(|child| child.kind() == "variable_assignment")
                .collect::<Vec<_>>();
            assignments(&nodes, source, complete)
        }
        "pipeline" => pipeline(node, source, complete),
        "list" => chain(node, source, complete),
        "redirected_statement" => redirected(node, source, complete),
        "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
            redirect_only(std::slice::from_ref(&node), source, complete)
        }
        "subshell" => subshell(node, source, complete),
        "compound_statement"
            if text(node, source).starts_with("((") && text(node, source).ends_with("))") =>
        {
            *complete = false;
            unmodeled_state_mutation(node, source, complete)
        }
        "compound_statement" => group(node, source, complete),
        "if_statement" => if_statement(node, source, complete),
        "while_statement" => loop_statement(node, source, complete),
        "for_statement" => for_statement(node, source, complete),
        "case_statement" => case_statement(node, source, complete),
        "function_definition" => function_definition(node, source, complete),
        "ERROR" if shell_pattern_word(text(node, source)) => {
            *complete = false;
            Statement::Command {
                name: text(node, source).to_owned(),
                name_substitutions: Vec::new(),
                assignments: Vec::new(),
                unmodeled_assignments: Vec::new(),
                arguments: Vec::new(),
                redirects: Vec::new(),
            }
        }
        "arithmetic_expansion" | "c_style_for_statement" => {
            *complete = false;
            unmodeled_state_mutation(node, source, complete)
        }
        other => {
            *complete = false;
            Statement::Unsupported {
                construct: other.to_owned(),
                statements: executable_descendants(node, source, complete),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoprocessCompound {
    Group,
    Subshell,
    If,
}

fn compound_coprocess(
    node: Node<'_>,
    source: &str,
    complete: &mut bool,
) -> Option<(Statement, usize)> {
    if node.kind() != "command"
        || node
            .child_by_field_name("name")
            .is_none_or(|name| text(name, source) != "coproc")
    {
        return None;
    }
    let (name, body_start, expected) = coprocess_compound_prefix(node.start_byte(), source)?;
    let tail = &source[body_start..];
    let tree = parse(tail).ok()?;
    let body_node = tree.root_node().named_child(0)?;
    if coprocess_compound_kind(body_node) != Some(expected) {
        return None;
    }
    let body_end = body_node.end_byte();
    let syntax = normalize(&tail[..body_end]).ok()?;
    let [body] = syntax.statements() else {
        return None;
    };
    *complete &= syntax.complete();
    Some((
        Statement::Coprocess {
            name,
            body: Box::new(body.clone()),
        },
        body_start + body_end,
    ))
}

fn command_or_coprocess(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let parsed = command(node, source, complete);
    let Statement::Command {
        name,
        name_substitutions,
        assignments,
        unmodeled_assignments,
        mut arguments,
        redirects,
    } = parsed
    else {
        return parsed;
    };
    if name != "coproc" || !name_substitutions.is_empty() {
        return Statement::Command {
            name,
            name_substitutions,
            assignments,
            unmodeled_assignments,
            arguments,
            redirects,
        };
    }
    if coprocess_has_compound_prefix(node.start_byte(), source) {
        *complete = false;
        return Statement::Unsupported {
            construct: "coprocess".to_owned(),
            statements: Vec::new(),
        };
    }
    if arguments.is_empty() {
        *complete = false;
        return Statement::Unsupported {
            construct: "coprocess-without-command".to_owned(),
            statements: Vec::new(),
        };
    }
    let program = arguments.remove(0);
    Statement::Coprocess {
        name: None,
        body: Box::new(Statement::Command {
            name: program.raw().to_owned(),
            name_substitutions: program.substitutions().to_vec(),
            assignments,
            unmodeled_assignments,
            arguments,
            redirects,
        }),
    }
}

fn coprocess_compound_prefix(
    start: usize,
    source: &str,
) -> Option<(Option<String>, usize, CoprocessCompound)> {
    let mut index = coprocess_body_start(start, source)?;
    if let Some(compound) = coprocess_compound_at(source, index) {
        return Some((None, index, compound));
    }
    let name_end = shell_identifier_end(source, index)?;
    let name = source[index..name_end].to_owned();
    index = skip_shell_whitespace(source, name_end);
    coprocess_compound_at(source, index).map(|compound| (Some(name), index, compound))
}

fn coprocess_has_compound_prefix(start: usize, source: &str) -> bool {
    let Some(mut index) = coprocess_body_start(start, source) else {
        return false;
    };
    if bash_compound_at(source, index) {
        return true;
    }
    let Some(name_end) = shell_identifier_end(source, index) else {
        return false;
    };
    index = skip_shell_whitespace(source, name_end);
    bash_compound_at(source, index)
}

fn coprocess_body_start(start: usize, source: &str) -> Option<usize> {
    let index = start.checked_add("coproc".len())?;
    (source[start..].starts_with("coproc")
        && source
            .as_bytes()
            .get(index)
            .is_some_and(u8::is_ascii_whitespace))
    .then(|| skip_shell_whitespace(source, index))
}

fn skip_shell_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn shell_identifier_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let first = *bytes.get(start)?;
    if first != b'_' && !first.is_ascii_alphabetic() {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
    {
        end += 1;
    }
    Some(end)
}

fn coprocess_compound_at(source: &str, index: usize) -> Option<CoprocessCompound> {
    match source.as_bytes().get(index) {
        Some(b'{') => Some(CoprocessCompound::Group),
        Some(b'(') => Some(CoprocessCompound::Subshell),
        Some(b'i') if shell_keyword_at(source, index, "if") => Some(CoprocessCompound::If),
        _ => None,
    }
}

fn bash_compound_at(source: &str, index: usize) -> bool {
    matches!(source.as_bytes().get(index), Some(b'{' | b'('))
        || source[index..].starts_with("[[")
        || ["if", "while", "until", "for", "select", "case"]
            .into_iter()
            .any(|keyword| shell_keyword_at(source, index, keyword))
}

fn shell_keyword_at(source: &str, index: usize, keyword: &str) -> bool {
    source[index..].starts_with(keyword)
        && source
            .as_bytes()
            .get(index + keyword.len())
            .is_none_or(|byte| !(*byte == b'_' || byte.is_ascii_alphanumeric()))
}

fn coprocess_compound_kind(node: Node<'_>) -> Option<CoprocessCompound> {
    let node = if node.kind() == "redirected_statement" {
        node.child_by_field_name("body")?
    } else {
        node
    };
    match node.kind() {
        "compound_statement" => Some(CoprocessCompound::Group),
        "subshell" => Some(CoprocessCompound::Subshell),
        "if_statement" => Some(CoprocessCompound::If),
        _ => None,
    }
}

fn shell_pattern_word(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.bytes().any(|byte| byte.is_ascii_whitespace())
        && raw.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn declaration_command(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let mut cursor = node.walk();
    let mut children = node.children(&mut cursor);
    let Some(name) = children.next() else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: Vec::new(),
        };
    };
    let mut assignments = Vec::new();
    let mut unmodeled_assignments = Vec::new();
    let mut arguments = Vec::new();
    for child in children {
        if child.kind() == "variable_assignment" {
            if let Some(binding) = assignment(child, source, complete) {
                assignments.push(binding);
            } else {
                unmodeled_assignments.push(UnmodeledStateExpansion::new(
                    assignments.len(),
                    true,
                    parse_word(child, source, complete),
                ));
            }
        } else if child.is_named() {
            arguments.push(parse_word(child, source, complete));
        } else {
            *complete = false;
        }
    }
    Statement::Command {
        name: text(name, source).to_owned(),
        name_substitutions: Vec::new(),
        assignments,
        unmodeled_assignments,
        arguments,
        redirects: Vec::new(),
    }
}

fn simple_builtin_command(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let mut cursor = node.walk();
    let mut children = node.children(&mut cursor);
    let Some(name) = children.next() else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: Vec::new(),
        };
    };
    let arguments = children
        .filter(|child| child.is_named())
        .map(|child| parse_word(child, source, complete))
        .collect();
    Statement::Command {
        name: text(name, source).to_owned(),
        name_substitutions: Vec::new(),
        assignments: Vec::new(),
        unmodeled_assignments: Vec::new(),
        arguments,
        redirects: Vec::new(),
    }
}

fn assignments(nodes: &[Node<'_>], source: &str, complete: &mut bool) -> Statement {
    let mut bindings = Vec::new();
    let mut unmodeled = Vec::new();
    for node in nodes {
        if let Some(binding) = assignment(*node, source, complete) {
            bindings.push(binding);
        } else {
            unmodeled.push(UnmodeledStateExpansion::new(
                bindings.len(),
                true,
                parse_word(*node, source, complete),
            ));
        }
    }
    Statement::Assignments {
        bindings,
        unmodeled,
    }
}

fn assignment(node: Node<'_>, source: &str, complete: &mut bool) -> Option<(String, Word)> {
    let Some(name) = node.child_by_field_name("name") else {
        *complete = false;
        return None;
    };
    let value = node.child_by_field_name("value");
    if value.is_none() && &source[name.end_byte()..node.end_byte()] == "=" {
        return Some((text(name, source).to_owned(), Word::from_literal("")));
    }
    let Some(value) = value else {
        *complete = false;
        return None;
    };
    if name.kind() != "variable_name"
        || value.kind() == "array"
        || &source[name.end_byte()..value.start_byte()] != "="
    {
        *complete = false;
        return None;
    }
    Some((
        text(name, source).to_owned(),
        parse_word(value, source, complete),
    ))
}

fn subshell(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let statements = delimited_statements(node, source, complete, &["(", ")", ";"]);
    Statement::Subshell { statements }
}

fn group(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let statements = delimited_statements(node, source, complete, &["{", "}", ";"]);
    Statement::Group { statements }
}

fn delimited_statements(
    node: Node<'_>,
    source: &str,
    complete: &mut bool,
    delimiters: &[&str],
) -> Vec<Statement> {
    let mut statements = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() && child.kind() != "comment" {
            statements.push(statement(child, source, complete));
        } else if child.kind() != "comment" && !delimiters.contains(&child.kind()) {
            *complete = false;
        }
    }
    statements
}

fn if_statement(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(condition_node) = node.child_by_field_name("condition") else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: executable_descendants(node, source, complete),
        };
    };
    let mut condition = vec![statement(condition_node, source, complete)];
    let mut body = Vec::new();
    let mut branches = Vec::new();
    let mut else_body = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if child == condition_node || !child.is_named() || child.kind() == "comment" {
            continue;
        }
        match child.kind() {
            "elif_clause" => branches.push(elif_clause(child, source, complete)),
            "else_clause" => else_body = else_clause(child, source, complete),
            _ => body.push(statement(child, source, complete)),
        }
    }
    branches.insert(
        0,
        ConditionalBranch::new(std::mem::take(&mut condition), body),
    );
    Statement::If {
        branches,
        else_body,
    }
}

fn elif_clause(node: Node<'_>, source: &str, complete: &mut bool) -> ConditionalBranch {
    let mut before_then = true;
    let mut condition = Vec::new();
    let mut body = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if child.kind() == "then" {
            before_then = false;
        } else if child.is_named() && child.kind() != "comment" {
            if before_then {
                condition.push(statement(child, source, complete));
            } else {
                body.push(statement(child, source, complete));
            }
        }
    }
    if condition.is_empty() {
        *complete = false;
    }
    ConditionalBranch::new(condition, body)
}

fn else_clause(node: Node<'_>, source: &str, complete: &mut bool) -> Vec<Statement> {
    node_statements(node, source, complete)
}

fn loop_statement(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let kind = if node.child(0).is_some_and(|child| child.kind() == "until") {
        LoopKind::Until
    } else {
        LoopKind::While
    };
    let Some(condition_node) = node.child_by_field_name("condition") else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: executable_descendants(node, source, complete),
        };
    };
    let Some(body_node) = node.child_by_field_name("body") else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: executable_descendants(node, source, complete),
        };
    };
    Statement::Loop {
        kind,
        condition: vec![statement(condition_node, source, complete)],
        body: node_statements(body_node, source, complete),
    }
}

fn for_statement(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(variable) = node.child_by_field_name("variable") else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: executable_descendants(node, source, complete),
        };
    };
    let Some(body_node) = node.child_by_field_name("body") else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: executable_descendants(node, source, complete),
        };
    };
    let mut values = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if node.field_name_for_child(index as u32) == Some("value") {
            values.push(parse_word(child, source, complete));
        }
    }
    if values.is_empty() {
        // An omitted `in` list expands the shell's positional parameters,
        // which are not present in the normalized syntax.
        *complete = false;
    }
    Statement::For {
        variable: text(variable, source).to_owned(),
        values,
        body: node_statements(body_node, source, complete),
    }
}

fn case_statement(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(value_node) = node.child_by_field_name("value") else {
        *complete = false;
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: executable_descendants(node, source, complete),
        };
    };
    let value = parse_word(value_node, source, complete);
    let arms = (0..node.child_count())
        .filter_map(|index| node.child(index))
        .filter(|child| child.kind() == "case_item")
        .map(|child| case_arm(child, source, complete))
        .collect();
    Statement::Case { value, arms }
}

fn function_definition(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    // Function scope and positional parameters are only partially modelled by
    // the action layer. Preserve the body for visible calls without claiming
    // that a definition executes it.
    *complete = false;
    let (Some(name), Some(body)) = (
        node.child_by_field_name("name"),
        node.child_by_field_name("body"),
    ) else {
        return Statement::Unsupported {
            construct: node.kind().to_owned(),
            statements: Vec::new(),
        };
    };
    let redirects = (0..node.child_count())
        .filter_map(|index| {
            (node.field_name_for_child(index as u32) == Some("redirect"))
                .then(|| node.child(index))
                .flatten()
        })
        .map(|redirect_node| redirect(redirect_node, source, complete))
        .collect();
    Statement::FunctionDefinition {
        name: text(name, source).to_owned(),
        body: Box::new(statement(body, source, complete)),
        redirects,
    }
}

fn case_arm(node: Node<'_>, source: &str, complete: &mut bool) -> CaseArm {
    let mut patterns = Vec::new();
    let mut body = Vec::new();
    let mut termination = CaseTermination::Break;
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if node.field_name_for_child(index as u32) == Some("value") {
            patterns.push(parse_word(child, source, complete));
        } else if matches!(child.kind(), ";&" | ";;&") {
            termination = if child.kind() == ";&" {
                CaseTermination::FallThrough
            } else {
                CaseTermination::ContinueMatching
            };
        } else if child.is_named() && child.kind() != "comment" {
            body.push(statement(child, source, complete));
        }
    }
    if patterns.is_empty() {
        *complete = false;
    }
    CaseArm::new(patterns, body, termination)
}

fn node_statements(node: Node<'_>, source: &str, complete: &mut bool) -> Vec<Statement> {
    let mut statements = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if !child.is_named() || child.kind() == "comment" {
            continue;
        }
        statements.push(statement(child, source, complete));
    }
    statements
}

fn executable_descendants(node: Node<'_>, source: &str, complete: &mut bool) -> Vec<Statement> {
    let mut statements = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if !child.is_named() || child.kind() == "comment" {
            continue;
        }
        if matches!(
            child.kind(),
            "command" | "pipeline" | "list" | "redirected_statement"
        ) {
            statements.push(statement(child, source, complete));
        } else if child.kind() != "function_definition" {
            statements.extend(executable_descendants(child, source, complete));
        }
    }
    statements
}

fn unmodeled_state_mutation(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let construct = if node.kind() == "compound_statement" {
        "arithmetic_command".to_owned()
    } else {
        node.kind().to_owned()
    };
    if node.kind() != "c_style_for_statement" {
        return Statement::UnmodeledStateMutation {
            construct,
            word: parse_word(node, source, complete),
            statements: Vec::new(),
        };
    }

    let body = node.child_by_field_name("body");
    let header_end = body.map_or(node.end_byte(), |body| body.start_byte());
    let mut substitutions = Vec::new();
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if child.start_byte() >= header_end {
            continue;
        }
        collect_substitutions(child, source, complete, &mut substitutions);
    }
    Statement::UnmodeledStateMutation {
        construct,
        word: word(
            source[node.start_byte()..header_end].to_owned(),
            substitutions,
        ),
        statements: body.map_or_else(Vec::new, |body| {
            executable_descendants(body, source, complete)
        }),
    }
}

fn parse_word(node: Node<'_>, source: &str, complete: &mut bool) -> Word {
    let mut substitutions = Vec::new();
    collect_substitutions(node, source, complete, &mut substitutions);
    word(text(node, source).to_owned(), substitutions)
}

fn command(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(name_node) = node.child_by_field_name("name") else {
        *complete = false;
        return Statement::Unsupported {
            construct: "command-without-name".to_owned(),
            statements: vec![],
        };
    };
    let name = command_name(node, name_node, source);
    if matches!(name, "{" | "}") {
        *complete = false;
    }
    let mut name_substitutions = Vec::new();
    collect_substitutions(name_node, source, complete, &mut name_substitutions);
    let mut command_assignments = Vec::new();
    let mut unmodeled_assignments = Vec::new();
    let mut arguments = Vec::new();
    let mut redirects = Vec::new();
    let mut previous_word_end = Some(name_node.end_byte());
    let mut index = 0;
    while index < node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        if child.is_error()
            && let Some(next) = node.child(index + 1)
            && recognized_extglob_error(child, source)
            && next.kind() == "subshell"
        {
            let mut substitutions = Vec::new();
            collect_substitutions(child, source, complete, &mut substitutions);
            collect_substitutions(next, source, complete, &mut substitutions);
            arguments.push(word(
                source[child.start_byte()..next.end_byte()].to_owned(),
                substitutions,
            ));
            previous_word_end = Some(next.end_byte());
            index += 2;
            continue;
        }
        match node.field_name_for_child(index as u32) {
            Some("name") => previous_word_end = Some(child.end_byte()),
            Some("argument") => {
                if previous_word_end == Some(child.start_byte()) {
                    *complete = false;
                }
                previous_word_end = Some(child.end_byte());
                arguments.push(parse_word(child, source, complete));
            }
            Some("redirect") => {
                let attached_fd = (previous_word_end == Some(child.start_byte()))
                    .then(|| arguments.last())
                    .flatten()
                    .and_then(|argument| redirect_fd(argument.raw()))
                    .map(str::to_owned);
                if attached_fd.is_some() {
                    arguments.pop();
                }
                previous_word_end = None;
                let parsed = redirect(child, source, complete);
                redirects.push(match (parsed.fd(), attached_fd) {
                    (None, Some(fd)) => parsed.with_fd(fd),
                    _ => parsed,
                });
            }
            _ if child.kind() == "variable_assignment" => {
                // Prefix assignments affect only this process. Preserve them
                // for consumers that model a named environment contract, but
                // keep coverage partial because arbitrary environment effects
                // are outside the normalized shell model.
                *complete = false;
                if let Some(binding) = assignment(child, source, complete) {
                    command_assignments.push(binding);
                } else {
                    unmodeled_assignments.push(UnmodeledStateExpansion::new(
                        command_assignments.len(),
                        false,
                        parse_word(child, source, complete),
                    ));
                }
                previous_word_end = None;
            }
            _ if child.kind() == "comment" => previous_word_end = None,
            _ => {
                previous_word_end = None;
                *complete = false;
            }
        }
        index += 1;
    }
    match (name, name_substitutions.is_empty()) {
        ("break", true) => Statement::LoopControl {
            kind: LoopControlKind::Break,
            arguments,
            redirects,
        },
        ("continue", true) => Statement::LoopControl {
            kind: LoopControlKind::Continue,
            arguments,
            redirects,
        },
        _ => Statement::Command {
            name: name.to_owned(),
            name_substitutions,
            assignments: command_assignments,
            unmodeled_assignments,
            arguments,
            redirects,
        },
    }
}

fn command_name<'a>(node: Node<'_>, name: Node<'_>, source: &'a str) -> &'a str {
    let Some(prefix) = node.prev_named_sibling().filter(|prefix| {
        prefix.kind() == "ERROR"
            && prefix.end_byte() == name.start_byte()
            && source[prefix.start_byte()..name.end_byte()].contains(['*', '?', '['])
    }) else {
        return text(name, source);
    };
    &source[prefix.start_byte()..name.end_byte()]
}

fn allocated_redirect_fd(raw: &str) -> Option<&str> {
    let name = raw.strip_prefix('{')?.strip_suffix('}')?;
    let mut bytes = name.bytes();
    let first = bytes.next()?;
    (first == b'_' || first.is_ascii_alphabetic()).then_some(())?;
    bytes
        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        .then_some(raw)
}

fn redirect_fd(raw: &str) -> Option<&str> {
    allocated_redirect_fd(raw).or_else(|| {
        (!raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit())).then_some(raw)
    })
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
            let raw = text(node, source);
            if matches!(raw.as_bytes(), [b'`', ..] | [b'$', b'`', ..]) {
                let delimited = raw.strip_prefix('$').unwrap_or(raw);
                let interior = delimited
                    .strip_prefix('`')
                    .and_then(|value| value.strip_suffix('`'));
                if interior.is_none_or(contains_unescaped_backtick) {
                    *complete = false;
                }
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
        if let Some(child) = node.child(index) {
            collect_substitutions(child, source, complete, out);
        }
    }
}

fn pipeline(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let mut operators = Vec::new();
    let mut stages = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(child.kind(), "|" | "|&") {
            operators.push(text(child, source).to_owned());
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
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        let mut cursor = node.walk();
        let mut children = node.children(&mut cursor).collect::<Vec<_>>();
        children.reverse();
        for child in children {
            pending.push(child);
        }
        while pending.last().is_some_and(|child| child.kind() != "list") {
            let child = pending.pop().expect("checked");
            if matches!(child.kind(), "&&" | "||") {
                operators.push(text(child, source).to_owned());
            } else if child.is_named() && child.kind() != "comment" {
                items.push(statement(child, source, complete));
            } else if child.kind() != "comment" {
                *complete = false;
            }
        }
    }
    if items.len().saturating_sub(1) != operators.len() {
        *complete = false;
    }
    Statement::Chain { operators, items }
}

fn redirected(node: Node<'_>, source: &str, complete: &mut bool) -> Statement {
    let Some(body_node) = node.child_by_field_name("body") else {
        let redirect_nodes = (0..node.child_count())
            .filter_map(|index| {
                (node.field_name_for_child(index as u32) == Some("redirect"))
                    .then(|| node.child(index))
                    .flatten()
            })
            .collect::<Vec<_>>();
        if !redirect_nodes.is_empty() {
            return redirect_only(&redirect_nodes, source, complete);
        }
        *complete = false;
        return Statement::Unsupported {
            construct: "redirect-without-body".to_owned(),
            statements: vec![],
        };
    };
    let mut body = statement(body_node, source, complete);
    let mut redirects = Vec::new();
    let mut continuation = None;
    let mut pending_redirect_fd = None;
    for index in 0..node.child_count() {
        let child = node.child(index).expect("tree-sitter child index is valid");
        match node.field_name_for_child(index as u32) {
            Some("body") => {}
            Some("redirect") => {
                if let Some(next) = heredoc_pipeline_continuation(child, source, complete)
                    && continuation.replace(next).is_some()
                {
                    *complete = false;
                }
                let parsed = redirect(child, source, complete);
                let attached_fd = pending_redirect_fd.take().or_else(|| {
                    (parsed.fd().is_none() && body_node.end_byte() == child.start_byte())
                        .then(|| {
                            let fd = text(body_node, source)
                                .split_ascii_whitespace()
                                .next_back()
                                .and_then(redirect_fd)?
                                .to_owned();
                            take_attached_redirect_fd(&mut body);
                            Some(fd)
                        })
                        .flatten()
                });
                redirects.push(match attached_fd {
                    Some(fd) => parsed.with_fd(fd),
                    None => parsed,
                });
                pending_redirect_fd = text(child, source)
                    .split_ascii_whitespace()
                    .next_back()
                    .and_then(redirect_fd)
                    .map(str::to_owned);
            }
            _ if child.kind() == "comment" => {}
            _ => *complete = false,
        }
    }
    if pending_redirect_fd.is_some() {
        *complete = false;
    }
    if redirects.is_empty() {
        *complete = false;
        return body;
    }
    let mut attached = body.clone();
    let attached = if attach_redirects_to_last_command(&mut attached, redirects.clone()) {
        attached
    } else {
        Statement::Redirected {
            body: Box::new(body),
            redirects,
        }
    };
    if let Some((operators, mut stages)) = continuation {
        stages.insert(0, attached);
        Statement::Pipeline { operators, stages }
    } else {
        attached
    }
}

fn redirect_only(nodes: &[Node<'_>], source: &str, complete: &mut bool) -> Statement {
    let redirects = nodes
        .iter()
        .map(|node| redirect(*node, source, complete))
        .collect::<Vec<_>>();
    let produces_stdout = redirects.as_slice().first().is_some_and(|redirect| {
        redirects.len() == 1
            && matches!(redirect.fd(), None | Some("0"))
            && redirect.operator() == "<"
            && nodes[0]
                .parent()
                .is_some_and(|parent| parent.kind() == "command_substitution")
    });
    Statement::RedirectOnly {
        redirects,
        produces_stdout,
    }
}

fn take_attached_redirect_fd(statement: &mut Statement) -> Option<String> {
    match statement {
        Statement::Command { arguments, .. } | Statement::LoopControl { arguments, .. } => {
            let argument = arguments.last()?;
            let fd = redirect_fd(argument.raw())?.to_owned();
            arguments.pop();
            Some(fd)
        }
        Statement::Pipeline { stages, .. } => take_attached_redirect_fd(stages.last_mut()?),
        Statement::Chain { items, .. } => take_attached_redirect_fd(items.last_mut()?),
        Statement::Redirected { body, .. } => take_attached_redirect_fd(body),
        Statement::Coprocess { body, .. } => take_attached_redirect_fd(body),
        Statement::Assignments { .. }
        | Statement::RedirectOnly { .. }
        | Statement::Subshell { .. }
        | Statement::Group { .. }
        | Statement::If { .. }
        | Statement::Loop { .. }
        | Statement::For { .. }
        | Statement::FunctionDefinition { .. }
        | Statement::Case { .. }
        | Statement::UnmodeledStateMutation { .. }
        | Statement::Unsupported { .. } => None,
    }
}

fn heredoc_pipeline_continuation(
    redirect: Node<'_>,
    source: &str,
    complete: &mut bool,
) -> Option<(Vec<String>, Vec<Statement>)> {
    let pipeline = (0..redirect.child_count())
        .filter_map(|index| redirect.child(index))
        .find(|child| child.kind() == "pipeline")?;
    let mut operators = Vec::new();
    let mut stages = Vec::new();
    for index in 0..pipeline.child_count() {
        let child = pipeline
            .child(index)
            .expect("tree-sitter child index is valid");
        if matches!(child.kind(), "|" | "|&") {
            operators.push(text(child, source).to_owned());
        } else if child.is_named() && child.kind() != "comment" {
            stages.push(statement(child, source, complete));
        } else if child.kind() != "comment" {
            *complete = false;
        }
    }
    if operators.len() != stages.len() || stages.is_empty() {
        *complete = false;
    }
    Some((operators, stages))
}

fn attach_redirects_to_last_command(statement: &mut Statement, redirects: Vec<Redirect>) -> bool {
    match statement {
        Statement::Command {
            redirects: command_redirects,
            ..
        } => {
            command_redirects.extend(redirects);
            true
        }
        Statement::Pipeline { stages, .. } => stages
            .last_mut()
            .is_some_and(|stage| attach_redirects_to_last_command(stage, redirects)),
        Statement::Chain { items, .. } => items
            .last_mut()
            .is_some_and(|item| attach_redirects_to_last_command(item, redirects)),
        Statement::Coprocess { body, .. } => attach_redirects_to_last_command(body, redirects),
        Statement::Redirected { .. }
        | Statement::Assignments { .. }
        | Statement::RedirectOnly { .. }
        | Statement::Subshell { .. }
        | Statement::Group { .. }
        | Statement::If { .. }
        | Statement::Loop { .. }
        | Statement::For { .. }
        | Statement::FunctionDefinition { .. }
        | Statement::LoopControl { .. }
        | Statement::Case { .. }
        | Statement::UnmodeledStateMutation { .. } => {
            let body = statement.clone();
            *statement = Statement::Redirected {
                body: Box::new(body),
                redirects,
            };
            true
        }
        Statement::Unsupported { .. } => false,
    }
}

fn redirect(node: Node<'_>, source: &str, complete: &mut bool) -> Redirect {
    let mut fd = None;
    let mut operator = None;
    let mut operator_end = None;
    let mut target_node = None;
    let mut body_node = None;
    let mut cursor = node.walk();
    for (index, child) in node.children(&mut cursor).enumerate() {
        match node.field_name_for_child(index as u32) {
            Some("descriptor") if fd.is_none() => fd = Some(text(child, source).to_owned()),
            Some("descriptor") => *complete = false,
            Some("destination") if target_node.is_none() => target_node = Some(child),
            Some("destination")
                if target_node.is_some_and(|target| {
                    target.end_byte() < child.start_byte()
                        && source[target.end_byte()..child.start_byte()]
                            .bytes()
                            .any(|byte| byte.is_ascii_whitespace())
                }) && redirect_fd(text(child, source)).is_some() => {}
            Some("destination") => *complete = false,
            _ if !child.is_named() && is_redirect_operator(child.kind()) => {
                let token = text(child, source);
                operator_end = Some(child.end_byte());
                match &mut operator {
                    None => operator = Some(token.to_owned()),
                    Some(existing) => {
                        let combined = format!("{existing}{token}");
                        if is_redirect_operator(&combined) {
                            *existing = combined;
                        }
                    }
                }
            }
            _ if child.kind() == "heredoc_start" && target_node.is_none() => {
                target_node = Some(child)
            }
            _ if child.kind() == "heredoc_body" && body_node.is_none() => body_node = Some(child),
            _ if child.kind() == "heredoc_end" => {}
            _ if child.kind() == "pipeline" => {}
            _ if node.kind() == "herestring_redirect" && target_node.is_none() => {
                target_node = Some(child)
            }
            _ if !child.is_named()
                && text(child, source)
                    .bytes()
                    .all(|byte| matches!(byte, b'<' | b'>' | b'&' | b'|' | b'-')) => {}
            _ if child.is_named()
                && child.end_byte() == node.end_byte()
                && allocated_redirect_fd(text(child, source)).is_some() => {}
            _ if recognized_multi_digit_redirect_artifact(child, source) => {}
            _ => *complete = false,
        }
    }
    if let Some(target) = target_node {
        let mut prefix = source[node.start_byte()..target.start_byte()].trim();
        if fd.as_deref().is_none_or(str::is_empty)
            && let Some((descriptor, redirect_operator)) = numeric_redirect_prefix(prefix)
        {
            fd = Some(descriptor.to_owned());
            operator = Some(redirect_operator.to_owned());
            prefix = redirect_operator;
        }
        if let Some(descriptor) = fd.as_deref() {
            prefix = prefix.strip_prefix(descriptor).unwrap_or(prefix).trim();
        }
        if is_redirect_operator(prefix) {
            operator = Some(prefix.to_owned());
        }
        if operator_end.is_some_and(|end| source[end..target.start_byte()].contains('\n')) {
            *complete = false;
        }
    }
    let mut synthetic_target = None;
    if target_node.is_none() {
        let mut raw = text(node, source).trim();
        if let Some(descriptor) = fd.as_deref() {
            raw = raw.strip_prefix(descriptor).unwrap_or(raw);
        }
        if let Some(prefix) = raw.strip_suffix('-')
            && matches!(prefix, ">&" | "<&")
        {
            operator = Some(prefix.to_owned());
            synthetic_target = Some("-".to_owned());
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
        *complete = false;
    }
    Redirect::new(
        fd,
        operator,
        target_node
            .map(|node| text(node, source).to_owned())
            .or(synthetic_target),
        body_node.map(|node| text(node, source).to_owned()),
        target_substitutions,
        body_substitutions,
    )
}

fn numeric_redirect_prefix(prefix: &str) -> Option<(&str, &str)> {
    let operator = prefix.find(['<', '>'])?;
    let descriptor = &prefix[..operator];
    let operator = &prefix[operator..];
    (!descriptor.is_empty()
        && descriptor.bytes().all(|byte| byte.is_ascii_digit())
        && is_redirect_operator(operator))
    .then_some((descriptor, operator))
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
