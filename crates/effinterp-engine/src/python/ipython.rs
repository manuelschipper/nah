//! IPython input transformation layered over the Python frontend.
//!
//! Operational syntax becomes same-offset sentinel statements. The Python
//! walk consumes their typed actions in order, so ordinary Python keeps its
//! parser and binding semantics while every emitted fact points at the cell.
//! `prepare` builds the actions; the `PythonWalker::ipython_*` methods apply them.

use std::collections::BTreeMap;

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ExecutionEdgeKind, ProvenanceRef, ResourceExpr, ResourceIdentity, Subject,
};
use rustpython_parser::Parse;
use rustpython_parser::ast::{self, Constant, Expr};
use rustpython_parser::text_size::TextRange;

use super::{DOMAINS, PythonWalker, resolve, resource_path_string};
use crate::builder::PlanBuilder;
use crate::lang::frontend::{self, FrontendInput};
use crate::nest::{Nest, Transition};
use crate::paths::resolve_fs_path;
use crate::summary::substitute_resource_expr;
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

#[derive(Clone, Debug)]
pub(super) enum Action {
    Shell {
        command: String,
        capture: bool,
    },
    LineMagic {
        name: String,
        arguments: String,
    },
    CellMagic {
        name: String,
        arguments: String,
        body: String,
        body_offset: usize,
    },
}

#[derive(Clone, Debug, Default)]
pub(super) struct CellActions {
    pub actions: BTreeMap<u32, Vec<Action>>,
}

struct PreparedCell {
    source: String,
    actions: CellActions,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn analyze(
    builder: &mut PlanBuilder,
    nest: &Nest,
    source: &str,
    source_cwd: Option<&str>,
    runtime_cwd: Option<&str>,
    cwd_node: Option<ProvenanceRef>,
    scope: Option<ProvenanceRef>,
    depth: u64,
) {
    let prepared = prepare(source);
    frontend::run(
        &super::PythonFrontend::ipython(prepared.actions),
        builder,
        nest,
        FrontendInput {
            source: &prepared.source,
            source_cwd,
            runtime_cwd,
            cwd_node,
            scope,
            depth,
        },
    );
}

fn prepare(source: &str) -> PreparedCell {
    let mut transformed = source.as_bytes().to_vec();
    let mut actions = CellActions::default();
    prepare_region(source, 0, &mut transformed, &mut actions, true);
    PreparedCell {
        source: String::from_utf8(transformed).expect("IPython replacement is UTF-8"),
        actions,
    }
}

fn prepare_region(
    source: &str,
    base: usize,
    transformed: &mut [u8],
    actions: &mut CellActions,
    allow_cell_magic: bool,
) {
    if allow_cell_magic && prepare_cell_magic(source, base, transformed, actions) {
        return;
    }

    let mut offset = 0;
    let mut triple_quote = None;
    for line in source.split_inclusive('\n') {
        let body = line
            .strip_suffix('\n')
            .unwrap_or(line)
            .strip_suffix('\r')
            .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));
        let start = base + offset;
        let end = start + body.len();
        if triple_quote.is_none() {
            let trimmed = body.trim_start_matches([' ', '\t']);
            let indentation = body.len() - trimmed.len();
            if indentation == 0 && !trimmed.starts_with('#') {
                if let Some(command) = trimmed.strip_prefix("!!") {
                    replace_with_sentinel(transformed, start, end);
                    actions.actions.insert(
                        start as u32,
                        vec![Action::Shell {
                            command: command.to_string(),
                            capture: true,
                        }],
                    );
                } else if let Some(command) = trimmed.strip_prefix('!')
                    && !trimmed.starts_with("!=")
                {
                    replace_with_sentinel(transformed, start, end);
                    actions.actions.insert(
                        start as u32,
                        vec![Action::Shell {
                            command: command.to_string(),
                            capture: false,
                        }],
                    );
                } else if let Some(magic) = trimmed.strip_prefix('%')
                    && !magic.starts_with('%')
                    && magic.chars().next().is_some_and(|character| {
                        character == '_' || character.is_ascii_alphabetic()
                    })
                {
                    let name_end = magic.find([' ', '\t']).unwrap_or(magic.len());
                    let name = &magic[..name_end];
                    let arguments = magic[name_end..].trim_start();
                    if matches!(name, "time" | "timeit") && !arguments.starts_with(['!', '%']) {
                        let prefix = body.len() - arguments.len();
                        rewrite_timing_prefix(transformed, start, prefix);
                    } else {
                        replace_with_sentinel(transformed, start, end);
                        actions
                            .actions
                            .insert(start as u32, line_magic_actions(name, arguments));
                    }
                }
            }
        }
        update_triple_quote(body, &mut triple_quote);
        offset += line.len();
    }
}

fn prepare_cell_magic(
    source: &str,
    base: usize,
    transformed: &mut [u8],
    actions: &mut CellActions,
) -> bool {
    let mut leading = 0;
    let mut lines = source.split_inclusive('\n');
    let first = loop {
        let Some(line) = lines.next() else {
            return false;
        };
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body.trim().is_empty() {
            leading += line.len();
            continue;
        }
        break line;
    };
    let first_body = first
        .strip_suffix('\n')
        .unwrap_or(first)
        .strip_suffix('\r')
        .unwrap_or_else(|| first.strip_suffix('\n').unwrap_or(first));
    let trimmed = first_body.trim_start_matches([' ', '\t']);
    if first_body.len() != trimmed.len() {
        return false;
    }
    let Some(header) = trimmed.strip_prefix("%%") else {
        return false;
    };
    let name_end = header.find([' ', '\t']).unwrap_or(header.len());
    let name = &header[..name_end];
    if name.is_empty() {
        return false;
    }
    let arguments = header[name_end..].trim();
    let header_start = base + leading;
    let header_end = header_start + first_body.len();
    let body_start = leading + first.len();
    let body = &source[body_start..];

    if matches!(name, "time" | "timeit" | "capture") {
        blank(transformed, header_start, header_end);
        prepare_region(body, base + body_start, transformed, actions, true);
        return true;
    }

    replace_with_sentinel(transformed, header_start, base + source.len());
    actions.actions.insert(
        header_start as u32,
        vec![Action::CellMagic {
            name: name.to_string(),
            arguments: arguments.to_string(),
            body: body.to_string(),
            body_offset: base + body_start,
        }],
    );
    true
}

fn line_magic_actions(name: &str, arguments: &str) -> Vec<Action> {
    if name == "cd"
        && let Some((directory, command)) = arguments.split_once(';')
        && let Some(command) = command.trim_start().strip_prefix('!')
    {
        return vec![
            Action::LineMagic {
                name: name.to_string(),
                arguments: directory.trim().to_string(),
            },
            Action::Shell {
                command: command.to_string(),
                capture: false,
            },
        ];
    }
    if matches!(name, "system" | "sx" | "sc") {
        return vec![Action::Shell {
            command: arguments.to_string(),
            capture: name != "system",
        }];
    }
    if matches!(name, "time" | "timeit")
        && let Some(command) = arguments.strip_prefix("!!")
    {
        return vec![Action::Shell {
            command: command.to_string(),
            capture: true,
        }];
    }
    if matches!(name, "time" | "timeit")
        && let Some(command) = arguments.strip_prefix('!')
    {
        return vec![Action::Shell {
            command: command.to_string(),
            capture: false,
        }];
    }
    vec![Action::LineMagic {
        name: name.to_string(),
        arguments: arguments.to_string(),
    }]
}

fn replace_with_sentinel(bytes: &mut [u8], start: usize, end: usize) {
    blank(bytes, start, end);
    if start < end {
        bytes[start] = b'0';
    }
}

fn blank(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if !matches!(*byte, b'\n' | b'\r') {
            *byte = b' ';
        }
    }
}

fn rewrite_timing_prefix(bytes: &mut [u8], start: usize, length: usize) {
    blank(bytes, start, start + length);
    let replacement = b"pass;";
    bytes[start..start + replacement.len()].copy_from_slice(replacement);
}

fn update_triple_quote(line: &str, active: &mut Option<&'static str>) {
    let mut offset = 0;
    while offset < line.len() {
        let rest = &line[offset..];
        if let Some(quote) = *active {
            let Some(end) = rest.find(quote) else { return };
            *active = None;
            offset += end + quote.len();
            continue;
        }
        let single = rest.find("'''").map(|index| (index, "'''"));
        let double = rest.find("\"\"\"").map(|index| (index, "\"\"\""));
        let next = match (single, double) {
            (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
            (left, right) => left.or(right),
        };
        let Some((index, quote)) = next else { return };
        if rest[..index].contains('#') {
            return;
        }
        *active = Some(quote);
        offset += index + quote.len();
    }
}

pub(super) struct IpythonState {
    pub(super) actions: std::collections::BTreeMap<u32, Vec<Action>>,
    pub(super) bindings: std::collections::HashMap<String, ResourceExpr>,
    pub(super) environment: std::collections::BTreeMap<String, Option<ResourceExpr>>,
    pub(super) environment_nodes: std::collections::BTreeMap<String, ProvenanceRef>,
    pub(super) get_ipython_owned: bool,
}

impl PythonWalker<'_, '_> {
    pub(super) fn ipython_sentinel(&mut self, statement: &ast::StmtExpr) -> bool {
        let start = u32::from(statement.range.start());
        let Some(actions) = self
            .ipython
            .as_mut()
            .and_then(|state| state.actions.remove(&start))
        else {
            return false;
        };
        for action in actions {
            self.ipython_action(action, statement.range);
        }
        true
    }

    fn ipython_action(&mut self, action: Action, span: TextRange) {
        match action {
            Action::Shell { command, capture } => self.ipython_shell(&command, capture, span),
            Action::LineMagic { name, arguments } => {
                self.ipython_line_magic(&name, &arguments, span)
            }
            Action::CellMagic {
                name,
                arguments,
                body,
                body_offset,
            } => self.ipython_cell_magic(&name, &arguments, &body, body_offset, span),
        }
    }

    pub(super) fn ipython_call(&mut self, call: &ast::ExprCall) -> bool {
        if !self
            .ipython
            .as_ref()
            .is_some_and(|state| state.get_ipython_owned)
        {
            return false;
        }
        if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "get_ipython")
            && call.args.is_empty()
            && call.keywords.is_empty()
        {
            return true;
        }
        let Expr::Attribute(method) = call.func.as_ref() else {
            return false;
        };
        let Expr::Call(receiver) = method.value.as_ref() else {
            return false;
        };
        if !matches!(receiver.func.as_ref(), Expr::Name(name) if name.id.as_str() == "get_ipython")
            || !receiver.args.is_empty()
            || !receiver.keywords.is_empty()
            || !call.keywords.is_empty()
        {
            return false;
        }
        match method.attr.as_str() {
            "system" | "getoutput" if call.args.len() == 1 => {
                let command = self
                    .ipython_expr_text(&call.args[0])
                    .unwrap_or_else(|| ipython_unresolved_expression(&call.args[0]));
                self.ipython_shell(&command, method.attr.as_str() == "getoutput", call.range);
                true
            }
            "run_line_magic" if call.args.len() == 2 => {
                let Some(name) = self.ipython_expr_text(&call.args[0]) else {
                    let node = self.span_node(call.range);
                    self.ipython_boundary(
                        BoundaryReason::UNMODELED_DYNAMIC,
                        BoundaryClass::Unresolved,
                        "IPython line magic name is unresolved".to_string(),
                        node,
                    );
                    return true;
                };
                let arguments = self
                    .ipython_expr_text(&call.args[1])
                    .unwrap_or_else(|| ipython_unresolved_expression(&call.args[1]));
                self.ipython_line_magic(&name, &arguments, call.range);
                true
            }
            "run_cell_magic" if call.args.len() == 3 => {
                let Some(name) = self.ipython_expr_text(&call.args[0]) else {
                    let node = self.span_node(call.range);
                    self.ipython_boundary(
                        BoundaryReason::UNMODELED_DYNAMIC,
                        BoundaryClass::Unresolved,
                        "IPython cell magic name is unresolved".to_string(),
                        node,
                    );
                    return true;
                };
                let arguments = self
                    .ipython_expr_text(&call.args[1])
                    .unwrap_or_else(|| ipython_unresolved_expression(&call.args[1]));
                let Some(body) = self.ipython_expr_text(&call.args[2]) else {
                    let node = self.span_node(call.range);
                    self.ipython_boundary(
                        BoundaryReason::UNMODELED_DYNAMIC,
                        BoundaryClass::Unresolved,
                        format!("IPython cell magic %{name} body is unresolved"),
                        node,
                    );
                    return true;
                };
                self.ipython_cell_magic(&name, &arguments, &body, 0, call.range);
                true
            }
            _ => false,
        }
    }

    pub(super) fn ipython_invalidate_getter_target(&mut self, target: &Expr) {
        if ipython_getter_target(target)
            && let Some(state) = self.ipython.as_mut()
        {
            state.get_ipython_owned = false;
        }
    }

    pub(super) fn ipython_track_assignment(&mut self, names: &[String], value: &Expr) {
        if self.ipython.is_none() || self.capture.is_some() || self.current_function.is_some() {
            return;
        }
        let resource = self.ipython_expr_resource(value);
        let Some(state) = self.ipython.as_mut() else {
            return;
        };
        for name in names {
            if let Some(resource) = &resource {
                state.bindings.insert(name.clone(), resource.clone());
            } else {
                state.bindings.remove(name);
            }
        }
    }

    fn ipython_expr_resource(&self, expr: &Expr) -> Option<ResourceExpr> {
        if let Some(value) = ipython_constant_text(expr) {
            return Some(ResourceExpr::Literal { value });
        }
        if let Expr::Name(name) = expr {
            return self
                .ipython
                .as_ref()?
                .bindings
                .get(name.id.as_str())
                .cloned();
        }
        let resource = resolve::concatenated_part_resource(
            expr,
            &self.imports,
            (!self.fact_file.is_empty()).then_some(self.fact_file.as_str()),
        )?;
        let bindings = &self.ipython.as_ref()?.bindings;
        let resource = substitute_resource_expr(&resource, bindings);
        ipython_flatten_literal(&resource).map(|value| ResourceExpr::Literal { value })
    }

    fn ipython_expr_text(&self, expr: &Expr) -> Option<String> {
        self.ipython_expr_resource(expr)
            .as_ref()
            .and_then(ipython_flatten_literal)
    }

    fn ipython_shell(&mut self, command: &str, _capture: bool, span: TextRange) {
        let node = self.span_node(span);
        let (command, unresolved) = self.ipython_interpolate(command);
        self.ipython_nest_subject(
            Subject::Shell {
                source: command,
                cwd: self.cwd.clone(),
                context: Default::default(),
            },
            node,
            0,
        );
        for name in unresolved {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                format!("IPython unresolved word: {name}"),
                node,
            );
        }
    }

    fn ipython_interpolate(&self, command: &str) -> (String, Vec<String>) {
        let bindings = self
            .ipython
            .as_ref()
            .map(|state| &state.bindings)
            .expect("IPython action has state");
        let bytes = command.as_bytes();
        let mut output = String::with_capacity(command.len());
        let mut unresolved = Vec::new();
        let mut offset = 0;
        let mut single_quoted = false;
        while offset < bytes.len() {
            if bytes[offset] == b'\'' {
                single_quoted = !single_quoted;
                output.push('\'');
                offset += 1;
                continue;
            }
            if bytes[offset] == b'{'
                && bytes.get(offset + 1) != Some(&b'{')
                && let Some(end) = bytes[offset + 1..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|end| offset + end + 1)
            {
                let expression = &command[offset + 1..end];
                if let Ok(expr) = ast::Expr::parse(expression, "<ipython-interpolation>")
                    && let Some(value) = self.ipython_expr_text(&expr)
                {
                    output.push_str(&value);
                } else {
                    let name = interpolation_name(expression);
                    output.push_str("${");
                    output.push_str(&name);
                    output.push('}');
                    unresolved.push(expression.to_string());
                }
                offset = end + 1;
                continue;
            }
            if bytes[offset] == b'$' && !single_quoted {
                if bytes.get(offset + 1) == Some(&b'$') {
                    output.push('$');
                    offset += 2;
                    continue;
                }
                let (start, end, consumed) = if bytes.get(offset + 1) == Some(&b'{') {
                    let start = offset + 2;
                    let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == b'}')
                    else {
                        output.push('$');
                        offset += 1;
                        continue;
                    };
                    let end = start + relative_end;
                    (start, end, end + 1)
                } else {
                    let start = offset + 1;
                    let mut end = start;
                    while bytes
                        .get(end)
                        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    {
                        end += 1;
                    }
                    if end == start {
                        output.push('$');
                        offset += 1;
                        continue;
                    }
                    (start, end, end)
                };
                let name = &command[start..end];
                if let Some(value) = bindings.get(name).and_then(ipython_flatten_literal) {
                    output.push_str(&value);
                } else {
                    output.push_str("${");
                    output.push_str(name);
                    output.push('}');
                    unresolved.push(name.to_string());
                }
                offset = consumed;
                continue;
            }
            let character = command[offset..]
                .chars()
                .next()
                .expect("character boundary");
            output.push(character);
            offset += character.len_utf8();
        }
        (output, unresolved)
    }

    fn ipython_line_magic(&mut self, name: &str, arguments: &str, span: TextRange) {
        match name {
            "system" | "sx" | "sc" => self.ipython_shell(arguments, name != "system", span),
            "cd" => self.ipython_change_directory(arguments, span),
            "run" => self.ipython_run(arguments, span),
            "env" => self.ipython_set_environment(arguments, span),
            "pip" | "conda" => self.ipython_package_manager(name, arguments, span),
            "time" | "timeit" if arguments.starts_with("!!") => {
                self.ipython_shell(&arguments[2..], true, span)
            }
            "time" | "timeit" if arguments.starts_with('!') => {
                self.ipython_shell(&arguments[1..], false, span)
            }
            "time" | "timeit" if !arguments.is_empty() => {
                let node = self.span_node(span);
                self.ipython_nest_source("python", None, arguments, 0, node);
            }
            name if ipython_noop_magic(name) => {}
            _ => {
                let node = self.span_node(span);
                self.ipython_boundary(
                    BoundaryReason::UNKNOWN_IPYTHON_MAGIC,
                    BoundaryClass::Unsupported,
                    format!("unrecognized IPython magic %{name}"),
                    node,
                );
            }
        }
    }

    fn ipython_cell_magic(
        &mut self,
        name: &str,
        arguments: &str,
        body: &str,
        body_offset: usize,
        span: TextRange,
    ) {
        let node = self.span_node(span);
        match name {
            "bash" | "sh" => {
                self.ipython_magic_options(name, arguments, node);
                self.ipython_nest_subject(
                    Subject::Shell {
                        source: body.to_string(),
                        cwd: self.cwd.clone(),
                        context: Default::default(),
                    },
                    node,
                    body_offset,
                );
            }
            "script" => {
                let words = ipython_split_words(arguments);
                let Some(interpreter) = words.first() else {
                    self.ipython_boundary(
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unsupported,
                        "IPython %%script has no interpreter".to_string(),
                        node,
                    );
                    return;
                };
                self.ipython_magic_options(interpreter, &words[1..].join(" "), node);
                if matches!(interpreter.as_str(), "bash" | "sh") {
                    self.ipython_nest_subject(
                        Subject::Shell {
                            source: body.to_string(),
                            cwd: self.cwd.clone(),
                            context: Default::default(),
                        },
                        node,
                        body_offset,
                    );
                } else if let Some((language, dialect)) = ipython_script_language(interpreter) {
                    self.ipython_nest_source(language, dialect, body, body_offset, node);
                } else {
                    self.ipython_boundary(
                        BoundaryReason::UNSUPPORTED_SOURCE,
                        BoundaryClass::Unsupported,
                        format!("unmodeled IPython %%script interpreter {interpreter}"),
                        node,
                    );
                }
            }
            "writefile" => {
                let words = ipython_split_words(arguments);
                let mut path = None;
                for word in words {
                    if word == "-a" || word == "--append" {
                        continue;
                    }
                    if word.starts_with('-') {
                        self.ipython_boundary(
                            BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                            BoundaryClass::Unsupported,
                            format!("unknown IPython %%writefile option {word}"),
                            node,
                        );
                    } else if path.is_none() {
                        path = Some(word);
                    }
                }
                if let Some(path) = path {
                    let resource = resolve_fs_path(&path, self.cwd.as_deref());
                    self.emit("filesystem.write", resource, &[], node);
                } else {
                    self.ipython_boundary(
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unsupported,
                        "IPython %%writefile has no path".to_string(),
                        node,
                    );
                }
            }
            "time" | "timeit" | "capture" => self.ipython_nest_source(
                "python",
                Some(effinterp_proto::SourceDialect::Ipython),
                body,
                body_offset,
                node,
            ),
            name if ipython_noop_magic(name) => {}
            _ => self.ipython_boundary(
                BoundaryReason::UNKNOWN_IPYTHON_MAGIC,
                BoundaryClass::Unsupported,
                format!("unrecognized IPython cell magic %%{name}"),
                node,
            ),
        }
    }

    fn ipython_magic_options(&mut self, magic: &str, arguments: &str, node: ProvenanceRef) {
        for option in ipython_split_words(arguments) {
            if ipython_known_magic_option(&option) {
                continue;
            }
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                format!("unknown IPython %%{magic} option {option}"),
                node,
            );
        }
    }

    fn ipython_change_directory(&mut self, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let (directory, unresolved) = self.ipython_interpolate(arguments.trim());
        if directory.is_empty() || !unresolved.is_empty() {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unresolved,
                "IPython %cd directory is unresolved".to_string(),
                node,
            );
            self.cwd = None;
            self.cwd_node = Some(node);
            return;
        }
        let resource = resolve_fs_path(&directory, self.cwd.as_deref());
        self.cwd = resource_path_string(&resource);
        self.cwd_node = Some(node);
    }

    fn ipython_set_environment(&mut self, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let Some((name, value)) = arguments.split_once('=') else {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                "IPython %env requires NAME=value".to_string(),
                node,
            );
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                "IPython %env has an empty name".to_string(),
                node,
            );
            return;
        }
        let (value, unresolved_names) = self.ipython_interpolate(value.trim());
        let resource = if unresolved_names.is_empty() {
            ResourceExpr::Literal { value }
        } else {
            unresolved_resource("value")
        };
        if let Some(state) = self.ipython.as_mut() {
            state
                .environment
                .insert(name.to_string(), Some(resource.clone()));
            state.environment_nodes.insert(name.to_string(), node);
        }
        self.emit(
            "environment.write",
            ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable {
                    name: name.to_string(),
                },
            },
            &[],
            node,
        );
    }

    fn ipython_run(&mut self, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let mut words = ipython_split_words(arguments);
        while words.first().is_some_and(|word| ipython_run_option(word)) {
            words.remove(0);
        }
        if words.is_empty() {
            self.ipython_boundary(
                BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                BoundaryClass::Unsupported,
                "IPython %run has no script".to_string(),
                node,
            );
            return;
        }
        words.insert(0, "python".to_string());
        self.ipython_exec(words, node);
    }

    fn ipython_package_manager(&mut self, name: &str, arguments: &str, span: TextRange) {
        let node = self.span_node(span);
        let mut words = ipython_split_words(arguments);
        words.insert(0, name.to_string());
        self.ipython_exec(words, node);
    }

    fn ipython_exec(&mut self, raw_words: Vec<String>, node: ProvenanceRef) {
        let mut words = Vec::with_capacity(raw_words.len());
        let mut resources = Vec::with_capacity(raw_words.len());
        for raw in raw_words {
            let (value, unresolved_names) = self.ipython_interpolate(&raw);
            if unresolved_names.is_empty() {
                let word = Word::literal(value.clone());
                words.push(word);
                resources.push(ResourceExpr::Literal { value });
            } else {
                words.push(Word::new(vec![WordPart::Unknown]));
                resources.push(unresolved_resource("process"));
                for name in unresolved_names {
                    self.ipython_boundary(
                        BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                        BoundaryClass::Unresolved,
                        format!("IPython unresolved word: {name}"),
                        node,
                    );
                }
            }
        }
        let cwd_resource = self.ipython_cwd_resource();
        let mut transition = Transition::exec(resources, words)
            .exec_cwd(self.cwd.as_deref())
            .runtime_cwd(self.cwd.as_deref())
            .cwd(cwd_resource, self.cwd_node)
            .kind(ExecutionEdgeKind::Launch);
        transition = self.ipython_environment(transition);
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    fn ipython_nest_source(
        &mut self,
        language: &str,
        dialect: Option<effinterp_proto::SourceDialect>,
        source: &str,
        source_offset: usize,
        node: ProvenanceRef,
    ) {
        self.ipython_nest_subject(
            Subject::Source {
                language: language.to_string(),
                dialect,
                source: source.to_string(),
                cwd: self.cwd.clone(),
                context: Default::default(),
            },
            node,
            source_offset,
        );
    }

    fn ipython_nest_subject(
        &mut self,
        subject: Subject,
        node: ProvenanceRef,
        source_offset: usize,
    ) {
        if self.capture.is_some() {
            self.nest(subject, node, self.ipython_cwd_resource(), self.cwd_node);
            return;
        }
        let source_cwd = self.nest.current_source_cwd();
        let cwd = self.cwd.clone();
        let mut transition = Transition::file(subject)
            .source_cwd(source_cwd.as_deref())
            .runtime_cwd(cwd.as_deref())
            .cwd(self.ipython_cwd_resource(), self.cwd_node)
            .source_span_offset(source_offset);
        transition = self.ipython_environment(transition);
        self.nest
            .nest(self.builder, transition, &[node], self.depth);
    }

    fn ipython_environment(&self, transition: Transition) -> Transition {
        let Some(state) = &self.ipython else {
            return transition;
        };
        transition.environment(
            state.environment.clone(),
            state.environment_nodes.clone(),
            Default::default(),
        )
    }

    fn ipython_cwd_resource(&self) -> Option<ResourceExpr> {
        self.cwd.as_ref().map(|cwd| ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path: cwd.clone() },
        })
    }

    fn ipython_boundary(
        &mut self,
        reason: BoundaryReason,
        class: BoundaryClass,
        detail: String,
        node: ProvenanceRef,
    ) {
        for domain in DOMAINS {
            self.out_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        self.out_boundary(Boundary {
            reason,
            class,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: DOMAINS.iter().map(|domain| Domain::new(*domain)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail),
        });
    }
}

fn ipython_constant_text(expr: &Expr) -> Option<String> {
    let Expr::Constant(constant) = expr else {
        return None;
    };
    match &constant.value {
        Constant::Str(value) => Some(value.clone()),
        Constant::Int(value) => Some(value.to_string()),
        Constant::Float(value) => Some(value.to_string()),
        Constant::Bool(value) => Some(if *value { "True" } else { "False" }.to_string()),
        Constant::None => Some("None".to_string()),
        _ => None,
    }
}

fn ipython_flatten_literal(resource: &ResourceExpr) -> Option<String> {
    match resource {
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Join { parts } => {
            let mut output = String::new();
            for part in parts {
                output.push_str(&ipython_flatten_literal(part)?);
            }
            Some(output)
        }
        _ => None,
    }
}

fn ipython_unresolved_expression(expr: &Expr) -> String {
    match expr {
        Expr::Name(name) => format!("${{{}}}", name.id),
        _ => "${IPYTHON_UNRESOLVED}".to_string(),
    }
}

fn ipython_getter_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "get_ipython")
            && call.args.is_empty()
            && call.keywords.is_empty())
}

fn ipython_getter_target(target: &Expr) -> bool {
    match target {
        Expr::Name(name) => name.id.as_str() == "get_ipython",
        Expr::Attribute(attribute) => ipython_getter_call(&attribute.value),
        Expr::Tuple(tuple) => tuple.elts.iter().any(ipython_getter_target),
        Expr::List(list) => list.elts.iter().any(ipython_getter_target),
        Expr::Starred(starred) => ipython_getter_target(&starred.value),
        _ => false,
    }
}

fn interpolation_name(expression: &str) -> String {
    let name = expression.trim();
    let mut bytes = name.bytes();
    if bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        name.to_string()
    } else {
        "IPYTHON_UNRESOLVED".to_string()
    }
}

fn ipython_split_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn ipython_known_magic_option(option: &str) -> bool {
    matches!(
        option,
        "--no-raise-error"
            | "--noprofile"
            | "--norc"
            | "--verbose"
            | "-e"
            | "-E"
            | "-u"
            | "-v"
            | "-x"
            | "-vx"
            | "-xv"
            | "-O"
            | "-OO"
            | "-B"
            | "-I"
            | "-s"
            | "-S"
    )
}

fn ipython_run_option(option: &str) -> bool {
    matches!(option, "-i" | "-n" | "-e" | "-G" | "-d" | "-t")
}

fn ipython_noop_magic(name: &str) -> bool {
    matches!(
        name,
        "load"
            | "history"
            | "hist"
            | "dirs"
            | "magic"
            | "page"
            | "matplotlib"
            | "load_ext"
            | "autoreload"
            | "pylab"
            | "precision"
            | "colors"
            | "pwd"
            | "tb"
            | "who"
            | "who_ls"
            | "whos"
            | "xmode"
            | "lsmagic"
            | "quickref"
            | "pdef"
            | "pdoc"
            | "pinfo"
            | "pinfo2"
            | "psource"
            | "pycat"
            | "pfile"
            | "psearch"
    )
}

fn ipython_script_language(
    interpreter: &str,
) -> Option<(&'static str, Option<effinterp_proto::SourceDialect>)> {
    let interpreter = interpreter.rsplit('/').next().unwrap_or(interpreter);
    match interpreter {
        "python" | "python2" | "python3" => Some(("python", None)),
        "ipython" | "ipython3" => Some(("python", Some(effinterp_proto::SourceDialect::Ipython))),
        "node" | "nodejs" | "javascript" | "js" => {
            Some(("js", Some(effinterp_proto::SourceDialect::Js)))
        }
        "ts-node" | "tsx" | "typescript" => Some(("js", Some(effinterp_proto::SourceDialect::Ts))),
        "ruby" => Some(("ruby", None)),
        "perl" => Some(("perl", None)),
        "php" => Some(("php", None)),
        "lua" => Some(("lua", None)),
        "R" | "Rscript" => Some(("r", None)),
        "julia" => Some(("julia", None)),
        "pwsh" | "powershell" => Some(("powershell", None)),
        _ => None,
    }
}
