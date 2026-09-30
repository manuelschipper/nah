//! IPython input transformation layered over the Python frontend.
//!
//! Operational syntax becomes same-offset sentinel statements. The Python
//! walk consumes their typed actions in order, so ordinary Python keeps its
//! parser and binding semantics while every emitted fact points at the cell.

use std::collections::BTreeMap;

use effinterp_proto::ProvenanceRef;

use crate::builder::PlanBuilder;
use crate::lang::frontend::{self, FrontendInput};
use crate::nest::Nest;

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
