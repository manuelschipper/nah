//! Bounded Rust entry macros and top-level include boundaries.

use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain, ProvenanceKind,
    ProvenanceRef,
};
use syn::Item;

use crate::builder::PlanBuilder;
use crate::module_summary::{CallEdge, ImportBinding};

use super::RUST_DOMAINS;

/// True when a comment-masked source line is a bounded declarative entry
/// macro: `path::bin!(ident)`, `main!(ident)`, or `entry!(ident)`. Discovery
/// uses this so a binary whose `fn main` exists only after expansion is still
/// a program entry.
pub(crate) fn is_entry_macro_line(trimmed: &str) -> bool {
    let t = trimmed.trim_end().trim_end_matches(';').trim_end();
    let Some(idx) = t.find("!(") else {
        return false;
    };
    if !t.ends_with(')') {
        return false;
    }
    let head = &t[..idx];
    if !head
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        return false;
    }
    let name = head.rsplit("::").next().unwrap_or(head);
    matches!(name, "bin" | "main" | "entry")
}

// ---------------------------------------------------------------------------
// Bounded declarative entry macros
// ---------------------------------------------------------------------------

/// A crate/module handoff produced by `bin!` / `main!` / `entry!`.
pub(super) struct RustEntryHandoff {
    crate_path: Vec<String>,
    func: String,
}

fn entry_macro_func(name: &str) -> Option<&'static str> {
    match name {
        "bin" => Some("uumain"),
        "main" => Some("main"),
        "entry" => Some("run"),
        _ => None,
    }
}

fn parse_entry_macro(mac: &syn::ItemMacro) -> Option<RustEntryHandoff> {
    let name = mac.mac.path.segments.last()?.ident.to_string();
    let func = entry_macro_func(&name)?.to_string();
    let crate_path = parse_handoff_path(&mac.mac.tokens)?;
    Some(RustEntryHandoff { crate_path, func })
}

/// The crate/module path the macro names: a single ident, a `foo::bar` path,
/// or the first path before a comma (`bin!(uu_cat, no_flush)`).
fn parse_handoff_path(tokens: &proc_macro2::TokenStream) -> Option<Vec<String>> {
    if let Ok(path) = syn::parse2::<syn::Path>(tokens.clone()) {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if !segs.is_empty() {
            return Some(segs);
        }
    }
    let mut segs = Vec::new();
    for tt in tokens.clone() {
        match tt {
            proc_macro2::TokenTree::Ident(id) => segs.push(id.to_string()),
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => break,
            proc_macro2::TokenTree::Punct(p) if p.as_char() == ':' => {}
            _ if segs.is_empty() => return None,
            _ => {}
        }
    }
    (!segs.is_empty()).then_some(segs)
}

/// Find declarative Rust entry macro handoffs using the first path operand without expanding the macro.
pub(super) fn entry_handoffs(file: &syn::File) -> Vec<RustEntryHandoff> {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Macro(m) => parse_entry_macro(m),
            _ => None,
        })
        .collect()
}

pub(super) fn handoff_call(h: &RustEntryHandoff) -> (CallEdge, ImportBinding) {
    let mut module = h.crate_path.clone();
    module.push(h.func.clone());
    (
        CallEdge {
            callee: h.func.clone(),
            ..Default::default()
        },
        ImportBinding {
            local: h.func.clone(),
            module: module.join("::"),
            imported: Some(h.func.clone()),
        },
    )
}

fn is_include_macro(mac: &syn::Macro) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|s| s.ident == "include")
}

/// Mark top-level Rust includes as opaque to every effect domain.
pub(super) fn record_unexpanded_includes(
    builder: &mut PlanBuilder,
    file: &syn::File,
    scope: Option<ProvenanceRef>,
) {
    for item in &file.items {
        let Item::Macro(m) = item else {
            continue;
        };
        if !is_include_macro(&m.mac) {
            continue;
        }
        for domain in RUST_DOMAINS {
            builder.declare_coverage(Domain::new(domain), CoverageLevel::Partial);
        }
        let node = builder.node(
            ProvenanceKind::ModelApplication {
                model: "rust/std@v0".to_string(),
            },
            scope.as_slice(),
        );
        let tokens = m.mac.tokens.to_string();
        let detail = if tokens.contains("OUT_DIR") {
            "include! of generated OUT_DIR source is not expanded"
        } else {
            "include! is not expanded"
        };
        builder.boundary(Boundary {
            reason: BoundaryReason::UNEXPANDED_MACRO,
            class: BoundaryClass::Unsupported,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: RUST_DOMAINS.iter().map(|d| Domain::new(*d)).collect(),
            provenance: vec![node],
            limit: None,
            detail: Some(detail.to_string()),
        });
    }
}
