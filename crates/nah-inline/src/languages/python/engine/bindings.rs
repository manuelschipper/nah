//! Finds Python assignment, capture, and global binding names in HIR.

use super::*;

pub(super) fn assigned_names(node: &HirNode, source: &str) -> BTreeSet<String> {
    fn visit(node: &HirNode, source: &str, names: &mut BTreeSet<String>, root: bool) {
        if !root {
            match node.kind() {
                HirKind::Function | HirKind::Class => {
                    if let Some(name) = node.child(HirField::Name) {
                        names.insert(unsafe_text(source, name).to_owned());
                    }
                    return;
                }
                HirKind::DecoratedDefinition => {
                    if let Some(name) = node
                        .child(HirField::Definition)
                        .and_then(|definition| definition.child(HirField::Name))
                    {
                        names.insert(unsafe_text(source, name).to_owned());
                    }
                    return;
                }
                HirKind::Lambda => return,
                _ => {}
            }
        }
        match node.kind() {
            HirKind::Assignment | HirKind::AugmentedAssignment | HirKind::For => {
                if let Some(left) = node.child(HirField::Left) {
                    collect_targets(left, source, names);
                }
            }
            HirKind::Import => {
                for imported in named_children(node) {
                    let (name, alias) = import_name(imported, source);
                    names.insert(alias.unwrap_or_else(|| {
                        name.split('.').next().unwrap_or(name.as_str()).to_owned()
                    }));
                }
                return;
            }
            HirKind::ImportFrom => {
                for imported in node.children().iter().filter(|child| {
                    matches!(child.kind(), HirKind::AliasedImport | HirKind::DottedName)
                        && child.field() != Some(HirField::ModuleName)
                }) {
                    let (name, alias) = import_name(imported, source);
                    names.insert(alias.unwrap_or(name));
                }
                return;
            }
            _ => {}
        }
        for child in node.children() {
            visit(child, source, names, false);
        }
    }
    fn collect_targets(node: &HirNode, source: &str, names: &mut BTreeSet<String>) {
        if node.kind() == HirKind::Identifier {
            names.insert(unsafe_text(source, node).to_owned());
        } else if matches!(
            node.kind(),
            HirKind::Tuple | HirKind::List | HirKind::ParenthesizedExpression
        ) || node.kind() == HirKind::Unsupported
            && unsafe_text(source, node).trim_start().starts_with('*')
        {
            for child in node.children() {
                collect_targets(child, source, names);
            }
        }
    }
    let mut names = BTreeSet::new();
    visit(node, source, &mut names, true);
    names
}

pub(super) fn capture_names(node: &HirNode, source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == HirKind::CasePattern {
            let mut pattern = vec![node];
            while let Some(node) = pattern.pop() {
                if node.kind() == HirKind::Identifier {
                    let name = unsafe_text(source, node);
                    if name != "_" {
                        names.insert(name.to_owned());
                    }
                } else {
                    pattern.extend(node.children());
                }
            }
            continue;
        }
        stack.extend(node.children());
    }
    names
}

pub(super) fn global_names(node: &HirNode, source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == HirKind::Unsupported {
            let text = unsafe_text(source, node).trim();
            if let Some(declared) = text.strip_prefix("global ") {
                names.extend(
                    declared
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned),
                );
            }
        }
        if matches!(
            node.kind(),
            HirKind::Function | HirKind::Class | HirKind::Lambda
        ) {
            continue;
        }
        stack.extend(node.children());
    }
    names
}

pub(super) fn contains_kind(node: &HirNode, kind: HirKind, source: &str, prefix: &str) -> bool {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == kind && unsafe_text(source, node).trim_start().starts_with(prefix) {
            return true;
        }
        if matches!(
            node.kind(),
            HirKind::Function | HirKind::Class | HirKind::Lambda
        ) {
            continue;
        }
        stack.extend(node.children());
    }
    false
}
