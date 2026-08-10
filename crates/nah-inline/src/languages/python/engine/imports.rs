//! Python module ownership, import registry, and import resolution semantics.

use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Module {
    Base64,
    Builtins,
    Io,
    Ipython,
    Os,
    Environment,
    OsPath,
    Pathlib,
    Requests,
    Httpx,
    Shutil,
    Subprocess,
    Sys,
    Urllib,
    UrllibRequest,
}

pub(super) const IMPORT_OWNED_MODULES: &[Module] = &[
    Module::Base64,
    Module::Builtins,
    Module::Io,
    Module::Os,
    Module::OsPath,
    Module::Pathlib,
    Module::Requests,
    Module::Httpx,
    Module::Shutil,
    Module::Subprocess,
    Module::Sys,
    Module::Urllib,
    Module::UrllibRequest,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImportRegistryRead {
    Contains,
    Copy,
    Get,
    GetItem,
    Items,
    Keys,
    Values,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImportRegistryMutation {
    Clear,
    DelItem,
    Ior,
    Pop,
    PopItem,
    SetDefault,
    SetItem,
    Update,
}

pub(super) fn module_value(name: &str) -> Option<Value> {
    let module = match name {
        "base64" => Module::Base64,
        "builtins" | "__builtin__" => Module::Builtins,
        "io" => Module::Io,
        "os" => Module::Os,
        "os.path" => Module::OsPath,
        "pathlib" => Module::Pathlib,
        "requests" => Module::Requests,
        "httpx" => Module::Httpx,
        "shutil" => Module::Shutil,
        "subprocess" => Module::Subprocess,
        "sys" => Module::Sys,
        "urllib" => Module::Urllib,
        "urllib.request" => Module::UrllibRequest,
        _ => return None,
    };
    Some(Value::Module(module))
}

pub(super) fn imported_value(module: &str, name: &str) -> Option<Value> {
    let module = module_value(module)?;
    let Value::Module(module) = module else {
        return None;
    };
    module_attribute(module, name)
}

pub(super) fn module_attribute(module: Module, attribute: &str) -> Option<Value> {
    let function = match (module, attribute) {
        (Module::Base64, "b64decode" | "urlsafe_b64decode") => KnownFunction::Base64Decode,
        (Module::Builtins, "eval") => KnownFunction::Eval,
        (Module::Builtins, "exec") => KnownFunction::Exec,
        (Module::Builtins, "compile") => KnownFunction::Compile,
        (Module::Builtins, "open") => KnownFunction::Open,
        (Module::Builtins, "getattr") => KnownFunction::Getattr,
        (Module::Builtins, "setattr") => KnownFunction::Setattr,
        (Module::Ipython, "system") => KnownFunction::IpythonSystem,
        (Module::Ipython, "getoutput") => KnownFunction::IpythonGetoutput,
        (Module::Ipython, "run_cell_magic") => KnownFunction::IpythonCell,
        (Module::Io, "FileIO") => KnownFunction::IoFile,
        (Module::Sys, "modules") => return Some(Value::ImportRegistry),
        (Module::Urllib, "request") => return Some(Value::Module(Module::UrllibRequest)),
        (Module::Os, "path") => return Some(Value::Module(Module::OsPath)),
        (Module::Os, "environ") => return Some(Value::Module(Module::Environment)),
        (Module::Os, "system") => KnownFunction::OsSystem,
        (Module::Os, "popen") => KnownFunction::OsPopen,
        (Module::Os, "chdir") => KnownFunction::OsChdir,
        (Module::Os, "execl") => KnownFunction::OsExec(StringKind::Execl),
        (Module::Os, "execlp") => KnownFunction::OsExec(StringKind::Execlp),
        (Module::Os, "execle") => KnownFunction::OsExec(StringKind::Execle),
        (Module::Os, "execv") => KnownFunction::OsExec(StringKind::Execv),
        (Module::Os, "execvp") => KnownFunction::OsExec(StringKind::Execvp),
        (Module::Os, "execvpe") => KnownFunction::OsExec(StringKind::Execvpe),
        (Module::Os, "remove") => KnownFunction::OsRemove,
        (Module::Os, "unlink") => KnownFunction::OsUnlink,
        (Module::Os, "rename") => KnownFunction::OsRename,
        (Module::Os, "replace") => KnownFunction::OsReplace,
        (Module::Os, "link") => KnownFunction::OsLink,
        (Module::Os, "symlink") => KnownFunction::OsSymlink,
        (Module::Os, "chmod") => KnownFunction::OsChmod,
        (Module::Os, "chown") => KnownFunction::OsChown,
        (Module::Os, "lchown") => KnownFunction::OsLchown,
        (Module::Os, "mkdir") => KnownFunction::OsMkdir,
        (Module::Os, "makedirs") => KnownFunction::OsMakedirs,
        (Module::Os, "rmdir") => KnownFunction::OsRmdir,
        (Module::Os, "removedirs") => KnownFunction::OsRemovedirs,
        (Module::Os, "truncate") => KnownFunction::OsTruncate,
        (Module::Os, "open") => KnownFunction::OsOpen,
        (Module::Os, "getenv") => KnownFunction::OsGetenv,
        (Module::OsPath, "expanduser") => KnownFunction::OsExpanduser,
        (Module::OsPath, "abspath") => KnownFunction::OsAbspath,
        (Module::OsPath, "realpath") => KnownFunction::OsRealpath,
        (Module::OsPath, "join") => KnownFunction::PathJoin,
        (Module::Pathlib, "Path") => KnownFunction::Path,
        (Module::Shutil, "rmtree") => KnownFunction::ShutilRmtree,
        (Module::Shutil, "move") => KnownFunction::ShutilMove,
        (Module::Shutil, "copy") => KnownFunction::ShutilCopy(CopyKind::Copy),
        (Module::Shutil, "copy2") => KnownFunction::ShutilCopy(CopyKind::Copy2),
        (Module::Shutil, "copyfile") => KnownFunction::ShutilCopy(CopyKind::Copyfile),
        (Module::Shutil, "copytree") => KnownFunction::ShutilCopy(CopyKind::Copytree),
        (Module::Shutil, "copymode") => KnownFunction::ShutilCopy(CopyKind::Copymode),
        (Module::Shutil, "copystat") => KnownFunction::ShutilCopy(CopyKind::Copystat),
        (Module::Shutil, "which") => KnownFunction::ShutilWhich,
        (Module::Subprocess, "PIPE") => return Some(Value::Int(-1)),
        (Module::Subprocess, "STDOUT") => return Some(Value::Int(-2)),
        (Module::Subprocess, "DEVNULL") => return Some(Value::Int(-3)),
        (Module::Subprocess, "run") => KnownFunction::Subprocess(SubprocessKind::Run),
        (Module::Subprocess, "call") => KnownFunction::Subprocess(SubprocessKind::Call),
        (Module::Subprocess, "Popen") => KnownFunction::Subprocess(SubprocessKind::Popen),
        (Module::Subprocess, "check_call") => KnownFunction::Subprocess(SubprocessKind::CheckCall),
        (Module::Subprocess, "check_output") => {
            KnownFunction::Subprocess(SubprocessKind::CheckOutput)
        }
        (Module::Requests, "get") => KnownFunction::Request(RequestKind::RequestsGet),
        (Module::Requests, "post") => KnownFunction::Request(RequestKind::RequestsPost),
        (Module::Requests, "put") => KnownFunction::Request(RequestKind::RequestsPut),
        (Module::Requests, "patch") => KnownFunction::Request(RequestKind::RequestsPatch),
        (Module::Requests, "delete") => KnownFunction::Request(RequestKind::RequestsDelete),
        (Module::Httpx, "get") => KnownFunction::Request(RequestKind::HttpxGet),
        (Module::Httpx, "post") => KnownFunction::Request(RequestKind::HttpxPost),
        (Module::Httpx, "put") => KnownFunction::Request(RequestKind::HttpxPut),
        (Module::Httpx, "patch") => KnownFunction::Request(RequestKind::HttpxPatch),
        (Module::Httpx, "delete") => KnownFunction::Request(RequestKind::HttpxDelete),
        (Module::UrllibRequest, "urlopen") => KnownFunction::Request(RequestKind::UrlOpen),
        (Module::UrllibRequest, "urlretrieve") => KnownFunction::Request(RequestKind::UrlRetrieve),
        _ => return None,
    };
    Some(Value::Known(function))
}

pub(super) fn import_registry_mutation(attribute: &str) -> Option<ImportRegistryMutation> {
    match attribute {
        "clear" => Some(ImportRegistryMutation::Clear),
        "__delitem__" => Some(ImportRegistryMutation::DelItem),
        "__ior__" => Some(ImportRegistryMutation::Ior),
        "pop" => Some(ImportRegistryMutation::Pop),
        "popitem" => Some(ImportRegistryMutation::PopItem),
        "setdefault" => Some(ImportRegistryMutation::SetDefault),
        "__setitem__" => Some(ImportRegistryMutation::SetItem),
        "update" => Some(ImportRegistryMutation::Update),
        _ => None,
    }
}

pub(super) fn import_registry_mutation_shape(
    mutation: ImportRegistryMutation,
    arguments: &Arguments,
) -> CallShape {
    match mutation {
        ImportRegistryMutation::Clear | ImportRegistryMutation::PopItem => {
            call_shape(arguments, 0, &[], 0, &[])
        }
        ImportRegistryMutation::DelItem | ImportRegistryMutation::Ior => {
            call_shape(arguments, 1, &["value"], 1, &[])
        }
        ImportRegistryMutation::Pop | ImportRegistryMutation::SetDefault => {
            call_shape(arguments, 1, &["key", "default"], 2, &[])
        }
        ImportRegistryMutation::SetItem => call_shape(arguments, 2, &["key", "value"], 2, &[]),
        ImportRegistryMutation::Update => {
            if arguments.positional.len() > 1 {
                CallShape::Invalid
            } else if arguments.complete {
                CallShape::Valid
            } else {
                CallShape::Incomplete
            }
        }
    }
}

pub(super) fn import_registry_read(attribute: &str) -> Option<ImportRegistryRead> {
    match attribute {
        "__contains__" => Some(ImportRegistryRead::Contains),
        "copy" => Some(ImportRegistryRead::Copy),
        "get" => Some(ImportRegistryRead::Get),
        "__getitem__" => Some(ImportRegistryRead::GetItem),
        "items" => Some(ImportRegistryRead::Items),
        "keys" => Some(ImportRegistryRead::Keys),
        "values" => Some(ImportRegistryRead::Values),
        _ => None,
    }
}

pub(super) fn import_registry_read_shape(
    read: ImportRegistryRead,
    arguments: &Arguments,
) -> CallShape {
    match read {
        ImportRegistryRead::Contains | ImportRegistryRead::GetItem => {
            call_shape(arguments, 1, &["key"], 1, &[])
        }
        ImportRegistryRead::Get => call_shape(arguments, 1, &["key", "default"], 2, &[]),
        ImportRegistryRead::Copy
        | ImportRegistryRead::Items
        | ImportRegistryRead::Keys
        | ImportRegistryRead::Values => call_shape(arguments, 0, &[], 0, &[]),
    }
}

pub(super) fn import_name(node: &HirNode, source: &str) -> (String, Option<String>) {
    if node.kind() == HirKind::AliasedImport {
        let name = node
            .child(HirField::Name)
            .map(|name| unsafe_text(source, name).to_owned())
            .unwrap_or_default();
        let alias = node
            .child(HirField::Alias)
            .map(|alias| unsafe_text(source, alias).to_owned());
        (name, alias)
    } else {
        (unsafe_text(source, node).to_owned(), None)
    }
}

pub(super) fn retain_owned_module(value: Value, state: &State) -> Value {
    match value {
        Value::Module(module) if state.invalid_modules.contains(&module) => Value::Unknown,
        value => value,
    }
}

pub(super) fn invalidate_module(module: Module, state: &mut State) {
    state.invalid_modules.insert(module);
    if module == Module::Environment {
        state.ipython_shell = IpythonShell::Unknown;
    }
    if module == Module::Builtins {
        for (name, function) in OWNED_BUILTINS {
            if state.bindings.get(*name) == Some(&Value::Known(*function)) {
                state.bindings.insert((*name).to_owned(), Value::Unknown);
            }
        }
    }
    for value in state.bindings.values_mut() {
        if *value == Value::Module(module) {
            *value = Value::Unknown;
        }
    }
    for cell in &mut state.cells {
        if let Cell::Sequence { values, .. } = cell {
            for value in values {
                if *value == Value::Module(module) {
                    *value = Value::Unknown;
                }
            }
        }
    }
}

pub(super) fn invalidate_import_ownership(state: &mut State) {
    for module in IMPORT_OWNED_MODULES {
        if *module == Module::Builtins {
            state.invalid_modules.insert(*module);
        } else {
            invalidate_module(*module, state);
        }
    }
}

pub(super) fn contains_import_registry(
    value: &Value,
    state: &State,
    visiting: &mut BTreeSet<usize>,
) -> bool {
    match value {
        Value::ImportRegistry | Value::ImportRegistryMutator(_) | Value::ImportRegistryRead(_) => {
            true
        }
        Value::Cell(cell) if visiting.insert(*cell) => {
            let contains = match state.cells.get(*cell) {
                Some(Cell::Sequence { values, .. }) => values
                    .iter()
                    .any(|value| contains_import_registry(value, state, visiting)),
                Some(Cell::Unknown) | None => false,
            };
            visiting.remove(cell);
            contains
        }
        _ => false,
    }
}

pub(super) fn is_import_registry(node: &HirNode, state: &State, source: &str) -> bool {
    match node.kind() {
        HirKind::Identifier | HirKind::Attribute => {
            registry_provenance(node, state, source) == RegistryProvenance::Exact
        }
        HirKind::Subscript => {
            registry_provenance(node, state, source) != RegistryProvenance::None
                || named_children(node).next().is_some_and(|object| {
                    registry_provenance(object, state, source) != RegistryProvenance::None
                })
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum RegistryProvenance {
    Exact,
    Possible,
    None,
}

pub(super) fn registry_provenance(
    node: &HirNode,
    state: &State,
    source: &str,
) -> RegistryProvenance {
    match node.kind() {
        HirKind::Identifier | HirKind::ParenthesizedExpression => {
            if static_value(node, state, source) == Some(Value::ImportRegistry) {
                RegistryProvenance::Exact
            } else {
                RegistryProvenance::None
            }
        }
        HirKind::Attribute if is_import_registry_attribute(node, state, source) => {
            RegistryProvenance::Exact
        }
        HirKind::Subscript => registry_subscript_provenance(node, state, source),
        _ => RegistryProvenance::None,
    }
}

pub(super) fn registry_subscript_provenance(
    node: &HirNode,
    state: &State,
    source: &str,
) -> RegistryProvenance {
    let mut children = named_children(node);
    let Some(object) = children.next() else {
        return RegistryProvenance::None;
    };
    let Some(index) = children.next() else {
        return RegistryProvenance::None;
    };
    if is_sys_module_dictionary(object, state, source) {
        return match static_string(index, state, source) {
            StaticString::Exact(value) if value == "modules" => RegistryProvenance::Exact,
            StaticString::Unknown => RegistryProvenance::Possible,
            StaticString::Exact(_) | StaticString::Other => RegistryProvenance::None,
        };
    }
    let Some(Value::Cell(cell)) = static_value(object, state, source) else {
        return RegistryProvenance::None;
    };
    let Some(Cell::Sequence { values, .. }) = state.cells.get(cell) else {
        return RegistryProvenance::None;
    };
    match static_index(index, state, source) {
        StaticIndex::Exact(index) => sequence_index(values, index)
            .filter(|value| matches!(value, Value::ImportRegistry))
            .map_or(RegistryProvenance::None, |_| RegistryProvenance::Exact),
        StaticIndex::Unknown
            if values
                .iter()
                .any(|value| contains_import_registry(value, state, &mut BTreeSet::new())) =>
        {
            RegistryProvenance::Possible
        }
        StaticIndex::Unknown | StaticIndex::Other => RegistryProvenance::None,
    }
}

pub(super) enum StaticString {
    Exact(String),
    Other,
    Unknown,
}

pub(super) fn static_string(node: &HirNode, state: &State, source: &str) -> StaticString {
    match static_value(node, state, source) {
        Some(Value::String(value) | Value::ImplicitString(value)) => StaticString::Exact(value),
        Some(Value::Unknown | Value::Produced(_)) | None => StaticString::Unknown,
        Some(_) => StaticString::Other,
    }
}

pub(super) enum StaticIndex {
    Exact(i64),
    Other,
    Unknown,
}

pub(super) fn static_index(node: &HirNode, state: &State, source: &str) -> StaticIndex {
    match static_value(node, state, source) {
        Some(Value::Int(value)) => StaticIndex::Exact(value),
        Some(Value::Bool(value)) => StaticIndex::Exact(i64::from(value)),
        Some(Value::Unknown | Value::Produced(_)) | None => StaticIndex::Unknown,
        Some(_) => StaticIndex::Other,
    }
}

pub(super) fn static_value(node: &HirNode, state: &State, source: &str) -> Option<Value> {
    match node.kind() {
        HirKind::Identifier => state.bindings.get(unsafe_text(source, node)).cloned(),
        HirKind::Integer => parse_integer(unsafe_text(source, node)).map(Value::Int),
        HirKind::True => Some(Value::Bool(true)),
        HirKind::False => Some(Value::Bool(false)),
        HirKind::String => static_literal_string(node, source).map(Value::String),
        HirKind::ParenthesizedExpression => named_children(node)
            .next()
            .and_then(|child| static_value(child, state, source)),
        HirKind::UnaryOperator => {
            let operator = node
                .child(HirField::Operator)
                .map(|operator| unsafe_text(source, operator))?;
            let value = node
                .child(HirField::Argument)
                .or_else(|| named_children(node).next())
                .and_then(|value| static_value(value, state, source))?;
            match (operator, value) {
                ("-", Value::Int(value)) => value.checked_neg().map(Value::Int),
                ("+", Value::Int(value)) => Some(Value::Int(value)),
                _ => None,
            }
        }
        HirKind::Subscript => {
            let mut children = named_children(node);
            let Value::Cell(cell) = static_value(children.next()?, state, source)? else {
                return None;
            };
            let StaticIndex::Exact(index) = static_index(children.next()?, state, source) else {
                return None;
            };
            let Cell::Sequence { values, .. } = state.cells.get(cell)? else {
                return None;
            };
            sequence_index(values, index).cloned()
        }
        _ => None,
    }
}

pub(super) fn static_literal_string(node: &HirNode, source: &str) -> Option<String> {
    let start = node
        .children()
        .iter()
        .find(|child| child.kind() == HirKind::StringStart)
        .map(|child| unsafe_text(source, child))?;
    let prefix_end = start.find(['\'', '"']).unwrap_or(start.len());
    let prefix = start[..prefix_end].to_ascii_lowercase();
    if prefix.contains(['b', 'f']) {
        return None;
    }
    let raw = prefix.contains('r');
    let mut value = String::new();
    for child in node.children() {
        match child.kind() {
            HirKind::StringContent => {
                value.push_str(&decode_string_fragment(unsafe_text(source, child), raw)?);
            }
            HirKind::Interpolation => return None,
            _ => {}
        }
    }
    Some(value)
}

pub(super) fn sequence_index(values: &[Value], index: i64) -> Option<&Value> {
    let len = i64::try_from(values.len()).ok()?;
    let index = if index < 0 {
        len.checked_add(index)?
    } else {
        index
    };
    usize::try_from(index)
        .ok()
        .and_then(|index| values.get(index))
}

pub(super) fn is_sys_module_dictionary(node: &HirNode, state: &State, source: &str) -> bool {
    node.kind() == HirKind::Attribute
        && node
            .child(HirField::Attribute)
            .is_some_and(|attribute| unsafe_text(source, attribute) == "__dict__")
        && node
            .child(HirField::Object)
            .and_then(|object| owned_module_target(object, state, source))
            == Some(Module::Sys)
}

pub(super) fn is_import_registry_attribute(node: &HirNode, state: &State, source: &str) -> bool {
    node.child(HirField::Attribute)
        .is_some_and(|attribute| unsafe_text(source, attribute) == "modules")
        && node
            .child(HirField::Object)
            .and_then(|object| owned_module_target(object, state, source))
            == Some(Module::Sys)
}

pub(super) fn owned_module_target(node: &HirNode, state: &State, source: &str) -> Option<Module> {
    match node.kind() {
        HirKind::Identifier => match state.bindings.get(unsafe_text(source, node)) {
            Some(Value::Module(module)) => Some(*module),
            _ => None,
        },
        HirKind::Attribute => {
            let object = owned_module_target(node.child(HirField::Object)?, state, source)?;
            let attribute = unsafe_text(source, node.child(HirField::Attribute)?);
            match module_attribute(object, attribute) {
                Some(Value::Module(module)) => Some(module),
                _ => Some(object),
            }
        }
        _ => None,
    }
}

pub(super) fn propagate_invalid_modules(modules: &BTreeSet<Module>, state: &mut State) {
    let modules = modules
        .difference(&state.invalid_modules)
        .copied()
        .collect::<Vec<_>>();
    for module in modules {
        if module == Module::Builtins {
            state.invalid_modules.insert(module);
        } else {
            invalidate_module(module, state);
        }
    }
}
