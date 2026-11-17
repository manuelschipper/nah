//! Member evidence for archives built through BytesIO and tarfile. Objects live
//! in the ordinary modeled bindings, so aliases share mutations and branch joins
//! discard conflicting state. No archive bytes are read from the host or decoded.

use std::ops::Range;
use std::rc::Rc;

use effinterp_proto::{PathPlatform, ResourceExpr, normalize_resource};
use rustpython_parser::ast::{self, Constant, Expr};

use super::model::{ModeledValue, supported_signature};
use super::{PythonWalker, int_literal, python_call_argument};
use crate::value::{fs_path_resource, unresolved_resource};
use crate::{SemanticValue, SemanticValueKind};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Member {
    name: SemanticValue,
    content: Option<MemberContent>,
}

// The immutable buffer range is checked when the member is added.
#[derive(Clone, PartialEq, Eq)]
struct MemberContent {
    bytes: Rc<Vec<u8>>,
    range: Range<usize>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum MemoryTarValue {
    Buffer {
        id: u32,
        bytes: Option<Rc<Vec<u8>>>,
        position: Option<usize>,
        members: Option<Rc<Vec<Member>>>,
        unresolved_members: bool,
    },
    Archive {
        id: u32,
        buffer: Box<MemoryTarValue>,
        writable: bool,
        closed: bool,
    },
    Info {
        id: u32,
        name: Box<SemanticValue>,
        size: Option<usize>,
    },
}

impl MemoryTarValue {
    fn id(&self) -> u32 {
        match self {
            Self::Buffer { id, .. } | Self::Archive { id, .. } | Self::Info { id, .. } => *id,
        }
    }

    fn holds_identity(&self, id: u32) -> bool {
        self.id() == id || matches!(self, Self::Archive { buffer, .. } if buffer.holds_identity(id))
    }

    fn invalidate(&mut self) {
        match self {
            Self::Buffer {
                bytes,
                members,
                position,
                unresolved_members,
                ..
            } => {
                *bytes = None;
                *members = None;
                *position = None;
                *unresolved_members = true;
            }
            Self::Info { name, size, .. } => {
                **name = SemanticValue::from(unresolved_resource("filesystem"));
                *size = None;
            }
            Self::Archive { buffer, .. } => buffer.invalidate(),
        }
    }
}

impl PythonWalker<'_, '_> {
    pub(super) fn memory_tar_value(&self, expr: &Expr, depth: usize) -> Option<MemoryTarValue> {
        if depth as u64 > self.nest.limits.max_value_depth {
            return None;
        }
        if let Expr::Name(name) = expr {
            return match self.modeled_values.get(name.id.as_str())? {
                ModeledValue::MemoryTar(value) => Some(value.clone()),
                _ => None,
            };
        }
        let Expr::Call(call) = expr else { return None };
        let id = u32::from(call.range.start());
        match self.imports.resolve_callee(&call.func)?.as_str() {
            "io.BytesIO" if supported_signature(call, 0, 1, &["initial_bytes"]) => {
                if !call.args.is_empty() && !call.keywords.is_empty() {
                    return None;
                }
                let bytes = python_call_argument(call, 0, "initial_bytes")
                    .map(|arg| self.memory_bytes(arg))
                    .unwrap_or_else(|| Some(Rc::new(Vec::new())));
                Some(MemoryTarValue::Buffer {
                    id,
                    bytes,
                    position: Some(0),
                    members: None,
                    unresolved_members: true,
                })
            }
            "tarfile.TarInfo" if supported_signature(call, 0, 1, &["name"]) => {
                if !call.args.is_empty() && !call.keywords.is_empty() {
                    return None;
                }
                let name = python_call_argument(call, 0, "name")
                    .map(|arg| self.memory_member_name(arg))
                    .unwrap_or_else(|| SemanticValue::literal(""));
                Some(MemoryTarValue::Info {
                    id,
                    name: Box::new(name),
                    size: Some(0),
                })
            }
            "tarfile.open"
                if supported_signature(call, 0, 2, &["name", "mode", "fileobj"])
                    && !call.keywords.iter().any(|kw| {
                        kw.arg.as_ref().is_some_and(|key| {
                            ["name", "mode"][..call.args.len()].contains(&key.as_str())
                        })
                    }) =>
            {
                if python_call_argument(call, 0, "name").is_some_and(
                    |arg| !matches!(arg, Expr::Constant(c) if c.value == Constant::None),
                ) {
                    return None;
                }
                let fileobj = python_call_argument(call, 2, "fileobj")?;
                let buffer = self.memory_tar_value(fileobj, depth + 1)?;
                if !matches!(buffer, MemoryTarValue::Buffer { .. }) {
                    return None;
                }
                let mode = python_call_argument(call, 1, "mode")
                    .map(|arg| self.known_string(arg))
                    .unwrap_or_else(|| Some("r".into()))?;
                let writable = match mode.as_str() {
                    "w" | "w:" => true,
                    "r" | "r:" | "r:*" => false,
                    _ => return None,
                };
                Some(MemoryTarValue::Archive {
                    id,
                    buffer: Box::new(buffer),
                    writable,
                    closed: false,
                })
            }
            _ => None,
        }
    }

    pub(super) fn memory_bytes(&self, expr: &Expr) -> Option<Rc<Vec<u8>>> {
        match expr {
            Expr::Constant(c) => match &c.value {
                Constant::Bytes(bytes)
                    if bytes.len() as u64 <= self.nest.limits.max_source_bytes =>
                {
                    Some(
                        self.literal_bytes
                            .borrow_mut()
                            .entry(c.range)
                            .or_insert_with(|| Rc::new(bytes.clone()))
                            .clone(),
                    )
                }
                _ => None,
            },
            Expr::Name(name) => match self.modeled_values.get(name.id.as_str())? {
                ModeledValue::KnownBytes(bytes) => Some(bytes.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    fn memory_member_name(&self, expr: &Expr) -> SemanticValue {
        self.known_string(expr)
            .map(SemanticValue::literal)
            .unwrap_or_else(|| SemanticValue::from(unresolved_resource("filesystem")))
    }

    fn memory_size(&self, expr: &Expr) -> Option<usize> {
        if let Some(size) = int_literal(expr) {
            return Some(usize::from(size));
        }
        if let Expr::Call(call) = expr
            && self.imports.resolve_callee(&call.func).as_deref() == Some("len")
            && supported_signature(call, 1, 1, &[])
        {
            return self.memory_bytes(&call.args[0]).map(|bytes| bytes.len());
        }
        None
    }

    fn mutate_memory_tar(&mut self, id: u32, mut update: impl FnMut(&mut MemoryTarValue)) {
        for value in self.modeled_values.values_mut() {
            if let ModeledValue::MemoryTar(value) = value {
                if value.id() == id {
                    update(value);
                }
                if let MemoryTarValue::Archive { buffer, .. } = value
                    && buffer.id() == id
                {
                    update(buffer);
                }
            }
        }
    }

    pub(super) fn retire_memory_tar_constructor(&mut self, expr: &Expr) {
        if !matches!(expr, Expr::Call(_)) {
            return;
        }
        let Some(value) = self.memory_tar_value(expr, 0) else {
            return;
        };
        // A loop can construct different objects at this source location. Old
        // references must become unknown before this location's id is reused.
        self.modeled_values.retain(|_, held| {
            !matches!(held, ModeledValue::MemoryTar(held) if held.holds_identity(value.id()))
        });
    }

    pub(super) fn invalidate_memory_tar_target(&mut self, target: &Expr) {
        let mut targets = vec![target];
        while let Some(target) = targets.pop() {
            match target {
                Expr::Attribute(attr) if self.memory_tar_value(&attr.value, 0).is_some() => {
                    self.invalidate_memory_tar();
                    return;
                }
                Expr::Tuple(tuple) => targets.extend(&tuple.elts),
                Expr::List(list) => targets.extend(&list.elts),
                Expr::Starred(starred) => targets.push(&starred.value),
                Expr::Subscript(subscript) => targets.push(&subscript.value),
                _ => {}
            }
        }
    }

    pub(super) fn track_memory_tar_attributes(&mut self, targets: &[Expr], value: &Expr) {
        for target in targets {
            if let Expr::Attribute(attr) = target
                && let Some(MemoryTarValue::Info { id, .. }) = self.memory_tar_value(&attr.value, 0)
                && matches!(attr.attr.as_str(), "size" | "name")
            {
                let size = self.memory_size(value);
                let member_name = self.memory_member_name(value);
                self.mutate_memory_tar(id, |object| {
                    if let MemoryTarValue::Info {
                        name,
                        size: held_size,
                        ..
                    } = object
                    {
                        if attr.attr.as_str() == "size" {
                            *held_size = size;
                        } else {
                            **name = member_name.clone();
                        }
                    }
                });
            } else {
                if let Expr::Attribute(attr) = target
                    && self.memory_tar_value(&attr.value, 0).is_some()
                {
                    self.invalidate_memory_tar();
                }
                self.track_instance_attr_assignments(std::slice::from_ref(target));
            }
        }
    }

    pub(super) fn invalidate_memory_tar(&mut self) {
        for value in self.modeled_values.values_mut() {
            if let ModeledValue::MemoryTar(value) = value {
                value.invalidate();
            }
        }
    }

    pub(super) fn memory_tar_call(&mut self, call: &ast::ExprCall) -> bool {
        if let Some(value) = self.memory_tar_value(&Expr::Call(call.clone()), 0) {
            if let MemoryTarValue::Archive {
                buffer,
                writable: true,
                ..
            } = value
            {
                self.mutate_memory_tar(buffer.id(), |object| {
                    if let MemoryTarValue::Buffer {
                        members,
                        bytes,
                        position,
                        unresolved_members,
                        ..
                    } = object
                    {
                        *members = (*position == Some(0)).then(|| Rc::new(Vec::new()));
                        *unresolved_members = members.is_none();
                        *bytes = None;
                    }
                });
            }
            return true;
        }
        let Expr::Attribute(attr) = call.func.as_ref() else {
            return false;
        };
        let Some(receiver) = self.memory_tar_value(&attr.value, 0) else {
            return false;
        };
        match receiver {
            MemoryTarValue::Buffer { id, .. }
                if attr.attr.as_str() == "seek"
                    && supported_signature(call, 1, 2, &["whence"])
                    && (call.args.len() != 2 || call.keywords.is_empty())
                    && python_call_argument(call, 1, "whence")
                        .map(int_literal)
                        .unwrap_or(Some(0))
                        == Some(0) =>
            {
                let position = int_literal(&call.args[0]).map(usize::from);
                self.mutate_memory_tar(id, |object| {
                    if let MemoryTarValue::Buffer { position: held, .. } = object {
                        *held = position;
                    }
                });
                true
            }
            MemoryTarValue::Archive { id, .. }
                if attr.attr.as_str() == "close" && supported_signature(call, 0, 0, &[]) =>
            {
                self.mutate_memory_tar(id, |object| {
                    if let MemoryTarValue::Archive { closed, .. } = object {
                        *closed = true;
                    }
                });
                true
            }
            MemoryTarValue::Archive {
                buffer,
                writable: true,
                closed: false,
                ..
            } if attr.attr.as_str() == "addfile"
                && supported_signature(call, 1, 2, &["fileobj"])
                && (call.args.len() != 2 || call.keywords.is_empty()) =>
            {
                let (name, size) = match self.memory_tar_value(&call.args[0], 0) {
                    Some(MemoryTarValue::Info { name, size, .. }) => (*name, size),
                    _ => (SemanticValue::from(unresolved_resource("filesystem")), None),
                };
                let source = python_call_argument(call, 1, "fileobj")
                    .and_then(|arg| self.memory_tar_value(arg, 0));
                if let Some(MemoryTarValue::Buffer { id, position, .. }) = &source {
                    let next = position.and_then(|pos| pos.checked_add(size?));
                    self.mutate_memory_tar(*id, |object| {
                        if let MemoryTarValue::Buffer { position, .. } = object {
                            *position = next;
                        }
                    });
                }
                let content = if size == Some(0) {
                    Some(MemberContent {
                        bytes: Rc::new(Vec::new()),
                        range: 0..0,
                    })
                } else if let Some(MemoryTarValue::Buffer {
                    bytes: Some(bytes),
                    position: Some(pos),
                    ..
                }) = source
                {
                    size.and_then(|size| {
                        let range = pos..pos.checked_add(size)?;
                        bytes.get(range.clone())?;
                        Some(MemberContent { bytes, range })
                    })
                } else {
                    None
                };
                let member = Member { name, content };
                let limit = self.nest.limits.max_value_cardinality as usize;
                self.mutate_memory_tar(buffer.id(), |object| {
                    if let MemoryTarValue::Buffer {
                        members,
                        position,
                        unresolved_members,
                        ..
                    } = object
                    {
                        if let Some(held) = members {
                            if held.len() < limit {
                                Rc::make_mut(held).push(member.clone());
                            } else {
                                // Retain known members; only the remainder becomes unresolved.
                                *unresolved_members = true;
                            }
                        }
                        *position = None;
                    }
                });
                true
            }
            MemoryTarValue::Archive {
                buffer,
                writable: false,
                closed: false,
                ..
            } if attr.attr.as_str() == "extractall"
                && supported_signature(call, 0, 1, &["path"]) =>
            {
                if !call.args.is_empty() && !call.keywords.is_empty() {
                    return false;
                }
                let destination = python_call_argument(call, 0, "path")
                    .map(|arg| self.resolve_fs(arg))
                    .unwrap_or_else(|| crate::paths::resolve_fs_path(".", self.cwd.as_deref()));
                let (members, unresolved_members) = match buffer.as_ref() {
                    MemoryTarValue::Buffer {
                        members,
                        position: Some(0),
                        unresolved_members,
                        ..
                    } => (members.clone(), *unresolved_members),
                    _ => (None, true),
                };
                let node = self.span_node(call.range);
                if unresolved_members {
                    self.emit(
                        "filesystem.write",
                        ResourceExpr::Join {
                            parts: vec![
                                destination.clone(),
                                ResourceExpr::Literal { value: "/".into() },
                                unresolved_resource("filesystem"),
                            ],
                        },
                        &[],
                        node,
                    );
                    self.opaque_boundary("in-memory tar members are unresolved", node);
                }
                for member in members.iter().flat_map(|members| members.iter()) {
                    let resource = match &member.name.kind {
                        SemanticValueKind::Literal(name) if name.starts_with('/') => {
                            fs_path_resource(name)
                        }
                        _ => ResourceExpr::Join {
                            parts: vec![
                                destination.clone(),
                                ResourceExpr::Literal { value: "/".into() },
                                member.name.lower_resource(),
                            ],
                        },
                    };
                    let write = self.emit(
                        "filesystem.write",
                        normalize_resource(resource, PathPlatform::Posix),
                        &[],
                        node,
                    );
                    if let Some(content) = member.content.as_ref().and_then(|content| {
                        std::str::from_utf8(&content.bytes[content.range.clone()]).ok()
                    }) {
                        self.set_effect_string_attribute(write, "written_content", content);
                    } else {
                        self.opaque_boundary(
                            "in-memory tar member has no known UTF-8 content",
                            node,
                        );
                    }
                    if !matches!(member.name.kind, SemanticValueKind::Literal(_)) {
                        self.opaque_boundary("in-memory tar member name is unresolved", node);
                    }
                }
                self.mutate_memory_tar(buffer.id(), |object| {
                    if let MemoryTarValue::Buffer { position, .. } = object {
                        *position = None;
                    }
                });
                true
            }
            _ => false,
        }
    }
}
