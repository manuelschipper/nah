//! Rust call resolution within one file, including use paths and declared receivers.

pub(super) mod dispatch_types;

use std::collections::{HashMap, HashSet};

use effinterp_proto::ResourceExpr;
use syn::visit::Visit;
use syn::{Block, FnArg, ImplItem, Item, Pat, UseTree};

use crate::TypeRef;
use crate::module_summary::{ClassEntry, DispatchImpl, DispatchSignature, ImportBinding};

use self::dispatch_types::{
    base_type_ident, generic_dispatch_types, outer_type_ident, receiver_type_ref,
    return_value_path, rust_dispatch_signature, rust_signature_type, type_idents,
};
use super::control::rust_guard_regions;
use super::model::is_known_api;
use super::syntax::str_lit;

pub(super) struct RustFunction<'a> {
    pub(super) params: Vec<String>,
    /// Declared base-type ident per parameter (through `&`/`Vec`/`Option`/
    /// `Box`/`Result` wrappers), when a single identifier names it. This is
    /// what lets a method call on a parameter dispatch by its declared type.
    pub(super) param_types: HashMap<String, String>,
    /// Proven outer receiver types, kept separately from peeled element types.
    pub(super) param_receiver_types: HashMap<String, TypeRef>,
    pub(super) receiver_shadow_types: HashSet<String>,
    pub(super) body: &'a Block,
    /// The impl type for a method (`impl App` -> "App"); None for free fns.
    pub(super) impl_type: Option<String>,
    /// Trait and canonical receiver named by an `impl Trait for Type` block.
    pub(super) dispatch_impl: Option<DispatchImpl>,
    pub(super) dispatch_signature: DispatchSignature,
    pub(super) is_async: bool,
    /// The class the function returns, when the return type's base ident is
    /// `Self`, the impl type, or a struct/enum defined in this file.
    pub(super) ret_class: Option<String>,
    /// Canonical identity for an externally defined returned class.
    pub(super) ret_type: Option<TypeRef>,
    /// File imports overlaid with every `use` item in this function body.
    pub(super) uses: RustUseResolver,
}

impl RustFunction<'_> {
    /// Parameters mapped to symbolic `Parameter` expressions, for summarizing.
    pub(super) fn param_env(&self) -> HashMap<String, ResourceExpr> {
        self.params
            .iter()
            .map(|p| (p.clone(), ResourceExpr::Parameter { name: p.clone() }))
            .collect()
    }

    /// Parameter names declared as `std::process::Command` in `uses`' scope.
    pub(super) fn command_params(&self, uses: &RustUseResolver) -> HashSet<String> {
        self.param_types
            .iter()
            .filter(|(_, t)| uses.resolve_use_path(&[(*t).clone()]) == "std::process::Command")
            .map(|(p, _)| p.clone())
            .collect()
    }
}

pub(super) struct RustFunctions<'a> {
    /// Free functions keyed by bare name; impl methods keyed `Type.method`
    /// (the form instance dispatch resolves at composition time).
    map: HashMap<String, RustFunction<'a>>,
    pub(super) order: Vec<String>,
    /// Structs/enums defined in the file, with struct fields' declared types
    /// as attribute classes.
    pub(super) classes: Vec<ClassEntry>,
    pub(super) class_receiver_types: HashMap<String, HashMap<String, TypeRef>>,
    pub(super) unit_variants: HashMap<String, String>,
    pub(super) consts: HashMap<String, String>,
}

impl<'a> RustFunctions<'a> {
    pub(super) fn get(&self, name: &str) -> Option<&RustFunction<'a>> {
        self.map.get(name)
    }
}

/// Index the first definition of each Rust call target, with its own import scope.
pub(super) fn collect_rust_functions<'a>(
    file: &'a syn::File,
    uses: &RustUseResolver,
) -> RustFunctions<'a> {
    let mut classes = Vec::new();
    let consts = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item) => str_lit(&item.expr).map(|value| (item.ident.to_string(), value)),
            Item::Static(item) => str_lit(&item.expr).map(|value| (item.ident.to_string(), value)),
            _ => None,
        })
        .collect();
    let mut declared_unit_variants = HashMap::<String, HashSet<String>>::new();
    for item in &file.items {
        match item {
            Item::Struct(s) => {
                let attr_classes = s
                    .fields
                    .iter()
                    .filter_map(|f| {
                        let name = f.ident.as_ref()?.to_string();
                        let ty = base_type_ident(&f.ty)?;
                        Some((name, ty))
                    })
                    .collect();
                classes.push(ClassEntry {
                    name: s.ident.to_string(),
                    attr_classes,
                    ..Default::default()
                });
            }
            Item::Enum(e) => {
                declared_unit_variants.insert(
                    e.ident.to_string(),
                    e.variants
                        .iter()
                        .filter(|variant| matches!(variant.fields, syn::Fields::Unit))
                        .map(|variant| variant.ident.to_string())
                        .collect(),
                );
                classes.push(ClassEntry {
                    name: e.ident.to_string(),
                    ..Default::default()
                });
            }
            Item::Trait(t) => classes.push(ClassEntry {
                name: t.ident.to_string(),
                ..Default::default()
            }),
            _ => {}
        }
    }
    let mut unit_variants = HashMap::from([("None".to_string(), "None".to_string())]);
    for glob in &uses.globs {
        if let Some(variants) = glob
            .last()
            .and_then(|enum_name| declared_unit_variants.get(enum_name))
        {
            unit_variants.extend(
                variants
                    .iter()
                    .map(|variant| (variant.clone(), variant.clone())),
            );
        }
    }
    for (alias, path) in &uses.aliases {
        let Some(variant) = path
            .last()
            .zip(path.iter().rev().nth(1))
            .filter(|(variant, owner)| {
                declared_unit_variants
                    .get(*owner)
                    .is_some_and(|variants| variants.contains(*variant))
            })
            .map(|(variant, _)| variant)
        else {
            continue;
        };
        unit_variants.insert(alias.clone(), variant.clone());
    }
    let mut class_names: HashSet<String> = classes.iter().map(|c| c.name.clone()).collect();
    class_names.extend(file.items.iter().filter_map(|item| match item {
        Item::Type(alias) => Some(alias.ident.to_string()),
        _ => None,
    }));
    let class_receiver_types = file
        .items
        .iter()
        .filter_map(|item| {
            let Item::Struct(item) = item else {
                return None;
            };
            let mut shadowed = class_names.clone();
            shadowed.extend(
                item.generics
                    .type_params()
                    .map(|param| param.ident.to_string()),
            );
            let fields = item
                .fields
                .iter()
                .filter_map(|field| {
                    Some((
                        field.ident.as_ref()?.to_string(),
                        receiver_type_ref(&field.ty, uses, &shadowed)?,
                    ))
                })
                .collect();
            Some((item.ident.to_string(), fields))
        })
        .collect();

    let mut map = HashMap::new();
    let mut order = Vec::new();
    for item in &file.items {
        match item {
            Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                add_fn(
                    &mut map,
                    &mut order,
                    name,
                    &f.sig,
                    &f.block,
                    None,
                    None,
                    &class_names,
                    uses,
                    None,
                );
            }
            Item::Impl(im) => {
                let Some(impl_type) = outer_type_ident(&im.self_ty) else {
                    continue;
                };
                let impl_generics: HashMap<_, _> = im
                    .generics
                    .type_params()
                    .enumerate()
                    .map(|(index, param)| (param.ident.to_string(), format!("$impl{index}")))
                    .collect();
                let mut impl_shadowed = class_names.clone();
                impl_shadowed.extend(
                    im.generics
                        .type_params()
                        .map(|param| param.ident.to_string()),
                );
                let dispatch_impl = im
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| path.segments.last())
                    .map(|segment| DispatchImpl {
                        contract: segment.ident.to_string(),
                        receiver: receiver_type_ref(&im.self_ty, uses, &impl_shadowed)
                            .and_then(|ty| match ty {
                                TypeRef::External { path } => Some(path),
                                TypeRef::Repo { .. } => None,
                            })
                            .unwrap_or_else(|| {
                                impl_generics.get(&impl_type).cloned().unwrap_or_else(|| {
                                    uses.resolve_use_path(std::slice::from_ref(&impl_type))
                                })
                            }),
                        type_arguments: match &segment.arguments {
                            syn::PathArguments::AngleBracketed(arguments) => arguments
                                .args
                                .iter()
                                .map(|argument| match argument {
                                    syn::GenericArgument::Type(ty) => {
                                        rust_signature_type(ty, uses, &impl_generics)
                                    }
                                    syn::GenericArgument::Lifetime(_) => "'_".to_string(),
                                    _ => "<unsupported>".to_string(),
                                })
                                .collect(),
                            _ => Vec::new(),
                        },
                    });
                for it in &im.items {
                    if let ImplItem::Fn(m) = it {
                        let name = format!("{impl_type}.{}", m.sig.ident);
                        add_fn(
                            &mut map,
                            &mut order,
                            name,
                            &m.sig,
                            &m.block,
                            Some(impl_type.clone()),
                            dispatch_impl.clone(),
                            &class_names,
                            uses,
                            Some(&impl_generics),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    collect_inline_mod_fns(
        &file.items,
        &mut Vec::new(),
        &mut map,
        &mut order,
        &class_names,
        uses,
    );
    RustFunctions {
        map,
        order,
        classes,
        class_receiver_types,
        unit_variants,
        consts,
    }
}

fn collect_inline_mod_fns<'a>(
    items: &'a [Item],
    prefix: &mut Vec<String>,
    map: &mut HashMap<String, RustFunction<'a>>,
    order: &mut Vec<String>,
    class_names: &HashSet<String>,
    uses: &RustUseResolver,
) {
    for item in items {
        let Item::Mod(module) = item else { continue };
        let Some((_, nested)) = &module.content else {
            continue;
        };
        prefix.push(module.ident.to_string());
        for item in nested {
            if let Item::Fn(function) = item {
                let name = format!("{}::{}", prefix.join("::"), function.sig.ident);
                add_fn(
                    map,
                    order,
                    name,
                    &function.sig,
                    &function.block,
                    None,
                    None,
                    class_names,
                    uses,
                    None,
                );
            }
        }
        collect_inline_mod_fns(nested, prefix, map, order, class_names, uses);
        prefix.pop();
    }
}

#[allow(clippy::too_many_arguments)]
fn add_fn<'a>(
    map: &mut HashMap<String, RustFunction<'a>>,
    order: &mut Vec<String>,
    name: String,
    sig: &'a syn::Signature,
    block: &'a Block,
    impl_type: Option<String>,
    dispatch_impl: Option<DispatchImpl>,
    class_names: &HashSet<String>,
    uses: &RustUseResolver,
    parent_generics: Option<&HashMap<String, String>>,
) {
    if map.contains_key(&name) {
        return; // keep the first definition; deterministic
    }
    let mut params = Vec::new();
    let mut param_types = HashMap::new();
    let mut param_receiver_types = HashMap::new();
    let mut receiver_shadow_types = class_names.clone();
    receiver_shadow_types.extend(
        sig.generics
            .type_params()
            .map(|param| param.ident.to_string()),
    );
    if let Some(parent_generics) = parent_generics {
        receiver_shadow_types.extend(parent_generics.keys().cloned());
    }
    let generic_types = generic_dispatch_types(sig);
    for arg in &sig.inputs {
        if let FnArg::Typed(pt) = arg
            && let Pat::Ident(id) = &*pt.pat
        {
            let pname = id.ident.to_string();
            if let Some(ty) = base_type_ident(&pt.ty) {
                param_types.insert(pname.clone(), generic_types.get(&ty).cloned().unwrap_or(ty));
            }
            if let Some(ty) = receiver_type_ref(&pt.ty, uses, &receiver_shadow_types) {
                param_receiver_types.insert(pname.clone(), ty);
            }
            params.push(pname);
        }
    }
    // The returned class: `Self`/the impl type when the return type mentions
    // it, else the single file-local class it names — searched through generic
    // arguments so `ConfigResult<Config>` still types as `Config`.
    let mut ret_type = None;
    let ret_class = match &sig.output {
        syn::ReturnType::Type(_, ty) => {
            let mut ids = Vec::new();
            type_idents(ty, &mut ids);
            if ids.iter().any(|i| i == "Self") {
                impl_type.clone()
            } else if let Some(t) = impl_type.as_ref().filter(|t| ids.contains(t)) {
                Some(t.clone())
            } else {
                let mut matches = ids.iter().filter(|i| class_names.contains(*i));
                match (matches.next(), matches.next()) {
                    (Some(t), None) => Some(t.clone()),
                    _ => return_value_path(ty).and_then(|path| {
                        let name = path.last()?.clone();
                        let identity = uses.resolve_use_path(&path);
                        if identity != name
                            && !identity.starts_with("crate::")
                            && !identity.starts_with("self::")
                            && !identity.starts_with("super::")
                        {
                            ret_type = Some(TypeRef::External { path: identity });
                            Some(name)
                        } else {
                            None
                        }
                    }),
                }
            }
        }
        syn::ReturnType::Default => None,
    };
    let dispatch_signature = rust_dispatch_signature(
        sig,
        uses,
        dispatch_impl.as_ref().and(impl_type.as_deref()),
        parent_generics,
    );
    let function_uses = uses.with_function_body(block);
    order.push(name.clone());
    map.insert(
        name,
        RustFunction {
            params,
            param_types,
            param_receiver_types,
            receiver_shadow_types,
            body: block,
            impl_type,
            dispatch_impl,
            dispatch_signature,
            is_async: sig.asyncness.is_some(),
            ret_class,
            ret_type,
            uses: function_uses,
        },
    );
}

// ---------------------------------------------------------------------------
// Use-path resolution (ownership)
// ---------------------------------------------------------------------------

/// Maps a local alias to the full path it refers to, so `remove_dir_all(..)`,
/// `fs::remove_dir_all(..)`, and `std::fs::remove_dir_all(..)` all resolve to
/// the same API. Glob prefixes let a bare name resolve through `use std::fs::*`.
#[derive(Clone, Default)]
pub(super) struct RustUseResolver {
    pub(super) guards: std::rc::Rc<crate::guards::GuardRegions>,
    pub(super) source_id: u64,
    /// alias -> full path segments (e.g. "fs" -> ["std","fs"]).
    aliases: HashMap<String, Vec<String>>,
    /// glob prefixes (e.g. ["std","fs"] from `use std::fs::*`).
    globs: Vec<Vec<String>>,
    /// import bindings in source order, for module_summaries.
    imports: Vec<ImportBinding>,
    /// Public imports forwarded by this module.
    exports: Vec<ImportBinding>,
}

impl RustUseResolver {
    pub(super) fn from_file(file: &syn::File, source: &str) -> Self {
        let mut r = RustUseResolver {
            source_id: source.bytes().fold(0xcbf29ce484222325, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
            }),
            ..RustUseResolver::default()
        };
        r.guards = std::rc::Rc::new(rust_guard_regions(file, source));
        for item in &file.items {
            match item {
                Item::Use(u) => r.walk_use(&u.tree, &mut Vec::new(), is_exported(&u.vis)),
                Item::ExternCrate(ext) => r.bind_extern_crate(ext),
                _ => {}
            }
        }
        r
    }

    /// `extern crate grep_cli as cli` binds `cli` like a `use` alias. A `pub`
    /// item is also a module export (`imported: None`) so a crate root can
    /// re-export another workspace crate as a path segment.
    fn bind_extern_crate(&mut self, ext: &syn::ItemExternCrate) {
        let crate_name = ext.ident.to_string();
        if crate_name == "self" || matches!(crate_name.as_str(), "std" | "core" | "alloc") {
            return;
        }
        let alias = ext
            .rename
            .as_ref()
            .map(|(_, ident)| ident.to_string())
            .unwrap_or_else(|| crate_name.clone());
        self.aliases.insert(alias.clone(), vec![crate_name.clone()]);
        if is_exported(&ext.vis) {
            self.exports.push(ImportBinding {
                local: alias,
                module: crate_name,
                imported: None,
            });
        }
    }

    fn walk_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>, exported: bool) {
        match tree {
            UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                self.walk_use(&p.tree, prefix, exported);
                prefix.pop();
            }
            UseTree::Name(n) => {
                let name = n.ident.to_string();
                if name == "self" {
                    if let Some(alias) = prefix.last().cloned() {
                        self.bind(alias, prefix.clone(), exported);
                    }
                } else {
                    let mut full = prefix.clone();
                    full.push(name.clone());
                    self.bind(name, full, exported);
                }
            }
            UseTree::Rename(rn) => {
                let mut full = prefix.clone();
                if rn.ident != "self" {
                    full.push(rn.ident.to_string());
                }
                self.bind(rn.rename.to_string(), full, exported);
            }
            UseTree::Group(g) => {
                for item in &g.items {
                    self.walk_use(item, prefix, exported);
                }
            }
            UseTree::Glob(_) => {
                self.globs.push(prefix.clone());
                // Exposed as a `*` binding so the repo layer can resolve names
                // through the glob target's own definitions and re-exports
                // (`use super::*` against a `lib.rs` re-export hub).
                let binding = ImportBinding {
                    local: "*".to_string(),
                    module: prefix.join("::"),
                    imported: None,
                };
                self.imports.push(binding.clone());
                if exported {
                    self.exports.push(binding);
                }
            }
        }
    }

    fn bind(&mut self, alias: String, full: Vec<String>, exported: bool) {
        let binding = ImportBinding {
            local: alias.clone(),
            module: full.join("::"),
            imported: full.last().cloned(),
        };
        self.imports.push(binding.clone());
        if exported {
            self.exports.push(binding);
        }
        self.aliases.insert(alias, full);
    }

    fn with_function_body(&self, body: &Block) -> Self {
        let mut local = RustUseResolver {
            source_id: self.source_id,
            guards: self.guards.clone(),
            ..RustUseResolver::default()
        };
        FunctionUseCollector {
            resolver: &mut local,
        }
        .visit_block(body);

        let mut aliases = self.aliases.clone();
        aliases.extend(local.aliases);
        local.aliases = aliases;
        local.globs.extend(self.globs.iter().cloned());
        local.imports = self.imports.clone();
        local.exports = self.exports.clone();
        local
    }

    /// Expand Rust use paths and retain the original spelling when no binding resolves.
    pub(super) fn resolve_use_path(&self, segs: &[String]) -> String {
        if segs.is_empty() {
            return String::new();
        }
        // Leading crate roots are already canonical.
        const ROOTS: [&str; 6] = ["std", "core", "alloc", "crate", "self", "super"];
        if ROOTS.contains(&segs[0].as_str()) {
            return segs.join("::");
        }
        if let Some(full) = self.aliases.get(&segs[0]) {
            let mut out = full.clone();
            out.extend_from_slice(&segs[1..]);
            return out.join("::");
        }
        // A bare name may have come through a glob import.
        if segs.len() == 1 {
            for g in &self.globs {
                let mut cand = g.clone();
                cand.push(segs[0].clone());
                if is_known_api(&cand.join("::")) {
                    return cand.join("::");
                }
            }
        }
        // A well-known std module or type reaching this file through a glob
        // re-export hub (`use super::*` against a lib.rs `pub(crate) use
        // std::{env, fs, process::Command, ...}`) resolves as std — the
        // pattern `just` uses throughout.
        if !self.globs.is_empty() {
            let prefix: Option<&[&str]> = match segs[0].as_str() {
                "env" | "fs" | "io" | "net" | "path" | "process" | "thread" => Some(&["std"]),
                "Command" => Some(&["std", "process"]),
                "File" | "OpenOptions" => Some(&["std", "fs"]),
                "TcpStream" | "TcpListener" => Some(&["std", "net"]),
                _ => None,
            };
            if let Some(prefix) = prefix {
                let mut out: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
                out.extend_from_slice(segs);
                return out.join("::");
            }
        }
        segs.join("::")
    }

    pub(super) fn imports(&self) -> Vec<ImportBinding> {
        self.imports.clone()
    }

    pub(super) fn exports(&self) -> Vec<ImportBinding> {
        self.exports.clone()
    }

    /// True when `name` is a named `use` binding in this file.
    pub(super) fn is_imported(&self, name: &str) -> bool {
        self.aliases.contains_key(name)
    }

    pub(super) fn path_is_imported(&self, segments: &[String]) -> bool {
        segments.first().is_some_and(|root| {
            self.aliases.contains_key(root) || matches!(root.as_str(), "std" | "core" | "alloc")
        })
    }
}

struct FunctionUseCollector<'a> {
    resolver: &'a mut RustUseResolver,
}

impl<'ast> Visit<'ast> for FunctionUseCollector<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.resolver.walk_use(&item.tree, &mut Vec::new(), false);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}

    fn visit_item_mod(&mut self, _item: &'ast syn::ItemMod) {}
}

pub(super) fn is_exported(visibility: &syn::Visibility) -> bool {
    match visibility {
        syn::Visibility::Public(_) => true,
        syn::Visibility::Restricted(restricted) => !restricted.path.is_ident("self"),
        syn::Visibility::Inherited => false,
    }
}

/// Well-known standard-library constructors, converters, and control functions
/// that carry no effect. When a call resolves to none of the modeled effects
/// and is not a local function, these names are treated as effectless rather
/// than as an unresolved-call boundary. Real code is dense with `Ok`/`Err`/
/// `drop`, and reporting each as unresolved degrades every domain to Partial
/// and drowns the genuine signal. Every name here is a pure/formatting/terminal
/// operation that cannot reach a filesystem, process, network, or environment
/// effect; anything that plausibly could (fs/process/net) is deliberately
/// excluded so it still raises a boundary.
const EFFECTLESS_CALLS: &[&str] = &[
    // Result / Option constructors and variants.
    "Ok",
    "Err",
    "Some",
    "None",
    // Pure constructors and conversions commonly written as associated calls.
    "new",
    "with_capacity",
    "from",
    "from_utf8",
    // Value drop is a no-op for our effect domains.
    "drop",
    // Common pure conversions / accessors that also appear as free calls.
    "default",
    "into",
    "to_string",
    "to_owned",
    "clone",
    "as_ref",
    "as_str",
    // Panic-on-None/Err unwrappers: control flow only, no modeled effect.
    "unwrap",
    "expect",
    // Iterator construction and collection: pure.
    "iter",
    "collect",
    // In-memory formatting (the `format!`-style helper, not the macro).
    "format",
    // Assertions: control flow / panics only.
    "assert",
    "assert_eq",
    "assert_ne",
];

/// True if a bare single-segment call names a known-effectless std constructor,
/// converter, or control function (see [`EFFECTLESS_CALLS`]).
pub(super) fn is_effectless_rust_call(name: &str) -> bool {
    EFFECTLESS_CALLS.contains(&name)
}
