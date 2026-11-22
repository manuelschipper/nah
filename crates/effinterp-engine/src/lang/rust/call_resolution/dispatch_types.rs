//! Declared Rust receiver types, trait contracts and signatures used for dispatch.

use std::collections::{HashMap, HashSet};

use syn::{Expr, FnArg, Item, TraitItem};

use crate::module_summary::{DispatchContract, DispatchSignature};
use crate::{TypeRef, canonical_rust_std_type};

use super::RustUseResolver;

/// The path of the value returned after peeling wrappers whose value is still
/// one instance. Collections are not peeled because returning `Vec<T>` does
/// not return a `T` receiver.
pub(in crate::lang::rust) fn return_value_path(ty: &syn::Type) -> Option<Vec<String>> {
    match ty {
        syn::Type::Reference(reference) => return_value_path(&reference.elem),
        syn::Type::Paren(paren) => return_value_path(&paren.elem),
        syn::Type::Path(path) => {
            let segment = path.path.segments.last()?;
            if matches!(
                segment.ident.to_string().as_str(),
                "Option" | "Box" | "Rc" | "Arc" | "Result"
            ) {
                let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
                    return None;
                };
                return arguments.args.iter().find_map(|argument| match argument {
                    syn::GenericArgument::Type(inner) => return_value_path(inner),
                    _ => None,
                });
            }
            Some(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect(),
            )
        }
        _ => None,
    }
}

pub(in crate::lang::rust) fn rust_dispatch_contracts(
    file: &syn::File,
    uses: &RustUseResolver,
) -> Vec<DispatchContract> {
    file.items
        .iter()
        .filter_map(|item| {
            let Item::Trait(item) = item else { return None };
            let trait_generics: HashMap<_, _> = item
                .generics
                .type_params()
                .enumerate()
                .map(|(index, param)| (param.ident.to_string(), format!("$trait{index}")))
                .collect();
            let mut methods: Vec<_> = item
                .items
                .iter()
                .filter_map(|member| match member {
                    TraitItem::Fn(method) => Some(method.sig.ident.to_string()),
                    _ => None,
                })
                .collect();
            let mut method_signatures: Vec<_> = item
                .items
                .iter()
                .filter_map(|member| match member {
                    TraitItem::Fn(method) => Some((
                        method.sig.ident.to_string(),
                        rust_dispatch_signature(&method.sig, uses, None, Some(&trait_generics)),
                    )),
                    _ => None,
                })
                .collect();
            methods.sort();
            methods.dedup();
            method_signatures.sort_by(|a, b| a.0.cmp(&b.0));
            method_signatures.dedup();
            (!methods.is_empty()).then(|| DispatchContract {
                name: item.ident.to_string(),
                methods,
                method_signatures,
            })
        })
        .collect()
}

pub(in crate::lang::rust) fn rust_dispatch_type_aliases(
    file: &syn::File,
    uses: &RustUseResolver,
) -> Vec<(String, String)> {
    let mut aliases: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| {
            let Item::Type(alias) = item else {
                return None;
            };
            let generics = alias
                .generics
                .type_params()
                .enumerate()
                .map(|(index, param)| (param.ident.to_string(), format!("${index}")))
                .collect();
            Some((
                alias.ident.to_string(),
                rust_signature_type(&alias.ty, uses, &generics),
            ))
        })
        .collect();
    aliases.sort();
    aliases
}

pub(in crate::lang::rust) fn generic_dispatch_types(
    sig: &syn::Signature,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for param in &sig.generics.params {
        let syn::GenericParam::Type(param) = param else {
            continue;
        };
        let mut traits = param.bounds.iter().filter_map(|bound| match bound {
            syn::TypeParamBound::Trait(bound) => bound.path.segments.last(),
            _ => None,
        });
        if let (Some(bound), None) = (traits.next(), traits.next()) {
            out.insert(param.ident.to_string(), bound.ident.to_string());
        }
    }
    if let Some(clause) = &sig.generics.where_clause {
        for predicate in &clause.predicates {
            let syn::WherePredicate::Type(predicate) = predicate else {
                continue;
            };
            let syn::Type::Path(ty) = &predicate.bounded_ty else {
                continue;
            };
            let Some(param) = ty.path.get_ident() else {
                continue;
            };
            let mut traits = predicate.bounds.iter().filter_map(|bound| match bound {
                syn::TypeParamBound::Trait(bound) => bound.path.segments.last(),
                _ => None,
            });
            if let (Some(bound), None) = (traits.next(), traits.next()) {
                out.insert(param.to_string(), bound.ident.to_string());
            }
        }
    }
    out
}

/// Normalize generic names by scope and position so dispatch signatures can compare across files.
pub(super) fn rust_dispatch_signature(
    sig: &syn::Signature,
    uses: &RustUseResolver,
    self_type: Option<&str>,
    parent_generics: Option<&HashMap<String, String>>,
) -> DispatchSignature {
    let mut generic_names = parent_generics.cloned().unwrap_or_default();
    generic_names.extend(
        sig.generics
            .type_params()
            .enumerate()
            .map(|(index, param)| (param.ident.to_string(), format!("$method{index}"))),
    );
    if let Some(self_type) = self_type {
        generic_names.insert(self_type.to_string(), "Self".to_string());
    }
    let params = sig
        .inputs
        .iter()
        .map(|input| match input {
            FnArg::Receiver(receiver) => {
                if receiver.reference.is_some() {
                    if receiver.mutability.is_some() {
                        "&mut self".to_string()
                    } else {
                        "&self".to_string()
                    }
                } else {
                    "self".to_string()
                }
            }
            FnArg::Typed(param) => rust_signature_type(&param.ty, uses, &generic_names),
        })
        .collect();
    let results = match &sig.output {
        syn::ReturnType::Default => Vec::new(),
        syn::ReturnType::Type(_, ty) => vec![rust_signature_type(ty, uses, &generic_names)],
    };
    DispatchSignature { params, results }
}

pub(super) fn rust_signature_type(
    ty: &syn::Type,
    uses: &RustUseResolver,
    generics: &HashMap<String, String>,
) -> String {
    match ty {
        syn::Type::Reference(reference) => format!(
            "&{}{}",
            if reference.mutability.is_some() {
                "mut "
            } else {
                ""
            },
            rust_signature_type(&reference.elem, uses, generics)
        ),
        syn::Type::Ptr(pointer) => format!(
            "*{} {}",
            if pointer.mutability.is_some() {
                "mut"
            } else {
                "const"
            },
            rust_signature_type(&pointer.elem, uses, generics)
        ),
        syn::Type::Slice(slice) => {
            format!("[{}]", rust_signature_type(&slice.elem, uses, generics))
        }
        syn::Type::Array(array) => format!(
            "[{};{}]",
            rust_signature_type(&array.elem, uses, generics),
            rust_signature_const_expr(&array.len, uses)
                .unwrap_or_else(|| "<unsupported>".to_string())
        ),
        syn::Type::Tuple(tuple) => format!(
            "({})",
            tuple
                .elems
                .iter()
                .map(|ty| rust_signature_type(ty, uses, generics))
                .collect::<Vec<_>>()
                .join(",")
        ),
        syn::Type::Path(path) => {
            if path.qself.is_some()
                || path
                    .path
                    .segments
                    .iter()
                    .take(path.path.segments.len().saturating_sub(1))
                    .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
            {
                return "<unsupported>".to_string();
            }
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if segments.len() == 1
                && let Some(generic) = generics.get(&segments[0])
            {
                return generic.clone();
            }
            let base = uses.resolve_use_path(&segments);
            let Some(arguments) = path.path.segments.last().and_then(|segment| {
                rust_signature_path_arguments(&segment.arguments, uses, generics)
            }) else {
                return "<unsupported>".to_string();
            };
            format!("{base}{arguments}")
        }
        syn::Type::TraitObject(object) => {
            let Some(bounds) = object
                .bounds
                .iter()
                .map(|bound| rust_signature_bound(bound, uses, generics))
                .collect::<Option<Vec<_>>>()
            else {
                return "<unsupported>".to_string();
            };
            bounds.join("+")
        }
        syn::Type::ImplTrait(object) => {
            let mut bounds = Vec::new();
            for bound in &object.bounds {
                let Some(bound) = rust_signature_bound(bound, uses, generics) else {
                    return "<unsupported>".to_string();
                };
                bounds.push(bound);
            }
            format!("impl {}", bounds.join("+"))
        }
        syn::Type::BareFn(function) => {
            let mut inputs = function
                .inputs
                .iter()
                .map(|input| rust_signature_type(&input.ty, uses, generics))
                .collect::<Vec<_>>();
            if function.variadic.is_some() {
                inputs.push("...".to_string());
            }
            let output = match &function.output {
                syn::ReturnType::Default => "()".to_string(),
                syn::ReturnType::Type(_, output) => rust_signature_type(output, uses, generics),
            };
            let safety = if function.unsafety.is_some() {
                "unsafe "
            } else {
                ""
            };
            let abi = function.abi.as_ref().map_or_else(String::new, |abi| {
                format!(
                    "extern:{} ",
                    abi.name
                        .as_ref()
                        .map(|name| name.value())
                        .unwrap_or_else(|| "C".to_string())
                )
            });
            format!("{safety}{abi}fn({})->{output}", inputs.join(","))
        }
        syn::Type::Paren(paren) => rust_signature_type(&paren.elem, uses, generics),
        syn::Type::Never(_) => "!".to_string(),
        _ => "<unsupported>".to_string(),
    }
}

fn rust_signature_path_arguments(
    arguments: &syn::PathArguments,
    uses: &RustUseResolver,
    generics: &HashMap<String, String>,
) -> Option<String> {
    match arguments {
        syn::PathArguments::None => Some(String::new()),
        syn::PathArguments::AngleBracketed(arguments) => arguments
            .args
            .iter()
            .map(|argument| rust_signature_generic_argument(argument, uses, generics))
            .collect::<Option<Vec<_>>>()
            .map(|arguments| format!("<{}>", arguments.join(","))),
        syn::PathArguments::Parenthesized(arguments) => {
            let inputs = arguments
                .inputs
                .iter()
                .map(|input| rust_signature_type(input, uses, generics))
                .collect::<Vec<_>>()
                .join(",");
            let output = match &arguments.output {
                syn::ReturnType::Default => "()".to_string(),
                syn::ReturnType::Type(_, output) => rust_signature_type(output, uses, generics),
            };
            Some(format!("({inputs})->{output}"))
        }
    }
}

fn rust_signature_generic_argument(
    argument: &syn::GenericArgument,
    uses: &RustUseResolver,
    generics: &HashMap<String, String>,
) -> Option<String> {
    match argument {
        syn::GenericArgument::Lifetime(_) => Some("'_".to_string()),
        syn::GenericArgument::Type(ty) => Some(rust_signature_type(ty, uses, generics)),
        syn::GenericArgument::Const(value) => rust_signature_const_expr(value, uses),
        syn::GenericArgument::AssocType(binding) => {
            if binding.generics.is_some() {
                return None;
            }
            Some(format!(
                "{}={}",
                binding.ident,
                rust_signature_type(&binding.ty, uses, generics)
            ))
        }
        syn::GenericArgument::AssocConst(binding) => {
            if binding.generics.is_some() {
                return None;
            }
            Some(format!(
                "{}={}",
                binding.ident,
                rust_signature_const_expr(&binding.value, uses)?
            ))
        }
        syn::GenericArgument::Constraint(_) => None,
        _ => None,
    }
}

fn rust_signature_bound(
    bound: &syn::TypeParamBound,
    uses: &RustUseResolver,
    generics: &HashMap<String, String>,
) -> Option<String> {
    match bound {
        syn::TypeParamBound::Trait(bound) if bound.lifetimes.is_none() => {
            if bound
                .path
                .segments
                .iter()
                .take(bound.path.segments.len().saturating_sub(1))
                .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
            {
                return None;
            }
            let segments = bound
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            let base = uses.resolve_use_path(&segments);
            let arguments = bound.path.segments.last().and_then(|segment| {
                rust_signature_path_arguments(&segment.arguments, uses, generics)
            })?;
            let modifier = match bound.modifier {
                syn::TraitBoundModifier::None => "",
                syn::TraitBoundModifier::Maybe(_) => "?",
            };
            Some(format!("{modifier}{base}{arguments}"))
        }
        syn::TypeParamBound::Lifetime(_) => Some("'_".to_string()),
        _ => None,
    }
}

fn rust_signature_const_expr(expr: &Expr, uses: &RustUseResolver) -> Option<String> {
    match expr {
        Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => Some(value.base10_digits().to_string()),
            syn::Lit::Bool(value) => Some(value.value.to_string()),
            syn::Lit::Char(value) => Some(format!("{:?}", value.value())),
            syn::Lit::Byte(value) => Some(value.value().to_string()),
            _ => None,
        },
        Expr::Path(path) if path.qself.is_none() => {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            path.path
                .segments
                .iter()
                .all(|segment| matches!(segment.arguments, syn::PathArguments::None))
                .then(|| uses.resolve_use_path(&segments))
        }
        Expr::Paren(paren) => rust_signature_const_expr(&paren.expr, uses),
        Expr::Group(group) => rust_signature_const_expr(&group.expr, uses),
        Expr::Block(block) if block.attrs.is_empty() => match block.block.stmts.as_slice() {
            [syn::Stmt::Expr(expr, None)] => rust_signature_const_expr(expr, uses),
            _ => None,
        },
        Expr::Unary(unary) => {
            let operator = match unary.op {
                syn::UnOp::Neg(_) => "-",
                syn::UnOp::Not(_) => "!",
                _ => return None,
            };
            Some(format!(
                "{operator}{}",
                rust_signature_const_expr(&unary.expr, uses)?
            ))
        }
        _ => None,
    }
}

/// Every type identifier a type mentions (path segments' final idents and
/// their generic arguments, recursively), for matching a return type against
/// the file's classes.
pub(in crate::lang::rust) fn type_idents(ty: &syn::Type, out: &mut Vec<String>) {
    match ty {
        syn::Type::Reference(r) => type_idents(&r.elem, out),
        syn::Type::Slice(s) => type_idents(&s.elem, out),
        syn::Type::Paren(p) => type_idents(&p.elem, out),
        syn::Type::Tuple(t) => {
            for e in &t.elems {
                type_idents(e, out);
            }
        }
        syn::Type::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                out.push(seg.ident.to_string());
                if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                    for a in &ab.args {
                        if let syn::GenericArgument::Type(t) = a {
                            type_idents(t, out);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// The base type identifier of a declared type, looking through references,
/// slices, and single-type-argument wrappers (`Vec<T>`, `Option<T>`, `Box<T>`,
/// `Result<T, E>`, `Rc`/`Arc`): the type a value of it dispatches on (an
/// element of `Vec<Input>` is an `Input`). None when no single ident names it.
pub(in crate::lang::rust) fn base_type_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(r) => base_type_ident(&r.elem),
        syn::Type::Slice(s) => base_type_ident(&s.elem),
        syn::Type::Paren(p) => base_type_ident(&p.elem),
        syn::Type::TraitObject(object) => {
            let mut traits = object.bounds.iter().filter_map(|bound| match bound {
                syn::TypeParamBound::Trait(bound) => bound.path.segments.last(),
                _ => None,
            });
            match (traits.next(), traits.next()) {
                (Some(trait_), None) => Some(trait_.ident.to_string()),
                _ => None,
            }
        }
        syn::Type::ImplTrait(object) => {
            let mut traits = object.bounds.iter().filter_map(|bound| match bound {
                syn::TypeParamBound::Trait(bound) => bound.path.segments.last(),
                _ => None,
            });
            match (traits.next(), traits.next()) {
                (Some(trait_), None) => Some(trait_.ident.to_string()),
                _ => None,
            }
        }
        syn::Type::Path(p) => {
            let seg = p.path.segments.last()?;
            let name = seg.ident.to_string();
            if matches!(
                name.as_str(),
                "Vec" | "Option" | "Box" | "Rc" | "Arc" | "Result"
            ) {
                if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                    for a in &ab.args {
                        if let syn::GenericArgument::Type(t) = a {
                            return base_type_ident(t);
                        }
                    }
                }
                return None;
            }
            Some(name)
        }
        _ => None,
    }
}

/// The receiver type named directly by a declaration, without peeling
/// collection wrappers to their element type.
pub(in crate::lang::rust) fn outer_type_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(reference) => outer_type_ident(&reference.elem),
        syn::Type::Paren(paren) => outer_type_ident(&paren.elem),
        syn::Type::Slice(_) => Some("slice".to_string()),
        syn::Type::Path(path) => Some(path.path.segments.last()?.ident.to_string()),
        _ => None,
    }
}

pub(in crate::lang::rust) fn receiver_type_ref(
    ty: &syn::Type,
    uses: &RustUseResolver,
    class_names: &HashSet<String>,
) -> Option<TypeRef> {
    match ty {
        syn::Type::Reference(reference) => receiver_type_ref(&reference.elem, uses, class_names),
        syn::Type::Paren(paren) => receiver_type_ref(&paren.elem, uses, class_names),
        syn::Type::Slice(_) => Some(TypeRef::External {
            path: "std::primitive::slice".to_string(),
        }),
        syn::Type::Path(path) => {
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            receiver_type_ref_from_path(&segments, uses, class_names)
        }
        _ => None,
    }
}

pub(in crate::lang::rust) fn receiver_type_ref_from_path(
    segments: &[String],
    uses: &RustUseResolver,
    class_names: &HashSet<String>,
) -> Option<TypeRef> {
    let local = segments.last()?;
    if segments.len() == 1 && class_names.contains(local) {
        return None;
    }
    if segments.len() == 1
        && canonical_rust_std_type(local).is_some()
        && uses.globs.iter().any(|glob| {
            !matches!(
                glob.first().map(String::as_str),
                Some("std" | "core" | "alloc")
            )
        })
    {
        return None;
    }
    let resolved = uses.resolve_use_path(segments);
    if resolved.starts_with("crate::")
        || resolved.starts_with("self::")
        || resolved.starts_with("super::")
    {
        return None;
    }
    if let Some(path) = canonical_rust_std_type(&resolved) {
        return Some(TypeRef::External { path });
    }
    (resolved.contains("::") || uses.is_imported(&segments[0]))
        .then_some(TypeRef::External { path: resolved })
}

/// Result/Option adapters that pass the underlying success value through, so a
/// `let x = Type::new(...).map_err(..)?` still types `x` (and carries the bind)
/// from the inner constructor call.
pub(in crate::lang::rust) const PEEL_METHODS: &[&str] = &[
    "map_err",
    "unwrap",
    "expect",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "ok",
    "clone",
    "as_ref",
    "as_mut",
    "to_owned",
];

pub(in crate::lang::rust) fn peels_outer_receiver_type(method: &str) -> bool {
    matches!(
        method,
        "unwrap" | "expect" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default" | "ok"
    )
}
