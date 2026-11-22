//! The Go package bindings visible while walking initializers and functions.

use std::collections::HashSet;

use gosyn::ast::{Declaration, Expression, File};

use super::summary::{constructed_class, named_type, package_var_names};
use super::walker::GoWalker;

/// Which package-level values a walk may read as exact.
///
/// A package `var`'s initializer describes only its declaration: any file of
/// the package may assign the name before the walked function runs, and a
/// single-file walk cannot see its siblings. So a function walk reads constants
/// only, and leaves a variable for composition, which knows the whole package
/// and refuses to substitute a name the package rebinds. The walk over the
/// package initializers themselves reads both, so the file still publishes each
/// variable's declared value for composition to judge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GoPackageValues {
    Constants,
    Declarations,
}

impl GoWalker<'_, '_> {
    /// Walk Go package initializers before entry bodies, keeping constants for later calls.
    pub(super) fn walk_go_package_initializers(&mut self, file: &File) {
        self.bind_go_package_values(file, GoPackageValues::Declarations);
        let variables: HashSet<_> = package_var_names(file).into_iter().collect();
        self.package_constants = self
            .values
            .iter()
            .filter(|(name, _)| !variables.contains(*name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        self.package_types = self.local_types.clone();
        for decl in &file.decl {
            if let Declaration::Variable(v) = decl {
                for spec in &v.specs {
                    if spec.values.is_empty()
                        && let Some(ty) = spec.typ.as_ref().and_then(named_type)
                    {
                        for name in &spec.name {
                            self.record_declared_construction(&name.name, &ty);
                        }
                    }
                    for (name, value) in spec.name.iter().zip(&spec.values) {
                        self.record_construction(&name.name, value);
                    }
                    for value in &spec.values {
                        self.walk_go_expression(value);
                    }
                }
            }
        }
    }

    /// Bind package-level declared and constructed types for function walks.
    pub(super) fn bind_go_package_values(&mut self, file: &File, values: GoPackageValues) {
        for decl in &file.decl {
            let Declaration::Variable(v) = decl else {
                continue;
            };
            for spec in &v.specs {
                let decl_ty = spec.typ.as_ref().and_then(named_type);
                self.package_vars
                    .extend(spec.name.iter().map(|id| id.name.clone()));
                for (id, value) in spec.name.iter().zip(&spec.values) {
                    if self.local_vars.contains(&id.name) {
                        continue;
                    }
                    if let Some(ty) = constructed_class(value)
                        .or_else(|| self.assigned_class(value))
                        .or_else(|| decl_ty.clone())
                    {
                        self.local_types.insert(id.name.clone(), ty);
                    }
                }
                if spec.values.is_empty()
                    && let Some(ty) = &decl_ty
                {
                    for id in &spec.name {
                        if !self.local_vars.contains(&id.name) {
                            self.local_types.insert(id.name.clone(), ty.clone());
                        }
                    }
                }
            }
        }
        for decl in &file.decl {
            match decl {
                Declaration::Variable(declaration) => {
                    for spec in &declaration.specs {
                        self.package_vars
                            .extend(spec.name.iter().map(|id| id.name.clone()));
                        if values != GoPackageValues::Declarations {
                            continue;
                        }
                        for (id, value) in spec.name.iter().zip(&spec.values) {
                            if !self.local_vars.contains(&id.name) {
                                self.bind_go_semantic_value(&Expression::Ident(id.clone()), value);
                            }
                        }
                    }
                }
                Declaration::Const(declaration) => {
                    // A const spec that omits its expression list repeats the
                    // previous one (`const ( first = "/x"; second )`). Only a
                    // plain literal is repeated: `const ( a = iota; b )` gives
                    // b a value of its own.
                    let mut carried: &[Expression] = &[];
                    for spec in &declaration.specs {
                        self.package_vars
                            .extend(spec.name.iter().map(|id| id.name.clone()));
                        let values = if spec.values.is_empty() {
                            if !carried.iter().all(|v| matches!(v, Expression::BasicLit(_))) {
                                continue;
                            }
                            carried
                        } else {
                            carried = &spec.values;
                            &spec.values
                        };
                        for (id, value) in spec.name.iter().zip(values) {
                            if !self.local_vars.contains(&id.name) {
                                self.bind_go_semantic_value(&Expression::Ident(id.clone()), value);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
