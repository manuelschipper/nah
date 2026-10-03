use effinterp_engine::{Assurance, ExternalCall, ResolvedObject};

use super::{
    Linker, Resolution, class_defined, instance, resolve_common_method, resolve_export,
    resolve_standard_callee, standard_class_candidates,
};
use crate::module::{ModuleFile, ModuleRegistry};

pub(crate) struct PhpLinker;

impl Linker for PhpLinker {
    fn resolve_callee<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        callee: &str,
    ) -> Resolution<'a> {
        let common = resolve_standard_callee(self, reg, file, callee);
        if !matches!(common, Resolution::Unknown) || callee.contains('.') {
            return common;
        }
        resolve_export(reg, file, callee)
    }

    fn class_candidates<'a>(
        &self,
        reg: &'a ModuleRegistry,
        file: &'a ModuleFile,
        name: &str,
    ) -> Vec<(ResolvedObject, Assurance)> {
        if let Some(target) = reg.php_class_file(name)
            && class_defined(target, name)
        {
            return vec![(instance(target, name), Assurance::Exact)];
        }
        standard_class_candidates(self, reg, file, name)
    }

    fn resolve_method<'a>(
        &self,
        reg: &'a ModuleRegistry,
        inst: &ResolvedObject,
        method: &str,
    ) -> Resolution<'a> {
        resolve_common_method(
            self,
            reg,
            inst,
            if method == "__init__" {
                "__construct"
            } else {
                method
            },
        )
    }

    fn classify_external(
        &self,
        _reg: &ModuleRegistry,
        _module: &str,
        _member: &str,
        _arity: Option<usize>,
    ) -> Option<ExternalCall> {
        None
    }

    fn classify_import(
        &self,
        _reg: &ModuleRegistry,
        _file: &ModuleFile,
        _spec: &str,
    ) -> Option<ExternalCall> {
        None
    }

    fn execution_roots<'a>(
        &self,
        _reg: &'a ModuleRegistry,
        _file: &'a ModuleFile,
    ) -> Vec<(&'a ModuleFile, Option<&'a str>)> {
        Vec::new()
    }
}
