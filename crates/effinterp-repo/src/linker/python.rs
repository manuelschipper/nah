use super::*;

pub(crate) struct PythonLinker;

macro_rules! standard_linker {
    ($ty:ty, $classify:expr) => {
        impl Linker for $ty {
            fn import_call_reference(
                &self,
                importer: &ModuleFile,
                edge: &effinterp_engine::CallEdge,
            ) -> Option<CalleeReference> {
                let callee = &edge.callee;
                let (local, suffix) = callee.split_once('.').unwrap_or((callee, ""));
                let binding = find_import(importer, local)?;
                let symbol = match (&binding.imported, suffix) {
                    (Some(imported), "") => imported.clone(),
                    (Some(imported), suffix) => format!("{imported}.{suffix}"),
                    (None, suffix) if !suffix.is_empty() => binding
                        .module
                        .strip_prefix(local)
                        .and_then(|module_suffix| module_suffix.strip_prefix('.'))
                        .and_then(|module_suffix| suffix.strip_prefix(module_suffix))
                        .and_then(|symbol| symbol.strip_prefix('.'))
                        .unwrap_or(suffix)
                        .to_string(),
                    (None, _) => return None,
                };
                let qualified = format!("{}.{}", binding.module, symbol);
                let (module, symbol) = qualified.rsplit_once('.')?;
                (!module.is_empty() && !symbol.is_empty()).then(|| CalleeReference {
                    module: module.to_string(),
                    symbol: symbol.to_string(),
                })
            }
            fn unresolved_call_is_boundary(&self) -> bool {
                true
            }

            fn resolve_callee<'a>(
                &self,
                reg: &'a ModuleRegistry,
                file: &'a ModuleFile,
                callee: &str,
            ) -> Resolution<'a> {
                resolve_standard_callee(self, reg, file, callee)
            }

            fn class_candidates<'a>(
                &self,
                reg: &'a ModuleRegistry,
                file: &'a ModuleFile,
                name: &str,
            ) -> Vec<(ResolvedObject, Assurance)> {
                standard_class_candidates(self, reg, file, name)
            }

            fn resolve_method<'a>(
                &self,
                reg: &'a ModuleRegistry,
                inst: &ResolvedObject,
                method: &str,
            ) -> Resolution<'a> {
                resolve_common_method(self, reg, inst, method)
            }

            fn classify_external(
                &self,
                _reg: &ModuleRegistry,
                module: &str,
                member: &str,
                arity: Option<usize>,
            ) -> Option<ExternalCall> {
                ($classify)(module, member, arity)
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
    };
}

standard_linker!(
    PythonLinker,
    |module: &str, member: &str, arity: Option<usize>| {
        if module.starts_with('.') {
            None
        } else {
            classify_python_call(&format!("{module}.{member}"), arity)
        }
    }
);
