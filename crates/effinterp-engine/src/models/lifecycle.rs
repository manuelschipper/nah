use std::sync::LazyLock;

use crate::Lang;
use effinterp_model_schema::{SigEvidence, SigRole};

/// A framework lifecycle model: the signatures through which a framework
/// registers, attaches or dispatches to user callables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameworkLifecycle {
    pub id: &'static str,
    pub lang: Option<Lang>,
    pub sigs: &'static [LifecycleSig],
}

/// One lifecycle signature: the method or import that hands a user callable to the
/// framework, its role, and the evidence required before it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleSig {
    pub method: Option<&'static str>,
    pub import_path: Option<&'static str>,
    pub role: SigRole,
    pub max_args: Option<usize>,
    /// Callable component: a function, public class methods, or module callables when omitted.
    pub component: Option<usize>,
    pub evidence: SigEvidence,
    pub receiver_type: Option<&'static str>,
    pub fields: &'static [&'static str],
    pub params: &'static [&'static str],
    pub hooks: &'static [&'static str],
    pub derive_result: Option<usize>,
    pub result_type: Option<&'static str>,
    pub field_tags: &'static [&'static str],
}

/// The framework lifecycles compiled from the bundled model documents.
pub static LIFECYCLE_CATALOG: LazyLock<Vec<FrameworkLifecycle>> =
    LazyLock::new(super::registry::builtin_lifecycles);

impl FrameworkLifecycle {
    pub(crate) fn component_signature(&self, canonical: &str) -> Option<&LifecycleSig> {
        (self.lang == Some(Lang::Python)).then_some(())?;
        self.sigs.iter().find(|sig| {
            sig.role == SigRole::Registers
                && sig.component.is_some()
                && sig.evidence == SigEvidence::ExactImport
                && sig
                    .import_path
                    .zip(sig.method)
                    .is_some_and(|(module, method)| {
                        canonical
                            .strip_prefix(module)
                            .and_then(|tail| tail.strip_prefix('.'))
                            == Some(method)
                    })
        })
    }
}
