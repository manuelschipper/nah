//! Python host environment bindings.
//! A program mutation can invalidate the observed value, and every substitution retains its provenance.

use effinterp_proto::{
    PathPlatform, ProvenanceKind, ProvenanceRef, ResourceExpr, normalize_resource,
};

use super::PythonWalker;

impl PythonWalker<'_, '_> {
    /// Replace an environment reference with the value the host supplied for
    /// it, so a path built from `$HOME` or `~` resolves as precisely as the
    /// same path written out. Every substituted name contributes the
    /// provenance of the binding it came from.
    fn resolve_host_environment(
        &mut self,
        resource: &mut ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) {
        match resource {
            ResourceExpr::Property { base, name }
                if name == crate::value::HOME_DIRECTORY_PROPERTY =>
            {
                let mut home = (**base).clone();
                if self.builder.is_host_realm()
                    && self.nest.current_environment_unsets().contains("HOME")
                    && matches!(&home, ResourceExpr::Environment { name } if name == "HOME")
                    && !self.environment_rewritten
                    && !self.imports.namespace_mutated
                {
                    home = self.nest.home_directory_value();
                    provenance.push(self.builder.node(
                        ProvenanceKind::HostContext {
                            name: "account_home".into(),
                        },
                        &[],
                    ));
                } else {
                    self.resolve_host_environment(&mut home, provenance);
                }
                *resource = home;
            }
            ResourceExpr::Environment { name } => {
                let Some(value) = self.host_environment_value(name) else {
                    return;
                };
                if let Some(node) = self.nest.current_environment_node(name) {
                    provenance.push(node);
                } else {
                    provenance.push(self.builder.node(
                        ProvenanceKind::HostContext {
                            name: format!("env.{name}"),
                        },
                        &[],
                    ));
                }
                *resource = value;
            }
            ResourceExpr::Join { parts }
            | ResourceExpr::Union {
                alternatives: parts,
            } => {
                for part in parts {
                    self.resolve_host_environment(part, provenance);
                }
            }
            ResourceExpr::Property { base, .. } => self.resolve_host_environment(base, provenance),
            _ => {}
        }
    }

    /// A filesystem resource with the host environment applied. A path read
    /// whole from the environment (`~` alone) lowers exactly as the same path
    /// written out, so it names the file it reaches rather than a string.
    pub(super) fn resolve_host_path(
        &mut self,
        mut resource: ResourceExpr,
        provenance: &mut Vec<ProvenanceRef>,
    ) -> ResourceExpr {
        let before = provenance.len();
        self.resolve_host_environment(&mut resource, provenance);
        if provenance.len() == before {
            return resource;
        }
        match normalize_resource(resource, PathPlatform::Posix) {
            literal @ ResourceExpr::Literal { .. } => self.lower_fs_literal(literal),
            resource => resource,
        }
    }

    /// The effective value of one environment name, preferring an override the
    /// enclosing execution established over the value the host supplied.
    fn host_environment_value(&self, name: &str) -> Option<ResourceExpr> {
        if let Some(value) = self
            .ipython
            .as_ref()
            .and_then(|state| state.environment.get(name))
        {
            return value.clone();
        }
        if self.environment_rewritten
            || self.imports.namespace_mutated
            || self.nest.current_environment_unsets().contains(name)
        {
            return None;
        }
        if let Some(value) = self
            .nest
            .environments
            .borrow()
            .last()
            .and_then(|environment| environment.get(name))
        {
            return value.clone();
        }
        self.nest
            .context
            .and_then(|context| context.env.get(name))
            .map(|value| ResourceExpr::Literal {
                value: value.clone(),
            })
    }
}
