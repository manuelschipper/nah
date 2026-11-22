use std::collections::HashMap;

use effinterp_proto::{Effect, ResourceExpr, ResourceIdentity};

use crate::summary::substitute_resource_expr;

use super::model::{self, RubyModeledSend, effect, exe};

/// Recover Ruby spawn command text only from a literal or a concrete filesystem path.
pub(super) fn ruby_spawn_command_text(expr: &ResourceExpr) -> Option<String> {
    match expr {
        ResourceExpr::Literal { value } => Some(value.clone()),
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path.clone()),
        _ => None,
    }
}

/// Apply call-site bindings to a Ruby spawn's shell source or argv, working
/// directory, and stdout target before replay.
pub(super) fn substitute_ruby_spawn(
    spawn: RubyModeledSend,
    bindings: &HashMap<String, ResourceExpr>,
) -> RubyModeledSend {
    match spawn {
        RubyModeledSend::ShellSpawn {
            source,
            cwd,
            stdout,
        } => RubyModeledSend::ShellSpawn {
            source: substitute_resource_expr(&source, bindings),
            cwd: cwd.map(|cwd| substitute_resource_expr(&cwd, bindings)),
            stdout: stdout.map(|stdout| substitute_resource_expr(&stdout, bindings)),
        },
        RubyModeledSend::ExecSpawn { argv, cwd, stdout } => RubyModeledSend::ExecSpawn {
            argv: argv
                .into_iter()
                .map(|word| substitute_resource_expr(&word, bindings))
                .collect(),
            cwd: cwd.map(|cwd| substitute_resource_expr(&cwd, bindings)),
            stdout: stdout.map(|stdout| substitute_resource_expr(&stdout, bindings)),
        },
        other => other,
    }
}

/// Represent a spawn in a summary with the executable identity this source establishes.
pub(super) fn materialize_ruby_spawn(spawn: &RubyModeledSend) -> Effect {
    let resource = match spawn {
        RubyModeledSend::ShellSpawn { source, .. } => ruby_spawn_command_text(source)
            .as_deref()
            .map(model::shell_exe)
            .unwrap_or_else(|| exe(None)),
        RubyModeledSend::ExecSpawn { argv, .. } => argv
            .first()
            .and_then(ruby_spawn_command_text)
            .map(|name| exe(Some(&name)))
            .unwrap_or_else(|| exe(None)),
        RubyModeledSend::SpawnUnresolved(argv0) => exe(argv0.as_deref()),
        _ => exe(None),
    };
    effect("process.exec", resource, false)
}
