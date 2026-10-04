//! PowerShell path resolution: provider paths, `~`, `$HOME` and `$env:`
//! expansion, and the filesystem resource and effect a bound path names.

use effinterp_proto::{
    CoverageLevel, Domain, Effect, Modality, Operation, PathPlatform, ProvenanceKind,
    ProvenanceRef, RequestAssurance, ResourceExpr, ResourceIdentity, ResourcePattern,
    filesystem_path, normalize_path,
};

use crate::builder::PlanBuilder;
use crate::nest::Nest;

use super::ps_words::{PsStatement, PsVariable, ps_variable};
use super::{Session, powershell_boundary, session_variable};

/// A filesystem resource for a Windows or POSIX path that a command expanded
/// as a wildcard, or took literally.
fn path_resource(path: &str, windows: bool, wildcards: bool) -> ResourceExpr {
    let path = filesystem_provider_path(path);
    let local;
    let path = if windows && path.starts_with("\\\\") {
        let parts = path
            .trim_start_matches('\\')
            .splitn(3, '\\')
            .collect::<Vec<_>>();
        if parts.len() == 3
            && parts[0].eq_ignore_ascii_case("localhost")
            && parts[1].len() == 2
            && parts[1].as_bytes()[0].is_ascii_alphabetic()
            && parts[1].ends_with('$')
        {
            local = format!("{}:\\{}", &parts[1][..1], parts[2]);
            &local
        } else {
            path
        }
    } else {
        path
    };
    let platform = if windows {
        PathPlatform::Windows
    } else {
        PathPlatform::Posix
    };
    if wildcards && path.contains(['*', '?', '[']) {
        return ResourceExpr::Pattern {
            pattern: ResourcePattern::FsPath {
                glob: normalize_path(path, platform),
                narrowing: Default::default(),
            },
        };
    }
    filesystem_path(path, None, platform)
}

/// Remove only a named filesystem provider; registry and environment
/// qualifiers must remain unresolved as filesystem paths.
fn filesystem_provider_path(path: &str) -> &str {
    path.split_once("::")
        .filter(|(provider, _)| {
            provider.eq_ignore_ascii_case("FileSystem")
                || provider.eq_ignore_ascii_case("Microsoft.PowerShell.Core\\FileSystem")
        })
        .map_or(path, |(_, path)| path)
}

/// Whether a path establishes an absolute filesystem location.
pub(super) fn absolute_filesystem_path(path: &str, cwd: Option<&str>) -> Option<bool> {
    let path = filesystem_provider_path(path);
    if path.starts_with("\\\\") {
        let mut parts = path.trim_start_matches('\\').split('\\');
        return (parts
            .next()
            .is_some_and(|part| !part.is_empty() && !matches!(part, "?" | "."))
            && parts.next().is_some_and(|part| !part.is_empty()))
        .then_some(true);
    }
    let windows = path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && (path.get(1..3) == Some(":\\") || path.get(1..3) == Some(":/"))
        && !path[2..].contains(':');
    let posix = path.starts_with('/') && !cwd.is_some_and(|cwd| cwd.contains(':'));
    (windows || posix).then_some(windows)
}

/// `$HOME` of the analyzed host, which PowerShell expands `~` to. A Windows
/// environment usually has no `HOME`; there PowerShell takes the home
/// directory from `USERPROFILE` instead. Whichever of the two is set decides,
/// so a `HOME` this analysis cannot recover does not fall through to the other.
fn home(nest: &Nest) -> Option<String> {
    ["HOME", "USERPROFILE"]
        .into_iter()
        .find_map(|name| environment(nest, name))
        .flatten()
}

/// One environment variable of the analyzed host: `None` where it is not set,
/// `Some(None)` where it is set to a value this analysis cannot recover.
fn environment(nest: &Nest, name: &str) -> Option<Option<String>> {
    if nest.current_environment_unsets().contains(name) {
        return None;
    }
    let current = nest
        .environments
        .borrow()
        .last()
        .and_then(|environment| environment.get(name).cloned());
    if let Some(value) = current {
        return Some(match value {
            Some(ResourceExpr::Literal { value }) => Some(value),
            Some(ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            }) => Some(path),
            _ => None,
        });
    }
    nest.context
        .and_then(|context| context.env.get(name))
        .cloned()
        .map(Some)
}

/// Expand `$HOME`, `$env:NAME` and the boolean constants in the expandable
/// words and redirection targets of `statement`, in place. Returns whether
/// every expansion was established; a word that was not keeps its text
/// behind a boundary.
pub(super) fn expand_environment_words(
    builder: &mut PlanBuilder,
    nest: &Nest,
    session: &Session,
    requests_web: bool,
    statement: &mut PsStatement,
    node: ProvenanceRef,
) -> bool {
    let mut complete = true;
    for word in statement.words.iter_mut().chain(
        statement
            .redirections
            .iter_mut()
            .filter_map(|redirection| redirection.target.as_mut()),
    ) {
        // A variable holding file content stays for the parameter that
        // consumes it, and a web request reads its own variables.
        if !word.expandable
            || session.content(word).is_some()
            || requests_web && session_variable(word)
        {
            continue;
        }
        match expand_home_variable(builder, nest, &word.text, node) {
            Ok(text) => word.text = text,
            Err(detail) => {
                powershell_boundary(builder, node, detail);
                complete = false;
            }
        }
    }
    complete
}

/// The text of an expandable string with its variables replaced, or the
/// reason a variable in it is not modeled.
fn expand_home_variable(
    builder: &mut PlanBuilder,
    nest: &Nest,
    text: &str,
    node: ProvenanceRef,
) -> Result<String, &'static str> {
    let mut expanded = String::new();
    let mut rest = text;
    let mut read = Vec::new();
    let mut environment_read_once = |builder: &mut PlanBuilder, name: &str| {
        if !read.iter().any(|read: &String| read == name) {
            ps_environment_read(builder, node, name);
            read.push(name.to_string());
        }
    };
    while let Some(start) = rest.find('$') {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let (found, length) = ps_variable(after)
            .ok_or("PowerShell expandable string contains an unmodeled variable")?;
        let token = &rest[start..start + 1 + length];
        rest = &after[length..];
        match found {
            // A switch value stays the literal the parameter binder reads.
            PsVariable::Boolean => expanded.push_str(token),
            // `$HOME` is PowerShell's automatic variable for the user's home
            // directory: HOME where the host sets it, otherwise USERPROFILE.
            PsVariable::Home => {
                environment_read_once(builder, "HOME");
                if environment(nest, "HOME").is_none() {
                    environment_read_once(builder, "USERPROFILE");
                }
                expanded.push_str(
                    &home(nest).ok_or("PowerShell HOME is not supplied by the host environment")?,
                );
            }
            PsVariable::Session => {
                return Err("PowerShell expandable string contains an unmodeled variable");
            }
            PsVariable::Environment(name) => {
                environment_read_once(builder, name);
                expanded.push_str(&environment(nest, name).flatten().ok_or(
                    "PowerShell environment variable is not supplied by the host environment",
                )?);
            }
        }
    }
    expanded.push_str(rest);
    builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    Ok(expanded)
}

/// An `environment.read` of the host variable `name`, which a `$env:NAME`
/// expansion reads.
fn ps_environment_read(builder: &mut PlanBuilder, node: ProvenanceRef, name: &str) {
    builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new("environment.read"),
        resource: ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
        },
        attributes: Default::default(),
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node],
    });
}

/// Resolve one bound path to the filesystem resource it names, raising the
/// boundary that says why not where it does not name one. A relative path
/// names an item under `location`, the current filesystem location where it
/// is known. A drive or provider qualifier (`Env:`, `HKLM:`) or a rooted path
/// is not relative to it.
pub(super) fn resolved_path(
    builder: &mut PlanBuilder,
    nest: &Nest,
    path: &str,
    wildcards: bool,
    location: Option<&str>,
    node: ProvenanceRef,
    command: &str,
) -> Option<ResourceExpr> {
    let Some(path) = expand_home(builder, nest, path, node) else {
        powershell_boundary(
            builder,
            node,
            "PowerShell ~ has no home directory in the host context",
        );
        return None;
    };
    let path = match location {
        Some(location)
            if absolute_filesystem_path(&path, None).is_none()
                && !path.contains(':')
                && !path.starts_with(['/', '\\']) =>
        {
            match absolute_filesystem_path(location, None) {
                Some(true) => format!("{}\\{path}", location.trim_end_matches(['/', '\\'])),
                // PowerShell also separates paths with `\` on a POSIX host.
                _ => format!(
                    "{}/{}",
                    location.trim_end_matches('/'),
                    path.replace('\\', "/")
                ),
            }
        }
        _ => path,
    };
    let Some(windows) = absolute_filesystem_path(&path, None) else {
        powershell_boundary(
            builder,
            node,
            &format!(
                "PowerShell {command} path does not establish an absolute filesystem provider"
            ),
        );
        return None;
    };
    Some(path_resource(&path, windows, wildcards))
}

/// Record one filesystem effect a cmdlet model states. `model` is the model
/// id recorded as the effect's provenance. Returns the effect slot, or
/// `None` when the plan refused the effect.
pub(super) fn filesystem_effect(
    builder: &mut PlanBuilder,
    operation: &str,
    resource: ResourceExpr,
    attributes: crate::models::common::Attrs,
    node: ProvenanceRef,
    model: &str,
) -> Option<u32> {
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: model.into(),
        },
        &[node],
    );
    builder.effect(Effect {
        id: Default::default(),
        operation: Operation::new(operation),
        resource,
        attributes,
        modality: Modality::May,
        request_assurance: RequestAssurance::Exact,
        realm: effinterp_proto::ExecutionRealm::Host,
        condition: None,
        execution: Default::default(),
        provenance: vec![node, model],
    })
}

/// `~` and `~\rest` name the home directory of the analyzed host.
fn expand_home(
    builder: &mut PlanBuilder,
    nest: &Nest,
    path: &str,
    node: ProvenanceRef,
) -> Option<String> {
    let rest = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(['\\', '/']) => rest,
        _ => return Some(path.to_string()),
    };
    let model = builder.node(
        ProvenanceKind::ModelApplication {
            model: "powershell/home-expansion@v1".into(),
        },
        &[node],
    );
    for name in ["HOME", "USERPROFILE"] {
        builder.effect(Effect {
            id: Default::default(),
            operation: Operation::new("environment.read"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::EnvironmentVariable { name: name.into() },
            },
            attributes: Default::default(),
            modality: Modality::May,
            request_assurance: RequestAssurance::Exact,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: Default::default(),
            provenance: vec![node, model],
        });
    }
    builder.declare_coverage(Domain::new("environment"), CoverageLevel::Full);
    Some(format!("{}{rest}", home(nest)?))
}

/// Raise a boundary where a collection binds several paths: PowerShell
/// accesses each of them, but the grammar does not model the collection's
/// own evaluation.
pub(super) fn binds_single_path(
    builder: &mut PlanBuilder,
    node: ProvenanceRef,
    paths: &[String],
) -> bool {
    if paths.len() > 1 {
        powershell_boundary(
            builder,
            node,
            "PowerShell collection argument binds several paths",
        );
        return false;
    }
    true
}

/// Whether `resource` is the one path `location` names or one of its
/// ancestors. Windows compares paths without case.
pub(super) fn names_location_or_ancestor(resource: &ResourceExpr, location: &str) -> bool {
    let (
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        },
        Some(windows),
    ) = (resource, absolute_filesystem_path(location, None))
    else {
        return false;
    };
    let ResourceExpr::Concrete {
        identity: ResourceIdentity::FsPath { path: location },
    } = path_resource(location, windows, false)
    else {
        return false;
    };
    let (path, location) = if windows {
        (path.to_ascii_lowercase(), location.to_ascii_lowercase())
    } else {
        (path.clone(), location)
    };
    let path = path.trim_end_matches('/');
    location == path
        || location
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether `path` is rooted at a Windows drive, as `C:/`.
pub(super) fn drive_rooted(path: &str) -> bool {
    path.as_bytes().get(1) == Some(&b':')
}

/// The filesystem path an item path names: the path itself, or the rest of a
/// path qualified by the FileSystem provider. `None` for a path qualified by
/// another provider.
pub(super) fn filesystem_item(path: &str) -> Option<&str> {
    for provider in ["Microsoft.PowerShell.Core\\FileSystem::", "FileSystem::"] {
        if path
            .get(..provider.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(provider))
        {
            return Some(&path[provider.len()..]);
        }
    }
    (!path.contains(':') || absolute_filesystem_path(path, None).is_some()).then_some(path)
}
