//! Trusted-root command persistence.

use std::path::Path;

use nah_proto::ctx::{AbsolutePath, TrustedRootId};

use crate::live_state::{home, host_platform};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustedProject {
    pub(crate) identity: TrustedRootId,
    pub(crate) path: String,
    pub(crate) configured_guards: usize,
    pub(crate) enabled_guards: usize,
    pub(crate) needs_reapproval: usize,
    pub(crate) missing_guards: usize,
}

/// Bundles a project root offers for later hash approval.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GuardProposals {
    pub(crate) guards: usize,
}

/// Counts the bundles a root would expose for review. Trust is decided before
/// anyone has approved these bytes, so this only enumerates directory entries
/// and never reads, parses, or validates bundle files.
pub(crate) fn guard_proposals(root: &str) -> GuardProposals {
    let extensions = Path::new(root).join(".nah");
    GuardProposals {
        guards: count_bundles(&extensions.join("guards")),
    }
}

/// A bundle is an immediate subdirectory, the shape the loader discovers.
/// A missing or unreadable directory counts as nothing.
fn count_bundles(directory: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .count()
}

pub(crate) fn trust_root(requested: &str) -> Result<String, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let root = canonical_project_root(requested, platform)?;
    if root == home {
        return Err("home directory cannot be trusted as a project root".into());
    }
    let trusted_path = root.as_str().to_owned();
    let trust_path = nah_extensions::trust_database_path(&home, platform);
    nah_extensions::record_trusted_root(&trust_path, platform, root)
        .map_err(|error| error.to_string())?;
    Ok(trusted_path)
}

pub(crate) fn untrust_root(requested: &str) -> Result<(String, usize), String> {
    let platform = host_platform();
    let home = home(platform)?;
    let root = canonical_project_root(requested, platform)?;
    let trusted_path = root.as_str().to_owned();
    let removed = nah_extensions::revoke_trusted_root(
        &nah_extensions::trust_database_path(&home, platform),
        &nah_extensions::activation_database_path(&home, platform),
        platform,
        &root,
    )
    .map_err(|error| error.to_string())?;
    Ok((trusted_path, removed))
}

pub(crate) fn trusted_projects() -> Result<Vec<TrustedProject>, String> {
    let platform = host_platform();
    let home = home(platform)?;
    let trust = nah_extensions::TrustDatabase::load(
        &nah_extensions::trust_database_path(&home, platform),
        platform,
    )
    .and_then(|database| database.projection())
    .map_err(|error| error.to_string())?;
    let activations = nah_extensions::ActivationDatabase::load(
        &nah_extensions::activation_database_path(&home, platform),
    )
    .map_err(|error| error.to_string())?;
    let (bundles, _) =
        nah_extensions::discover_bundles(&home, platform, &trust, &crate::catalog::shipped_names())
            .map_err(|error| error.to_string())?;
    Ok(trust
        .trusted_roots()
        .iter()
        .map(|root| {
            let records = activations
                .records()
                .iter()
                .filter(|record| {
                    record.projection().identity().trusted_root() == Some(root.identity())
                })
                .collect::<Vec<_>>();
            let mut active = 0;
            let mut needs_reapproval = 0;
            let mut missing = 0;
            for record in &records {
                match bundles
                    .iter()
                    .find(|bundle| bundle.projection().identity() == record.projection().identity())
                {
                    Some(bundle) if bundle.projection() == record.projection() => active += 1,
                    Some(_) => needs_reapproval += 1,
                    None => missing += 1,
                }
            }
            TrustedProject {
                identity: root.identity().clone(),
                path: root.path().as_str().to_owned(),
                configured_guards: records.len(),
                enabled_guards: active,
                needs_reapproval,
                missing_guards: missing,
            }
        })
        .collect())
}

pub(crate) fn canonical_project_root(
    requested: &str,
    platform: nah_proto::ctx::Platform,
) -> Result<AbsolutePath, String> {
    let root = std::fs::canonicalize(requested).map_err(|_| {
        format!("project root {requested:?} cannot be resolved; choose an existing directory")
    })?;
    if !root.is_dir() {
        return Err(format!("project root {requested:?} is not a directory"));
    }
    let root = root
        .to_str()
        .ok_or_else(|| format!("project root {requested:?} is not UTF-8"))?;
    let root = if platform == nah_proto::ctx::Platform::Windows {
        nah_observe::normalize_windows_observed_path(root)
    } else {
        root.to_owned()
    };
    AbsolutePath::new(platform, root).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{GuardProposals, guard_proposals};

    #[test]
    fn bundle_directories_are_counted_without_reading_their_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let extensions = temp.path().join(".nah");
        // Empty bundles: the count must not depend on manifest or run bytes.
        std::fs::create_dir_all(extensions.join("guards").join("corp-api")).unwrap();
        std::fs::create_dir_all(extensions.join("guards").join("corp-net")).unwrap();
        std::fs::write(extensions.join("guards").join("README.md"), "not a bundle").unwrap();

        assert_eq!(
            guard_proposals(temp.path().to_str().unwrap()),
            GuardProposals { guards: 2 }
        );
    }

    #[test]
    fn absent_and_malformed_layouts_count_as_zero() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_str().unwrap().to_owned();

        assert_eq!(guard_proposals(&root), GuardProposals::default());

        // A file where the bundle directory belongs cannot be enumerated; the
        // dialog still has to open.
        let extensions = temp.path().join(".nah");
        std::fs::create_dir(&extensions).unwrap();
        std::fs::write(extensions.join("guards"), "clutter").unwrap();

        assert_eq!(guard_proposals(&root), GuardProposals::default());
    }
}
