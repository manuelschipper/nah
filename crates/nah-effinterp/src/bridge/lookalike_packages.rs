//! Whether a call adds a dependency one typing slip from a package the
//! project already has (`nah_proto::labels::dependency::lookalike`), which
//! `untrusted-code/lookalike-package` blocks before an install runs it. A call
//! adds a dependency by installing it, as the engine states an install's
//! literal package operands on its download (`requested_packages`), or by
//! writing it into a manifest (`requirements*.txt`, `pyproject.toml`,
//! `package.json`), whose text the engine records: the whole file an edit
//! leaves (`resulting_content`) where it knows it, else what the write puts
//! there (`written_content`), whole unless it appends or edits in place. Which
//! packages the project has is asked of the host per project directory:
//! the manifest's own directory, or the directory the install runs in.

use std::collections::{BTreeMap, BTreeSet};

use effinterp_proto::{AttrValue, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::ctx::{AbsolutePath, Platform};
use nah_proto::labels::dependency::{
    Ecosystem, Manifest, Requirement, install_operand, lookalike, same_version,
};
use nah_proto::observation::{Observation, ObservationQuery, ObservationValue, Observed};

const KEY_PREFIX: &str = "effinterp-installed-packages-";

/// What the call adds that a lookalike check can judge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LookalikeDependency {
    /// A dependency the project does not have is one slip from one it has.
    pub(crate) name: bool,
    /// That dependency also starts from a version the project has of the
    /// package it imitates.
    pub(crate) same_version: bool,
}

/// Each dependency the plan adds, with the project directory it is judged in.
fn added_dependencies(plan: &Plan, cwd: &str) -> Vec<(String, Requirement)> {
    let mut added = Vec::new();
    for effect in &plan.effects {
        let attribute = |name: &str| match effect.attributes.get(name) {
            Some(AttrValue::String(value)) => Some(value.as_str()),
            _ => None,
        };
        match effect.operation.as_str() {
            "network.download" => {
                let (Some(ecosystem), Some(AttrValue::List(operands))) = (
                    attribute("package_ecosystem").and_then(Ecosystem::from_attribute),
                    effect.attributes.get("requested_packages"),
                ) else {
                    continue;
                };
                let directory = plan
                    .execution_graph
                    .nodes
                    .get(effect.execution.0 as usize)
                    .and_then(|node| concrete_path(node.cwd.as_ref()?))
                    .unwrap_or(cwd);
                added.extend(operands.iter().filter_map(|operand| match operand {
                    AttrValue::String(operand) => {
                        Some((directory.to_owned(), install_operand(ecosystem, operand)?))
                    }
                    _ => None,
                }));
            }
            "filesystem.write" | "filesystem.create" => {
                let Some(path) = concrete_path(&effect.resource) else {
                    continue;
                };
                let Some(manifest) = Manifest::of_path(path) else {
                    continue;
                };
                let Some((directory, _)) = path.rsplit_once(['/', '\\']) else {
                    continue;
                };
                let flag = |name: &str, value: bool| {
                    effect.attributes.get(name) == Some(&AttrValue::Bool(value))
                };
                let (content, whole) = match attribute("resulting_content") {
                    Some(content) => (content, true),
                    None => {
                        let Some(content) = attribute("written_content") else {
                            continue;
                        };
                        let fragment = flag("append", true)
                            || flag("in_place", true)
                            || flag("truncate", false);
                        (content, !fragment)
                    }
                };
                added.extend(
                    manifest
                        .requirements(content, whole)
                        .into_iter()
                        .map(|requirement| (directory.to_owned(), requirement)),
                );
            }
            _ => {}
        }
    }
    added
}

fn concrete_path(resource: &ResourceExpr) -> Option<&str> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => Some(path),
        _ => None,
    }
}

/// The added names, grouped by project directory and ecosystem.
fn asked(plan: &Plan, cwd: &str) -> BTreeMap<(String, Ecosystem), BTreeSet<String>> {
    let mut asked = BTreeMap::<_, BTreeSet<_>>::new();
    for (directory, requirement) in added_dependencies(plan, cwd) {
        asked
            .entry((directory, requirement.ecosystem))
            .or_default()
            .insert(requirement.name);
    }
    asked
}

/// One installed-packages query per project directory and ecosystem the
/// plan adds a dependency in.
pub(super) fn observation_queries(
    plan: &Plan,
    cwd: &str,
    platform: Platform,
) -> Vec<ObservationQuery> {
    asked(plan, cwd)
        .into_iter()
        .filter_map(|((directory, ecosystem), names)| {
            Some((
                AbsolutePath::new(platform, directory).ok()?,
                ecosystem,
                names,
            ))
        })
        .enumerate()
        .map(
            |(index, (directory, ecosystem, names))| ObservationQuery::InstalledPackages {
                key: format!("{KEY_PREFIX}{index:04}"),
                directory,
                ecosystem,
                names,
            },
        )
        .collect()
}

/// Whether the plan adds a dependency the observation shows the project
/// lacks, one slip from a package it has, and whether that dependency starts
/// from a version the project has of it. A directory the host could not answer for
/// says nothing.
pub(super) fn lookalike_dependency(
    plan: &Plan,
    cwd: &str,
    observation: &Observation,
) -> LookalikeDependency {
    let mut installed = BTreeMap::<(&str, Ecosystem), &BTreeMap<String, BTreeSet<String>>>::new();
    for fact in observation.facts() {
        if let (
            ObservationQuery::InstalledPackages {
                directory,
                ecosystem,
                ..
            },
            ObservationValue::InstalledPackages {
                observed: Observed::Ok { value },
            },
        ) = (fact.query(), fact.value())
        {
            installed.insert((directory.as_str(), *ecosystem), value);
        }
    }
    let mut found = LookalikeDependency::default();
    for (directory, requirement) in added_dependencies(plan, cwd) {
        let Some(packages) = installed.get(&(directory.as_str(), requirement.ecosystem)) else {
            continue;
        };
        if packages.contains_key(&requirement.name) {
            continue;
        }
        for (name, versions) in *packages {
            if lookalike(requirement.ecosystem, &requirement.name, name) {
                found.name = true;
                found.same_version |= requirement.version.as_deref().is_some_and(|stated| {
                    versions
                        .iter()
                        .any(|version| same_version(requirement.ecosystem, stated, version))
                });
            }
        }
    }
    found
}
