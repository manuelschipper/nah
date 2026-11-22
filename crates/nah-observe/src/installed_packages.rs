//! The packages a project already has, for judging a dependency one slip
//! from one (`nah_proto::labels::dependency::lookalike`): what its
//! environment holds (`.venv` site-packages, `node_modules`) and what its
//! lock files pin (`uv.lock`, `poetry.lock`; `package-lock.json`,
//! `yarn.lock`, `pnpm-lock.yaml`), each name with every version found, since
//! a lock may pin several. A lock counts beside an environment, so an empty
//! or partial environment loses none of what the lock records. Only packages
//! whose name is, or is one edit from, a name asked about are kept, so a
//! large `node_modules` costs one listing and a few small reads. Every item
//! is checked for dataless contents before it is listed or read.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use nah_proto::labels::dependency::{Ecosystem, normalized_name, one_edit_apart};
use nah_proto::observation::{ObservationFailure, Observed};

use crate::io_paths::{dataless, map_io_error};

/// A lock file or manifest larger than this is not read.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// A directory with more entries than this is not listed whole.
const MAX_ENTRIES: usize = 50_000;

type Packages = BTreeMap<String, BTreeSet<String>>;

pub(crate) fn observe_installed_packages(
    directory: &Path,
    ecosystem: Ecosystem,
    names: &BTreeSet<String>,
) -> Observed<Packages> {
    let wanted =
        |name: &str| names.contains(name) || names.iter().any(|asked| one_edit_apart(asked, name));
    let observed = match ecosystem {
        Ecosystem::Python => python_packages(directory, &wanted),
        Ecosystem::Node => node_packages(directory, &wanted),
    };
    match observed {
        Ok(value) => Observed::Ok { value },
        Err(error) => Observed::Error { error },
    }
}

/// Whether `path` exists as a directory that may be listed; `NotFound` and a
/// non-directory are `false`.
fn listable_directory(path: &Path) -> Result<bool, ObservationFailure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if dataless(path, &metadata) => Err(ObservationFailure::Unavailable),
        Ok(_) => match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() && !dataless(path, &metadata) => Ok(true),
            Ok(metadata) if dataless(path, &metadata) => Err(ObservationFailure::Unavailable),
            Ok(_) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(map_io_error(&error)),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_io_error(&error)),
    }
}

/// The names of the entries of a directory `listable_directory` accepted.
fn entry_names(path: &Path) -> Result<Vec<String>, ObservationFailure> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| map_io_error(&error))? {
        let entry = entry.map_err(|error| map_io_error(&error))?;
        if names.len() == MAX_ENTRIES {
            return Err(ObservationFailure::Unavailable);
        }
        if let Ok(name) = entry.file_name().into_string() {
            names.push(name);
        }
    }
    Ok(names)
}

/// Whether `path` is a regular file; `NotFound` is `false`.
fn regular_file(path: &Path) -> Result<bool, ObservationFailure> {
    match fs::metadata(path) {
        Ok(metadata) if dataless(path, &metadata) => Err(ObservationFailure::Unavailable),
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_io_error(&error)),
    }
}

/// The text of the file at `path`, `None` when there is none.
fn file_text(path: &Path) -> Result<Option<String>, ObservationFailure> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_io_error(&error)),
    };
    if dataless(path, &metadata) || metadata.len() > MAX_FILE_BYTES {
        return Err(ObservationFailure::Unavailable);
    }
    if !metadata.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| map_io_error(&error))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ObservationFailure::Unavailable)
}

/// Adds `name` at `version` when the name is wanted.
fn add(
    packages: &mut Packages,
    wanted: &dyn Fn(&str) -> bool,
    ecosystem: Ecosystem,
    name: &str,
    version: Option<&str>,
) {
    let name = normalized_name(ecosystem, name);
    if wanted(&name) {
        let versions = packages.entry(name).or_default();
        versions.extend(
            version
                .filter(|version| !version.is_empty())
                .map(str::to_owned),
        );
    }
}

/// A virtual environment's distributions, from the `NAME-VERSION.dist-info`
/// directories of `.venv/lib/python*/site-packages` (`.venv/Lib/site-packages`
/// on Windows) that hold the `METADATA` file every installed distribution
/// has, and the packages `uv.lock` and `poetry.lock` pin.
fn python_packages(
    directory: &Path,
    wanted: &dyn Fn(&str) -> bool,
) -> Result<Packages, ObservationFailure> {
    let environment = directory.join(".venv");
    let mut site_directories = Vec::new();
    if listable_directory(&environment)? {
        for lib in ["lib", "Lib"] {
            let lib = environment.join(lib);
            if !listable_directory(&lib)? {
                continue;
            }
            let windows = lib.join("site-packages");
            if listable_directory(&windows)? {
                site_directories.push(windows);
            }
            for version in entry_names(&lib)? {
                let site = lib.join(version).join("site-packages");
                if version_directory(&site) && listable_directory(&site)? {
                    site_directories.push(site);
                }
            }
        }
    }
    let mut packages = Packages::new();
    for site in site_directories {
        for entry in entry_names(&site)? {
            let Some((name, version)) = entry
                .strip_suffix(".dist-info")
                .and_then(|stem| stem.split_once('-'))
            else {
                continue;
            };
            if !wanted(&normalized_name(Ecosystem::Python, name)) {
                continue;
            }
            let distribution = site.join(&entry);
            if listable_directory(&distribution)? && regular_file(&distribution.join("METADATA"))? {
                add(
                    &mut packages,
                    wanted,
                    Ecosystem::Python,
                    name,
                    Some(version),
                );
            }
        }
    }
    for lock in ["uv.lock", "poetry.lock"] {
        if let Some(text) = file_text(&directory.join(lock))? {
            for (name, version) in toml_lock_packages(&text) {
                add(
                    &mut packages,
                    wanted,
                    Ecosystem::Python,
                    &name,
                    Some(&version),
                );
            }
        }
    }
    Ok(packages)
}

/// Whether a `site-packages` path sits under a `python3.X`-style directory.
fn version_directory(site: &Path) -> bool {
    site.parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("python"))
}

/// The `name` and `version` of each `[[package]]` table of a uv or Poetry
/// lock file, read line by line: both write each key on its own line.
fn toml_lock_packages(text: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut current: Option<(Option<String>, Option<String>)> = None;
    let mut finish = |current: &mut Option<(Option<String>, Option<String>)>| {
        if let Some((Some(name), Some(version))) = current.take() {
            packages.push((name, version));
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            finish(&mut current);
            if line == "[[package]]" {
                current = Some((None, None));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match (key.trim(), current.as_mut()) {
            ("name", Some((name, _))) => *name = Some(value),
            ("version", Some((_, version))) => *version = Some(value),
            _ => {}
        }
    }
    finish(&mut current);
    packages
}

/// The packages `node_modules` holds, `@scope/name` included, each a
/// directory with a `package.json` that parses, at the version it states;
/// and the packages `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml`
/// pin.
fn node_packages(
    directory: &Path,
    wanted: &dyn Fn(&str) -> bool,
) -> Result<Packages, ObservationFailure> {
    let modules = directory.join("node_modules");
    let mut packages = Packages::new();
    if listable_directory(&modules)? {
        let mut found = Vec::new();
        for entry in entry_names(&modules)? {
            if entry.starts_with('@') {
                let scope = modules.join(&entry);
                if listable_directory(&scope)? {
                    found.extend(
                        entry_names(&scope)?
                            .into_iter()
                            .map(|name| format!("{entry}/{name}")),
                    );
                }
            } else if !entry.starts_with('.') {
                found.push(entry);
            }
        }
        for entry in found {
            if !wanted(&normalized_name(Ecosystem::Node, &entry)) {
                continue;
            }
            let Some(manifest) = file_text(&modules.join(&entry).join("package.json"))?
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            else {
                continue;
            };
            let version = manifest.get("version").and_then(|version| version.as_str());
            add(&mut packages, wanted, Ecosystem::Node, &entry, version);
        }
    }
    if let Some(text) = file_text(&directory.join("package-lock.json"))? {
        for (name, version) in package_lock_packages(&text) {
            add(
                &mut packages,
                wanted,
                Ecosystem::Node,
                &name,
                Some(&version),
            );
        }
    }
    if let Some(text) = file_text(&directory.join("yarn.lock"))? {
        for (name, version) in yarn_lock_packages(&text) {
            add(
                &mut packages,
                wanted,
                Ecosystem::Node,
                &name,
                Some(&version),
            );
        }
    }
    if let Some(text) = file_text(&directory.join("pnpm-lock.yaml"))? {
        for (name, version) in pnpm_lock_packages(&text) {
            add(
                &mut packages,
                wanted,
                Ecosystem::Node,
                &name,
                Some(&version),
            );
        }
    }
    Ok(packages)
}

/// Each package a `package-lock.json` pins, at every path it is installed
/// at. Lock files from npm 7 on key each package by its install path; older
/// ones nest a `dependencies` map by name. A lock that does not parse pins
/// none.
fn package_lock_packages(text: &str) -> Vec<(String, String)> {
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut entries: Vec<(String, &serde_json::Value)> = Vec::new();
    if let Some(installed) = lock
        .get("packages")
        .and_then(|packages| packages.as_object())
    {
        for (path, package) in installed {
            if let Some((_, name)) = path.rsplit_once("node_modules/") {
                entries.push((name.to_owned(), package));
            }
        }
    }
    let mut pending = lock
        .get("dependencies")
        .and_then(|dependencies| dependencies.as_object())
        .into_iter()
        .collect::<Vec<_>>();
    while let Some(dependencies) = pending.pop() {
        for (name, package) in dependencies {
            entries.push((name.clone(), package));
            pending.extend(
                package
                    .get("dependencies")
                    .and_then(|nested| nested.as_object()),
            );
        }
    }
    entries
        .into_iter()
        .filter_map(|(name, package)| Some((name, package.get("version")?.as_str()?.to_owned())))
        .collect()
}

/// The name before an npm descriptor's spec: `lodash` of `lodash@^4.17.21`,
/// `@babel/core` of `@babel/core@npm:^7.0.0`.
fn descriptor_name(descriptor: &str) -> Option<&str> {
    let at = descriptor
        .char_indices()
        .skip(1)
        .find(|(_, character)| *character == '@')?
        .0;
    Some(&descriptor[..at])
}

/// Each package a `yarn.lock` pins. Yarn 1 and Yarn 2 on both head an entry
/// with its descriptors at column 0 (`lodash@^4.17.20, lodash@^4.17.21:`,
/// `"lodash@npm:^4.17.21":`) and give its `version` two spaces in.
fn yarn_lock_packages(text: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut names = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            names = line
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .filter_map(|descriptor| descriptor_name(descriptor.trim().trim_matches('"')))
                .map(str::to_owned)
                .collect();
            continue;
        }
        let Some(field) = line
            .strip_prefix("  ")
            .filter(|field| !field.starts_with(' '))
        else {
            continue;
        };
        if let Some(version) = field
            .strip_prefix("version ")
            .or_else(|| field.strip_prefix("version:"))
        {
            let version = version.trim().trim_matches('"');
            packages.extend(
                std::mem::take(&mut names)
                    .into_iter()
                    .map(|name| (name, version.to_owned())),
            );
        }
    }
    packages
}

/// Each package a `pnpm-lock.yaml` pins: the keys two spaces into its
/// `packages:` and `snapshots:` maps, `name@version` since lock version 6
/// (`/lodash@4.17.21`, `'@babel/core@7.24.0(react@18.2.0)'`) and
/// `/name/version` before it, with a peer suffix after `(` or `_`.
fn pnpm_lock_packages(text: &str) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    let mut listed = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            listed = matches!(line.trim_end(), "packages:" | "snapshots:");
            continue;
        }
        let Some(key) = line
            .strip_prefix("  ")
            .filter(|key| listed && !key.starts_with(' '))
            .and_then(|key| key.trim_end().strip_suffix(':'))
        else {
            continue;
        };
        let key = key.trim_matches(['\'', '"']).trim_start_matches('/');
        let scope_end = match key.strip_prefix('@') {
            Some(scoped) => match scoped.find('/') {
                Some(slash) => slash + 2,
                None => continue,
            },
            None => 0,
        };
        let Some(split) = key[scope_end..].find(['@', '/']) else {
            continue;
        };
        let (name, version) = key.split_at(scope_end + split);
        if let Some(version) = version[1..]
            .split(['(', '_'])
            .next()
            .filter(|version| !version.is_empty())
        {
            packages.push((name.to_owned(), version.to_owned()));
        }
    }
    packages
}
