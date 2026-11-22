//! Dependencies a call adds, and whether one is a lookalike: a package one
//! typing slip from a package the project already has. The bridge reads what
//! a call adds (an install's operands, a manifest's written text), the host
//! observation lists what the project has installed, and
//! `untrusted-code/lookalike-package` judges the two with [`lookalike`].

use serde::{Deserialize, Serialize};

/// The package ecosystems whose manifests and installs are read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    /// PyPI packages: pip, `requirements*.txt` and `pyproject.toml`.
    Python,
    /// npm registry packages: npm, pnpm, Yarn and Bun, and `package.json`.
    Node,
}

impl Ecosystem {
    /// The ecosystem an install effect's `package_ecosystem` attribute names.
    pub fn from_attribute(value: &str) -> Option<Self> {
        match value {
            "pypi" => Some(Self::Python),
            "npm" => Some(Self::Node),
            _ => None,
        }
    }
}

/// A dependency a call names: its normalized name and the version it starts
/// from, when it names one: its exact pin, or the lower bound of its range
/// (`>=`, PyPI's `~=`, and npm's and Poetry's `^` and `~`).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Requirement {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
}

/// A package name as its registry compares names: PyPI folds case and treats
/// runs of `-`, `_` and `.` as one `-` (PEP 503); npm names are lowercase.
pub fn normalized_name(ecosystem: Ecosystem, name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match ecosystem {
        Ecosystem::Node => lower,
        Ecosystem::Python => {
            let mut out = String::with_capacity(lower.len());
            for character in lower.chars() {
                if matches!(character, '-' | '_' | '.') {
                    if !out.ends_with('-') {
                        out.push('-');
                    }
                } else {
                    out.push(character);
                }
            }
            out
        }
    }
}

/// Whether two spellings name one release. PyPI compares versions as PEP 440
/// does, ignoring case, a leading `v` and trailing zero release segments
/// (`3.8.3` and `3.8.3.0`); npm compares them exactly after a leading `v`.
pub fn same_version(ecosystem: Ecosystem, a: &str, b: &str) -> bool {
    match ecosystem {
        Ecosystem::Node => a.trim_start_matches('v') == b.trim_start_matches('v'),
        Ecosystem::Python => pep440_release(a) == pep440_release(b),
    }
}

/// A PyPI version's release numbers without trailing zeros, and the rest.
fn pep440_release(version: &str) -> (Vec<u64>, String) {
    let lower = version.trim().to_ascii_lowercase();
    let lower = lower.strip_prefix('v').unwrap_or(&lower);
    let end = lower
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(lower.len());
    let (release, rest) = lower.split_at(end);
    let mut numbers = release
        .split('.')
        .filter(|number| !number.is_empty())
        .map(|number| number.parse().unwrap_or(u64::MAX))
        .collect::<Vec<u64>>();
    while numbers.len() > 1 && numbers.last() == Some(&0) {
        numbers.pop();
    }
    (numbers, rest.to_owned())
}

/// Whether `a` and `b` differ by exactly one insertion, deletion,
/// substitution or swap of two adjacent characters: the slips a typist makes.
pub fn one_edit_apart(a: &str, b: &str) -> bool {
    let (a, b) = (a.chars().collect::<Vec<_>>(), b.chars().collect::<Vec<_>>());
    if a == b || a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[prefix..], &b[prefix..]);
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Less => a == &b[1..],
        std::cmp::Ordering::Greater => &a[1..] == b,
        std::cmp::Ordering::Equal => {
            a[1..] == b[1..] || (a.len() >= 2 && a[0] == b[1] && a[1] == b[0] && a[2..] == b[2..])
        }
    }
}

/// A name segment shorter than this is left out of [`lookalike`]: short
/// segments sit one edit from many real names (`ms`, `qs` and `ws`; `tox`
/// and `nox`; `mypy-boto3-sqs` and `mypy-boto3-sns`).
const MIN_SEGMENT_CHARS: usize = 5;

/// Whether `requested`, a dependency the project does not have, is one slip
/// away from `installed`, a package it has. Both are [`normalized_name`]s.
/// Pairs of real packages that ordinarily sit one edit apart are left out:
///
/// - two names in one npm scope, which only the scope's owner can publish
///   (`@types/ms` and `@types/qs`, `@aws-sdk/client-sso` and `-ssm`);
/// - an edit within a name segment of fewer than [`MIN_SEGMENT_CHARS`]
///   characters, segments being split at `-`, `_`, `.` and `/`;
/// - names that differ only in a segment's trailing digits, as a major
///   version or a build variant does (`boto` and `boto3`, `psycopg` and
///   `psycopg2`, `nvidia-nccl-cu12` and `-cu13`).
///
/// A companion that adds a whole word, such as `types-requests` or
/// `requests-stubs`, is more than one edit away.
pub fn lookalike(ecosystem: Ecosystem, requested: &str, installed: &str) -> bool {
    if requested == installed || !one_edit_apart(requested, installed) {
        return false;
    }
    if ecosystem == Ecosystem::Node
        && let (Some(a), Some(b)) = (npm_scope(requested), npm_scope(installed))
        && a == b
    {
        return false;
    }
    let split = |name: &str| {
        name.trim_start_matches('@')
            .split(['-', '_', '.', '/'])
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let (a, b) = (split(requested), split(installed));
    if a.len() == b.len() {
        let mut differing = a.iter().zip(&b).filter(|(x, y)| x != y);
        if let (Some((x, y)), None) = (differing.next(), differing.next()) {
            let digitless = |segment: &str| {
                segment
                    .trim_end_matches(|character: char| character.is_ascii_digit())
                    .to_owned()
            };
            if x.chars().count().min(y.chars().count()) < MIN_SEGMENT_CHARS
                || digitless(x) == digitless(y)
            {
                return false;
            }
        }
    }
    true
}

/// The scope of a scoped npm name (`@babel` of `@babel/core`).
fn npm_scope(name: &str) -> Option<&str> {
    name.starts_with('@')
        .then(|| name.split_once('/').map(|(scope, _)| scope))
        .flatten()
}

/// A file whose text names a project's dependencies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Manifest {
    /// pip's `requirements*.txt` or pip-tools' `requirements*.in`.
    Requirements,
    /// A Python project's `pyproject.toml`.
    PyProject,
    /// An npm package's `package.json`.
    PackageJson,
}

impl Manifest {
    /// The manifest a path's file name makes it, if any.
    pub fn of_path(path: &str) -> Option<Self> {
        let name = path.rsplit(['/', '\\']).next().unwrap_or_default();
        if name == "pyproject.toml" {
            Some(Self::PyProject)
        } else if name == "package.json" {
            Some(Self::PackageJson)
        } else if name.starts_with("requirements")
            && (name.ends_with(".txt") || name.ends_with(".in"))
        {
            Some(Self::Requirements)
        } else {
            None
        }
    }

    /// The dependencies `content`, written to this manifest, names. `whole`
    /// says the content is the whole file the write leaves; otherwise it is
    /// a fragment, such as an append or an edit's replacement text. Every
    /// requirements line is a requirement wherever it sits, but where a
    /// fragment of `pyproject.toml` or `package.json` sits is unknown, so it
    /// names none.
    pub fn requirements(self, content: &str, whole: bool) -> Vec<Requirement> {
        match self {
            Self::Requirements => requirements_lines(content),
            _ if !whole => Vec::new(),
            Self::PyProject => pyproject_requirements(content),
            Self::PackageJson => package_json_requirements(content),
        }
    }
}

/// The requirement an install operand names: pip's `name[extras]==1.2` or
/// npm's `name@1.2.3` and `@scope/name@^1.2.3`. Paths, URLs, archives, VCS
/// and alias specs name no registry package and give `None`.
pub fn install_operand(ecosystem: Ecosystem, operand: &str) -> Option<Requirement> {
    match ecosystem {
        Ecosystem::Python => pip_requirement(operand),
        Ecosystem::Node => npm_operand(operand),
    }
}

/// One PEP 508 requirement, as a requirements line or a `pyproject.toml`
/// string spells it, its specifiers bare or in parentheses
/// (`name (==1.2)`). Its version is the first `===`, `==`, `~=` or `>=`
/// clause's.
fn pip_requirement(text: &str) -> Option<Requirement> {
    let text = text.trim();
    let end = text
        .find(|character: char| !(character.is_ascii_alphanumeric() || "._-".contains(character)))
        .unwrap_or(text.len());
    let (name, rest) = text.split_at(end);
    if name.is_empty()
        || !name.starts_with(|character: char| character.is_ascii_alphanumeric())
        || !name.ends_with(|character: char| character.is_ascii_alphanumeric())
        || [".whl", ".zip", ".tar.gz", ".tgz"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
    {
        return None;
    }
    let mut rest = rest.trim_start();
    if let Some(extras) = rest.strip_prefix('[') {
        rest = extras.split_once(']')?.1.trim_start();
    }
    // A path or URL operand, or a direct reference (`name @ URL`), installs
    // no registry release of that name.
    if rest.starts_with(['/', '\\', ':', '@']) {
        return None;
    }
    let specifiers = rest.split(';').next().unwrap_or_default().trim_start();
    // Anything but a version specifier or a trailing option (`--hash=…`)
    // after the name is not a requirement, as in prose.
    if !(specifiers.is_empty() || specifiers.starts_with(['=', '<', '>', '!', '~', '(', '-'])) {
        return None;
    }
    let specifiers = match specifiers.strip_prefix('(') {
        Some(enclosed) => enclosed.split_once(')')?.0,
        None => specifiers,
    };
    let version = specifiers.split(',').find_map(|specifier| {
        let specifier = specifier.trim();
        let floor = ["===", "==", "~=", ">="]
            .iter()
            .find_map(|operator| specifier.strip_prefix(operator))?
            .split_whitespace()
            .next()?;
        (!floor.contains('*')).then(|| floor.to_owned())
    });
    Some(Requirement {
        ecosystem: Ecosystem::Python,
        name: normalized_name(Ecosystem::Python, name),
        version,
    })
}

/// The requirements of a requirements file: one per line, after joining `\`
/// continuations and dropping comments. Option lines (`-r`, `-e`, `--hash`)
/// name no registry requirement.
fn requirements_lines(content: &str) -> Vec<Requirement> {
    content
        .replace("\\\r\n", " ")
        .replace("\\\n", " ")
        .lines()
        .filter_map(|line| {
            let line = match line.find(" #").or_else(|| line.find("\t#")) {
                Some(comment) => &line[..comment],
                None => line,
            };
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', '-']) {
                return None;
            }
            pip_requirement(line)
        })
        .collect()
}

/// The version an npm spec starts from: a plain `1.2.3`, alone or after
/// `=`, `v`, `^`, `~` or `>=`, as the first bound of a range. A union of
/// ranges (`||`), a wildcard or a dist-tag starts from none.
fn npm_spec_version(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.contains("||") {
        return None;
    }
    let version = [">=", "^", "~", "="]
        .iter()
        .find_map(|operator| spec.strip_prefix(operator))
        .unwrap_or(spec)
        .split_whitespace()
        .next()?
        .trim_start_matches('v');
    let (core, suffix) = match version.find(['-', '+']) {
        Some(split) => version.split_at(split),
        None => (version, ""),
    };
    let numbers = core.split('.').collect::<Vec<_>>();
    (numbers.len() == 3
        && numbers
            .iter()
            .all(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-+.".contains(&byte)))
    .then(|| version.to_owned())
}

/// Whether an npm spec selects a registry release, rather than a path, URL,
/// Git repository, workspace link or alias (`npm:other@1`).
fn npm_registry_spec(spec: &str) -> bool {
    !spec.contains([':', '/'])
}

/// A valid npm package name, scoped or not.
fn npm_name(name: &str) -> bool {
    let bare = match name.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, bare)) if !scope.is_empty() => bare,
            _ => return false,
        },
        None => name,
    };
    !bare.is_empty()
        && !bare.starts_with(['.', '_'])
        && bare
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
}

fn npm_operand(operand: &str) -> Option<Requirement> {
    let operand = operand.trim();
    // A scoped name's own `@` opens it; the next one starts the spec.
    match operand
        .char_indices()
        .skip(1)
        .find(|(_, character)| *character == '@')
    {
        Some((at, _)) => npm_dependency(&operand[..at], &operand[at + 1..]),
        None => npm_dependency(operand, ""),
    }
}

fn npm_dependency(name: &str, spec: &str) -> Option<Requirement> {
    (npm_name(name) && npm_registry_spec(spec)).then(|| Requirement {
        ecosystem: Ecosystem::Node,
        name: normalized_name(Ecosystem::Node, name),
        version: npm_spec_version(spec),
    })
}

/// The entries of a `package.json`'s dependency tables. A file that does not
/// parse names none: npm refuses it too.
fn package_json_requirements(content: &str) -> Vec<Requirement> {
    const TABLES: &[&str] = &[
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    let Ok(serde_json::Value::Object(manifest)) = serde_json::from_str(content) else {
        return Vec::new();
    };
    TABLES
        .iter()
        .filter_map(|table| manifest.get(*table)?.as_object())
        .flatten()
        .filter_map(|(name, spec)| npm_dependency(name, spec.as_str()?))
        .collect()
}

/// The dependencies a `pyproject.toml` declares: the PEP 508 strings of
/// `project.dependencies`, of each `project.optional-dependencies` and
/// `dependency-groups` list, and of `build-system.requires`, which a build
/// frontend installs before it builds; and Poetry's dependency tables, whose
/// keys are names and whose values are version strings or tables with a
/// `version`. A file that does not parse names none: no tool reads it.
fn pyproject_requirements(content: &str) -> Vec<Requirement> {
    let Ok(document) = content.parse::<toml::Table>() else {
        return Vec::new();
    };
    let table = |path: &[&str]| {
        path.iter()
            .try_fold(&document, |table, key| table.get(*key)?.as_table())
    };
    let strings = |value: &toml::Value| {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .filter_map(pip_requirement)
            .collect::<Vec<_>>()
    };
    let mut found = Vec::new();
    for (path, key) in [
        (["project"], "dependencies"),
        (["build-system"], "requires"),
    ] {
        if let Some(value) = table(&path).and_then(|table| table.get(key)) {
            found.extend(strings(value));
        }
    }
    for lists in [
        table(&["project", "optional-dependencies"]),
        table(&["dependency-groups"]),
    ]
    .into_iter()
    .flatten()
    {
        found.extend(lists.values().flat_map(strings));
    }
    let poetry = table(&["tool", "poetry"]);
    let groups = poetry
        .and_then(|poetry| poetry.get("group")?.as_table())
        .into_iter()
        .flat_map(|groups| groups.values())
        .filter_map(|group| group.get("dependencies")?.as_table());
    let poetry_tables = ["dependencies", "dev-dependencies"]
        .iter()
        .filter_map(|key| poetry?.get(*key)?.as_table())
        .chain(groups);
    for (name, value) in poetry_tables.flatten() {
        if name != "python" {
            found.extend(poetry_dependency(name, value));
        }
    }
    found
}

/// A Poetry dependency entry: `name = "^1.2"` or `name = { version = "1.2" }`.
/// Its first constraint's `^`, `~`, `~=`, `=`, `==` and `>=` keep the version
/// they start from; an entry with no version string (a path or Git
/// dependency) names none.
fn poetry_dependency(name: &str, value: &toml::Value) -> Option<Requirement> {
    let spec = match value {
        toml::Value::String(spec) => spec.as_str(),
        toml::Value::Table(table) => table.get("version")?.as_str()?,
        _ => return None,
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return None;
    }
    let first = spec.split(',').next().unwrap_or_default().trim();
    let version = [">=", "==", "~=", "^", "~", "="]
        .iter()
        .find_map(|operator| first.strip_prefix(operator))
        .unwrap_or(first)
        .trim();
    Some(Requirement {
        ecosystem: Ecosystem::Python,
        name: normalized_name(Ecosystem::Python, name),
        version: (!version.is_empty()
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.'))
        .then(|| version.to_owned()),
    })
}
