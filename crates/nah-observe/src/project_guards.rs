//! Loads the bounded project guard declaration for an observed project root.

use nah_proto::observation::{
    BindingError, Observed, ProjectGuardDeclaration, ProjectGuardObservation, Root, RootKind,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

const PROJECT_GUARDS_MAX_BYTES: u64 = 16 * 1024;

pub(crate) fn observe_project_guards(
    roots: &Observed<Vec<Root>>,
) -> Result<ProjectGuardObservation, BindingError> {
    let Observed::Ok { value: roots } = roots else {
        return ProjectGuardObservation::new(None, ProjectGuardDeclaration::ReadFailure);
    };
    let Some(project) = roots.iter().find(|root| root.kind() == RootKind::Project) else {
        return ProjectGuardObservation::new(None, ProjectGuardDeclaration::Absent);
    };
    let path = Path::new(project.path().as_str()).join(".nah/project.toml");
    let declaration = read_project_guards(&path);
    ProjectGuardObservation::new(Some(project.clone()), declaration)
}

fn read_project_guards(path: &Path) -> ProjectGuardDeclaration {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ProjectGuardDeclaration::Absent;
        }
        Err(_) => return ProjectGuardDeclaration::ReadFailure,
    };
    if !metadata.file_type().is_file() || metadata.len() > PROJECT_GUARDS_MAX_BYTES {
        return ProjectGuardDeclaration::ReadFailure;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let read = fs::File::open(path).and_then(|file| {
        file.take(PROJECT_GUARDS_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
    });
    if read.is_err() || bytes.len() as u64 > PROJECT_GUARDS_MAX_BYTES {
        return ProjectGuardDeclaration::ReadFailure;
    }
    match String::from_utf8(bytes) {
        Ok(text) => parse_project_guards(&text),
        Err(_) => ProjectGuardDeclaration::Malformed,
    }
}

fn parse_project_guards(text: &str) -> ProjectGuardDeclaration {
    let Ok(table) = text.parse::<toml::Table>() else {
        return ProjectGuardDeclaration::Malformed;
    };
    if table.len() != 1 {
        return ProjectGuardDeclaration::Malformed;
    }
    let Some(values) = table.get("enable-guards").and_then(toml::Value::as_array) else {
        return ProjectGuardDeclaration::Malformed;
    };
    let mut names = Vec::with_capacity(values.len());
    let mut unique = BTreeSet::new();
    for value in values {
        let Some(name) = value.as_str() else {
            return ProjectGuardDeclaration::Malformed;
        };
        if name.is_empty() || !unique.insert(name) {
            return ProjectGuardDeclaration::Malformed;
        }
        names.push(name.to_owned());
    }
    ProjectGuardDeclaration::Present { names }
}
