//! Model directory I/O: reading and writing model documents and fixtures, the
//! canonical JSON form they are written in, and the sorted list of every JSON
//! path under a model directory.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::FactoryError;

pub(crate) fn read(path: &Path) -> Result<String, FactoryError> {
    fs::read_to_string(path).map_err(|error| FactoryError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

pub(crate) fn write(path: &Path, bytes: &[u8]) -> Result<(), FactoryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| FactoryError::Io {
            path: parent.to_path_buf(),
            detail: error.to_string(),
        })?;
    }
    fs::write(path, bytes).map_err(|error| FactoryError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })
}

pub(crate) fn pretty_model_json<T: serde::Serialize>(value: &T) -> Result<String, FactoryError> {
    let mut output = serde_json::to_string_pretty(value)
        .map_err(|error| FactoryError::Json(error.to_string()))?;
    output.push('\n');
    Ok(output)
}

/// Every `.json` file under `directory`, recursively, as sorted slash-separated
/// paths relative to it. No document is read or schema-checked here: callers parse
/// each one as a promoted model document, so any other JSON in the tree (a
/// fixture or candidate, say) makes them fail rather than being skipped.
pub(crate) fn model_json_paths(directory: &Path) -> Result<BTreeSet<String>, FactoryError> {
    let mut paths = BTreeSet::new();
    collect_json(directory, directory, &mut paths)?;
    Ok(paths)
}

fn collect_json(
    root: &Path,
    directory: &Path,
    paths: &mut BTreeSet<String>,
) -> Result<(), FactoryError> {
    let entries = fs::read_dir(directory).map_err(|error| FactoryError::Io {
        path: directory.to_path_buf(),
        detail: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| FactoryError::Io {
            path: directory.to_path_buf(),
            detail: error.to_string(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_json(root, &path, paths)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
            let relative = path.strip_prefix(root).unwrap();
            paths.insert(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}
