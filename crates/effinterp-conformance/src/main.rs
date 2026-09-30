// Conformance runner: reads case files and reports on stderr.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn json_files(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            json_files(&entry?.path(), files)?;
        }
    } else if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
        files.push(path.to_path_buf());
    }
    Ok(())
}

fn main() -> ExitCode {
    let Some(root) = env::args_os().nth(1) else {
        eprintln!("usage: effinterp-conformance FIXTURE_DIRECTORY");
        return ExitCode::from(2);
    };
    if env::args_os().nth(2).is_some() {
        eprintln!("usage: effinterp-conformance FIXTURE_DIRECTORY");
        return ExitCode::from(2);
    }
    let mut files = Vec::new();
    if let Err(failure) = json_files(Path::new(&root), &mut files) {
        eprintln!("{}: {failure}", Path::new(&root).display());
        return ExitCode::from(2);
    }
    files.sort();
    if files.is_empty() {
        eprintln!("{}: no JSON fixtures", Path::new(&root).display());
        return ExitCode::from(1);
    }
    let mut failed = false;
    for path in files {
        let invalid = path.components().any(|part| part.as_os_str() == "invalid");
        let result = fs::read(&path)
            .map_err(|failure| failure.to_string())
            .and_then(|bytes| {
                effinterp_conformance::validate_conformance_bytes(&bytes)
                    .map_err(|failure| failure.to_string())
            });
        match (invalid, result) {
            (false, Ok(())) | (true, Err(_)) => {}
            (false, Err(failure)) => {
                failed = true;
                eprintln!("{}: {failure}", path.display());
            }
            (true, Ok(())) => {
                failed = true;
                eprintln!("{}: invalid fixture was accepted", path.display());
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
