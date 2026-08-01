//! Creates the minimal external-extension template; it does not enable the generated extension.

use std::error::Error;
use std::fmt;
use std::fs;

use nah_proto::ctx::{AbsolutePath, GuardIdentity, Platform};

use crate::bundle::guard_directory_path;

pub fn create_user_guard(
    home: &AbsolutePath,
    platform: Platform,
    name: &str,
) -> Result<std::path::PathBuf, TemplateError> {
    validate_name(name)?;
    create_guard_in(&guard_directory_path(home, platform), name, "user")
}

pub fn create_project_guard(
    root: &AbsolutePath,
    name: &str,
) -> Result<std::path::PathBuf, TemplateError> {
    validate_name(name)?;
    let nah = std::path::Path::new(root.as_str()).join(".nah");
    ensure_directory(&nah)?;
    let guards = nah.join("guards");
    ensure_directory(&guards)?;
    create_guard_in(&guards, name, "agent")
}

fn create_guard_in(
    parent: &std::path::Path,
    name: &str,
    provenance: &str,
) -> Result<std::path::PathBuf, TemplateError> {
    let directory = parent.join(name);
    if fs::symlink_metadata(&directory).is_ok() {
        return Err(TemplateError::AlreadyExists);
    }
    fs::create_dir_all(parent).map_err(|_| TemplateError::Io)?;
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(TemplateError::AlreadyExists);
        }
        Err(_) => return Err(TemplateError::Io),
    }
    let manifest = format!(
        "name = \"{name}\"\nmatch = [\"{name}\"]\nprotocol = \"exec/v1\"\nprovenance = \"{provenance}\"\n"
    );
    fs::write(directory.join("policy.toml"), manifest).map_err(|_| TemplateError::Io)?;
    let outcome = format!(
        r#"if argv == [{name:?}, "destroy", "--all"]:
        response = {{"block": True, "reason": "blocked the exact example command"}}
        break"#
    );
    let run = format!(
        r#"#!/usr/bin/env python3
import json
import sys

request = json.load(sys.stdin)
effects = request["action_stream"]["effects"]
response = {{"abstain": True}}
for effect in effects:
    invocation = effect["kind"].get("invocation")
    if not invocation or invocation.get("program") != {name:?}:
        continue
    input = invocation.get("input", {{}})
    argv = input.get("argv") if input.get("kind") == "shell" else None
    {outcome}
print(json.dumps(response))
"#
    );
    let run_path = directory.join("run");
    fs::write(&run_path, run).map_err(|_| TemplateError::Io)?;
    make_executable(&run_path)?;
    fs::write(
        directory.join("README.md"),
        format!(
            "# {name}\n\nExample `guard` extension. Review `run` and `nah docs extending` before asking a human to activate it.\n"
        ),
    )
    .map_err(|_| TemplateError::Io)?;
    Ok(directory)
}

fn ensure_directory(path: &std::path::Path) -> Result<(), TemplateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(TemplateError::UnsafePath),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(TemplateError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| TemplateError::Io)
        }
        Err(_) => Err(TemplateError::Io),
    }
}

fn validate_name(name: &str) -> Result<(), TemplateError> {
    GuardIdentity::user(name)
        .map(|_| ())
        .map_err(|_| TemplateError::InvalidName)
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) -> Result<(), TemplateError> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|_| TemplateError::Io)?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).map_err(|_| TemplateError::Io)
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) -> Result<(), TemplateError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateError {
    AlreadyExists,
    InvalidName,
    Io,
    UnsafePath,
}

impl TemplateError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AlreadyExists => "policy-already-exists",
            Self::InvalidName => "invalid-policy-name",
            Self::Io => "policy-template-io-failed",
            Self::UnsafePath => "guard-template-symlink-unsupported",
        }
    }
}

impl fmt::Display for TemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for TemplateError {}
