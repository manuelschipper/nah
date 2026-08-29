#![cfg(windows)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;

use nah_extensions::discover_bundles;
use nah_proto::ctx::{AbsolutePath, Platform, TrustProjection};

fn home(path: &std::path::Path) -> AbsolutePath {
    AbsolutePath::new(Platform::Windows, path.to_str().unwrap()).unwrap()
}

fn write_manifest(directory: &std::path::Path, data: Option<&str>) {
    fs::write(
        directory.join("policy.toml"),
        format!(
            "name = \"tool\"\nmatch = [\"tool\"]\nprotocol = \"exec/v1\"\nprovenance = \"user\"\n{}",
            data.unwrap_or_default()
        ),
    )
    .unwrap();
}

#[test]
fn windows_selects_one_entrypoint_and_covers_cross_platform_entrypoints() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".nah/guards/tool");
    fs::create_dir_all(&directory).unwrap();
    write_manifest(&directory, None);
    fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::write(directory.join("run.cmd"), "@echo off\r\nexit /b 0\r\n").unwrap();

    let trust = TrustProjection::new(vec![]).unwrap();
    let before = discover_bundles(&home(temp.path()), Platform::Windows, &trust, &[])
        .unwrap()
        .0
        .remove(0);
    assert_eq!(before.run(), directory.join("run.cmd"));
    assert_eq!(before.covered_files(), ["policy.toml", "run", "run.cmd"]);

    fs::write(directory.join("run"), "#!/bin/sh\necho changed\n").unwrap();
    let after = discover_bundles(&home(temp.path()), Platform::Windows, &trust, &[])
        .unwrap()
        .0
        .remove(0);
    assert_ne!(
        before.projection().bundle_hash(),
        after.projection().bundle_hash()
    );
}

#[test]
fn windows_missing_or_ambiguous_entrypoints_are_inactive() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".nah/guards/tool");
    fs::create_dir_all(&directory).unwrap();
    write_manifest(&directory, None);
    let trust = TrustProjection::new(vec![]).unwrap();

    let (missing, warnings) =
        discover_bundles(&home(temp.path()), Platform::Windows, &trust, &[]).unwrap();
    assert!(missing.is_empty());
    assert!(
        warnings
            .iter()
            .any(|warning| warning.ends_with("missing-policy-bundle-file"))
    );

    fs::write(directory.join("run.cmd"), "@echo off\r\n").unwrap();
    fs::write(directory.join("run.bat"), "@echo off\r\n").unwrap();
    let (ambiguous, warnings) =
        discover_bundles(&home(temp.path()), Platform::Windows, &trust, &[]).unwrap();
    assert!(ambiguous.is_empty());
    assert!(
        warnings
            .iter()
            .any(|warning| warning.ends_with("invalid-policy-manifest"))
    );
}

#[test]
fn windows_entrypoint_names_cannot_be_declared_as_data() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join(".nah/guards/tool");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("run.cmd"), "@echo off\r\n").unwrap();
    let trust = TrustProjection::new(vec![]).unwrap();

    for name in ["run", "run.exe", "run.cmd", "run.bat"] {
        write_manifest(&directory, Some(&format!("data = [\"{name}\"]\n")));
        let (bundles, warnings) =
            discover_bundles(&home(temp.path()), Platform::Windows, &trust, &[]).unwrap();
        assert!(bundles.is_empty(), "{name}");
        assert!(
            warnings
                .iter()
                .any(|warning| warning.ends_with("invalid-policy-manifest")),
            "{name}: {warnings:?}"
        );
    }
}
