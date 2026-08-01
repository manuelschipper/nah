#![cfg(unix)]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::fs;
use std::path::Path;

use nah_extensions::{
    ActivationDatabase, BundleError, activation_database_path, discover_bundles,
    load_active_extensions,
};
use nah_proto::ctx::{Platform, TrustProjection, TrustedRoot, TrustedRootId};

use support::{Fixture, absolute, make_executable, write_manifest};

#[test]
fn bundle_drift_deactivates_and_identity_collisions_stay_local() {
    let fixture = Fixture::shell(
        "drift",
        "printf '%s\\n' '{\"block\":true,\"reason\":\"before\"}'",
    );
    fs::write(
        &fixture.run,
        "#!/bin/sh\nprintf '%s\\n' '{\"block\":true,\"reason\":\"after\"}'\n",
    )
    .unwrap();
    make_executable(&fixture.run);
    let trust = TrustProjection::new(vec![]).unwrap();
    let database =
        ActivationDatabase::load(&activation_database_path(&fixture.home, Platform::Linux))
            .unwrap();
    let reloaded =
        load_active_extensions(&fixture.home, Platform::Linux, &trust, &database, &[]).unwrap();
    assert!(reloaded.extensions().is_empty());
    assert!(
        reloaded
            .warnings()
            .iter()
            .any(|warning| warning.contains("bytes have changed"))
    );

    let other = Path::new(fixture.home.as_str()).join(".nah/guards/other-folder");
    fs::create_dir_all(&other).unwrap();
    write_manifest(&other, "drift", "tool");
    fs::write(other.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&other.join("run"));
    let healthy = Path::new(fixture.home.as_str()).join(".nah/guards/healthy");
    fs::create_dir_all(&healthy).unwrap();
    write_manifest(&healthy, "healthy", "tool");
    fs::write(healthy.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&healthy.join("run"));

    let (bundles, warnings) =
        discover_bundles(&fixture.home, Platform::Linux, &trust, &[]).unwrap();
    assert_eq!(
        bundles
            .iter()
            .map(|bundle| bundle.projection().identity().name())
            .collect::<Vec<_>>(),
        ["healthy"]
    );
    assert_eq!(
        warnings
            .iter()
            .filter(|warning| warning.contains("policy-identity-collision"))
            .count(),
        2
    );
}

#[test]
fn a_broken_bundle_is_skipped_without_hiding_its_healthy_siblings() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let guards = temp.path().join(".nah/guards");
    for (folder, name) in [("healthy", "healthy"), ("shadow", "fs-root")] {
        let directory = guards.join(folder);
        fs::create_dir_all(&directory).unwrap();
        write_manifest(&directory, name, "tool");
        fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
        make_executable(&directory.join("run"));
    }
    let broken = guards.join("broken");
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join("policy.toml"), "this is not toml").unwrap();

    let (bundles, warnings) = discover_bundles(
        &home,
        Platform::Linux,
        &TrustProjection::new(vec![]).unwrap(),
        &["fs-root"],
    )
    .unwrap();

    assert_eq!(
        bundles
            .iter()
            .map(|bundle| bundle.projection().identity().name())
            .collect::<Vec<_>>(),
        ["healthy"]
    );
    assert_eq!(
        warnings,
        [
            format!(
                "inactive extension bundle `broken`: {}",
                BundleError::InvalidManifest
            ),
            format!(
                "inactive extension bundle `shadow`: {}",
                BundleError::ReservedName
            ),
        ]
    );
}

#[test]
fn project_manifests_are_not_read_before_the_root_is_trusted() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join(".nah/guards/broken")).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::write(
        project.join(".nah/guards/broken/policy.toml"),
        "this is not toml",
    )
    .unwrap();
    let home = absolute(&home);
    let (untrusted, silent) = discover_bundles(
        &home,
        Platform::Linux,
        &TrustProjection::new(vec![]).unwrap(),
        &[],
    )
    .unwrap();
    assert!(untrusted.is_empty());
    assert!(silent.is_empty());

    let trust = TrustProjection::new(vec![TrustedRoot::new(
        TrustedRootId::new("root:project").unwrap(),
        absolute(&project),
    )])
    .unwrap();
    let (bundles, warnings) = discover_bundles(&home, Platform::Linux, &trust, &[]).unwrap();
    assert!(bundles.is_empty());
    assert_eq!(
        warnings,
        [format!(
            "inactive extension bundle `broken`: {}",
            BundleError::InvalidManifest
        )]
    );
}

#[test]
fn declared_data_bytes_are_covered_by_the_bundle_hash() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let directory = temp.path().join(".nah/guards/data");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("policy.toml"),
        "name = \"data\"\nmatch = [\"tool\"]\nprotocol = \"exec/v1\"\nprovenance = \"user\"\ndata = [\"rules.txt\"]\n",
    )
    .unwrap();
    fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&directory.join("run"));
    fs::write(directory.join("rules.txt"), "before").unwrap();
    let trust = TrustProjection::new(vec![]).unwrap();
    let before = discover_bundles(&home, Platform::Linux, &trust, &[])
        .unwrap()
        .0
        .remove(0);
    assert_eq!(
        before.covered_files().to_vec(),
        vec!["policy.toml", "rules.txt", "run"]
    );
    fs::write(directory.join("rules.txt"), "after").unwrap();
    let after = discover_bundles(&home, Platform::Linux, &trust, &[])
        .unwrap()
        .0
        .remove(0);
    assert_ne!(
        before.projection().bundle_hash(),
        after.projection().bundle_hash()
    );
}

#[test]
fn shipped_guard_names_are_reserved() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let directory = temp.path().join(".nah/guards/shadow");
    fs::create_dir_all(&directory).unwrap();
    write_manifest(&directory, "fs-root", "tool");
    fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&directory.join("run"));
    let (bundles, warnings) = discover_bundles(
        &home,
        Platform::Linux,
        &TrustProjection::new(vec![]).unwrap(),
        &["fs-root"],
    )
    .unwrap();

    assert!(bundles.is_empty());
    assert_eq!(
        warnings,
        [format!(
            "inactive extension bundle `shadow`: {}",
            BundleError::ReservedName
        )]
    );
}

#[test]
fn obsolete_manifest_kind_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let directory = temp.path().join(".nah/guards/wrong-kind");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("policy.toml"),
        "kind = \"guard\"\nname = \"wrong-kind\"\nmatch = [\"tool\"]\nprotocol = \"exec/v1\"\nprovenance = \"user\"\n",
    )
    .unwrap();
    fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&directory.join("run"));

    let (bundles, warnings) = discover_bundles(
        &home,
        Platform::Linux,
        &TrustProjection::new(vec![]).unwrap(),
        &[],
    )
    .unwrap();

    assert!(bundles.is_empty());
    assert_eq!(
        warnings,
        [format!(
            "inactive extension bundle `wrong-kind`: {}",
            BundleError::InvalidManifest
        )]
    );
}

#[test]
fn extension_names_are_lowercase_bounded_and_local_to_their_bundle() {
    let temp = tempfile::tempdir().unwrap();
    let home = absolute(temp.path());
    let guards = temp.path().join(".nah/guards");
    for (folder, name) in [
        ("healthy", "healthy"),
        ("uppercase", "FS-ROOT"),
        ("trailing", "trailing-"),
        ("too-long", &"a".repeat(65)),
    ] {
        let directory = guards.join(folder);
        fs::create_dir_all(&directory).unwrap();
        write_manifest(&directory, name, "tool");
        fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
        make_executable(&directory.join("run"));
    }

    let (bundles, warnings) = discover_bundles(
        &home,
        Platform::Linux,
        &TrustProjection::new(vec![]).unwrap(),
        &["fs-root"],
    )
    .unwrap();
    assert_eq!(
        bundles
            .iter()
            .map(|bundle| bundle.projection().identity().name())
            .collect::<Vec<_>>(),
        ["healthy"]
    );
    assert_eq!(warnings.len(), 3, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .all(|warning| warning.contains("invalid-policy-manifest"))
    );
}
