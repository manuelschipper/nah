use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use super::support::{absolute, request, value};
use crate::fulfill_observation_request;
use nah_proto::ctx::SchemaVersion;
use nah_proto::labels::dependency::Ecosystem;
use nah_proto::observation::{
    ObservationFailure, ObservationQuery, ObservationRequest, ObservationValue, Observed,
};

/// Each project directory's packages near `names`, as the host observer
/// answers them.
fn installed(
    projects: &[(&std::path::Path, Ecosystem)],
    names: &[&str],
) -> Vec<Observed<BTreeMap<String, BTreeSet<String>>>> {
    let cwd = projects[0].0;
    let mut queries = request(cwd, &[]).queries().to_vec();
    for (index, (directory, ecosystem)) in projects.iter().enumerate() {
        queries.push(ObservationQuery::InstalledPackages {
            key: format!("packages-{index}"),
            directory: absolute(directory),
            ecosystem: *ecosystem,
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        });
    }
    let observation = fulfill_observation_request(
        &ObservationRequest::new(SchemaVersion::V1, "request", queries).expect("request"),
    )
    .expect("observation");
    (0..projects.len())
        .map(
            |index| match value(&observation, &format!("packages-{index}")) {
                ObservationValue::InstalledPackages { observed } => observed.clone(),
                other => panic!("installed packages answer: {other:?}"),
            },
        )
        .collect()
}

fn found(packages: &[(&str, &[&str])]) -> Observed<BTreeMap<String, BTreeSet<String>>> {
    Observed::Ok {
        value: packages
            .iter()
            .map(|(name, versions)| {
                (
                    (*name).to_owned(),
                    versions
                        .iter()
                        .map(|version| (*version).to_owned())
                        .collect(),
                )
            })
            .collect(),
    }
}

fn write(path: &std::path::Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
    fs::write(path, text).expect("file");
}

/// The environment and the lock files answer together, each name with every
/// version found, and only names equal to or one edit from an asked name
/// are kept. An entry without the metadata an install leaves is no package,
/// and a dataless environment is never listed.
#[test]
fn installed_packages_come_from_the_environment_and_the_lock_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let venv = temp.path().join("venv-project");
    let site = venv.join(".venv/lib/python3.12/site-packages");
    for distribution in [
        "matplotlib-3.8.3.dist-info",
        "Typing_Extensions-4.10.0.dist-info",
        "numpy-1.26.4.dist-info",
    ] {
        write(
            &site.join(distribution).join("METADATA"),
            "Metadata-Version: 2.1\n",
        );
    }
    // Leftovers of an install that never finished.
    fs::create_dir_all(site.join("reqeusts-2.31.0.dist-info")).expect("bare dist-info");
    write(&site.join("matplotib-3.8.3.dist-info"), "");
    write(
        &venv.join("uv.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
    );

    // An empty environment beside a universal lock pinning two versions.
    let locked = temp.path().join("locked-project");
    fs::create_dir_all(locked.join(".venv/lib/python3.12/site-packages")).expect("empty venv");
    write(
        &locked.join("uv.lock"),
        "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.2.1\"\n",
    );

    let node = temp.path().join("node-project");
    for (entry, manifest) in [
        ("lodash", "{\"name\": \"lodash\", \"version\": \"4.17.21\"}"),
        ("@types/lodash", "{\"version\": \"4.17.0\"}"),
        ("react", "{\"version\": \"18.2.0\"}"),
    ] {
        write(
            &node.join("node_modules").join(entry).join("package.json"),
            manifest,
        );
    }
    fs::create_dir_all(node.join("node_modules/lodahs")).expect("leftover directory");
    write(
        &node.join("package-lock.json"),
        "{\"lockfileVersion\": 3, \"packages\": {\"\": {}, \"node_modules/lodash\": {\"version\": \"4.17.21\"}, \"node_modules/a/node_modules/lodash\": {\"version\": \"3.10.1\"}}}",
    );

    let npm_locked = temp.path().join("npm-locked-project");
    fs::create_dir_all(npm_locked.join("node_modules")).expect("empty node_modules");
    write(
        &npm_locked.join("package-lock.json"),
        "{\"lockfileVersion\": 1, \"dependencies\": {\"lodash\": {\"version\": \"4.17.21\"}, \"a\": {\"version\": \"1.0.0\", \"dependencies\": {\"@types/lodash\": {\"version\": \"4.17.0\"}}}}}",
    );

    let yarn = temp.path().join("yarn-project");
    write(
        &yarn.join("yarn.lock"),
        "# yarn lockfile v1\n\n\nlodash@^4.17.20, lodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n\n\"@types/lodash@^4.17.0\":\n  version \"4.17.0\"\n  dependencies:\n    version \"9.9.9\"\n",
    );
    let berry = temp.path().join("berry-project");
    write(
        &berry.join("yarn.lock"),
        "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n",
    );
    let pnpm = temp.path().join("pnpm-project");
    write(
        &pnpm.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        version: 4.17.21\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\n  '@types/lodash@4.17.0':\n    resolution: {integrity: sha512-y}\n\nsnapshots:\n\n  '@types/lodash@4.17.0(react@18.2.0)': {}\n",
    );
    let pnpm_old = temp.path().join("pnpm-old-project");
    write(
        &pnpm_old.join("pnpm-lock.yaml"),
        "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-x}\n\n  /@types/lodash/4.17.0_react@18.2.0:\n    dev: true\n",
    );

    let cloud = temp.path().join("cloud-project");
    fs::create_dir_all(cloud.join(".venv")).expect("cloud environment");
    crate::io_paths::simulated::make_dataless(&cloud.join(".venv"));

    let empty = temp.path().join("empty-project");
    fs::create_dir_all(&empty).expect("empty project");

    let answers = installed(
        &[
            (&venv, Ecosystem::Python),
            (&locked, Ecosystem::Python),
            (&node, Ecosystem::Node),
            (&npm_locked, Ecosystem::Node),
            (&yarn, Ecosystem::Node),
            (&berry, Ecosystem::Node),
            (&pnpm, Ecosystem::Node),
            (&pnpm_old, Ecosystem::Node),
            (&cloud, Ecosystem::Python),
            (&empty, Ecosystem::Node),
        ],
        &[
            "matplotib",
            "typing-extensions",
            "reqeusts",
            "lodahs",
            "@types/lodahs",
        ],
    );
    let lodash_types = [
        ("@types/lodash", &["4.17.0"][..]),
        ("lodash", &["4.17.21"][..]),
    ];
    assert_eq!(
        answers,
        [
            found(&[
                ("matplotlib", &["3.8.3"]),
                ("requests", &["2.31.0"]),
                ("typing-extensions", &["4.10.0"]),
            ]),
            found(&[("requests", &["2.31.0", "2.32.3"])]),
            found(&[
                ("@types/lodash", &["4.17.0"]),
                ("lodash", &["3.10.1", "4.17.21"]),
            ]),
            found(&lodash_types),
            found(&lodash_types),
            found(&[("lodash", &["4.17.21"])]),
            found(&lodash_types),
            found(&lodash_types),
            Observed::Error {
                error: ObservationFailure::Unavailable
            },
            found(&[]),
        ]
    );
}
