#![allow(dead_code, clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nah_extensions::{
    ActivationDatabase, MemoCache, activation_database_path, consult_extensions, discover_bundles,
    load_active_extensions, memo_cache_path, record_activation,
};
use nah_proto::action::{ActionStream, Coverage, EffectKind};
use nah_proto::ctx::{AbsolutePath, Ctx, Platform, SchemaVersion, TrustProjection};
use nah_proto::extension::ConsultationOutcome;
use nah_proto::observation::{
    Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    ProjectGuardDeclaration, ProjectGuardObservation,
};

pub(crate) struct Fixture {
    _temp: tempfile::TempDir,
    pub(crate) home: AbsolutePath,
    pub(crate) catalog: nah_extensions::ActiveExtensionCatalog,
    pub(crate) ctx: Ctx,
    pub(crate) observation: Observation,
    pub(crate) action_stream: ActionStream,
    pub(crate) cache: MemoCache,
    pub(crate) run: PathBuf,
}

impl Fixture {
    #[cfg(unix)]
    pub(crate) fn shell(name: &str, body: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = absolute(temp.path());
        let directory = temp.path().join(".nah").join("guards").join(name);
        fs::create_dir_all(&directory).unwrap();
        write_manifest(&directory, name, "tool");
        let run = directory.join("run");
        fs::write(&run, format!("#!/bin/sh\n{body}\n")).unwrap();
        make_executable(&run);
        finish(temp, home, run, "tool")
    }

    #[cfg(windows)]
    pub(crate) fn batch(name: &str, body: &str) -> Self {
        Self::batch_in_folder(name, name, body)
    }

    #[cfg(windows)]
    pub(crate) fn batch_in_folder(folder: &str, name: &str, body: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = absolute(temp.path());
        let directory = temp.path().join(".nah").join("guards").join(folder);
        fs::create_dir_all(&directory).unwrap();
        write_manifest(&directory, name, "tool");
        let run = directory.join("run.cmd");
        fs::write(&run, format!("@echo off\r\n{body}\r\n")).unwrap();
        finish_windows(temp, home, run, "tool")
    }

    pub(crate) fn consult(&self) -> nah_extensions::ConsultationOutput {
        consult_extensions(
            &self.catalog,
            &self.ctx,
            &self.observation,
            &self.action_stream,
            &self.cache,
        )
    }
}

pub(crate) fn finish(
    temp: tempfile::TempDir,
    home: AbsolutePath,
    run: PathBuf,
    program: &str,
) -> Fixture {
    finish_for_platform(temp, home, run, program, Platform::Linux)
}

#[cfg(windows)]
pub(crate) fn finish_windows(
    temp: tempfile::TempDir,
    home: AbsolutePath,
    run: PathBuf,
    program: &str,
) -> Fixture {
    finish_for_platform(temp, home, run, program, Platform::Windows)
}

fn finish_for_platform(
    temp: tempfile::TempDir,
    home: AbsolutePath,
    run: PathBuf,
    program: &str,
    platform: Platform,
) -> Fixture {
    let trust = TrustProjection::new(vec![]).unwrap();
    let bundle = discover_bundles(&home, platform, &trust, &[])
        .unwrap()
        .0
        .into_iter()
        .next()
        .unwrap();
    let activation_path = activation_database_path(&home, platform);
    record_activation(
        &activation_path,
        bundle.projection().clone(),
        "tester".into(),
        1,
    )
    .unwrap();
    let activations = ActivationDatabase::load(&activation_path).unwrap();
    let catalog = load_active_extensions(&home, platform, &trust, &activations, &[]).unwrap();
    let ctx = Ctx::new(platform, home.clone(), vec![], catalog.activations(), trust).unwrap();
    let observation = observation(&home);
    let action_stream = ActionStream::new(
        Coverage::Full,
        vec![vec![EffectKind::known(program, "read-only").unwrap()]],
        vec![],
    )
    .unwrap();
    let cache = MemoCache::new(memo_cache_path(&home, platform));
    Fixture {
        _temp: temp,
        home,
        catalog,
        ctx,
        observation,
        action_stream,
        cache,
        run,
    }
}

pub(crate) fn write_manifest(directory: &Path, name: &str, program: &str) {
    fs::write(
        directory.join("policy.toml"),
        format!(
            "name = \"{name}\"\nmatch = [\"{program}\"]\nprotocol = \"exec/v1\"\nprovenance = \"user\"\n"
        ),
    )
    .unwrap();
}

#[cfg(unix)]
pub(crate) fn make_executable(path: &Path) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).unwrap();
}

pub(crate) fn absolute(path: &Path) -> AbsolutePath {
    AbsolutePath::new(host_platform(), path.to_str().unwrap()).unwrap()
}

const fn host_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

fn observation(home: &AbsolutePath) -> Observation {
    let cwd = ObservationQuery::Cwd {
        key: "cwd".into(),
        requested: home.clone(),
    };
    let roots = ObservationQuery::Roots {
        key: "roots".into(),
        cwd_key: "cwd".into(),
    };
    let guards = ObservationQuery::ProjectGuards {
        key: "guards".into(),
        roots_key: "roots".into(),
    };
    Observation::new(
        SchemaVersion::V1,
        "extension-test",
        vec![
            ObservationFact::new(
                cwd,
                ObservationValue::Cwd {
                    observed: Observed::Ok {
                        value: home.clone(),
                    },
                },
            )
            .unwrap(),
            ObservationFact::new(
                roots,
                ObservationValue::Roots {
                    observed: Observed::Ok { value: vec![] },
                },
            )
            .unwrap(),
            ObservationFact::new(
                guards,
                ObservationValue::ProjectGuards {
                    observation: ProjectGuardObservation::new(
                        None,
                        ProjectGuardDeclaration::Absent,
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

pub(crate) fn consultation_outcomes(
    output: nah_extensions::ConsultationOutput,
) -> Vec<ConsultationOutcome> {
    output
        .consultations
        .into_iter()
        .map(|consultation| consultation.outcome)
        .collect()
}
