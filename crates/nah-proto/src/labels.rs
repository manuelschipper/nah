//! Nah-owned labels applied to interpreted effects.

use serde::{Deserialize, Serialize};

use crate::ctx::AbsolutePath;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PathScope {
    Project { root: AbsolutePath },
    Home,
    System,
    OutsideProject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    None,
    EnvironmentSecret,
    CredentialSecret,
    OtherSensitive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NahProtectionTier {
    Critical,
    Permanent,
    Proposal,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostIntegrityClass {
    ShellProfile,
    StartupPersistence,
    AuthIdentity,
}
