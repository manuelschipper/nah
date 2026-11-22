//! Typed runtime wiring status and mutations shared by the CLI and TUI.

use std::path::PathBuf;

use clap::ValueEnum;

use crate::runtime::{FailurePolicy, Runtime};

use super::{
    antigravity_hook_status, antigravity_self_protection_paths, claude_hook_status,
    claude_self_protection_paths, codex_hook_status, codex_self_protection_paths,
    cursor_hook_status, cursor_self_protection_paths, hermes_hook_status,
    hermes_self_protection_paths, mutate_antigravity_hook, mutate_claude_hook, mutate_codex_hook,
    mutate_cursor_hook, mutate_hermes_hook, mutate_openclaw_hook, mutate_opencode_hook,
    mutate_pi_hook, openclaw_hook_status, openclaw_self_protection_paths, opencode_hook_status,
    opencode_self_protection_paths, pi_hook_status, pi_self_protection_paths,
};

type RuntimeInspector = fn() -> Result<RuntimeHookStatus, String>;

pub(super) fn reject_unsupported_windows_runtime(
    platform: nah_proto::ctx::Platform,
) -> Result<(), String> {
    if platform == nah_proto::ctx::Platform::Windows {
        Err("runtime-platform-unsupported".into())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeHookStatus {
    WiringCurrent,
    WiringCurrentFailClosed,
    NotConfigured,
    NeedsReinstall,
    NeedsReinstallFailClosed,
}

impl RuntimeHookStatus {
    pub(crate) const fn stale(policy: FailurePolicy) -> Self {
        match policy {
            FailurePolicy::Delegate => Self::NeedsReinstall,
            FailurePolicy::Block => Self::NeedsReinstallFailClosed,
        }
    }

    pub(crate) const fn failure_policy(self) -> FailurePolicy {
        match self {
            Self::WiringCurrentFailClosed | Self::NeedsReinstallFailClosed => FailurePolicy::Block,
            Self::WiringCurrent | Self::NotConfigured | Self::NeedsReinstall => {
                FailurePolicy::Delegate
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeMutation {
    action: &'static str,
    subject: &'static str,
    path: PathBuf,
    follow_up: Option<&'static str>,
    pub(super) coverage_notice: Option<&'static str>,
    failure_policy: Option<FailurePolicy>,
}

impl RuntimeMutation {
    pub(crate) fn new(
        installed: bool,
        subject: &'static str,
        path: PathBuf,
        follow_up: Option<&'static str>,
    ) -> Self {
        Self {
            action: if installed {
                "installed"
            } else {
                "uninstalled"
            },
            subject,
            path,
            follow_up: if installed { follow_up } else { None },
            coverage_notice: None,
            failure_policy: None,
        }
    }

    /// The failure policy an install wrote; `None` for an uninstall.
    pub(crate) fn failure_policy(&self) -> Option<FailurePolicy> {
        self.failure_policy
    }

    pub(crate) fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "{} {} in {}",
            self.action,
            self.subject,
            self.path.display()
        )];
        if let Some(follow_up) = self.follow_up {
            lines.push(follow_up.to_owned());
        }
        if let Some(notice) = self.coverage_notice {
            lines.push(notice.to_owned());
        }
        lines
    }

    pub(crate) fn summary(&self) -> String {
        self.lines().join(" ")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeEntry {
    pub(crate) runtime: Runtime,
    pub(crate) name: &'static str,
    pub(crate) docs_topic: &'static str,
    pub(crate) status: Result<RuntimeHookStatus, String>,
    pub(crate) coverage_notice: Option<&'static str>,
}

pub(crate) fn runtime_entries() -> Vec<RuntimeEntry> {
    nah_proto::runtime::HOOK_RUNTIME_NAMES
        .iter()
        .map(|name| Runtime::from_str(name, false).expect("hook runtime is a CLI runtime"))
        .map(runtime_entry)
        .collect()
}

pub(crate) fn runtime_entry(runtime: Runtime) -> RuntimeEntry {
    let inspect: RuntimeInspector = match runtime {
        Runtime::Antigravity => antigravity_hook_status,
        Runtime::Claude => claude_hook_status,
        Runtime::Codex => codex_hook_status,
        Runtime::Cursor => cursor_hook_status,
        Runtime::Hermes => hermes_hook_status,
        Runtime::OpenClaw => openclaw_hook_status,
        Runtime::OpenCode => opencode_hook_status,
        Runtime::Pi => pi_hook_status,
    };
    let status = inspect();
    let coverage_notice = if runtime == Runtime::Codex
        && status
            .as_ref()
            .is_ok_and(|status| *status != RuntimeHookStatus::NotConfigured)
    {
        super::codex_installation::codex_coverage_notice(crate::live_state::host_platform())
    } else {
        None
    };
    RuntimeEntry {
        runtime,
        name: runtime.display_name(),
        docs_topic: runtime.docs_topic(),
        status,
        coverage_notice,
    }
}

pub(crate) fn set_runtime_configured(
    runtime: Runtime,
    install: bool,
    failure_policy: Option<FailurePolicy>,
) -> Result<RuntimeMutation, String> {
    let failure_policy = match (install, failure_policy) {
        (true, Some(policy)) => policy,
        // Status is only a preservation hint. The installer still owns error
        // reporting and safety checks when existing wiring cannot be inspected.
        (true, None) => runtime_entry(runtime)
            .status
            .map(RuntimeHookStatus::failure_policy)
            .unwrap_or(FailurePolicy::Delegate),
        (false, _) => FailurePolicy::Delegate,
    };
    let mutation = match runtime {
        Runtime::Antigravity => mutate_antigravity_hook(install, failure_policy),
        Runtime::Claude => mutate_claude_hook(install, failure_policy),
        Runtime::Codex => mutate_codex_hook(install, failure_policy),
        Runtime::Cursor => mutate_cursor_hook(install, failure_policy),
        Runtime::Hermes => mutate_hermes_hook(install, failure_policy),
        Runtime::OpenClaw => mutate_openclaw_hook(install, failure_policy),
        Runtime::OpenCode => mutate_opencode_hook(install, failure_policy),
        Runtime::Pi => mutate_pi_hook(install, failure_policy),
    }?;
    Ok(RuntimeMutation {
        failure_policy: install.then_some(failure_policy),
        ..mutation
    })
}

pub(crate) fn runtime_self_protection(
    runtime: Runtime,
) -> Result<nah_proto::runtime_protection::SelfProtectionProjection, String> {
    // The deciding runtime keeps today's failure: a projection that cannot be
    // built is an evaluation failure. Every other runtime contributes only
    // when its hook is installed and its paths can be built. An absent Hermes
    // home, for example, stays NotConfigured and adds nothing, instead of
    // failing a Claude decision with `hermes-home-unavailable`.
    let mut protected_paths = self_protection_path_bufs(runtime)?;
    for other in Runtime::value_variants() {
        if *other == runtime {
            continue;
        }
        if !installed_hook(*other) {
            continue;
        }
        if let Ok(more) = self_protection_path_bufs(*other) {
            protected_paths.extend(more);
        }
    }
    let platform = crate::live_state::host_platform();
    let protected_paths = protected_paths
        .into_iter()
        .map(|path| {
            path.to_str()
                .ok_or_else(|| "runtime-self-protection-path-not-utf8".to_owned())
                .and_then(|path| {
                    nah_proto::ctx::AbsolutePath::new(platform, path)
                        .map_err(|error| error.to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(nah_proto::runtime_protection::SelfProtectionProjection::new(protected_paths))
}

fn self_protection_path_bufs(runtime: Runtime) -> Result<Vec<PathBuf>, String> {
    match runtime {
        Runtime::Antigravity => antigravity_self_protection_paths(),
        Runtime::Claude => claude_self_protection_paths(),
        Runtime::Codex => codex_self_protection_paths(),
        Runtime::Cursor => cursor_self_protection_paths(),
        Runtime::Hermes => hermes_self_protection_paths(),
        Runtime::OpenClaw => openclaw_self_protection_paths(),
        Runtime::OpenCode => opencode_self_protection_paths(),
        Runtime::Pi => pi_self_protection_paths(),
    }
}

/// A hook Nah can see on disk. Status that cannot be read, and a runtime that
/// was never installed, contribute no paths.
fn installed_hook(runtime: Runtime) -> bool {
    matches!(
        runtime_entry(runtime).status,
        Ok(status) if status != RuntimeHookStatus::NotConfigured
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_entries_cover_every_cli_runtime_in_order() {
        if crate::live_state::reran_in_temporary_home() {
            return;
        }
        let entries = runtime_entries();
        let runtimes = entries
            .iter()
            .map(|entry| entry.runtime)
            .collect::<Vec<_>>();

        assert_eq!(runtimes, Runtime::value_variants());
    }

    #[test]
    fn unsupported_windows_runtimes_share_one_installation_error() {
        assert_eq!(
            reject_unsupported_windows_runtime(nah_proto::ctx::Platform::Windows),
            Err("runtime-platform-unsupported".into())
        );
        for platform in [
            nah_proto::ctx::Platform::Linux,
            nah_proto::ctx::Platform::Macos,
        ] {
            assert_eq!(reject_unsupported_windows_runtime(platform), Ok(()));
        }
    }

    #[cfg(windows)]
    #[test]
    fn unsupported_windows_runtime_status_is_not_configured() {
        for runtime in [Runtime::Hermes, Runtime::OpenCode] {
            assert_eq!(
                runtime_entry(runtime).status,
                Ok(RuntimeHookStatus::NotConfigured),
                "{runtime:?}"
            );
        }
    }
}
