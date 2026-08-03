//! Typed runtime wiring status and mutations shared by the CLI and TUI.

use std::path::PathBuf;

use clap::ValueEnum;

use crate::runtime::{FailurePolicy, Runtime};

use super::{
    amp_hook_status, amp_self_protection_paths, antigravity_hook_status,
    antigravity_self_protection_paths, claude_hook_status, claude_self_protection_paths,
    cline_hook_status, cline_self_protection_paths, codex_hook_status, codex_self_protection_paths,
    copilot_hook_status, copilot_self_protection_paths, cursor_hook_status,
    cursor_self_protection_paths, devin_hook_status, devin_self_protection_paths,
    droid_hook_status, droid_self_protection_paths, hermes_hook_status,
    hermes_self_protection_paths, kiro_hook_status, kiro_self_protection_paths, mutate_amp_hook,
    mutate_antigravity_hook, mutate_claude_hook, mutate_cline_hook, mutate_codex_hook,
    mutate_copilot_hook, mutate_cursor_hook, mutate_devin_hook, mutate_droid_hook,
    mutate_hermes_hook, mutate_kiro_hook, mutate_openclaw_hook, mutate_opencode_hook,
    mutate_pi_hook, openclaw_hook_status, openclaw_self_protection_paths, opencode_hook_status,
    opencode_self_protection_paths, pi_hook_status, pi_self_protection_paths,
};

type RuntimeInspector = fn() -> Result<RuntimeHookStatus, String>;

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
        }
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
}

pub(crate) fn runtime_entries() -> Vec<RuntimeEntry> {
    Runtime::value_variants()
        .iter()
        .copied()
        .map(runtime_entry)
        .collect()
}

pub(crate) fn runtime_entry(runtime: Runtime) -> RuntimeEntry {
    let inspect: RuntimeInspector = match runtime {
        Runtime::Amp => amp_hook_status,
        Runtime::Antigravity => antigravity_hook_status,
        Runtime::Claude => claude_hook_status,
        Runtime::Cline => cline_hook_status,
        Runtime::Codex => codex_hook_status,
        Runtime::Copilot => copilot_hook_status,
        Runtime::Cursor => cursor_hook_status,
        Runtime::Devin => devin_hook_status,
        Runtime::Droid => droid_hook_status,
        Runtime::Hermes => hermes_hook_status,
        Runtime::Kiro => kiro_hook_status,
        Runtime::OpenClaw => openclaw_hook_status,
        Runtime::OpenCode => opencode_hook_status,
        Runtime::Pi => pi_hook_status,
    };
    RuntimeEntry {
        runtime,
        name: runtime.display_name(),
        docs_topic: runtime.docs_topic(),
        status: inspect(),
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
    match runtime {
        Runtime::Amp => mutate_amp_hook(install, failure_policy),
        Runtime::Antigravity => mutate_antigravity_hook(install, failure_policy),
        Runtime::Claude => mutate_claude_hook(install, failure_policy),
        Runtime::Cline => mutate_cline_hook(install, failure_policy),
        Runtime::Codex => mutate_codex_hook(install, failure_policy),
        Runtime::Copilot => mutate_copilot_hook(install, failure_policy),
        Runtime::Cursor => mutate_cursor_hook(install, failure_policy),
        Runtime::Devin => mutate_devin_hook(install, failure_policy),
        Runtime::Droid => mutate_droid_hook(install, failure_policy),
        Runtime::Hermes => mutate_hermes_hook(install, failure_policy),
        Runtime::Kiro => mutate_kiro_hook(install, failure_policy),
        Runtime::OpenClaw => mutate_openclaw_hook(install, failure_policy),
        Runtime::OpenCode => mutate_opencode_hook(install, failure_policy),
        Runtime::Pi => mutate_pi_hook(install, failure_policy),
    }
}

pub(crate) fn runtime_self_protection(
    runtime: Runtime,
) -> Result<nah_actions::SelfProtectionProjection, String> {
    let protected_paths = match runtime {
        Runtime::Amp => amp_self_protection_paths(),
        Runtime::Antigravity => antigravity_self_protection_paths(),
        Runtime::Claude => claude_self_protection_paths(),
        Runtime::Cline => cline_self_protection_paths(),
        Runtime::Codex => codex_self_protection_paths(),
        Runtime::Copilot => copilot_self_protection_paths(),
        Runtime::Cursor => cursor_self_protection_paths(),
        Runtime::Devin => devin_self_protection_paths(),
        Runtime::Droid => droid_self_protection_paths(),
        Runtime::Hermes => hermes_self_protection_paths(),
        Runtime::Kiro => kiro_self_protection_paths(),
        Runtime::OpenClaw => openclaw_self_protection_paths(),
        Runtime::OpenCode => opencode_self_protection_paths(),
        Runtime::Pi => pi_self_protection_paths(),
    }?;
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
    Ok(nah_actions::SelfProtectionProjection::new(protected_paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_entries_cover_every_cli_runtime_in_order() {
        let entries = runtime_entries();
        let runtimes = entries
            .iter()
            .map(|entry| entry.runtime)
            .collect::<Vec<_>>();

        assert_eq!(runtimes, Runtime::value_variants());
    }
}
