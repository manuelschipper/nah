//! The interactive `nah nap` command: which argument lists start a nap, which
//! guards the nap pauses, and the typed confirmation the operator must give.

use std::collections::BTreeSet;
use std::io::Write;

use nah_proto::decision::ExitCode;

use crate::args::{Cli, Command, parse_from};
use crate::catalog::NAP_ALL;
use crate::live_state;
use crate::nap::{self, NapMode};

use super::custom_guard_entries;

/// Every argument list the grammar accepts as `nah nap` takes the interactive
/// path, returning its requested guard names. Help and usage errors fall
/// through to the ordinary dispatcher, which prints them without starting a
/// nap.
pub(crate) fn interactive_nap_request(args: &[String]) -> Option<Vec<String>> {
    match parse_from(std::iter::once("nah".to_owned()).chain(args.iter().cloned())) {
        Ok(Cli {
            command: Command::Nap(nap),
        }) => Some(nap.guards),
        _ => None,
    }
}

/// Resolves `nah nap` arguments against the guards `nah guards` lists.
/// `custom` yields one name per listed custom guard, so a name listed in
/// several scopes is ambiguous, as it is for `nah guard disable`; it is read
/// only when guard names were given.
pub(crate) fn nap_mode(
    requested: Vec<String>,
    shipped: &[&str],
    custom: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<NapMode, String> {
    let requested = requested.into_iter().collect::<BTreeSet<_>>();
    if requested.is_empty() {
        return Ok(NapMode::SelfProtection);
    }
    if requested.contains(NAP_ALL) {
        return if requested.len() == 1 {
            Ok(NapMode::All)
        } else {
            Err(format!("`{NAP_ALL}` cannot be combined with guard names"))
        };
    }
    let custom = custom()?;
    for name in &requested {
        match custom.iter().filter(|custom| *custom == name).count() {
            0 if shipped.contains(&name.as_str()) => {}
            0 => {
                let valid = shipped
                    .iter()
                    .map(|name| (*name).to_owned())
                    .chain(custom)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                return Err(format!(
                    "unknown guard `{name}`; valid guards: {}",
                    valid.join(", ")
                ));
            }
            1 => {}
            _ => return Err(format!("guard name `{name}` is ambiguous across scopes")),
        }
    }
    Ok(NapMode::Guards(requested.into_iter().collect()))
}

pub(crate) fn live_custom_guard_names() -> Result<Vec<String>, String> {
    Ok(custom_guard_entries()?
        .into_iter()
        .map(|entry| entry.target.name().to_owned())
        .collect())
}

pub(crate) fn run_interactive_nap<R: std::io::BufRead, W: Write, E: Write>(
    mode: NapMode,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let scope = nap_prompt(&mode);
    let _ = writeln!(
        stdout,
        "Pause nah globally for 10 minutes?\n{scope}\nThis affects every session using this nah installation.\nPersistent changes remain after the nap expires.\nIf nah or its hook is removed, expiration cannot restore it.\n\nType nap to continue:"
    );
    let _ = stdout.flush();
    let mut input = String::new();
    if stdin.read_line(&mut input).is_err() {
        let _ = writeln!(stderr, "nah: nap confirmation failed");
        return ExitCode::COMMAND_FAILURE.value();
    }
    if !nap_confirmation(&input) {
        let _ = writeln!(stderr, "nah: nap cancelled");
        return ExitCode::COMMAND_FAILURE.value();
    }
    let platform = live_state::host_platform();
    let result = live_state::home(platform)
        .and_then(|home| nap::start(&home, platform, mode).map_err(|error| error.to_string()));
    match result {
        Ok(active) => {
            let _ = writeln!(
                stdout,
                "nah {} is napping for 10 minutes\nrun `nah wake` to resume sooner",
                active.mode().scope()
            );
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "nah: {error}");
            ExitCode::COMMAND_FAILURE.value()
        }
    }
}

fn nap_confirmation(input: &str) -> bool {
    input
        .trim_end_matches(['\r', '\n'])
        .eq_ignore_ascii_case("nap")
}

fn nap_prompt(mode: &NapMode) -> String {
    match mode {
        NapMode::SelfProtection => "Self-protection will pause; guards remain active.".to_owned(),
        NapMode::All => {
            "All non-permanent enforcement will pause; other calls will delegate to their runtime."
                .to_owned()
        }
        NapMode::Guards(_) => format!(
            "Only {} will pause; self-protection and every other guard remain active.",
            mode.scope()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_nap_shapes_enter_the_interactive_path() {
        let request = |args: &[&str]| {
            interactive_nap_request(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(request(&["nap"]), Some(vec![]));
        assert_eq!(request(&["nap", "all"]), Some(vec!["all".into()]));
        assert_eq!(
            request(&["nap", "fs-home", "no-such-guard"]),
            Some(vec!["fs-home".into(), "no-such-guard".into()])
        );
        for help_or_usage_error in [
            &["nap", "--help"][..],
            &["nap", "-h"],
            &["nap", "fs-home", "--help"],
            &["nap", "--all"],
            &["nap", "--bogus"],
            &["wake"],
        ] {
            assert_eq!(
                request(help_or_usage_error),
                None,
                "{help_or_usage_error:?}"
            );
        }

        let shipped = ["fs-home", "git-history"];
        let custom = || Ok(vec!["corp".to_owned(), "shared".into(), "shared".into()]);
        let unread = || -> Result<Vec<String>, String> { panic!("custom guards were read") };
        let names = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(
            nap_mode(vec![], &shipped, unread),
            Ok(NapMode::SelfProtection)
        );
        assert_eq!(
            nap_mode(names(&["all", "all"]), &shipped, unread),
            Ok(NapMode::All)
        );
        assert_eq!(
            nap_mode(
                names(&["git-history", "corp", "git-history"]),
                &shipped,
                custom
            ),
            Ok(NapMode::Guards(names(&["corp", "git-history"])))
        );
        assert!(nap_mode(names(&["all", "fs-home"]), &shipped, custom).is_err());
        let unknown = nap_mode(names(&["fs-home", "nope"]), &shipped, custom).unwrap_err();
        assert!(unknown.contains("nope"), "{unknown}");
        for valid in ["corp", "fs-home", "git-history", "shared"] {
            assert!(unknown.contains(valid), "{unknown}");
        }
        let ambiguous = nap_mode(names(&["shared"]), &shipped, custom).unwrap_err();
        assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
    }

    #[test]
    fn confirmation_copy_distinguishes_self_and_all() {
        let guards = NapMode::Guards(vec!["corp".into(), "fs-home".into()]);
        let scopes = [
            nap_prompt(&NapMode::SelfProtection),
            nap_prompt(&NapMode::All),
            nap_prompt(&guards),
        ];
        for (index, scope) in scopes.iter().enumerate() {
            assert!(!scope.trim().is_empty());
            assert!(!scopes[..index].contains(scope));
        }
        assert!(scopes[2].contains("corp") && scopes[2].contains("fs-home"));
    }

    #[test]
    fn nap_confirmation_is_case_insensitive() {
        for input in ["NAP\n", "nap\r\n", "Nap\n", "nAP"] {
            assert!(nap_confirmation(input), "{input:?}");
        }
        for input in ["NAP ALL\n", "nap all", "", "naps\n"] {
            assert!(!nap_confirmation(input), "{input:?}");
        }
    }
}
