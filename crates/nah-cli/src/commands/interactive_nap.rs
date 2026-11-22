//! The interactive `nah nap` command: which argument lists start a nap, which
//! guards or rules the nap pauses, and the typed confirmation the operator
//! must give.

use std::collections::BTreeSet;
use std::io::Write;

use nah_proto::decision::ExitCode;

use crate::args::{Cli, Command, parse_from};
use nah_proto::ctx::Guard;

use crate::catalog::NAP_ALL;
use crate::live_state;
use crate::nap::{self, NapMode};

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

/// Resolves `nah nap` arguments against what `nah guards` lists: a guard or a
/// rule (`guard/rule`). `self` alone is the bare nap.
pub(crate) fn nap_mode(requested: Vec<String>, rules: &[&str]) -> Result<NapMode, String> {
    let requested = requested.into_iter().collect::<BTreeSet<_>>();
    if requested.is_empty() {
        return Ok(NapMode::SelfProtection);
    }
    for whole in [NAP_ALL, Guard::SelfProtection.name()] {
        if requested.contains(whole) {
            if requested.len() > 1 {
                return Err(format!("`{whole}` cannot be combined with other names"));
            }
            return Ok(if whole == NAP_ALL {
                NapMode::All
            } else {
                NapMode::SelfProtection
            });
        }
    }
    for name in &requested {
        if Guard::from_name(name).is_some() || rules.contains(&name.as_str()) {
            continue;
        }
        if let Some(error) = crate::catalog::legacy_name_error(name) {
            return Err(error);
        }
        return Err(format!(
            "unknown guard or rule `{name}`; run `nah guards` to list them"
        ));
    }
    Ok(NapMode::Guards(requested.into_iter().collect()))
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
        Ok((active, replaced_other_version)) => {
            if replaced_other_version {
                let _ = writeln!(stdout, "replaced a nap written by another Nah version");
            }
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
            "Only {} will pause; self-protection and every other rule remain active.",
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
            request(&["nap", "work", "no-such-guard"]),
            Some(vec!["work".into(), "no-such-guard".into()])
        );
        for help_or_usage_error in [
            &["nap", "--help"][..],
            &["nap", "-h"],
            &["nap", "work", "--help"],
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

        let rules = ["work/stash-drop", "machine/system-halt"];
        let names = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(nap_mode(vec![], &rules), Ok(NapMode::SelfProtection));
        assert_eq!(
            nap_mode(names(&["self"]), &rules),
            Ok(NapMode::SelfProtection)
        );
        assert_eq!(nap_mode(names(&["all", "all"]), &rules), Ok(NapMode::All));
        assert_eq!(
            nap_mode(names(&["work", "machine/system-halt"]), &rules),
            Ok(NapMode::Guards(names(&["machine/system-halt", "work"])))
        );
        assert_eq!(
            nap_mode(names(&["work/stash-drop", "work/stash-drop"]), &rules),
            Ok(NapMode::Guards(names(&["work/stash-drop"])))
        );
        assert!(nap_mode(names(&["all", "work"]), &rules).is_err());
        assert!(nap_mode(names(&["self", "work"]), &rules).is_err());
        let unknown = nap_mode(names(&["work", "nope"]), &rules).unwrap_err();
        assert!(unknown.contains("nope"), "{unknown}");
        // A 1.x name names the rules it became.
        let legacy = nap_mode(names(&["git-hard-reset"]), &rules).unwrap_err();
        assert!(legacy.contains("work/changes-discard"), "{legacy}");
        assert!(nap_mode(names(&["custom/corp"]), &rules).is_err());
    }

    #[test]
    fn confirmation_copy_distinguishes_self_and_all() {
        let guards = NapMode::Guards(vec!["secrets".into(), "work".into()]);
        let scopes = [
            nap_prompt(&NapMode::SelfProtection),
            nap_prompt(&NapMode::All),
            nap_prompt(&guards),
        ];
        for (index, scope) in scopes.iter().enumerate() {
            assert!(!scope.trim().is_empty());
            assert!(!scopes[..index].contains(scope));
        }
        assert!(scopes[2].contains("secrets") && scopes[2].contains("work"));
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
