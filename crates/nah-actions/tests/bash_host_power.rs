mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, InvocationEffect, SemanticCode};
use support::{bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn has_host_power(source: &str) -> bool {
    stream(source).effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::Invocation {
                invocation: InvocationEffect::Known { operation, .. }
            } if operation == &SemanticCode::HOST_POWER
        )
    })
}

#[test]
fn reviewed_unix_host_power_forms_are_typed() {
    for source in [
        "shutdown now",
        "shutdown -h now",
        "shutdown --reboot +5 maintenance",
        "reboot",
        "reboot -f",
        "halt --no-wall",
        "poweroff -n",
        "init 0",
        "telinit 6",
        "systemctl poweroff",
        "systemctl reboot --force",
        "systemctl halt",
        "systemctl kexec",
        "systemctl suspend",
        "systemctl hibernate",
        "systemctl hybrid-sleep",
        "systemctl suspend-then-hibernate",
        "systemctl --when=tomorrow reboot",
    ] {
        assert!(has_host_power(source), "{source}");
    }
}

#[test]
fn wrappers_and_system_paths_preserve_host_power_identity() {
    for source in [
        "sudo shutdown -P now",
        "sudo -n /sbin/reboot",
        "/bin/systemctl poweroff",
        "/sbin/halt",
        "/usr/bin/systemctl suspend",
        "/usr//bin/systemctl hibernate",
        "PATH=/tmp /usr/sbin/shutdown -r now",
    ] {
        assert!(has_host_power(source), "{source}");
    }
}

#[test]
fn non_executing_and_unreviewed_forms_do_not_acquire_host_power() {
    for source in [
        "shutdown --help",
        "shutdown --version",
        "shutdown -c",
        "shutdown -k now",
        "shutdown --show",
        "reboot -w",
        "poweroff --wtmp-only",
        "halt --dry-run",
        "systemctl --dry-run poweroff",
        "systemctl reboot --dry-run",
        "systemctl --when=show reboot",
        "shutdown -h",
        "init",
        "init 2",
        "systemctl",
        "systemctl restart sshd",
        "systemctl --host remote reboot",
        "reboot later",
        "shutdown --unknown now",
        "systemctl reboot extra",
    ] {
        assert!(!has_host_power(source), "{source}");
    }
}

#[test]
fn dynamic_path_overridden_and_arbitrary_executables_stay_outside() {
    for source in [
        "ACTION=reboot; $ACTION",
        "systemctl \"$ACTION\"",
        "shutdown -h \"$WHEN\"",
        "init \"$LEVEL\"",
        "PATH=/tmp reboot",
        "export PATH=/tmp; systemctl poweroff",
        "./reboot",
        "/tmp/reboot",
    ] {
        assert!(!has_host_power(source), "{source}");
    }
}
