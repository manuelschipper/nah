mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
use nah_proto::ctx::Platform;
use support::{bash_plan_on, observe_on};

fn stream(source: &str, platform: Platform) -> ActionStream {
    let plan = bash_plan_on(source, platform);
    finalize(
        plan.clone(),
        observe_on(plan.observation_request(), "echo", platform),
    )
}

fn manages_startup(source: &str, platform: Platform) -> bool {
    has_system_state(source, platform, &SemanticCode::STARTUP_MANAGEMENT)
}

fn stops_service(source: &str, platform: Platform) -> bool {
    has_system_state(source, platform, &SemanticCode::SERVICE_STOP)
}

fn has_system_state(source: &str, platform: Platform, expected: &SemanticCode) -> bool {
    stream(source, platform).effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation }
                if operation == expected
        )
    })
}

#[test]
fn linux_systemctl_persistent_unit_file_commands_are_recognized() {
    for source in [
        "systemctl enable backup.service",
        "systemctl disable backup.service",
        "systemctl reenable backup.service",
        "systemctl preset backup.service",
        "systemctl preset-all",
        "systemctl mask backup.service",
        "systemctl unmask backup.service",
        "systemctl link /tmp/backup.service",
        "systemctl link ~/backup.service",
        "systemctl revert backup.service",
        "systemctl add-wants multi-user.target backup.service",
        "systemctl add-requires multi-user.target backup.service",
        "systemctl set-default multi-user.target",
        "systemctl edit --stdin backup.service",
        "systemctl --user --host host --force --no-reload --no-block --quiet --no-pager --no-ask-password enable backup.service",
        "systemctl -q -H host -M machine --now enable backup.service",
        "systemctl --global --host=host --machine=machine disable backup.service",
        "systemctl --preset-mode=enable-only preset backup.service",
        "systemctl edit --stdin --full --drop-in=override.conf backup.service",
        "/bin/systemctl enable backup.service",
        "/sbin/systemctl enable backup.service",
        "/usr/bin/systemctl enable backup.service",
        "/usr/sbin/systemctl enable backup.service",
    ] {
        assert!(
            manages_startup(source, Platform::Linux),
            "expected startup-management effect for {source}"
        );
    }
}

#[test]
fn systemctl_runtime_offline_editor_and_malformed_forms_remain_outside() {
    for source in [
        "systemctl enable",
        "systemctl preset-all backup.service",
        "systemctl add-wants multi-user.target",
        "systemctl set-default",
        "systemctl set-default one.target two.target",
        "systemctl edit backup.service",
        "systemctl --stdin enable backup.service",
        "systemctl --preset-mode=full enable backup.service",
        "systemctl --runtime enable backup.service",
        "systemctl --root /mnt enable backup.service",
        "systemctl --root=/mnt enable backup.service",
        "systemctl --image /tmp/root.raw enable backup.service",
        "systemctl --image=/tmp/root.raw enable backup.service",
        "systemctl --dry-run enable backup.service",
        "systemctl start backup.service",
        "systemctl stop backup.service",
        "systemctl restart backup.service",
        "systemctl reload backup.service",
        "systemctl status backup.service",
        "systemctl daemon-reload",
        "systemctl --help enable backup.service",
        "systemctl --version",
        "systemctl --host enable backup.service",
        "systemctl -H enable backup.service",
        "systemctl --machine enable backup.service",
        "systemctl edit --stdin --drop-in --force backup.service",
        "systemctl --preset-mode --force preset backup.service",
        "systemctl --unknown-scope enable backup.service",
        "systemctl enable *.service",
        "systemctl \"$VERB\" backup.service",
        "systemctl enable \"$UNIT\"",
        "/tmp/systemctl enable backup.service",
    ] {
        assert!(
            !manages_startup(source, Platform::Linux),
            "unexpected startup-management effect for {source}"
        );
    }
    assert!(!manages_startup(
        "systemctl enable backup.service",
        Platform::Macos
    ));
}

#[test]
fn macos_launchctl_persistent_forms_are_recognized() {
    for source in [
        "launchctl enable system/com.example.backup",
        "launchctl disable gui/501/com.example.backup",
        "launchctl load -w /Library/LaunchDaemons/com.example.backup.plist",
        "launchctl load -w ~/Library/LaunchAgents/com.example.backup.plist",
        "launchctl unload -Fw -S Background /Library/LaunchAgents/com.example.backup.plist",
        "launchctl load -wDsystem /Library/LaunchDaemons/com.example.backup.plist",
        "/bin/launchctl disable system/com.example.backup",
        "/usr/bin/launchctl enable system/com.example.backup",
    ] {
        assert!(
            manages_startup(source, Platform::Macos),
            "expected startup-management effect for {source}"
        );
    }
}

#[test]
fn launchctl_runtime_dynamic_and_malformed_forms_remain_outside() {
    for source in [
        "launchctl enable",
        "launchctl enable com.example.backup",
        "launchctl enable other/com.example.backup",
        "launchctl enable system/com/example/backup",
        "launchctl enable system/com.example.backup extra",
        "launchctl load /Library/LaunchDaemons/com.example.backup.plist",
        "launchctl load -w",
        "launchctl load -w -",
        "launchctl load -S /Library/LaunchDaemons/com.example.backup.plist",
        "launchctl load -xw /Library/LaunchDaemons/com.example.backup.plist",
        "launchctl bootstrap system /Library/LaunchDaemons/com.example.backup.plist",
        "launchctl bootout system/com.example.backup",
        "launchctl start com.example.backup",
        "launchctl stop com.example.backup",
        "launchctl kickstart system/com.example.backup",
        "launchctl submit -l backup -- /bin/true",
        "launchctl config system path /usr/bin",
        "launchctl enable \"$TARGET\"",
        "launchctl load -w /Library/LaunchDaemons/*.plist",
        "/tmp/launchctl enable system/com.example.backup",
    ] {
        assert!(
            !manages_startup(source, Platform::Macos),
            "unexpected startup-management effect for {source}"
        );
    }
    assert!(!manages_startup(
        "launchctl enable system/com.example.backup",
        Platform::Linux
    ));
}

#[test]
fn crontab_install_and_removal_forms_are_recognized_on_supported_hosts() {
    for platform in [Platform::Linux, Platform::Macos] {
        for source in [
            "crontab -",
            "crontab schedule.txt",
            "crontab ~/schedule.txt",
            "crontab -r",
            "crontab -i -r",
            "crontab -u root -",
            "crontab -uroot schedule.txt",
            "crontab -u root -r",
            "/usr/bin/crontab schedule.txt",
        ] {
            assert!(
                manages_startup(source, platform),
                "expected startup-management effect for {source} on {platform:?}"
            );
        }
    }
}

#[test]
fn crontab_read_editor_test_dynamic_and_malformed_forms_remain_outside() {
    for source in [
        "crontab -l",
        "crontab -e",
        "crontab -T schedule.txt",
        "crontab --help",
        "crontab --version",
        "crontab -u",
        "crontab -u -r",
        "crontab -i schedule.txt",
        "crontab -r schedule.txt",
        "crontab one two",
        "crontab \"$FILE\"",
        "/tmp/crontab schedule.txt",
    ] {
        assert!(
            !manages_startup(source, Platform::Linux),
            "unexpected startup-management effect for {source}"
        );
    }
}

#[test]
fn linux_service_stop_forms_are_recognized() {
    for source in [
        "systemctl stop sshd",
        "systemctl kill sshd",
        "systemctl isolate rescue.target",
        "systemctl stop sshd nginx",
        "systemctl --user --quiet stop backup.service",
        "systemctl -- stop sshd",
        "service docker stop",
        "service 'sshd' stop",
        "sudo systemctl stop sshd",
        "/bin/systemctl stop sshd",
        "/usr/sbin/systemctl isolate emergency.target",
    ] {
        assert!(
            stops_service(source, Platform::Linux),
            "expected service-stop effect for {source}"
        );
        assert!(
            !manages_startup(source, Platform::Linux),
            "service-stop must not also be startup-management for {source}"
        );
    }
}

#[test]
fn service_stop_carve_outs_remain_outside() {
    for source in [
        "systemctl stop",
        "systemctl start sshd",
        "systemctl restart sshd",
        "systemctl reload sshd",
        "systemctl daemon-reload",
        "systemctl status sshd",
        "systemctl --help stop sshd",
        "systemctl stop --help",
        "systemctl --dry-run stop sshd",
        "systemctl --runtime stop sshd",
        "systemctl --root /mnt stop sshd",
        "systemctl --image /tmp/root.raw stop sshd",
        "systemctl stop *.service",
        "systemctl stop \"$UNIT\"",
        "systemctl isolate",
        "service docker start",
        "service docker restart",
        "service docker stop extra",
        "service --status-all",
        "service stop docker",
        "/tmp/systemctl stop sshd",
    ] {
        assert!(
            !stops_service(source, Platform::Linux),
            "unexpected service-stop effect for {source}"
        );
    }
    assert!(!stops_service("systemctl stop sshd", Platform::Macos));
    assert!(!stops_service("service docker stop", Platform::Macos));
}

#[test]
fn macos_launchctl_stop_forms_are_recognized() {
    for source in [
        "launchctl stop com.example.backup",
        "launchctl bootout system/com.example.backup",
        "launchctl bootout gui/501/com.example.backup",
        "/bin/launchctl stop com.example.backup",
    ] {
        assert!(
            stops_service(source, Platform::Macos),
            "expected service-stop effect for {source}"
        );
        assert!(
            !manages_startup(source, Platform::Macos),
            "service-stop must not also be startup-management for {source}"
        );
    }
}

#[test]
fn launchctl_restart_and_malformed_stop_forms_remain_outside() {
    for source in [
        "launchctl start com.example.backup",
        "launchctl kickstart -k system/com.example.backup",
        "launchctl kickstart system/com.example.backup",
        "launchctl stop",
        "launchctl stop -x com.example.backup",
        "launchctl bootout",
        "launchctl bootout system",
        "launchctl bootout system/com.example.backup extra",
        "launchctl stop \"$LABEL\"",
        "/tmp/launchctl stop com.example.backup",
    ] {
        assert!(
            !stops_service(source, Platform::Macos),
            "unexpected service-stop effect for {source}"
        );
    }
    assert!(!stops_service(
        "launchctl stop com.example.backup",
        Platform::Linux
    ));
}
