use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, BoundaryClass, CoverageLevel, Domain, ExecutionEdgeKind, Plan, ProvenanceKind,
    ResourceExpr, Subject, display_resource, validate_plan,
};
use serde_json::json;

fn shell(source: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

#[test]
fn system_commands_preserve_targets_and_action_attributes() {
    for (source, op, resource, attrs) in [
        (
            "systemctl start nginx",
            "service_start",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl stop nginx",
            "service_stop",
            "svc:nginx",
            json!({"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "systemctl kill nginx",
            "service_stop",
            "svc:nginx",
            json!({"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "systemctl restart nginx",
            "service_restart",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl reload-or-restart nginx",
            "service_restart",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl try-restart nginx",
            "service_restart",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl reload nginx",
            "service_restart",
            "svc:nginx",
            json!({"reload":true}),
        ),
        (
            "systemctl enable nginx",
            "service_enable",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl preset nginx",
            "service_enable",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl disable nginx",
            "service_disable",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl --user --no-reload mask telemetry.service",
            "service_disable",
            "svc:telemetry.service",
            json!({"mask":true,"user_scope":true}),
        ),
        (
            "systemctl --now enable nginx",
            "service_start",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl --now disable nginx",
            "service_stop",
            "svc:nginx",
            json!({}),
        ),
        (
            "systemctl --runtime --now mask nginx",
            "service_stop",
            "svc:nginx",
            json!({"mask":true,"runtime":true}),
        ),
        (
            "systemctl isolate rescue.target",
            "service_stop",
            "sys:*",
            json!({"isolate":true,"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "systemctl isolate rescue.target",
            "service_start",
            "svc:rescue.target",
            json!({}),
        ),
        (
            "systemctl poweroff",
            "power",
            "host:self",
            json!({"action":"poweroff","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "service docker stop",
            "service_stop",
            "svc:docker",
            json!({"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "service docker reload",
            "service_restart",
            "svc:docker",
            json!({"reload":true}),
        ),
        (
            "sudo systemctl disable backup.service",
            "service_disable",
            "svc:backup.service",
            json!({}),
        ),
        (
            "shutdown -h now",
            "power",
            "host:self",
            json!({"action":"poweroff","when":"now","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "shutdown",
            "power",
            "host:self",
            json!({"action":"poweroff","when":"+1","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "shutdown -r +5",
            "power",
            "host:self",
            json!({"action":"reboot","when":"+5","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "shutdown -H now",
            "power",
            "host:self",
            json!({"action":"halt","when":"now","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "shutdown -c",
            "power",
            "host:self",
            json!({"cancel":true,"active":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "reboot",
            "power",
            "host:self",
            json!({"action":"reboot","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "halt",
            "power",
            "host:self",
            json!({"action":"halt","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "poweroff",
            "power",
            "host:self",
            json!({"action":"poweroff","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "init 0",
            "power",
            "host:self",
            json!({"action":"poweroff","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "telinit 6",
            "power",
            "host:self",
            json!({"action":"reboot","active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "init 3",
            "service_stop",
            "sys:*",
            json!({"isolate":true,"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "launchctl stop com.example.backup",
            "service_stop",
            "svc:com.example.backup",
            json!({"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "launchctl bootout system/com.example.backup",
            "service_stop",
            "svc:system/com.example.backup",
            json!({"active":true,"cancel":false,"help":false,"runtime_only":false,"persistent":false}),
        ),
        (
            "launchctl enable system/com.example.backup",
            "service_enable",
            "svc:system/com.example.backup",
            json!({}),
        ),
        (
            "launchctl disable gui/501/com.example.backup",
            "service_disable",
            "svc:gui/501/com.example.backup",
            json!({}),
        ),
        ("crontab -r", "scheduled_job_delete", "job:cron", json!({})),
        (
            "crontab -u alice -r",
            "scheduled_job_delete",
            "job:cron@alice",
            json!({}),
        ),
        (
            "crontab schedule.txt",
            "scheduled_job_write",
            "job:cron",
            json!({}),
        ),
        ("crontab -", "scheduled_job_write", "job:cron", json!({})),
        ("at now", "scheduled_job_write", "job:at", json!({})),
        ("at -r 3", "scheduled_job_delete", "job:at", json!({})),
        ("at -d 3", "scheduled_job_delete", "job:at", json!({})),
        ("atrm 3", "scheduled_job_delete", "job:at", json!({})),
        ("date -s now", "clock_set", "host:self", json!({})),
        ("date --set now", "clock_set", "host:self", json!({})),
        ("date --set=now", "clock_set", "host:self", json!({})),
        (
            "timedatectl set-time now",
            "clock_set",
            "host:self",
            json!({}),
        ),
        (
            "timedatectl set-timezone UTC",
            "clock_set",
            "host:self",
            json!({}),
        ),
        (
            "timedatectl set-ntp true",
            "clock_set",
            "host:self",
            json!({}),
        ),
        ("hwclock --systohc", "clock_set", "host:self", json!({})),
        ("hwclock -s", "clock_set", "host:self", json!({})),
    ] {
        let plan = shell(source);
        let effect = plan
            .effects
            .iter()
            .find(|e| {
                e.operation.0 == format!("system.{op}") && display_resource(&e.resource) == resource
            })
            .unwrap_or_else(|| panic!("{source}: {:?}", plan.effects));
        assert_eq!(
            serde_json::to_value(&effect.attributes).unwrap(),
            attrs,
            "{source}"
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("system")].level,
            if matches!(source, "crontab -" | "at now") {
                CoverageLevel::Partial
            } else {
                CoverageLevel::Full
            },
            "{source}"
        );
        if matches!(source, "crontab -" | "at now") {
            assert!(
                plan.boundaries
                    .iter()
                    .any(|b| b.reason.as_str() == "dynamic_source")
            );
        } else {
            assert!(
                plan.boundaries.is_empty(),
                "{source}: {:?}",
                plan.boundaries
            );
        }
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.0 == "process.signal")
        );
    }
    let plan = shell("systemctl stop nginx redis");
    assert_eq!(
        plan.effects
            .iter()
            .filter(|e| e.operation.0 == "system.service_stop")
            .count(),
        2
    );
    assert!(
        shell("crontab schedule.txt")
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.read"
                && display_resource(&e.resource) == "fs:/w/schedule.txt")
    );
    assert!(
        shell("printf true | at now")
            .effects
            .iter()
            .any(|e| e.operation.0 == "process.code_execution"
                && e.attributes.get("source") == Some(&AttrValue::String("stdin".into())))
    );
}

// A replacement, edit or removal changes the user's crontab through its
// scheduled-job effect alone; claiming the spool file too would name a path no
// cron layout agrees on and leave the filesystem domain unresolved.
#[test]
fn crontab_names_the_spool_file_only_without_a_scheduled_job_effect() {
    let spool = "join(fs:/var/spool/cron/, <fs:?>)";
    let files = |plan: &Plan| -> Vec<(String, String)> {
        plan.effects
            .iter()
            .filter(|e| e.operation.domain() == "filesystem")
            .map(|e| (e.operation.0.to_string(), display_resource(&e.resource)))
            .collect()
    };
    let backup = |name: &str| {
        format!("join(one_of($XDG_CACHE_HOME, join($HOME, \"/.cache\")), fs:crontab/{name})")
    };
    for (source, expected) in [
        ("crontab -l", vec![("filesystem.read", spool.to_string())]),
        ("crontab -c", vec![("filesystem.read", spool.to_string())]),
        ("crontab -n", vec![("filesystem.write", spool.to_string())]),
        (
            "crontab -r",
            vec![("filesystem.write", backup("crontab.bak"))],
        ),
        ("crontab -b -r", vec![]),
        (
            "crontab -ir -ualice",
            vec![(
                "filesystem.write",
                format!(
                    "one_of({}, {})",
                    backup("crontab.alice.bak"),
                    backup("crontab.bak")
                ),
            )],
        ),
        (
            "crontab schedule.txt",
            vec![
                ("filesystem.write", backup("crontab.bak")),
                ("filesystem.read", "fs:/w/schedule.txt".to_string()),
            ],
        ),
        (
            "crontab -T schedule.txt",
            vec![("filesystem.read", "fs:/w/schedule.txt".to_string())],
        ),
        // getopt rejects the option or the second action before any runs.
        ("crontab -q -r", vec![]),
        ("crontab -l -r", vec![]),
        ("crontab -u", vec![]),
    ] {
        let plan = shell(source);
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(operation, resource)| (operation.to_string(), resource))
            .collect();
        assert_eq!(files(&plan), expected, "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("filesystem")].level,
            CoverageLevel::Full,
            "{source}"
        );
    }

    // -e installs what an editor named by VISUAL or EDITOR leaves behind.
    let edit = shell("crontab -e");
    assert!(
        edit.effects
            .iter()
            .any(|e| e.operation.0 == "system.scheduled_job_write")
    );
    assert_eq!(
        files(&edit),
        [("filesystem.write".to_string(), backup("crontab.bak"))]
    );
    assert!(edit.effects.iter().any(|e| e.operation.0 == "process.exec"
        && matches!(e.resource, ResourceExpr::Unresolved { .. })));
    assert!(
        edit.boundaries
            .iter()
            .any(|b| b.reason.as_str() == "unresolved_command")
    );

    // Bare crontab installs from stdin like `-`.
    let piped = shell("printf '* * * * * rm -rf /x\\n' | crontab");
    assert!(
        piped
            .effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"
                && display_resource(&e.resource) == "fs:/x")
    );
}

#[test]
fn at_analyzes_literal_jobs_and_marks_unresolved_jobs_opaque() {
    let literal = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: "at now <<< 'rm -rf /'".into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&literal).unwrap();
    let scheduled = literal
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "system.scheduled_job_write")
        .unwrap();
    assert!(literal.effects.iter().any(|effect| {
        effect.operation.0 == "process.code_execution"
            && effect.attributes.get("source") == Some(&AttrValue::String("stdin".into()))
    }));
    let delete = literal
        .effects
        .iter()
        .find(|effect| {
            effect.operation.0 == "filesystem.delete"
                && display_resource(&effect.resource) == "fs:/"
        })
        .unwrap();
    let deferred = literal
        .execution_graph
        .edges
        .iter()
        .find(|edge| edge.from == scheduled.execution && edge.kind == ExecutionEdgeKind::Script)
        .unwrap();
    assert!(literal.execution_graph.edges.iter().any(|edge| {
        edge.from == deferred.to
            && edge.to == delete.execution
            && edge.kind == ExecutionEdgeKind::Launch
    }));
    assert!(literal.boundaries.is_empty(), "{:?}", literal.boundaries);

    for source in ["at now", "at now <<< \"$JOB\""] {
        let plan = shell(source);
        let boundary = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason.as_str() == "unrecoverable_source")
            .unwrap_or_else(|| panic!("{source}: {:?}", plan.boundaries));
        assert_eq!(
            boundary.domains,
            ["environment", "filesystem", "network", "process", "system"]
                .into_iter()
                .map(Domain::new)
                .collect::<Vec<_>>()
        );
        let dynamic = plan
            .boundaries
            .iter()
            .find(|boundary| boundary.reason.as_str() == "dynamic_source")
            .unwrap_or_else(|| panic!("{source}: {:?}", plan.boundaries));
        assert_eq!(dynamic.class, BoundaryClass::Unresolved);
        assert_eq!(dynamic.domains, boundary.domains);
        assert_eq!(dynamic.provenance, boundary.provenance);
        for domain in &boundary.domains {
            assert_eq!(plan.coverage.level(domain), Some(CoverageLevel::Partial));
        }
        if source.contains("$JOB") {
            assert!(boundary.provenance.iter().any(|reference| matches!(
                plan.provenance[reference.0 as usize].kind,
                ProvenanceKind::SourceSpan { .. }
            )));
        }
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "system.scheduled_job_write")
        );
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution")
        );
    }

    for source in ["atrm 3", "at -r 3", "at -d 3"] {
        let removal = shell(source);
        assert!(removal.boundaries.is_empty(), "{source}");
        assert!(
            !removal
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "process.code_execution"),
            "{source}"
        );
    }

    let file = shell("at -f job.sh now");
    assert!(file.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && display_resource(&effect.resource) == "fs:/w/job.sh"
    }));
    assert!(file.effects.iter().any(|effect| {
        effect.operation.0 == "process.code_execution"
            && effect.attributes.get("source") == Some(&AttrValue::String("file".into()))
    }));
    assert!(file.boundaries.iter().any(|boundary| {
        boundary.reason.as_str() == "unrecoverable_source"
            && boundary.domains.contains(&Domain::new("system"))
    }));
    assert_eq!(
        file.coverage.level(&Domain::new("system")),
        Some(CoverageLevel::Partial)
    );

    let written = shell("printf 'rm -rf /queued\n' > job.sh; at -f job.sh now");
    assert!(written.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && display_resource(&effect.resource) == "fs:/queued"
    }));
}

#[test]
fn system_read_only_forms_and_unknown_verbs_have_honest_coverage() {
    for source in [
        "systemctl status nginx",
        "systemctl --dry-run poweroff",
        "systemctl show nginx",
        "systemctl list-units",
        "systemctl is-active nginx",
        "systemctl cat nginx",
        "systemctl daemon-reload",
        "systemctl daemon-reexec",
        "service nginx status",
        "shutdown -k now",
        "crontab -l",
        "at -l",
        "at -c 3",
        "date -u +%F",
        "date -d yesterday",
        "date -Iseconds",
        "date --rfc-3339=seconds",
        "timedatectl status",
        "hwclock --show",
    ] {
        let plan = shell(source);
        assert!(
            !plan
                .effects
                .iter()
                .any(|e| e.operation.domain() == "system"),
            "{source}"
        );
        assert!(plan.boundaries.is_empty(), "{source}");
        assert_eq!(
            plan.coverage.0[&Domain::new("system")].level,
            CoverageLevel::Full
        );
        if source.starts_with("at ") {
            assert!(
                !plan
                    .effects
                    .iter()
                    .any(|effect| effect.operation.0 == "process.code_execution"),
                "{source}"
            );
        }
    }
    for source in ["systemctl frobnicate x", "service nginx frobnicate"] {
        let plan = shell(source);
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_subcommand"
                    && b.domains == vec![Domain::new("system")])
        );
        assert_eq!(
            plan.coverage.0[&Domain::new("system")].level,
            CoverageLevel::Partial
        );
    }
    for (source, expected_shell) in [
        ("printf '* * * * * chmod 000 /bin/tool' | crontab -", None),
        (
            "printf 'SHELL = /bin/bash\n@reboot chmod 000 /bin/tool\n' | crontab -",
            Some("/bin/bash"),
        ),
    ] {
        let cron = shell(source);
        assert!(
            cron.effects
                .iter()
                .any(|effect| effect.operation.0 == "system.scheduled_job_write")
        );
        assert!(cron.effects.iter().any(|effect| {
            effect.operation.0 == "filesystem.metadata"
                && display_resource(&effect.resource) == "fs:/bin/tool"
        }));
        assert!(
            cron.boundaries.is_empty(),
            "{source}: {:?}",
            cron.boundaries
        );
        let nested = cron
            .execution_graph
            .nodes
            .iter()
            .find(|node| {
                matches!(&node.subject, Subject::Shell { source, .. } if source.starts_with("chmod "))
            })
            .unwrap();
        assert_eq!(
            nested.environment.get("SHELL").and_then(Option::as_ref),
            expected_shell
                .map(|value| ResourceExpr::Literal {
                    value: value.to_string()
                })
                .as_ref()
        );
    }
    for source in ["date --reference /etc/passwd"] {
        let plan = shell(source);
        let boundary = plan
            .boundaries
            .iter()
            .position(|b| b.reason.as_str() == "unrecognized_arguments")
            .unwrap();
        for domain in ["filesystem", "process", "system"] {
            let domain = Domain::new(domain);
            assert_eq!(plan.coverage.level(&domain), Some(CoverageLevel::Partial));
            assert!(
                plan.coverage
                    .gaps(&domain)
                    .contains(&effinterp_proto::BoundaryRef(boundary as u32))
            );
        }
    }
}

#[test]
fn date_file_inputs_are_program_inputs_only_for_accepted_display_grammar() {
    for source in [
        "date -f dates.txt",
        "date --file dates.txt",
        "date --file=dates.txt",
        "date -f dates.txt +%F",
        "date -f dates.txt -R",
        "date -f dates.txt -R --rfc-3339=seconds",
        "date -f dates.txt -Iseconds",
    ] {
        let plan = shell(source);
        let read = plan
            .effects
            .iter()
            .find(|effect| {
                effect.operation.0 == "filesystem.read"
                    && display_resource(&effect.resource) == "fs:/w/dates.txt"
            })
            .unwrap_or_else(|| panic!("missing date input read for {source}"));
        assert_eq!(
            read.attributes.get("access_purpose"),
            Some(&AttrValue::String("program_input".into())),
            "{source}"
        );
        assert!(plan.boundaries.is_empty(), "{source}");
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "system.clock_set"),
            "{source}"
        );
    }

    let repeated = shell("date -f ignored.txt --file dates.txt");
    assert!(repeated.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && display_resource(&effect.resource) == "fs:/w/dates.txt"
    }));
    assert!(!repeated.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.read"
            && display_resource(&effect.resource) == "fs:/w/ignored.txt"
    }));

    let stdin = shell("date --file=-");
    assert!(
        !stdin
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(stdin.boundaries.is_empty());

    for source in [
        "date -f",
        "date --file=",
        "date -f dates.txt -d yesterday",
        "date -f dates.txt -s now",
        "date -f dates.txt --rfc-3339=invalid",
        "date -f dates.txt -R +%F",
        "date -f dates.txt +%F --rfc-3339=seconds",
        "date -f dates.txt -Iseconds +%F",
        "date --file dates.txt --unknown",
    ] {
        let plan = shell(source);
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.read"
                    || effect.operation.0 == "system.clock_set"),
            "{source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unrecognized_arguments"),
            "{source}"
        );
    }
}

#[test]
fn system_controls_reject_help_dry_run_and_unknown_options() {
    for source in [
        "systemctl --help stop sshd",
        "systemctl stop --unknown sshd",
        "systemctl --global stop sshd",
        "systemctl --global poweroff",
        "systemctl --root --help stop sshd",
        "systemctl --dry-run stop sshd",
        "shutdown --help",
        "shutdown --unknown now",
        "reboot --unknown",
        "reboot -k",
        "halt -r",
        "reboot now",
        "shutdown tomorrow",
        "shutdown 99:99",
        "shutdown é",
        "shutdown -hk now",
        "service docker stop --unknown",
    ] {
        let plan = shell(source);
        assert!(
            !plan.effects.iter().any(|effect| {
                matches!(
                    effect.operation.0.as_str(),
                    "system.power" | "system.service_stop"
                )
            }),
            "{source}: {:?}",
            plan.effects
        );
    }
    let cancel = shell("shutdown -c now");
    let effect = cancel
        .effects
        .iter()
        .find(|effect| effect.operation.0 == "system.power")
        .expect("cancellation remains explicit");
    assert_eq!(
        effect.attributes.get("active"),
        Some(&AttrValue::Bool(false))
    );
    assert_eq!(
        effect.attributes.get("cancel"),
        Some(&AttrValue::Bool(true))
    );
    assert!(shell("shutdown now --help").effects.iter().any(|effect| {
        effect.operation.0 == "system.power"
            && effect.attributes.get("active") == Some(&AttrValue::Bool(true))
    }));
    assert!(!shell("shutdown -rc now").effects.iter().any(|effect| {
        effect.operation.0 == "system.power"
            && effect.attributes.get("active") == Some(&AttrValue::Bool(true))
    }));
}

#[test]
fn kernel_writes_layer_system_effects_with_the_same_execution_context() {
    for source in [
        "echo b > /proc/sysrq-trigger",
        "printf b | tee /proc/sysrq-trigger",
        "dd of=/proc/sys/kernel/sysrq",
        "cp input /sys/power/state",
        "true && echo b > /proc/sysrq-trigger",
    ] {
        let plan = shell(source);
        let trigger = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "system.kernel_trigger")
            .unwrap();
        let write = plan
            .effects
            .iter()
            .find(|e| e.operation.0 == "filesystem.write" && e.resource == trigger.resource)
            .unwrap();
        assert_eq!(trigger.provenance, write.provenance);
        assert_eq!(trigger.realm, write.realm);
        assert_eq!(trigger.condition, write.condition);
        assert_eq!(trigger.execution, write.execution);
        assert_eq!(
            plan.coverage.0[&Domain::new("system")].level,
            CoverageLevel::Full
        );
    }
    assert!(
        !shell("echo b > /tmp/x")
            .effects
            .iter()
            .any(|e| e.operation.domain() == "system")
    );
}

#[test]
fn powershell_power_requires_a_literal_local_command() {
    for source in ["Stop-Computer", "stop-computer -Force"] {
        let plan = shell(&format!("pwsh -Command '{source}'"));
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == "system.power")
            .unwrap();
        assert_eq!(display_resource(&effect.resource), "host:self");
        assert_eq!(
            effect.attributes.get("active"),
            Some(&AttrValue::Bool(true))
        );
        assert_eq!(
            effect.attributes.get("action"),
            Some(&AttrValue::String("poweroff".into()))
        );
    }
    for source in [
        "Stop-Computer -WhatIf",
        "Stop-Computer -Unknown",
        "Stop-Computer -Force -Force",
        "Stop-Computer $args",
    ] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            !plan
                .effects
                .iter()
                .any(|effect| effect.operation.0 == "system.power"),
            "{source}"
        );
        assert_eq!(
            plan.boundaries.len(),
            usize::from(!source.contains("-WhatIf")),
            "{source}"
        );
    }
    // A statement separator does not hide the power statement: it runs, and
    // the statement beside it that no grammar reaches is one boundary.
    for source in ["Stop-Computer; Get-Item x", "Stop-Computer\nGet-Item x"] {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: None,
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        assert!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.0 == "system.power"),
            "{source}"
        );
        assert_eq!(plan.boundaries.len(), 1, "{source}");
    }
}

fn effects(plan: &Plan) -> Vec<(String, String, serde_json::Value)> {
    plan.effects
        .iter()
        .filter(|e| matches!(e.operation.domain(), "system" | "filesystem"))
        .map(|e| {
            (
                e.operation.0.to_string(),
                display_resource(&e.resource),
                serde_json::to_value(&e.attributes).unwrap(),
            )
        })
        .collect()
}

#[test]
fn systemctl_sleep_states_and_scheduled_shutdowns_are_power_actions() {
    let power = |attrs: serde_json::Value| {
        let mut attrs = attrs;
        for (name, value) in [
            ("active", true),
            ("cancel", false),
            ("help", false),
            ("runtime_only", false),
            ("persistent", false),
        ] {
            attrs[name] = json!(value);
        }
        attrs
    };
    for (source, attrs) in [
        (
            "systemctl hybrid-sleep",
            power(json!({"action": "hybrid-sleep"})),
        ),
        (
            "systemctl suspend-then-hibernate",
            power(json!({"action": "suspend-then-hibernate"})),
        ),
        (
            "systemctl --when=tomorrow reboot",
            power(json!({"action": "reboot", "when": "tomorrow"})),
        ),
        (
            "systemctl --when 18:00 poweroff",
            power(json!({"action": "poweroff", "when": "18:00"})),
        ),
        (
            "systemctl --when=cancel reboot",
            json!({"active": false, "cancel": true, "help": false, "runtime_only": false, "persistent": false}),
        ),
    ] {
        let plan = shell(source);
        assert_eq!(
            effects(&plan),
            [("system.power".into(), "host:self".into(), attrs)],
            "{source}"
        );
        assert!(plan.coverage.is_full(&Domain::new("system")), "{source}");
    }
    // --when=show only prints the schedule; only the shutdown verbs take --when.
    assert!(effects(&shell("systemctl --when=show reboot")).is_empty());
    let enable = shell("systemctl --when=now enable backup.service");
    assert!(effects(&enable).is_empty());
    assert_eq!(
        enable.coverage.level(&Domain::new("system")),
        Some(CoverageLevel::Partial)
    );
}

#[test]
fn systemctl_unit_file_commands_change_startup() {
    for (source, expected) in [
        (
            "systemctl reenable backup.service",
            vec![
                ("system.service_disable", "svc:backup.service", json!({})),
                ("system.service_enable", "svc:backup.service", json!({})),
            ],
        ),
        (
            "systemctl unmask backup.service",
            vec![(
                "system.service_enable",
                "svc:backup.service",
                json!({"unmask": true}),
            )],
        ),
        (
            "systemctl revert backup.service",
            vec![(
                "system.service_enable",
                "svc:backup.service",
                json!({"revert": true}),
            )],
        ),
        (
            "systemctl link /tmp/backup.service",
            vec![(
                "system.service_enable",
                "svc:backup.service",
                json!({"link": true}),
            )],
        ),
        (
            "HOME=/home/dev systemctl link ~/backup.service",
            vec![(
                "system.service_enable",
                "svc:backup.service",
                json!({"link": true}),
            )],
        ),
        (
            "systemctl set-default multi-user.target",
            vec![(
                "system.service_enable",
                "svc:multi-user.target",
                json!({"default": true}),
            )],
        ),
        (
            "systemctl add-wants multi-user.target backup.service",
            vec![(
                "system.service_enable",
                "svc:backup.service",
                json!({"dependency": "wants", "target": "multi-user.target"}),
            )],
        ),
        (
            "systemctl --preset-mode=enable-only preset backup.service",
            vec![("system.service_enable", "svc:backup.service", json!({}))],
        ),
        (
            "systemctl --preset-mode disable-only preset backup.service",
            vec![("system.service_disable", "svc:backup.service", json!({}))],
        ),
        (
            "systemctl preset-all",
            vec![
                ("system.service_enable", "sys:*", json!({})),
                ("system.service_disable", "sys:*", json!({})),
            ],
        ),
        (
            "systemctl edit --stdin backup.service",
            vec![(
                "filesystem.write",
                "fs:/etc/systemd/system/backup.service.d/override.conf",
                json!({}),
            )],
        ),
        (
            "systemctl edit --stdin --drop-in=limits backup.service",
            vec![(
                "filesystem.write",
                "fs:/etc/systemd/system/backup.service.d/limits.conf",
                json!({}),
            )],
        ),
        (
            "systemctl edit --stdin --full --drop-in=override.conf backup.service",
            vec![(
                "filesystem.write",
                "fs:/etc/systemd/system/backup.service",
                json!({}),
            )],
        ),
        (
            "systemctl --user edit --stdin backup.service",
            vec![(
                "filesystem.write",
                r#"join(one_of($XDG_CONFIG_HOME, join($HOME, "/.config")), fs:systemd/user/backup.service.d/override.conf)"#,
                json!({}),
            )],
        ),
    ] {
        let plan = shell(source);
        let expected = expected
            .into_iter()
            .map(|(op, resource, attrs)| (op.to_string(), resource.to_string(), attrs))
            .collect::<Vec<_>>();
        assert_eq!(effects(&plan), expected, "{source}");
        assert!(plan.coverage.is_full(&Domain::new("system")), "{source}");
    }
    // An editor session, a unit-less set-default and preset-all with units stay unmodeled.
    for source in [
        "systemctl edit backup.service",
        "systemctl set-default",
        "systemctl preset-all backup.service",
        "systemctl --stdin enable backup.service",
        "systemctl --user --runtime edit --stdin backup.service",
    ] {
        let plan = shell(source);
        assert!(effects(&plan).is_empty(), "{source}");
        assert_eq!(
            plan.coverage.level(&Domain::new("system")),
            Some(CoverageLevel::Partial),
            "{source}"
        );
    }
}

#[test]
fn systemctl_host_and_machine_run_the_command_in_their_realm() {
    for (source, realm) in [
        (
            "systemctl --user --host admin@host --no-block enable backup.service",
            effinterp_proto::ExecutionRealm::Remote {
                endpoint: "host".into(),
            },
        ),
        (
            "systemctl -Hhost disable backup.service",
            effinterp_proto::ExecutionRealm::Remote {
                endpoint: "host".into(),
            },
        ),
        (
            "systemctl -q -H host -M machine --now enable backup.service",
            effinterp_proto::ExecutionRealm::Container {
                runtime: "systemd-nspawn".into(),
                name: "machine".into(),
            },
        ),
    ] {
        let plan = shell(source);
        let enabled = plan
            .effects
            .iter()
            .filter(|e| e.operation.domain() == "system")
            .collect::<Vec<_>>();
        assert!(!enabled.is_empty(), "{source}");
        assert!(enabled.iter().all(|e| e.realm == realm), "{source}");
        assert!(plan.coverage.is_full(&Domain::new("system")), "{source}");
    }
}
