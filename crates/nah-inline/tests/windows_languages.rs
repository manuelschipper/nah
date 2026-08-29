use nah_inline::{
    FindingKind, InlineInput, LanguageAnalysis, LanguageCallKind, NestedExecution, ProtectionInput,
    interpret_language_effects,
};
use nah_proto::{
    action::FilesystemOperation,
    ctx::{AbsolutePath, Platform},
};

fn analyze(program: &str, code: &str) -> LanguageAnalysis {
    analyze_on(program, code, Platform::Windows, r"C:\Users\test")
}

fn analyze_on(program: &str, code: &str, platform: Platform, home: &str) -> LanguageAnalysis {
    interpret_language_effects(
        InlineInput {
            program,
            code,
            home,
            platform,
        },
        ProtectionInput {
            critical_paths: &[],
            ambient_variables: &[],
        },
    )
}

#[test]
fn powershell_collection_bindings_remain_partial_and_keep_protection_active() {
    for source in [
        r"Remove-Item -Recurse -LiteralPath 'safe','C:\Users\test'",
        r"Move-Item -Path 'first','second' -Destination 'target'",
        r"Get-Content -Path 'first','second'",
        r"Set-Content -Path 'first','second' -Value 'value'",
        r"Set-Content -Path 'target' -Value 'first','second'",
    ] {
        assert!(!analyze("pwsh", source).draft().complete(), "{source}");
    }

    let critical = AbsolutePath::new(Platform::Windows, r"C:\Users\test\.nah\policy.toml").unwrap();
    let analysis = interpret_language_effects(
        InlineInput {
            program: "pwsh",
            code: r"Set-Content -Path 'safe','C:\Users\test\.nah\policy.toml' -Value x",
            home: r"C:\Users\test",
            platform: Platform::Windows,
        },
        ProtectionInput {
            critical_paths: &[critical],
            ambient_variables: &[],
        },
    );
    assert!(
        analysis
            .report()
            .contains_conservative(FindingKind::NahTampering)
    );
}

#[test]
fn powershell_filesystem_cmdlets_emit_bounded_typed_operations() {
    let analysis = analyze(
        "pwsh",
        r#"Remove-Item -Recurse -Path 'C:\cache\*'; Move-Item -LiteralPath 'C:\from' -Destination 'C:\to'; Get-Content 'C:\read'; Set-Content -Path 'C:\write' -Value 'x'; Add-Content 'C:\append' 'x'; Clear-Content 'C:\clear'; 'x' | Out-File 'C:\out'; 'x' > 'C:\redirect'"#,
    );
    let calls = analysis.draft().calls();
    assert!(analysis.draft().complete());
    assert_eq!(calls.len(), 8);
    assert_eq!(
        calls[0].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert!(calls[0].filesystems()[0].recursive());
    assert!(calls[0].filesystems()[0].pattern());
    assert!(!calls[1].filesystems()[0].pattern());
    assert_eq!(calls[1].filesystems()[1].identity_path(), Some(r"C:\from"));
    assert_eq!(
        calls[2].filesystems()[0].operation(),
        FilesystemOperation::Read
    );
    assert!(calls[3..].iter().all(|call| {
        call.filesystems()
            .iter()
            .all(|filesystem| filesystem.operation() == FilesystemOperation::Write)
    }));
}

#[test]
fn powershell_false_positive_controls_do_not_overclaim() {
    for source in [
        r"Remove-Item -Recurse C:\ -WhatIf",
        r"Remove-Item -Recurse C:\ -WhatIf:$true",
        r"Out-File C:\target -WhatIf",
    ] {
        let what_if = analyze("pwsh", source);
        assert!(
            what_if.draft().calls()[0].filesystems().is_empty(),
            "{source}"
        );
    }
    let false_what_if = analyze("pwsh", r"Remove-Item C:\target -WhatIf:$false");
    assert_eq!(false_what_if.draft().calls()[0].filesystems().len(), 1);

    let filtered = analyze(
        "pwsh",
        r"Remove-Item -Filter C:\ -Include C:\ -Exclude C:\ -Path C:\safe",
    );
    assert_eq!(
        filtered.draft().calls()[0].filesystems()[0].requested(),
        Some(r"C:\safe")
    );

    let positional_filter = analyze("pwsh", r"Remove-Item C:\temp *.txt");
    assert!(positional_filter.draft().complete());
    assert_eq!(positional_filter.draft().calls()[0].filesystems().len(), 1);
    assert_eq!(
        positional_filter.draft().calls()[0].filesystems()[0].requested(),
        Some(r"C:\temp")
    );

    for source in [
        "Remove-Item $(Get-Target)",
        "Remove-Item @paths",
        "Remove-Item { C:\\target }",
        "$name = 'C:\\target'; Remove-Item $name",
    ] {
        assert!(!analyze("pwsh", source).draft().complete(), "{source}");
    }
}

#[test]
fn powershell_unknown_whatif_values_keep_destructive_effects_partial() {
    for source in [
        r"Remove-Item -Recurse -LiteralPath C:\Users\test -WhatIf:0",
        r#"Remove-Item -Recurse -LiteralPath C:\Users\test -WhatIf:"""#,
        r"Remove-Item -Recurse -LiteralPath C:\Users\test -WhatIf:''",
    ] {
        let analysis = analyze("pwsh", source);
        assert!(!analysis.draft().complete(), "{source}");
        assert_eq!(analysis.draft().calls()[0].filesystems().len(), 1);
        assert!(
            analysis
                .report()
                .contains_exact(FindingKind::HomeDestruction),
            "{source}"
        );
    }

    let critical = AbsolutePath::new(Platform::Windows, r"C:\Users\test\.nah\policy.toml").unwrap();
    let analysis = interpret_language_effects(
        InlineInput {
            program: "pwsh",
            code: r"Set-Content -Path C:\Users\test\.nah\policy.toml -Value evil -WhatIf:0",
            home: r"C:\Users\test",
            platform: Platform::Windows,
        },
        ProtectionInput {
            critical_paths: &[critical],
            ambient_variables: &[],
        },
    );
    assert!(!analysis.draft().complete());
    assert!(
        analysis
            .report()
            .contains_conservative(FindingKind::NahTampering)
    );
}

#[test]
fn windows_shell_escapes_preserve_non_ascii_characters() {
    for source in [r#"Remove-Item "a`ébc""#, "Remove-Item a`ébc"] {
        let analysis = analyze("pwsh", source);
        assert!(analysis.draft().complete(), "{source}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            Some("aébc"),
            "{source}"
        );
    }

    let analysis = analyze("cmd", "del a^éb");
    assert!(analysis.draft().complete());
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some("aéb")
    );
}

#[test]
fn powershell_hash_starts_comments_only_at_token_boundaries() {
    for (source, expected) in [
        (
            r"Remove-Item -Recurse -LiteralPath C:\Users\test#backup",
            r"C:\Users\test#backup",
        ),
        (
            r"Remove-Item -Recurse -LiteralPath 'C:\Users\test<#backup#>'",
            r"C:\Users\test<#backup#>",
        ),
    ] {
        let path = analyze("pwsh", source);
        assert!(path.draft().complete(), "{source}");
        assert_eq!(
            path.draft().calls()[0].filesystems()[0].requested(),
            Some(expected),
            "{source}"
        );
        assert!(
            !path.report().contains_exact(FindingKind::HomeDestruction),
            "{source}"
        );
    }

    for source in [
        r"Write-Output x#y; Remove-Item -Recurse -LiteralPath C:\Users\test",
        "Write-Output x # comment\nRemove-Item -Recurse -LiteralPath C:\\Users\\test",
    ] {
        let analysis = analyze("pwsh", source);
        assert!(analysis.draft().complete(), "{source}");
        assert_eq!(analysis.draft().calls().len(), 2, "{source}");
        assert!(
            analysis
                .report()
                .contains_exact(FindingKind::HomeDestruction),
            "{source}"
        );
    }
}

#[test]
fn windows_shell_line_continuations_remain_partial_without_fabricated_effects() {
    let overclaim = analyze(
        "pwsh",
        "Write-Output ok `\nRemove-Item -Recurse C:\\Users\\test",
    );
    assert!(!overclaim.draft().complete());
    assert!(
        overclaim
            .draft()
            .calls()
            .iter()
            .all(|call| call.filesystems().is_empty())
    );

    let deletion = analyze("pwsh", "Remove-Item -Recurse `\nC:\\Users\\test");
    assert!(!deletion.draft().complete());
    assert_eq!(
        deletion.draft().calls()[0].filesystems()[0].requested(),
        Some(r"C:\Users\test")
    );
    assert!(
        deletion
            .report()
            .contains_exact(FindingKind::HomeDestruction)
    );

    for source in [
        "del /q ^\nC:\\Users\\test\\secret.txt",
        "del /q ^\r\nC:\\Users\\test\\secret.txt",
    ] {
        let analysis = analyze("cmd", source);
        assert!(!analysis.draft().complete(), "{source:?}");
        assert!(analysis.draft().calls().is_empty(), "{source:?}");
    }

    let critical = AbsolutePath::new(Platform::Windows, r"C:\Users\test\.nah\config.toml").unwrap();
    let analysis = interpret_language_effects(
        InlineInput {
            program: "pwsh",
            code: "Write-Output x > `\nC:\\Users\\test\\.nah\\config.toml",
            home: r"C:\Users\test",
            platform: Platform::Windows,
        },
        ProtectionInput {
            critical_paths: &[critical],
            ambient_variables: &[],
        },
    );
    assert!(!analysis.draft().complete());
    assert!(
        analysis
            .report()
            .contains_conservative(FindingKind::NahTampering)
    );
}

#[test]
fn powershell_attached_redirection_emits_a_static_write() {
    for source in [
        r"Write-Output evil>C:\target",
        r"Write-Output evil> C:\target",
        r"Write-Output evil>>C:\target",
    ] {
        let analysis = analyze("pwsh", source);
        assert!(analysis.draft().complete(), "{source}");
        let filesystems = analysis
            .draft()
            .calls()
            .iter()
            .flat_map(|call| call.filesystems())
            .collect::<Vec<_>>();
        assert_eq!(filesystems.len(), 1, "{source}");
        assert_eq!(filesystems[0].operation(), FilesystemOperation::Write);
        assert_eq!(filesystems[0].requested(), Some(r"C:\target"));
    }

    for source in [
        r#"Write-Output "evil>C:\literal""#,
        r"Write-Output evil`>C:\literal",
    ] {
        let analysis = analyze("pwsh", source);
        assert!(analysis.draft().complete(), "{source}");
        assert!(
            analysis
                .draft()
                .calls()
                .iter()
                .all(|call| call.filesystems().is_empty()),
            "{source}"
        );
    }
}

#[test]
fn powershell_home_references_require_static_boundaries() {
    for (source, expected) in [
        (r"Remove-Item -Recurse -LiteralPath '~'", r"C:\Users\test"),
        (
            r"Set-Content -LiteralPath '~\.nah\policy.toml' -Value x",
            r"C:\Users\test\.nah\policy.toml",
        ),
        (
            r#"Set-Content -LiteralPath "$HOME/.nah/policy.toml" -Value x"#,
            r"C:\Users\test/.nah/policy.toml",
        ),
        (
            r"Set-Content -LiteralPath '$HOME\literal' -Value x",
            r"$HOME\literal",
        ),
        (
            r#"Set-Content -LiteralPath "`$HOME\literal" -Value x"#,
            r"$HOME\literal",
        ),
        (
            r#"Set-Content -LiteralPath "$env:USERPROFILE/.nah/policy.toml" -Value x"#,
            r"C:\Users\test/.nah/policy.toml",
        ),
    ] {
        let analysis = analyze("pwsh", source);
        assert!(analysis.draft().complete(), "{source}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            Some(expected),
            "{source}"
        );
    }

    let home_delete = analyze("pwsh", r"Remove-Item -Recurse -LiteralPath '~'");
    assert!(
        home_delete
            .report()
            .contains_exact(FindingKind::HomeDestruction)
    );

    for source in [
        r"Remove-Item -Recurse $homelab",
        r"Remove-Item -Recurse $HOMEWORK",
        r"Remove-Item -Recurse $env:userprofileX",
        r"Remove-Item -Recurse ${home}lab",
    ] {
        let analysis = analyze("pwsh", source);
        assert!(!analysis.draft().complete(), "{source}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            None,
            "{source}"
        );
    }
}

#[test]
fn powershell_dialect_aliases_never_invent_download_destinations() {
    for program in ["powershell", "pwsh"] {
        for command in ["curl", "wget"] {
            let analysis = analyze(
                program,
                &format!("{command} https://example.test/x -OutFile C:\\payload"),
            );
            assert!(!analysis.draft().complete());
            assert_eq!(
                analysis.draft().calls()[0].kind(),
                LanguageCallKind::NetworkTransfer
            );
            assert!(analysis.draft().calls()[0].filesystems().is_empty());
        }
    }

    let exact = analyze(
        "powershell",
        r"curl.exe -o C:\payload https://example.test/x",
    );
    assert!(matches!(
        exact.report().nested_executions(),
        [NestedExecution::Command { argv, .. }]
            if argv.first().map(String::as_str) == Some("curl.exe")
    ));
}

#[test]
fn pwsh_uses_windows_only_aliases_only_on_windows() {
    for command in [
        "del /tmp/target",
        "erase /tmp/target",
        "rd /tmp/target",
        "rmdir /tmp/target",
        "type /tmp/target",
    ] {
        let analysis = analyze_on("pwsh", command, Platform::Linux, "/home/test");
        assert!(!analysis.draft().complete(), "{command}");
        assert!(analysis.draft().calls().is_empty(), "{command}");
    }

    let stable_alias = analyze_on("pwsh", "rm /tmp/target", Platform::Linux, "/home/test");
    assert!(stable_alias.draft().complete());
    assert_eq!(
        stable_alias.draft().calls()[0].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
}

#[test]
fn reviewed_powershell_network_forms_emit_only_their_static_targets() {
    let analysis = analyze(
        "pwsh",
        r#"Invoke-WebRequest -Uri 'https://example.test/a' -OutFile 'C:\a'; Invoke-RestMethod 'https://example.test/b'; (New-Object System.Net.WebClient).DownloadFile('https://example.test/c','C:\c')"#,
    );
    let calls = analysis.draft().calls();
    assert!(analysis.draft().complete());
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].endpoint(), Some("https://example.test/a"));
    assert_eq!(calls[0].filesystems()[0].requested(), Some(r"C:\a"));
    assert!(calls[1].filesystems().is_empty());
    assert_eq!(calls[2].filesystems()[0].requested(), Some(r"C:\c"));
}

#[test]
fn powershell_webclient_and_redirection_stay_within_reviewed_static_shapes() {
    for source in [
        r"(Get-Thing System.Net.WebClient).DownloadFile('https://example.test/x','C:\x')",
        r"(New-Object System.Net.WebClient).DownloadFile('https://example.test/x','C:\x','extra')",
        r"(New-Object System.Net.WebClient).DownloadFile('https://example.test/x','C:\x').ToString()",
        "<# unfinished",
    ] {
        assert!(!analyze("pwsh", source).draft().complete(), "{source}");
    }

    let merged = analyze("pwsh", r"Write-Output ok 2>&1");
    assert!(merged.draft().complete());
    assert!(merged.draft().calls()[0].filesystems().is_empty());
}

#[test]
fn exact_windows_children_use_one_nested_argv_contract() {
    for (program, source, child) in [
        ("pwsh", "git status", "git"),
        ("pwsh", "cmd /c del C:\\target", "cmd"),
        (
            "cmd",
            "powershell -Command Remove-Item C:\\target",
            "powershell",
        ),
        ("cmd", "cmd /c rd /s C:\\target", "cmd"),
    ] {
        let analysis = analyze(program, source);
        assert!(
            analysis
                .report()
                .nested_executions()
                .iter()
                .any(|execution| {
                    matches!(execution, NestedExecution::Command { argv, .. }
                if argv.first().is_some_and(|program| program.eq_ignore_ascii_case(child)))
                })
        );
    }
}

#[test]
fn static_invoke_expression_reuses_the_powershell_interpreter() {
    let analysis = analyze(
        "pwsh",
        r#"Invoke-Expression "Remove-Item -Recurse -LiteralPath 'C:\Users\test'""#,
    );
    assert!(analysis.draft().complete());
    assert_eq!(analysis.draft().calls().len(), 2);
    assert_eq!(
        analysis.draft().calls()[1].filesystems()[0].requested(),
        Some(r"C:\Users\test")
    );

    let shadowed = analyze(
        "pwsh",
        "Set-Alias -Name rm -Value Write-Output; rm 'C:\\Users\\test'",
    );
    assert!(!shadowed.draft().complete());
    assert!(shadowed.draft().calls().is_empty());

    let removed_alias = analyze("pwsh", "Remove-Item -Path Alias:rm; rm 'C:\\Users\\test'");
    assert!(!removed_alias.draft().complete());
    assert!(removed_alias.draft().calls().is_empty());
}

#[test]
fn named_move_source_keeps_the_positional_destination() {
    let analysis = analyze("pwsh", r"Move-Item -LiteralPath C:\from C:\to");
    assert!(analysis.draft().complete());
    let filesystems = analysis.draft().calls()[0].filesystems();
    assert_eq!(filesystems[0].requested(), Some(r"C:\from"));
    assert_eq!(filesystems[1].requested(), Some(r"C:\to"));
}

#[test]
fn cmd_filesystem_and_directory_boundaries_are_explicit() {
    let analysis = analyze(
        "cmd",
        r"del /s /q C:\cache\* & rd C:\empty & rd /s /q C:\tree & move /y C:\from C:\to & type C:\read > C:\out",
    );
    let calls = analysis.draft().calls();
    assert!(analysis.draft().complete());
    assert_eq!(calls.len(), 6);
    assert!(calls[0].filesystems()[0].recursive());
    assert!(calls[0].filesystems()[0].file_only_target());
    assert!(!calls[1].filesystems()[0].recursive());
    assert!(calls[2].filesystems()[0].recursive());
    assert_eq!(
        calls[3].filesystems()[0].operation(),
        FilesystemOperation::Delete
    );
    assert_eq!(
        calls[3].filesystems()[1].operation(),
        FilesystemOperation::Write
    );
    assert_eq!(
        calls[5].filesystems()[0].operation(),
        FilesystemOperation::Read
    );
    assert_eq!(
        calls[4].filesystems()[0].operation(),
        FilesystemOperation::Write
    );
}

#[test]
fn cmd_move_with_extra_operands_is_partial() {
    assert!(!analyze("cmd", r"move C:\a C:\b C:\c").draft().complete());
}

#[test]
fn reviewed_certutil_download_is_a_network_bound_write() {
    let analysis = analyze(
        "cmd",
        r"certutil.exe -urlcache -split -f https://example.test/x C:\payload",
    );
    assert!(analysis.draft().complete());
    let call = &analysis.draft().calls()[0];
    assert_eq!(call.kind(), LanguageCallKind::NetworkTransfer);
    assert_eq!(call.endpoint(), Some("https://example.test/x"));
    assert_eq!(call.filesystems()[0].requested(), Some(r"C:\payload"));
}

#[test]
fn powershell_quoted_segments_do_not_make_later_expansions_exact() {
    for source in [
        r"Remove-Item -Recurse -Force 'C:\Users\test'$rest",
        r"Remove-Item -Recurse -Force ~\$rest",
        r"Remove-Item -Recurse -Force ''$rest",
        r#"Remove-Item -Recurse -Force "C:\Users\test"$rest"#,
    ] {
        let analysis = analyze("pwsh", source);
        assert!(!analysis.draft().complete(), "{source}");
        assert_eq!(
            analysis.draft().calls()[0].filesystems()[0].requested(),
            None,
            "{source}"
        );
    }

    for source in [
        r"Remove-Item -Recurse -Force ''$HOME",
        r"Remove-Item -Recurse -Force ''$env:USERPROFILE",
    ] {
        let analysis = analyze("pwsh", source);
        assert!(analysis.draft().complete(), "{source}");
        assert!(
            analysis
                .report()
                .contains_exact(FindingKind::HomeDestruction),
            "{source}"
        );
    }
}

#[test]
fn powershell_binds_unambiguous_parameter_prefixes() {
    let analysis = analyze("pwsh", r"Remove-Item -Rec -Force C:\Users\test");
    assert!(analysis.draft().complete());
    let filesystem = &analysis.draft().calls()[0].filesystems()[0];
    assert!(filesystem.recursive());
    assert_eq!(filesystem.requested(), Some(r"C:\Users\test"));

    let analysis = analyze("pwsh", r"Remove-Item -LiteralP C:\Users\test");
    assert_eq!(
        analysis.draft().calls()[0].filesystems()[0].requested(),
        Some(r"C:\Users\test")
    );

    let ambiguous = analyze("pwsh", r"Remove-Item -E stop C:\Users\test");
    assert!(!ambiguous.draft().complete());

    let common_ambiguous = analyze("pwsh", r"Remove-Item -Recurse C:\Users\test -w");
    assert!(!common_ambiguous.draft().complete());
    assert!(common_ambiguous.draft().calls()[0].filesystems()[0].recursive());
    assert!(
        common_ambiguous
            .report()
            .contains_exact(FindingKind::HomeDestruction)
    );
}
