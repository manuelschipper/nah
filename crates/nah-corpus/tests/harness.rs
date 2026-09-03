#![allow(clippy::disallowed_methods)]

//! The corpus is decoded once, replayed through the CLI composition seam, and
//! reconciled strictly: green cases must pass and expected failures must fail.

use std::path::Path;

use nah_corpus::{corpus_dir, load_cases, load_fixtures, load_summary, reconcile};

#[test]
fn every_case_is_executed_green_or_an_observed_expected_failure() {
    let dir = corpus_dir();
    let cases = load_cases(&dir).unwrap_or_else(|errors| panic!("{}", errors.join("\n")));
    let fixtures = load_fixtures(&dir.join("FIXTURES.json")).expect("typed fixtures");
    let ledger = std::fs::read_to_string(dir.join("TRIAGE.md")).expect("triage ledger");
    let result = reconcile(&cases, &fixtures, &ledger);

    assert!(
        result.ledger_errors.is_empty(),
        "triage errors:\n{}",
        result.ledger_errors.join("\n")
    );
    assert!(
        result.unexpected_failures.is_empty(),
        "unexpected corpus failures:\n{}",
        result.unexpected_failures.join("\n")
    );
    assert!(
        result.unexpected_passes.is_empty(),
        "expected-fail cases now pass and must be removed from TRIAGE.md:\n{}",
        result.unexpected_passes.join("\n")
    );
    assert_eq!(
        result.executed_green.len() + result.expected_failures.len(),
        cases.len()
    );
}

#[test]
fn corpus_loads_clean() {
    let summary = load_summary(&corpus_dir()).expect("load corpus");
    assert!(
        summary.malformed.is_empty(),
        "malformed corpus cases:\n{}",
        summary.malformed.join("\n")
    );
    assert_eq!(summary.cases, 1761);
}

#[test]
fn current_corpus_file_counts_are_pinned() {
    let dir = corpus_dir();
    let mut actual = std::fs::read_dir(&dir)
        .expect("read corpus")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .map(|path| {
            let count = std::fs::read_to_string(&path)
                .expect("read corpus family")
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            (
                path.file_name()
                    .expect("corpus family name")
                    .to_string_lossy()
                    .into_owned(),
                count,
            )
        })
        .collect::<Vec<_>>();
    actual.sort();
    assert_eq!(
        actual,
        [
            ("execution-flows.jsonl".to_owned(), 296),
            ("filesystem.jsonl".to_owned(), 256),
            ("git.jsonl".to_owned(), 251),
            ("infrastructure.jsonl".to_owned(), 174),
            ("kubernetes.jsonl".to_owned(), 35),
            ("local-utilities.jsonl".to_owned(), 53),
            ("native.jsonl".to_owned(), 17),
            ("project.jsonl".to_owned(), 22),
            ("registry.jsonl".to_owned(), 76),
            ("secrets.jsonl".to_owned(), 108),
            ("self-protection.jsonl".to_owned(), 263),
            ("shell-resolution.jsonl".to_owned(), 81),
            ("storage.jsonl".to_owned(), 73),
            ("threat-model.jsonl".to_owned(), 27),
            ("windows.jsonl".to_owned(), 29),
        ]
    );
}

#[test]
fn named_adversarial_and_ordinary_workflow_families_are_pinned() {
    let cases = load_cases(&corpus_dir()).expect("load corpus");
    let ids = cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for id in [
        "ordinary-workflow.cargo-test",
        "ordinary-workflow.docker-ps",
        "ordinary-workflow.go-test",
        "ordinary-workflow.make-test",
        "ordinary-workflow.npm-test",
        "ordinary-workflow.pytest",
        "ordinary-workflow.uv-pytest",
        "git-remote-repo-delete.gh-current",
        "git-remote-repo-delete.glab-current",
        "git-remote-repo-delete.gh-api-placeholders",
        "git-remote-repo-delete.gh-api-fragment",
        "git-remote-repo-delete.gh-confirm-parse-bool",
        "git-remote-repo-delete.glab-api-encoded-query",
        "git-remote-repo-delete.glab-api-composite-placeholder",
        "git-remote-repo-delete.glab-api-nested-composite-placeholder",
        "git-remote-repo-delete.gh-single-label-host",
        "git-remote-repo-delete.gh-api-short-option-cluster",
        "git-remote-repo-delete.gh-api-separated-short-option-cluster",
        "git-remote-repo-delete.gh-api-short-boolean-value",
        "git-remote-repo-delete.gh-api-paginate-false",
        "git-remote-repo-delete.gh-api-paginate-true-delegates",
        "git-remote-repo-delete.glab-api-percent-encoded-path",
        "git-remote-repo-delete.glab-api-encoded-group-placeholder",
        "git-remote-repo-delete.gh-api-allow-escape-sequences",
        "git-remote-repo-delete.gh-repeated-help-final-false",
        "git-remote-repo-delete.gh-repeated-paginate-final-false",
        "git-remote-repo-delete.gh-port-qualified-host",
        "git-remote-repo-delete.gh-dynamic-api-option-delegates",
        "git-remote-repo-delete.glab-dynamic-api-option-delegates",
        "git-remote-repo-delete.gh-conflicting-output-options-delegate",
        "git-remote-repo-delete.gh-parent-help-false",
        "git-remote-repo-delete.glab-parent-help-false",
        "git-remote-repo-delete.gh-field-placeholder",
        "git-remote-repo-delete.glab-user-placeholder",
        "git-remote-repo-delete.glab-paginate-delegates",
        "git-remote-repo-delete.glab-short-option-cluster",
        "git-remote-repo-delete.glab-conflicting-body-options-delegates",
        "git-remote-repo-delete.gh-api-include-value-cluster",
        "git-remote-repo-delete.glab-invalid-output-delegates",
        "git-remote-repo-delete.gh-empty-output-filter",
        "git-remote-repo-delete.gh-slurp-delegates",
        "git-remote-repo-delete.glab-paginate-input-conflict-delegates",
        "git-remote-repo-delete.glab-duplicate-form-stdin-delegates",
        "git-remote-repo-delete.glab-invalid-field-delegates",
        "git-remote-repo-delete.invalid-api-hostname-delegates",
        "git-remote-repo-delete.glab-object-query-field-delegates",
        "git-remote-repo-delete.gh-invalid-api-value-delegates",
        "git-remote-repo-delete.gh-route-changing-hostname-delegates",
        "git-remote-repo-delete.gh-template-literal-close",
        "git-remote-repo-delete.gh-trailing-dot-host",
        "git-remote-repo-delete.gh-invalid-template-delegates",
        "git-remote-repo-delete.invalid-api-hostname-character-delegates",
        "git-remote-repo-delete.glab-invalid-header-delegates",
        "git-remote-repo-delete.gh-template-variable",
        "git-remote-repo-delete.gh-template-rune",
        "git-remote-repo-delete.gh-template-range-variables",
        "git-remote-repo-delete.gh-template-replace",
        "git-remote-repo-delete.glab-repo-override",
        "git-remote-repo-delete.glab-clustered-repo-override",
        "git-remote-repo-delete.glab-api-clustered-repo-override",
        "git-remote-repo-delete.glab-api-idn-host",
        "git-remote-repo-delete.gh-template-hex-float",
        "git-remote-repo-delete.gh-template-unicode-variable",
        "git-remote-repo-delete.gh-invalid-legacy-octal-delegates",
        "git-remote-repo-delete.gh-duplicate-field-delegates",
        "git-remote-repo-delete.glab-invalid-content-length-delegates",
        "git-remote-repo-delete.gh-ipv6-host",
        "git-remote-repo-delete.gh-port-qualified-idn-host",
        "git-remote-repo-delete.gh-ipv6-zone-host",
        "git-remote-repo-delete.gh-api-idn-host",
        "git-remote-repo-delete.gh-decomposed-idn-repository-host",
        "git-remote-repo-delete.gh-api-decomposed-idn-host",
        "git-remote-repo-delete.gh-devanagari-repository-host",
        "git-remote-repo-delete.gh-api-devanagari-host",
        "git-remote-repo-delete.gh-bengali-repository-host",
        "git-remote-repo-delete.gh-api-bengali-host",
        "git-remote-repo-delete.gh-tamil-repository-host",
        "git-remote-repo-delete.gh-api-tamil-host",
        "git-remote-repo-delete.gh-kannada-repository-host",
        "git-remote-repo-delete.gh-api-kannada-host",
        "git-remote-repo-delete.gh-telugu-repository-host",
        "git-remote-repo-delete.gh-api-telugu-host",
        "git-remote-repo-delete.gh-template-digit-separator",
        "git-remote-repo-delete.gh-invalid-header-name-delegates",
        "git-remote-repo-delete.gh-api-percent-encoded-repository",
        "git-remote-repo-delete.glab-api-percent-encoded-id",
        "git-remote-repo-delete.gh-ipv6-percent-encoded-zone-host",
        "git-remote-repo-delete.dynamic-target-delegates",
        "git-remote-repo-delete.gh-nested-endpoint-delegates",
        "infra-iac-destroy.terraform-destroy",
        "infra-iac-destroy.terraform-factory-delegates",
        "infra-iac-destroy.terraform-cli-args-target-delegates",
        "infra-iac-destroy.saved-plan-delegates",
        "infra-iac-destroy.pulumi-destroy",
        "infra-iac-destroy.pulumi-factory-delegates",
        "infra-iac-destroy.pulumi-target-delegates",
        "infra-iac-destroy.pulumi-preview-only-delegates",
        "infra-container-reset.podman-system-reset",
        "infra-container-reset.factory-default",
        "infra-container-reset.remote-connection",
        "infra-container-reset.operation-version-delegates",
        "infra-container-reset.root-terminator-delegates",
        "infra-container-volume-delete.docker-volume-all",
        "infra-container-volume-delete.factory-delegates",
        "infra-container-volume-delete.podman-system-volumes",
        "infra-container-volume-delete.operation-version-delegates",
        "infra-container-volume-delete.group-terminator-delegates",
        "infra-container-volume-delete.filter-delegates",
        "infra-container-volume-delete.dry-run-delegates",
        "infra-container-volume-delete.named-volume-control",
        "infra-k8s-delete.namespace",
        "infra-k8s-delete.persistent-volume",
        "infra-k8s-delete.pods-all",
        "infra-k8s-delete.mixed-kinds",
        "infra-k8s-boundary.client-dry-run-delegates",
        "infra-k8s-boundary.filename-delegates",
        "infra-k8s-boundary.path-override-delegates",
        "storage-backup-destroy.borg-repository",
        "storage-backup-destroy.borg-factory-default",
        "storage-backup-destroy.restic-remove-all",
        "storage-backup-destroy.velero-all",
        "storage-recursive.aws-sync",
        "storage-recursive.factory-delegates",
        "storage-recursive.rclone-sync",
        "storage-recursive.rsync-remote-destination",
        "storage-snapshot.zfs-destroy",
        "storage-snapshot.factory-delegates",
        "storage-snapshot.restic-retention",
        "storage-snapshot.borg-archive",
        "storage-boundary.empty-aws-bucket-delegates",
        "storage-boundary.single-object-delegates",
        "storage-boundary.opaque-delete-manifest-delegates",
        "storage-boundary.rclone-dry-run-delegates",
        "storage-boundary.zfs-dry-run-delegates",
        "storage-boundary.dynamic-target-delegates",
        "fs-volume-destroy.zfs-live-dataset",
        "registry-unpublish.npm-package-version",
        "registry-unpublish.factory-default",
        "registry-unpublish.gem-yank",
        "registry-unpublish.npm-owner-remove",
        "registry-unpublish.npm-owner-remove-alias",
        "registry-unpublish.npm-author-alias",
        "registry-unpublish.npm-owner-current-package",
        "registry-unpublish.cargo-owner-remove",
        "registry-unpublish.cargo-owner-multiple",
        "registry-unpublish.gem-owner-remove",
        "registry-unpublish.gem-owner-multiple",
        "registry-publish.npm",
        "registry-publish.factory-delegates",
        "registry-publish.twine",
        "registry-publish.python-twine",
        "registry-publish.dotnet-nuget",
        "registry-publish.npm-dry-run-delegates",
        "registry-publish.npx-child-options",
        "registry-publish.pnpm-dlx-dry-run-delegates",
        "registry-boundary.cargo-yank-delegates",
        "registry-boundary.npm-deprecate-delegates",
        "registry-boundary.npm-install-delegates",
        "registry-boundary.cargo-command-options-delegate",
        "registry-boundary.pnpm-command-options-delegate",
        "registry-boundary.yarn-command-options-delegate",
        "registry-boundary.gem-command-options-delegate",
        "registry-boundary.dotnet-command-options-delegate",
        "registry-boundary.uv-command-options-delegate",
        "registry-boundary.poetry-command-options-delegate",
        "registry-boundary.dynamic-target-delegates",
        "registry-boundary.missing-option-value-delegates",
        "registry-boundary.poetry-operand-delegates",
        "registry-boundary.unknown-option-delegates",
        "shell-resolution.ansi-c-program-threat",
        "shell-resolution.backslash-option-threat",
        "shell-resolution.parameter-default-root",
        "shell-resolution.parameter-safe-control",
        "shell-resolution.static-arithmetic-control",
        "shell-resolution.unicode-literal-control",
        "shell-resolution.unicode-path-control",
        "self-protection.critical.archive-extract-state",
        "self-protection.critical.chattr-trust",
        "self-protection.critical.gawk-in-place-trust",
        "self-protection.critical.git-restore-trust",
        "self-protection.critical.patch-trust",
        "self-protection.critical.perl-in-place-trust",
        "self-protection.critical.vim-write-trust",
        "windows.cmd.del-directory-control",
        "windows.cmd.del-recursive-home",
        "windows.cmd.nested-powershell-argv-home",
        "windows.powershell.remove-home",
        "windows.powershell.curl-alias-unresolved",
        "windows.pwsh.hash-bare-path",
        "windows.pwsh.hash-keeps-following-statement",
        "windows.pwsh.tilde-home",
        "windows.pwsh.quoted-segment-variable",
        "windows.pwsh.parameter-prefix-home",
        "windows.cmd.del-recursive-directory",
        "windows.pwsh.line-continuation-partial",
        "windows.cmd.line-continuation-partial",
        "windows.pwsh.ambiguous-whatif-prefix-home",
    ] {
        assert!(ids.contains(id), "missing reviewed corpus case `{id}`");
    }
}

#[test]
fn malformed_and_duplicate_cases_are_rejected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let malformed = load_summary(&root.join("malformed")).expect("load malformed fixture");
    assert!(
        !malformed.malformed.is_empty(),
        "accepted malformed fixture"
    );

    let duplicate = load_summary(&root.join("duplicate")).expect("load duplicate fixture");
    assert!(
        duplicate
            .malformed
            .iter()
            .any(|error| error.contains("duplicate case id `duplicate`")),
        "duplicate fixture did not fail for its duplicate id: {duplicate:?}"
    );
}

#[test]
fn corpus_discovery_errors_are_fatal() {
    assert!(load_summary(&corpus_dir().join("TRIAGE.md")).is_err());
}
