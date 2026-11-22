//! Shared cloud argument readers. Each caller chooses the option grammar that covers its verb.

use crate::models::args::FlagSpec;
use crate::word::Word;

/// Candidate operands from `start`, with their argv indices.
/// The scan skips literal words starting with `-` and the word after a
/// literal flag in [`CLOUD_SCOPE_FLAGS`]. Other detached option values can
/// still be returned as operands.
pub(super) fn cloud_operands(argv: &[Word], start: usize) -> Vec<(u32, &Word)> {
    argv.iter()
        .enumerate()
        .skip(start)
        .filter(|(i, w)| {
            !w.as_literal().is_some_and(|t| t.starts_with('-'))
                && !i
                    .checked_sub(1)
                    .and_then(|p| argv[p].as_literal())
                    .is_some_and(|p| CLOUD_SCOPE_FLAGS.contains(&p))
        })
        .map(|(i, w)| (i as u32, w))
        .collect()
}

pub(super) const AWS_COMMON_VALUES: &[&str] = &[
    "--region",
    "--profile",
    "--endpoint-url",
    "--output",
    "--query",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--color",
    "--ca-bundle",
    "--cli-binary-format",
];
pub(super) const AWS_COMMON_SWITCHES: &[&str] = &[
    "--debug",
    "--no-verify-ssl",
    "--no-paginate",
    "--no-sign-request",
    "--no-cli-pager",
    "--cli-auto-prompt",
    "--no-cli-auto-prompt",
];
pub(super) const GCLOUD_COMMON_VALUES: &[&str] = &[
    "--project",
    "--account",
    "--configuration",
    "--billing-project",
    "--impersonate-service-account",
    "--format",
    "--verbosity",
    "--access-token-file",
    "--flatten",
    "--trace-token",
    "--http-timeout",
    "--authority-selector",
    "--authorization-token-file",
    "--credential-file-override",
    "--universe-domain",
];

/// gsutil options taking a separate value, so the verb after them is found.
pub(super) const GSUTIL_GLOBAL_FLAGS: &[&str] = &["-h", "-o", "-u", "-i"];

/// gsutil subcommand options are clustered single-dash letters (`rsync -dr`),
/// so a letter counts as present anywhere in such a word.
pub(super) fn cloud_has_short_option(argv: &[Word], start: usize, letters: &[char]) -> bool {
    argv.iter().skip(start).any(|word| {
        word.as_literal().is_some_and(|text| {
            text.starts_with('-')
                && !text.starts_with("--")
                && text[1..].chars().any(|letter| letters.contains(&letter))
        })
    })
}

/// Whether the Azure CLI reads an argument from a file. It replaces a word,
/// or the value after a word's `=`, that starts with `@` with the content of
/// the file named there, and keeps the word only when no such file exists.
pub(super) fn az_reads_argument_file(argv: &[Word]) -> bool {
    argv.iter()
        .skip(1)
        .filter_map(Word::as_literal)
        .any(|word| {
            let value = word.split_once('=').map_or(word, |(_, value)| value);
            value.len() > 1 && value.starts_with('@')
        })
}

/// Azure CLI global arguments that take a value.
pub(super) const AZ_GLOBAL_VALUE_FLAGS: &[&str] = &["--subscription", "--output", "-o", "--query"];

pub(super) const CLOUD_SCOPE_FLAGS: &[&str] = &[
    "--region",
    "--endpoint-url",
    "--profile",
    "--project",
    "--zone",
    "--subscription",
    "--resource-group",
    "-g",
    "--account-name",
    "--configuration",
    "--flags-file",
];

pub(super) const CLOUD_LITERAL_FLAGS: FlagSpec<'static> = FlagSpec {
    allow_abbreviation: false,
    value_flags: &[
        "--target",
        "--document-name",
        "--instance-ids",
        "--parameters",
        "--bucket",
        "--key",
        "--db-instance-identifier",
        "--stack-name",
        "--file",
        "-f",
        "--ids",
        "--name",
        "-n",
        "--command-id",
        "--blob-url",
        "--container-name",
        "-c",
        "--snapshot-id",
        "--volume-id",
        "--source",
        "--profile",
        "--region",
        "--endpoint-url",
        "--project",
        "--exclude",
        "--include",
    ],
    known_flags: &[
        "--recursive",
        "--delete",
        "--delete-unmatched-destination-objects",
        "--force",
        "-r",
        "-d",
    ],
};

/// AzCopy treats an explicit `false` or `False` option value as unset.
pub(super) fn azcopy_flag(argv: &[Word], name: &str) -> bool {
    argv.iter().any(|word| {
        word.as_literal()
            .is_some_and(|text| match text.split_once('=') {
                Some((flag, value)) => flag == name && !matches!(value, "false" | "False"),
                None => text == name,
            })
    })
}

/// The argv index of the AWS service word when every word before it is a
/// global option the CLI documents, with its value.
pub(super) fn aws_service_after_globals(argv: &[Word]) -> Option<usize> {
    let mut index = 1;
    loop {
        let word = argv.get(index)?.as_literal()?;
        if !word.starts_with('-') {
            return Some(index);
        }
        let (flag, attached) = match word.split_once('=') {
            Some((flag, _)) => (flag, true),
            None => (word, false),
        };
        if AWS_COMMON_SWITCHES.contains(&flag) && !attached {
            index += 1;
        } else if AWS_COMMON_VALUES.contains(&flag) {
            index += if attached { 1 } else { 2 };
        } else {
            return None;
        }
    }
}
