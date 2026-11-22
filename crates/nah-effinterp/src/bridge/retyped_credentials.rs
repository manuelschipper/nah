//! Whether a call types out a credential: in its command or source text, in
//! content a native write states, or in any other tool argument. An agent that
//! has seen a token can type it instead of naming its variable, and then the
//! plan reads no variable at all. Two kinds of text count. One is the exact
//! value of a credential-shaped variable the hook's environment holds. The
//! other is a token of a well-known format whose prefix and shape ordinary
//! text does not take, which needs no environment: the agent may have read it
//! from a file or an earlier tool's output. Only literal text counts: content
//! a shell write expands from `$GITHUB_TOKEN` names the variable, which
//! `secrets/env-files-read` judges. The values never leave the observation.

use effinterp_proto::{Plan, Subject, ToolCall};
use nah_proto::observation::{Observation, ObservationValue};

/// Shorter values occur in ordinary text by chance.
const MIN_VALUE_CHARS: usize = 16;

/// The observation key of the credential-shaped environment variables.
pub(super) const CREDENTIAL_ENVIRONMENT_KEY: &str = "effinterp-credential-environment";

/// A token format a provider issues. Each prefix is the provider's own, and
/// the body's alphabet and length are what it issues, so neither prose nor
/// identifiers nor hashes, UUIDs or base64 data take the shape.
///
/// Left out because ordinary text takes their shape, or because they are no
/// secret: AWS access key IDs (`AKIA…`, an identifier; the secret key that
/// goes with one has no prefix), Google API keys (`AIza…`, made to ship in
/// client code), JWTs (example and expired tokens fill docs and tests),
/// Stripe test keys (`sk_test_…`, published in docs and moving no money) and
/// private key blocks (test suites carry fixture keys).
struct TokenFormat {
    prefixes: &'static [&'static str],
    body: fn(char) -> bool,
    length: std::ops::RangeInclusive<usize>,
    /// What the whole body must look like beyond its alphabet and length.
    shape: fn(&str) -> bool,
}

fn any_shape(_: &str) -> bool {
    true
}

/// A Slack token body: dash-separated groups, the first all digits
/// (`xoxb-17653672481-…`, `xapp-1-A0123…`, `xoxe-1-…`). A kebab-case name
/// that happens to start with a Slack prefix (`xapp-config-loader-…`) is not.
fn digit_group_first(body: &str) -> bool {
    body.split_once('-').is_some_and(|(first, _)| {
        !first.is_empty() && first.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn alphanumeric(character: char) -> bool {
    character.is_ascii_alphanumeric()
}

fn alphanumeric_or_underscore(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn alphanumeric_or_dash(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

fn base64url(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
}

fn base64url_or_dot(character: char) -> bool {
    base64url(character) || character == '.'
}

const TOKEN_FORMATS: &[TokenFormat] = &[
    // GitHub personal, OAuth, user-to-server and refresh tokens.
    TokenFormat {
        prefixes: &["ghp_", "gho_", "ghu_", "ghr_"],
        body: alphanumeric,
        length: 36..=36,
        shape: any_shape,
    },
    // GitHub App installation tokens: the legacy 36 alphanumerics, or the
    // stateless form GitHub mints since October 2026, the app ID and a JWT
    // (`ghs_APPID_HEADER.PAYLOAD.SIGNATURE`, about 520 characters). GitHub's
    // migration guidance matches both as `ghs_[A-Za-z0-9._-]{36,}`.
    TokenFormat {
        prefixes: &["ghs_"],
        body: base64url_or_dot,
        length: 36..=usize::MAX,
        shape: any_shape,
    },
    // GitHub fine-grained personal access tokens.
    TokenFormat {
        prefixes: &["github_pat_"],
        body: alphanumeric_or_underscore,
        length: 82..=82,
        shape: any_shape,
    },
    // GitLab personal access tokens.
    TokenFormat {
        prefixes: &["glpat-"],
        body: base64url,
        length: 20..=usize::MAX,
        shape: any_shape,
    },
    // Slack tokens: bot (`xoxb-`), user (`xoxp-`), app-level (`xapp-`),
    // workflow (`xwfp-`), and rotating refresh and configuration refresh
    // tokens (`xoxe-`), with the legacy workspace app, refresh and session
    // forms (`xoxa-`, `xoxr-`, `xoxs-`). A rotated access token or a
    // configuration token (`xoxe.xoxb-1-…`, `xoxe.xoxp-1-…`, `xoxe.xapp-1-…`)
    // is matched by the prefix after its dot.
    TokenFormat {
        prefixes: &[
            "xoxb-", "xoxp-", "xapp-", "xwfp-", "xoxe-", "xoxa-", "xoxr-", "xoxs-",
        ],
        body: alphanumeric_or_dash,
        length: 40..=usize::MAX,
        shape: digit_group_first,
    },
    // Anthropic API keys.
    TokenFormat {
        prefixes: &["sk-ant-"],
        body: base64url,
        length: 80..=usize::MAX,
        shape: any_shape,
    },
    // OpenAI project, service account and admin keys.
    TokenFormat {
        prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
        body: base64url,
        length: 40..=usize::MAX,
        shape: any_shape,
    },
    // Stripe live secret and restricted keys.
    TokenFormat {
        prefixes: &["sk_live_", "rk_live_"],
        body: alphanumeric,
        length: 24..=usize::MAX,
        shape: any_shape,
    },
    // npm access tokens.
    TokenFormat {
        prefixes: &["npm_"],
        body: alphanumeric,
        length: 36..=36,
        shape: any_shape,
    },
    // PyPI API tokens: a macaroon whose encoded header names pypi.org.
    TokenFormat {
        prefixes: &["pypi-AgEIcHlwaS5vcmc"],
        body: base64url,
        length: 50..=usize::MAX,
        shape: any_shape,
    },
    // Hugging Face access tokens.
    TokenFormat {
        prefixes: &["hf_"],
        body: alphanumeric,
        length: 34..=34,
        shape: any_shape,
    },
];

/// Bytes of a native call's withheld content the scan reads. The scan is
/// linear, and over this many bytes of the costliest inputs measured,
/// repeated token prefixes, it takes about 0.1 s optimized and 3 s in a debug
/// build, inside a hook's five-second timeout. Content past it is left
/// unscanned, a gap of its own.
const WITHHELD_SCAN_BYTE_BUDGET: usize = 4 * 1024 * 1024;

/// The text the call states: its shell, SQL or source code, its argv, the
/// paths a native write, edit or patch names and the content it adds, and
/// every other tool argument. An edit's old text and a patch's context and
/// removed lines are the file's own, and removing a credential from a file
/// exposes nothing new. A native call whose content the plan withheld is
/// read as given, up to `WITHHELD_SCAN_BYTE_BUDGET`.
fn stated_text<'a>(plan: &'a Plan, withheld: Option<&'a ToolCall>) -> Vec<&'a str> {
    match &plan.subject {
        Subject::Shell { source, .. }
        | Subject::Sql { source, .. }
        | Subject::Source { source, .. } => vec![source],
        Subject::Exec { argv, .. } => argv.iter().map(String::as_str).collect(),
        Subject::ToolCall { call, .. } => match withheld {
            Some(withheld) => {
                let mut budget = WITHHELD_SCAN_BYTE_BUDGET;
                call_text(withheld)
                    .into_iter()
                    .filter_map(|text| {
                        let end = (0..=budget.min(text.len()))
                            .rev()
                            .find(|end| text.is_char_boundary(*end))?;
                        budget -= end;
                        (end > 0).then(|| &text[..end])
                    })
                    .collect()
            }
            None => call_text(call),
        },
    }
}

/// Whether a native call's withheld content runs past what the scan reads.
pub(super) fn withheld_past_scan_budget(withheld: &ToolCall) -> bool {
    call_text(withheld)
        .iter()
        .map(|text| text.len())
        .sum::<usize>()
        > WITHHELD_SCAN_BYTE_BUDGET
}

/// [`stated_text`] of a tool call.
fn call_text(call: &ToolCall) -> Vec<&str> {
    match call {
        ToolCall::FileWrite(args) => vec![&args.path, &args.content],
        ToolCall::FileEdit(args) => vec![&args.path, &args.new],
        ToolCall::FileEditBatch(args) => [args.path.as_str()]
            .into_iter()
            .chain(args.edits.iter().map(|edit| edit.new.as_str()))
            .collect(),
        ToolCall::FilePatch(args) => {
            let mut text = effinterp_engine::patch_header_lines(args);
            text.extend(effinterp_engine::patch_added_lines(args));
            text
        }
        ToolCall::FileRead(args) => vec![&args.path],
        ToolCall::FileTransfer(args) => vec![&args.path],
        ToolCall::FileDelete(args) => vec![&args.path],
        ToolCall::FsList(args) => vec![&args.path],
        ToolCall::FsGlob(args) => [&args.pattern]
            .into_iter()
            .chain(&args.root)
            .map(String::as_str)
            .collect(),
        ToolCall::FsFind(args) => vec![&args.pattern, &args.root],
        ToolCall::FsGrep(args) => [&args.pattern]
            .into_iter()
            .chain(args.paths.iter().flatten())
            .chain(&args.root)
            .chain(&args.globs)
            .chain(&args.types)
            .map(String::as_str)
            .collect(),
        ToolCall::McpCall(args) => {
            let mut text = Vec::new();
            json_strings(&args.arguments, &mut text);
            text
        }
        ToolCall::Unknown(args) => {
            let mut text = Vec::new();
            json_strings(&args.args, &mut text);
            text
        }
    }
}

/// Every string in a tool's JSON arguments, object keys included: a tool
/// that takes a map of arbitrary metadata sends its keys too.
fn json_strings<'a>(value: &'a serde_json::Value, text: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(string) => text.push(string),
        serde_json::Value::Array(items) => {
            for item in items {
                json_strings(item, text);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                text.push(key);
                json_strings(field, text);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Whether the call states text long enough to hold a credential value, so
/// the credential-shaped variables are worth observing.
pub(super) fn states_text(plan: &Plan, withheld: Option<&ToolCall>) -> bool {
    stated_text(plan, withheld)
        .into_iter()
        .any(|text| text.chars().count() >= MIN_VALUE_CHARS)
}

/// Whether the call's text holds a token of a well-known format, or the
/// value, of at least `MIN_VALUE_CHARS`, of a credential-shaped variable the
/// observation found.
pub(super) fn retypes_credential(
    plan: &Plan,
    withheld: Option<&ToolCall>,
    observation: &Observation,
) -> bool {
    let values = observation
        .facts()
        .iter()
        .filter_map(|fact| match fact.value() {
            ObservationValue::CredentialEnvironment { variables } => Some(variables.values()),
            _ => None,
        })
        .flatten()
        .filter(|value| value.chars().count() >= MIN_VALUE_CHARS)
        .collect::<Vec<_>>();
    stated_text(plan, withheld)
        .into_iter()
        .any(|text| holds_token(text) || values.iter().any(|value| text.contains(value.as_str())))
}

/// Whether `text` holds a token of a `TOKEN_FORMATS` format: a prefix that
/// does not continue a word, then a body of the format's alphabet and length
/// that looks random.
fn holds_token(text: &str) -> bool {
    TOKEN_FORMATS.iter().any(|format| {
        format
            .prefixes
            .iter()
            .any(|prefix| holds_prefixed_token(text, format, prefix))
    })
}

/// [`holds_token`] for one prefix, in one pass linear in `text`. Bodies that
/// start inside one run of body characters all end where it ends, so the run
/// is measured once. A body there that is too uniform to be a token leaves
/// every later one in the run too uniform as well, since each is a suffix of
/// it, so they are skipped.
fn holds_prefixed_token(text: &str, format: &TokenFormat, prefix: &str) -> bool {
    let mut run_end = 0;
    let mut uniform_run_end = None;
    for (start, _) in text.match_indices(prefix) {
        if text[..start]
            .chars()
            .next_back()
            .is_some_and(alphanumeric_or_underscore)
        {
            continue;
        }
        let body_start = start + prefix.len();
        if body_start > run_end {
            run_end = text[body_start..]
                .find(|character| !(format.body)(character))
                .map_or(text.len(), |length| body_start + length);
        }
        let body = &text[body_start..run_end];
        if !format.length.contains(&body.len())
            || uniform_run_end == Some(run_end)
            || !(format.shape)(body)
        {
            continue;
        }
        if looks_random(body) {
            return true;
        }
        uniform_run_end = Some(run_end);
    }
    false
}

/// Whether an issued token's body is random rather than a placeholder such as
/// `ghp_XXXX…` or `xoxb-0000…`: it mixes at least two of lowercase letters,
/// uppercase letters and digits, and draws on at least eight characters.
fn looks_random(body: &str) -> bool {
    let classes = [
        char::is_ascii_lowercase,
        char::is_ascii_uppercase,
        char::is_ascii_digit,
    ]
    .iter()
    .filter(|class| body.chars().any(|character| class(&character)))
    .count();
    let distinct = body
        .chars()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    classes >= 2 && distinct >= 8
}

#[cfg(test)]
mod tests {
    use effinterp_proto::{FilePatchArgs, PatchFormat};

    #[test]
    fn patch_lines_split_added_content_from_file_headers() {
        let lines = |format, text: &str| {
            let args = FilePatchArgs {
                format,
                text: text.into(),
            };
            (
                effinterp_engine::patch_added_lines(&args).join("|"),
                effinterp_engine::patch_header_lines(&args).join("|"),
            )
        };
        assert_eq!(
            lines(
                PatchFormat::ApplyPatch,
                "*** Begin Patch\n*** Add File: a\n+++ kept\n+plain\n*** End Patch"
            ),
            (
                "++ kept|plain".into(),
                "*** Begin Patch|*** Add File: a|*** End Patch".into()
            )
        );
        // A unified diff's headers sit outside its hunks; a `+++ ` or `--- `
        // line inside a hunk is content.
        assert_eq!(
            lines(
                PatchFormat::Unified,
                "--- a/f\n+++ b/f\n@@ -1,2 +1,3 @@\n context\n-gone\n+++ kept\n+new\n--- a/g\n+++ b/g\n@@ -1 +1 @@\n-x\n+y"
            ),
            (
                "++ kept|new|y".into(),
                "--- a/f|+++ b/f|@@ -1,2 +1,3 @@|--- a/g|+++ b/g|@@ -1 +1 @@".into()
            )
        );
    }
}
