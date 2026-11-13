//! Failure-only protection for established destructive targets or credential
//! reads. Healthy analysis, including ordinary uncertainty, keeps its verdict.

use nah_proto::ctx::Ctx;
use nah_proto::decision::{DecisionCore, Verdict};
use nah_proto::effinterp_proto::{AttrValue, Plan, ResourceExpr, ResourceIdentity};
use nah_proto::labels::sensitivity::environment_file;
use nah_proto::labels::system_tree::selects_root_or_system_tree;
use nah_proto::tool::ToolCallInput;

use super::DecisionResult;

pub(super) fn block_suspicious_failure(
    result: &mut DecisionResult,
    input: &ToolCallInput,
    ctx: &Ctx,
    mode: nah_policy::EnforcementMode,
    exceeded: Option<&[&str]>,
) {
    if mode == nah_policy::EnforcementMode::AllPaused
        || result.core().verdict() == Verdict::Block
        || !result.evaluation_failed()
    {
        return;
    }
    // Once shipped guards have run, only their unfinished queries may need
    // suspicion protection. A late deadline does not undo completed exemptions.
    if exceeded.is_some_and(<[&str]>::is_empty) {
        return;
    }
    let suspected = match result.effinterp() {
        Some(analysis) => from_plan(analysis.plan(), ctx, exceeded),
        None => prescreen(input, ctx),
    };
    if let Some(guard) = suspected {
        let reason = format!(
            "nah could not finish safety evaluation; available evidence suggests {guard}; this call was blocked; ask the operator before retrying"
        );
        result.replace_core(
            DecisionCore::structural_block_with_coverage(result.core().coverage(), &reason)
                .expect("fixed failure protection reason is valid"),
        );
    }
}

fn enabled(ctx: &Ctx, guard: &str, exceeded: Option<&[&str]>) -> bool {
    exceeded.is_none_or(|guards| guards.contains(&guard))
        && ctx
            .shipped_guards()
            .iter()
            .any(|state| state.name() == guard && state.enabled())
}

fn from_plan(plan: &Plan, ctx: &Ctx, exceeded: Option<&[&str]>) -> Option<&'static str> {
    plan.effects.iter().find_map(|effect| {
        if !effect.realm.is_host() {
            return None;
        }
        let read = effect.operation.as_str() == "filesystem.read";
        let delete = effect.operation.as_str() == "filesystem.delete"
            && effect.attributes.get("recursive") == Some(&AttrValue::Bool(true));
        if !read && !delete {
            return None;
        }
        resource_suspicion(&effect.resource, read, delete, ctx, exceeded).or_else(|| {
            let AttrValue::String(path) = effect.attributes.get("spelled_path")? else {
                return None;
            };
            path_suspicion(path, read, delete, ctx, exceeded)
        })
    })
}

fn resource_suspicion(
    resource: &ResourceExpr,
    read: bool,
    delete: bool,
    ctx: &Ctx,
    exceeded: Option<&[&str]>,
) -> Option<&'static str> {
    match resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => path_suspicion(path, read, delete, ctx, exceeded),
        ResourceExpr::Environment { name }
            if delete && matches!(name.as_str(), "HOME" | "USERPROFILE") =>
        {
            enabled(ctx, "fs-home", exceeded).then_some("fs-home")
        }
        ResourceExpr::Union { alternatives } => alternatives
            .iter()
            .find_map(|resource| resource_suspicion(resource, read, delete, ctx, exceeded)),
        _ => None,
    }
}

fn path_suspicion(
    path: &str,
    read: bool,
    delete: bool,
    ctx: &Ctx,
    exceeded: Option<&[&str]>,
) -> Option<&'static str> {
    if delete
        && path.trim_end_matches('/') == ctx.home().as_str().trim_end_matches('/')
        && enabled(ctx, "fs-home", exceeded)
    {
        Some("fs-home")
    } else if delete
        && selects_root_or_system_tree(path)
        && enabled(ctx, "fs-system-tree", exceeded)
    {
        Some("fs-system-tree")
    } else if read
        && environment_file(path, ctx.platform())
        && enabled(ctx, "secrets-env", exceeded)
    {
        Some("secrets-env")
    } else {
        None
    }
}

/// With no plan, recognize only direct rm, cat and curl calls with plain words.
/// Shell syntax, quoting, wrappers and source files require the engine. Help,
/// version, templates and count-only pipelines never trigger this screen.
fn prescreen(input: &ToolCallInput, ctx: &Ctx) -> Option<&'static str> {
    if input.tool() == "Read" {
        return path_suspicion(
            input.input().get("file_path")?.as_str()?,
            true,
            false,
            ctx,
            None,
        );
    }
    if input.tool() != "Bash" || ctx.platform() == nah_proto::ctx::Platform::Windows {
        return None;
    }
    let command = input.input().get("command")?.as_str()?;
    if command.len() > 4096
        || !command
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" \t-_/.:~@=%".contains(&byte))
    {
        return None;
    }
    let words = command.split_ascii_whitespace().collect::<Vec<_>>();
    let (head, args) = words.split_first()?;
    if args
        .iter()
        .any(|word| matches!(*word, "--help" | "--version"))
    {
        return None;
    }
    match *head {
        "rm" | "/bin/rm" | "/usr/bin/rm" => {
            let mut recursive = false;
            let mut paths = args;
            while let Some((word, rest)) = paths.split_first() {
                if !word.starts_with('-') {
                    break;
                }
                paths = rest;
                if *word == "--recursive" {
                    recursive = true;
                } else if *word == "--" {
                    break;
                } else if matches!(*word, "--force" | "--no-preserve-root") {
                } else if let Some(flags) = word.strip_prefix('-') {
                    if flags.is_empty() || !flags.bytes().all(|byte| b"frR".contains(&byte)) {
                        return None;
                    }
                    recursive |= flags.contains(['r', 'R']);
                }
            }
            if !recursive {
                return None;
            }
            paths.iter().find_map(|path| {
                let path = if path.trim_end_matches('/') == "~" {
                    ctx.home().as_str()
                } else {
                    path
                };
                path_suspicion(path, false, true, ctx, None)
            })
        }
        "cat" | "/bin/cat" | "/usr/bin/cat" => args
            .iter()
            .filter(|word| !word.starts_with('-'))
            .find_map(|path| path_suspicion(path, true, false, ctx, None)),
        "curl" | "/bin/curl" | "/usr/bin/curl" => {
            let mut args = args.iter();
            let mut suspected = None;
            while let Some(word) = args.next() {
                let path = match *word {
                    "-s" | "-S" | "-sS" | "-f" | "-L" | "--silent" | "--show-error" => continue,
                    "-X" | "--request" | "--url" | "-o" | "--output" | "--data-raw" => {
                        args.next()?;
                        continue;
                    }
                    "-T" | "--upload-file" => *args.next()?,
                    "-F" | "--form" => {
                        let (_, value) = args.next()?.split_once('=')?;
                        let Some(path) = value.strip_prefix('@') else {
                            continue;
                        };
                        path
                    }
                    "-d" | "--data" | "--data-binary" | "--data-urlencode" | "--json" => {
                        let value = args.next()?;
                        let Some(path) = value.strip_prefix('@') else {
                            continue;
                        };
                        path
                    }
                    word if !word.starts_with('-') => continue,
                    _ => return None,
                };
                suspected = suspected.or_else(|| path_suspicion(path, true, false, ctx, None));
            }
            suspected
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nah_corpus_schema::{CaseInput, Expectation, ExpectedVerdict, read_corpus_rows};
    use nah_proto::ctx::{AbsolutePath, SchemaVersion, TrustProjection};

    // A timeout must not turn routine cleanup, templates, quoted examples or
    // any other benign corpus shell call into an unconditional block.
    #[test]
    fn no_plan_screen_preserves_benign_corpus_calls_and_guard_choices() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let fixtures: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(corpus.join("FIXTURES.json")).unwrap())
                .unwrap();
        let mut checked = 0;
        for row in read_corpus_rows(&corpus).unwrap() {
            let case = row.case.unwrap();
            if !matches!(
                case.expected,
                Expectation::Decision {
                    verdict: ExpectedVerdict::Delegate,
                    ..
                }
            ) {
                continue;
            }
            let CaseInput::Command(command) = &case.input else {
                continue;
            };
            let fixture = &fixtures["ctx_fixtures"][&case.ctx_fixture];
            let platform = serde_json::from_value(fixture["platform"].clone()).unwrap();
            let states = match fixture["shipped_guards"].as_str() {
                Some("all-enabled") => crate::catalog::all_shipped_guard_states_enabled(),
                Some("all-disabled") => vec![],
                Some(_) => crate::catalog::shipped_guard_states(),
                None => {
                    serde_json::from_value(fixture["shipped_guards"]["states"].clone()).unwrap()
                }
            };
            let ctx = Ctx::new(
                platform,
                AbsolutePath::new(platform, fixture["home"].as_str().unwrap()).unwrap(),
                states,
                vec![],
                TrustProjection::new(vec![]).unwrap(),
            )
            .unwrap();
            let input = ToolCallInput::new(
                SchemaVersion::V1,
                "Bash",
                serde_json::json!({"command":command}),
                if platform == nah_proto::ctx::Platform::Windows {
                    "C:\\repo"
                } else {
                    "/repo"
                },
                None,
            )
            .unwrap();
            assert_eq!(prescreen(&input, &ctx), None, "{}: {command}", case.id);
            checked += 1;
        }
        assert!(checked > 1000);

        let input = ToolCallInput::new(
            SchemaVersion::V1,
            "Bash",
            serde_json::json!({"command":"rm -rf ~"}),
            "/repo",
            None,
        )
        .unwrap();
        let ctx = Ctx::new(
            nah_proto::ctx::Platform::Linux,
            AbsolutePath::new(nah_proto::ctx::Platform::Linux, "/home/test").unwrap(),
            vec![],
            vec![],
            TrustProjection::new(vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(prescreen(&input, &ctx), None);
    }
}
