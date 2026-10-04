//! The `git remote` command: the remote settings `add`, `set-url` and
//! `rename` write, and the remote-tracking refs `remove` deletes.

use effinterp_proto::AttrValue;

use crate::builder::PlanBuilder;
use crate::models::args::FlagSpec;
use crate::models::common::{Attrs, attrs};
use crate::resource_transfer::TransferBinding;
use crate::word::Word;

use super::git_options::{git_operands_known, git_options, git_options_known};
use super::git_repository::selects_by_discovery;
use super::{SubCtx, request_attrs};

pub(super) fn remote(builder: &mut PlanBuilder, s: &SubCtx) {
    s.repo_effect(builder, "git.config_write", Attrs::new());
    record_remote_settings(builder, s);
    let operands = s.operands(false);
    // `git remote add -f` fetches the new remote as soon as it is added.
    if operands.first().and_then(|(_, action)| action.as_literal()) == Some("add")
        && s.scanned(&["-f", "--fetch"]).has(&["-f", "--fetch"])
    {
        let synced = s.repo_effect_slot(builder, "git.remote_sync", attrs(&[("fetch", true)]));
        let source = s.remote_network(builder, "network.download");
        if let (Some(source), Some(synced)) = (source, synced) {
            builder.transfer_binding(TransferBinding::new(source, synced));
        }
    }
    let [(_, action), (_, name)] = operands.as_slice() else {
        return;
    };
    if !matches!(action.as_literal(), Some("remove" | "rm")) {
        return;
    }
    let Some(name) = name
        .as_literal()
        .filter(|name| !name.is_empty() && !name.starts_with('-'))
    else {
        return;
    };
    s.repo_effect(
        builder,
        "git.ref_update",
        Attrs::from([
            ("delete".into(), AttrValue::Bool(true)),
            ("remote".into(), AttrValue::String(name.into())),
        ]),
    );
    let mut request = request_attrs(&[("delete", true), ("selection_complete", false)]);
    request.insert("remote".into(), AttrValue::String(name.into()));
    request.insert("scope".into(), AttrValue::String("selected".into()));
    request.insert("broad".into(), AttrValue::Bool(false));
    s.request_effect(builder, "git.ref_delete_request", request);
}

/// Record the `remote.<name>.mirror=true` that `git remote add` writes for
/// `--mirror=push`, or for `--mirror` alone, which mirrors both ways. A
/// mirror mode the model cannot read may be push; a name it cannot read is
/// recorded under an unknown key. `git remote rename` moves the remote's
/// section, so a literal rename adds each earlier recorded setting of the
/// old remote under the new name.
fn record_remote_settings(builder: &mut PlanBuilder, s: &SubCtx) {
    let parsed = git_options(
        s,
        &FlagSpec {
            value_flags: &["-t", "--track", "-m", "--master"],
            known_flags: &[
                "-f",
                "--fetch",
                "--no-fetch",
                "--tags",
                "--no-tags",
                "--mirror",
                "--no-mirror",
                "-v",
                "--verbose",
                "--progress",
                "--no-progress",
            ],
            allow_abbreviation: true,
        },
    );
    let [(_, action), (_, name), ..] = parsed.operands.as_slice() else {
        return;
    };
    if action.as_literal() == Some("rename")
        && git_options_known(&parsed)
        && let [_, _, (_, new_name)] = parsed.operands.as_slice()
        && let (Some(old), Some(new)) = (name.as_literal(), new_name.as_literal())
    {
        let renamed: Vec<_> = builder
            .git_config_writes()
            .filter_map(|write| {
                let (section, rest) = write.key.as_deref()?.split_once('.')?;
                let (subsection, variable) = rest.rsplit_once('.')?;
                (section.eq_ignore_ascii_case("remote") && subsection == old).then(|| {
                    (
                        write.scope,
                        write.repository.clone(),
                        format!("remote.{new}.{variable}"),
                        write.value.clone(),
                    )
                })
            })
            .collect();
        for (scope, repository, key, value) in renamed {
            builder.record_git_config_write(scope, repository, Some(key), value);
        }
        return;
    }
    record_remote_url(builder, s);
    if action.as_literal() != Some("add") {
        return;
    }
    let argv = &s.ctx.argv[s.rest_offset as usize - 1..];
    let mode = parsed.flags.iter().rev().find_map(|flag| match flag.name {
        "--no-mirror" => Some(Some("none")),
        "--mirror" => Some(
            argv[flag.index as usize]
                .as_literal()
                .map(|text| text.split_once('=').map_or("push", |(_, mode)| mode)),
        ),
        _ => None,
    });
    // A word whose literal start spells `--mirror` may carry any mode.
    let dynamic_mirror = |index: u32| {
        let word = &argv[index as usize];
        let prefix = word.literal_prefix();
        word.as_literal().is_none()
            && prefix.len() >= 4
            && ("--mirror".starts_with(prefix) || prefix.starts_with("--mirror"))
    };
    if !parsed
        .unknown_flags
        .iter()
        .any(|(index, _)| dynamic_mirror(*index))
        && !matches!(mode, Some(None | Some("push")))
    {
        return;
    }
    let repository = selects_by_discovery(builder, s.ctx, s.globals).then(|| s.repo.clone());
    // A dynamic word may be an option that shifts which operand is the name.
    let operands_known = git_operands_known(&parsed)
        && parsed.unknown_flags.iter().all(|(index, _)| {
            dynamic_mirror(*index)
                || parsed
                    .flags
                    .iter()
                    .any(|flag| flag.index == *index && flag.name == "--mirror")
        });
    let key = name
        .as_literal()
        .filter(|_| operands_known)
        .map(|name| format!("remote.{name}.mirror"));
    builder.record_git_config_write(
        crate::builder::GitConfigScope::Local,
        repository,
        key,
        Some("true".into()),
    );
}

/// Record the `remote.<name>.url` that `git remote add <name> <url>` and
/// `git remote set-url <name> <url>` write, or the `remote.<name>.pushurl`
/// of `set-url --push`, so a later transfer in the subject that names the
/// remote reaches the URL. Only a literal name and URL are recorded: the
/// unresolved endpoint a named remote always keeps covers every other form.
fn record_remote_url(builder: &mut PlanBuilder, s: &SubCtx) {
    let Some(words) = s
        .rest
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let mut operands = Vec::new();
    let mut variable = "url";
    let mut words = words.into_iter();
    match words.next() {
        Some("add") => {
            // git-remote(1): `-t <branch>` and `-m <master>` take the next
            // word; every other `add` option stands alone.
            while let Some(word) = words.next() {
                match word {
                    "-t" | "--track" | "-m" | "--master" => {
                        words.next();
                    }
                    option if option.starts_with('-') => {}
                    operand => operands.push(operand),
                }
            }
        }
        Some("set-url") => {
            for word in words {
                match word {
                    "--push" => variable = "pushurl",
                    "--add" => {}
                    // `--delete` removes URLs matching a pattern.
                    option if option.starts_with('-') => return,
                    operand => operands.push(operand),
                }
            }
        }
        _ => return,
    }
    let [name, url, ..] = operands.as_slice() else {
        return;
    };
    let repository = selects_by_discovery(builder, s.ctx, s.globals).then(|| s.repo.clone());
    builder.record_git_config_write(
        crate::builder::GitConfigScope::Local,
        repository,
        Some(format!("remote.{name}.{variable}")),
        Some((*url).to_string()),
    );
}
