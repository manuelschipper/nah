//! git commands that read the objects they name: `git show REV:PATH`,
//! `git cat-file`, `git archive`, and the tree and ref queries `merge-base`,
//! `ls-tree`, `diff-tree` and `show-ref`.

use effinterp_proto::{AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain};

use crate::builder::PlanBuilder;
use crate::models::common::{Attrs, arg_node};

use super::{ALL_DOMAINS, SubCtx, git_argument_boundary};

/// `git merge-base`, `ls-tree`, `diff-tree` and `show-ref` read the
/// repository; an option outside the closed set each one takes is an
/// unrecognized-arguments boundary.
pub(super) fn tree_or_ref_query(builder: &mut PlanBuilder, sub: &str, s: &SubCtx) {
    let spec = match sub {
        "merge-base" => crate::models::args::FlagSpec {
            allow_abbreviation: false,
            value_flags: &[],
            known_flags: &[
                "-a",
                "--all",
                "--octopus",
                "--independent",
                "--is-ancestor",
                "--fork-point",
            ],
        },
        "ls-tree" => crate::models::args::FlagSpec {
            allow_abbreviation: false,
            value_flags: &["--format", "--abbrev"],
            known_flags: &[
                "-d",
                "-r",
                "-t",
                "-l",
                "-z",
                "--name-only",
                "--name-status",
                "--object-only",
                "--full-name",
                "--full-tree",
                "--long",
            ],
        },
        "diff-tree" => crate::models::args::FlagSpec {
            allow_abbreviation: false,
            value_flags: &["--diff-filter", "--format", "--pretty", "--abbrev"],
            known_flags: &[
                "-r",
                "-t",
                "-z",
                "-p",
                "-s",
                "-m",
                "-c",
                "--cc",
                "--root",
                "--no-commit-id",
                "--name-only",
                "--name-status",
                "--raw",
                "--stat",
                "--numstat",
                "--shortstat",
                "--summary",
                "--quiet",
                "--exit-code",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--no-patch",
                "--patch",
                "--binary",
                "--full-index",
            ],
        },
        _ => crate::models::args::FlagSpec {
            allow_abbreviation: false,
            value_flags: &[],
            known_flags: &[
                "--head",
                "--heads",
                "--branches",
                "--tags",
                "--verify",
                "--exists",
                "--quiet",
                "-q",
                "--hash",
                "-s",
                "--dereference",
                "-d",
                "--exclude-existing",
            ],
        },
    };
    let mut parsed = crate::models::args::scan(&s.ctx.argv[s.sub_index as usize..], &spec);
    for (index, _) in &mut parsed.unknown_flags {
        *index += s.sub_index;
    }
    crate::models::common::unrecognized_arguments_boundary(
        builder,
        s.model_node,
        &ALL_DOMAINS,
        &parsed.unknown_flags,
    );
    s.repo_effect(builder, "git.read", Attrs::new());
}

/// `git archive` reads the repository and writes the file `-o` names.
/// `--remote`, `--exec` and the `--add-file` options take input or run
/// a program the model does not follow.
pub(super) fn archive(builder: &mut PlanBuilder, s: &SubCtx) {
    let mut parsed = crate::models::args::scan_with_value_indices(
        &s.ctx.argv[s.sub_index as usize..],
        &crate::models::args::FlagSpec {
            allow_abbreviation: false,
            value_flags: &[
                "-o",
                "--output",
                "--format",
                "--prefix",
                "--remote",
                "--exec",
                "--add-file",
                "--add-virtual-file",
            ],
            known_flags: &[
                "-v",
                "--verbose",
                "-l",
                "--list",
                "--worktree-attributes",
                "-0",
                "-1",
                "-2",
                "-3",
                "-4",
                "-5",
                "-6",
                "-7",
                "-8",
                "-9",
            ],
        },
        true,
    );
    for flag in &parsed.flags {
        if flag.value.is_none() && matches!(flag.name, "-o" | "--output" | "--remote" | "--exec") {
            parsed
                .unknown_flags
                .push((flag.index, flag.name.to_string()));
        }
    }
    for (index, _) in &mut parsed.unknown_flags {
        *index += s.sub_index;
    }
    crate::models::common::unrecognized_arguments_boundary(
        builder,
        s.model_node,
        &ALL_DOMAINS,
        &parsed.unknown_flags,
    );
    if !parsed.unknown_flags.is_empty() {
        return;
    }
    if parsed.has(&["--remote", "--exec", "--add-file", "--add-virtual-file"]) {
        crate::models::common::unrecognized_arguments_boundary(
            builder,
            s.model_node,
            &ALL_DOMAINS,
            &[(
                s.sub_index,
                "archive external input or remote execution".to_string(),
            )],
        );
        return;
    }
    s.repo_effect(builder, "git.read", Attrs::new());
    if let Some((index, file)) = parsed.values_of(&["-o", "--output"]).last() {
        s.filesystem_path_effect(
            builder,
            s.sub_index + *index,
            file,
            "filesystem.write",
            Attrs::new(),
        );
    }
}

/// `git cat-file <mode> <object>` reads one object, printing its
/// contents unless the mode asks only for its type, size or existence.
/// The batch modes take their object selectors from stdin.
pub(super) fn cat_file(builder: &mut PlanBuilder, s: &SubCtx) {
    if matches!(s.rest, [mode] if mode.as_literal().is_some_and(|arg| {
        matches!(
            arg.split('=').next(),
            Some("--batch" | "--batch-check" | "--batch-command")
        )
    })) {
        builder.boundary(Boundary {
            reason: BoundaryReason::INPUT_DETERMINED_ARGUMENTS,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(s.repo.clone()),
            callee: None,
            domains: vec![Domain::new("git"), Domain::new("filesystem")],
            provenance: vec![s.model_node],
            limit: None,
            detail: Some("git cat-file batch object selectors come from stdin".into()),
        });
        return;
    }
    let [mode, object] = s.rest else {
        crate::models::common::unrecognized_arguments_boundary(
            builder,
            s.model_node,
            &ALL_DOMAINS,
            &[(
                s.sub_index,
                "cat-file requires a mode and one object".into(),
            )],
        );
        return;
    };
    let Some(mode @ ("blob" | "tree" | "commit" | "tag" | "-p" | "-t" | "-s" | "-e")) =
        mode.as_literal()
    else {
        crate::models::common::unrecognized_arguments_boundary(
            builder,
            s.model_node,
            &ALL_DOMAINS,
            &[(
                s.rest_offset,
                "cat-file object selection or conversion is unmodeled".into(),
            )],
        );
        return;
    };
    let Some(object) = object.as_literal() else {
        let node = arg_node(builder, s.ctx, s.rest_offset + 1);
        builder.boundary(Boundary {
            reason: BoundaryReason::DYNAMIC_SOURCE,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Invocation,
            affected_resource: Some(s.repo.clone()),
            callee: None,
            domains: vec![Domain::new("git")],
            provenance: vec![s.model_node, node],
            limit: None,
            detail: Some("git cat-file object selector is dynamic".into()),
        });
        return;
    };
    if object.is_empty() || object.starts_with('-') {
        git_argument_boundary(builder, s, "cat-file requires an object selector");
        return;
    }
    let mut attributes = Attrs::from([
        ("object".into(), AttrValue::String(object.into())),
        ("mode".into(), AttrValue::String(mode.into())),
    ]);
    if !matches!(mode, "-t" | "-s" | "-e") {
        attributes.insert("output".into(), AttrValue::String("stdout".into()));
    }
    s.object_read(
        builder,
        s.rest_offset + 1,
        object,
        attributes,
        if matches!(mode, "-t" | "-s" | "-e" | "tree") {
            "metadata"
        } else {
            "contents"
        },
    );
}

/// The `REV:PATH` operands of a `git show` whose words are all literal.
/// The options that shape how a commit is shown (`--stat`, `-s`,
/// `--no-patch`, `--format=…`, `--pretty=…`) leave a blob as it is: git
/// prints its contents whatever they say, before or after the operand.
pub(super) fn shown_objects<'a>(s: &'a SubCtx<'a>) -> Vec<(u32, &'a str)> {
    if s.rest
        .iter()
        .any(|word| word.as_literal().is_none_or(|text| text == "--"))
    {
        return Vec::new();
    }
    s.operands(false)
        .into_iter()
        .filter_map(|(index, word)| Some((index, word.as_literal()?)))
        .filter(|(_, object)| object.contains(':'))
        .collect()
}

/// State the contents read of each object `git show` prints.
pub(super) fn record_shown_object_reads(builder: &mut PlanBuilder, s: &SubCtx) {
    for (index, object) in shown_objects(s) {
        s.object_read(
            builder,
            index,
            object,
            Attrs::from([
                ("object".into(), AttrValue::String(object.into())),
                ("output".into(), AttrValue::String("stdout".into())),
            ]),
            "contents",
        );
    }
}
