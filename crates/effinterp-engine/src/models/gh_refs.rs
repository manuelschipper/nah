//! Remote Git ref writes through `gh api`: GitHub's "update a reference"
//! (`PATCH repos/{owner}/{repo}/git/refs/{ref}`) and "delete a reference"
//! (`DELETE` on the same route), and the update sent with `curl`. Each is
//! stated as the `git.push_request` a `git push` of that ref would make, so
//! the Git push guards read both.
//!
//! GitHub documents the update's `force` field: "Leaving this out or setting
//! it to false will make sure you're not overwriting work." Such an update is
//! a non-forced push, which the protected-branch guard still decides.

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, Effect,
    ExecutionNodeRef, ExecutionRealm, Modality, Operation, ProvenanceRef, RequestAssurance,
};

use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{Attrs, arg_node};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

/// The `gh` options that take a value, as the gh model declares them; any
/// other option word stands alone.
const VALUE_FLAGS: &[&str] = &[
    "--repo",
    "-R",
    "--hostname",
    "--method",
    "-X",
    "--raw-field",
    "-f",
    "--field",
    "-F",
    "--input",
    "--json",
    "--jq",
    "-q",
    "--template",
    "-t",
    "--limit",
    "--state",
    "--search",
    "--pattern",
    "--dir",
    "--head",
    "--base",
    "--body",
    "--title",
    "--name",
    "--branch",
    "--status",
    "--preview",
    "-p",
    "--cache",
    "--header",
    "-H",
    "--visibility",
    "--env-file",
];

enum Method {
    Update,
    Delete,
    Symbolic,
}

enum Force {
    Yes,
    No,
    Unknown,
}

/// State the ref write a `gh api` invocation requests, after the gh model
/// accepted its syntax by emitting effects from `start` on.
pub(super) fn api_ref_request(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    start: usize,
) {
    if ctx.argv.get(1).and_then(Word::as_literal) != Some("api") || builder.effects_len() == start {
        return;
    }
    let mut method = None;
    let mut route = None;
    let mut fields = Vec::new();
    let mut input = None;
    let mut hostname = None;
    let mut index = 2;
    while index < ctx.argv.len() {
        let word = &ctx.argv[index];
        let prefix = word.literal_prefix();
        if prefix.len() > 1 && prefix.starts_with('-') {
            let (name, attached) = if prefix.starts_with("--") {
                word.split_assignment()
                    .map_or((prefix.to_owned(), None), |(name, value)| {
                        (name.to_owned(), Some(value))
                    })
            } else {
                // A short cluster such as `-iXDELETE` sets Boolean letters up
                // to the first option that takes a value, which takes the
                // rest of the word after an optional `=` (`-X=DELETE`);
                // `-i=false` gives its Boolean letter a value.
                let letters = &prefix[1..];
                let taking = letters
                    .char_indices()
                    .take_while(|(_, letter)| *letter != '=')
                    .find(|(_, letter)| VALUE_FLAGS.contains(&format!("-{letter}").as_str()));
                let Some((at, letter)) = taking else {
                    index += 1;
                    continue;
                };
                let rest = Word::new(
                    std::iter::once(WordPart::Literal(
                        letters[at + letter.len_utf8()..]
                            .strip_prefix('=')
                            .unwrap_or(&letters[at + letter.len_utf8()..])
                            .into(),
                    ))
                    .chain(word.parts[1..].iter().cloned())
                    .collect(),
                );
                (
                    format!("-{letter}"),
                    (rest.as_literal() != Some("")).then_some(rest),
                )
            };
            if VALUE_FLAGS.contains(&name.as_str()) {
                let value = match attached {
                    Some(value) => value,
                    None => {
                        index += 1;
                        ctx.argv
                            .get(index)
                            .cloned()
                            .unwrap_or_else(|| Word::literal(""))
                    }
                };
                match name.as_str() {
                    "-X" | "--method" => method = Some(value),
                    "-f" | "--raw-field" => fields.push((false, value)),
                    "-F" | "--field" => fields.push((true, value)),
                    "--input" => input = Some(value),
                    "--hostname" => hostname = Some(value),
                    _ => {}
                }
            }
        } else if route.is_none() {
            route = Some(index);
        }
        index += 1;
    }
    let method = match method.as_ref().map(Word::as_literal) {
        Some(Some(value)) if value.eq_ignore_ascii_case("PATCH") => Method::Update,
        Some(Some(value)) if value.eq_ignore_ascii_case("DELETE") => Method::Delete,
        Some(None) => Method::Symbolic,
        _ => return,
    };
    let Some(route) = route else {
        return;
    };
    let Some(destination) = ref_route(&ctx.argv[route], hostname.as_ref()) else {
        return;
    };
    // A nonempty `--input` names the body, and gh then sends the fields as
    // query parameters, so only a body without one states `force`. gh reads
    // the last `--input`, and an empty one names no body. `--input -` is
    // standard input, whose bytes a pipe, here-document or here-string may
    // establish; a file's are not read here.
    let body_from_input = input
        .as_ref()
        .is_some_and(|input| input.as_literal() != Some(""));
    let (mut force, mut source) = match (&input, ctx.stdin) {
        (Some(input), Some(stdin)) if input.as_literal() == Some("-") => {
            json_body_force(&stdin.word)
        }
        _ if body_from_input => (Force::Unknown, None),
        _ => (Force::No, None),
    };
    if !body_from_input {
        for (typed, field) in &fields {
            let (key, value) = match field.split_assignment() {
                Some((key, value)) => (key, value),
                // A key the shell supplies may be `force`.
                _ if field.as_literal().is_none() => {
                    force = Force::Unknown;
                    continue;
                }
                _ => continue,
            };
            match key {
                // `-F` sends `true` and `false` as JSON booleans; `-f` sends
                // a string GitHub does not take as the boolean, and any other
                // value is not established here.
                "force" => {
                    force = match (typed, value.as_literal()) {
                        (true, Some("true")) => Force::Yes,
                        (true, Some("false")) => Force::No,
                        _ => Force::Unknown,
                    }
                }
                "sha" => source = value.as_literal().map(str::to_owned),
                _ => {}
            }
        }
    }
    let arg = arg_node(builder, ctx, route as u32);
    ref_write_request(
        builder,
        &method,
        &force,
        destination,
        source,
        node,
        arg,
        "GitHub ref name or update force is symbolic, or comes from a string field or an --input body that is not read",
    );
}

/// State the ref update a `curl -X PATCH` of GitHub's "update a reference"
/// route requests. `body` is its one data body, `None` when curl reads it from
/// a file or joins several; the caller has established the method and that
/// nothing else reshapes the request.
pub(super) fn curl_ref_request(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    (url_index, url): (u32, &Word),
    body: Option<&Word>,
) {
    // curl sends a URL without a scheme over plain HTTP, never to the API.
    if !url.literal_prefix().starts_with("https://") {
        return;
    }
    let Some(destination) = ref_route(url, None) else {
        return;
    };
    let (force, source) = body.map_or((Force::Unknown, None), json_body_force);
    let arg = arg_node(builder, ctx, url_index);
    ref_write_request(
        builder,
        &Method::Update,
        &force,
        destination,
        source,
        node,
        arg,
        "GitHub ref name or update force is symbolic, or comes from a body the shell supplies",
    );
}

/// The `force` and `sha` a JSON request body states. A part the shell
/// supplies is read only inside a JSON string, standing for its text: a
/// literal `"force": true` then stands as written, but an absent or false
/// `force` is unknown, since the supplied text is not established.
fn json_body_force(body: &Word) -> (Force, Option<String>) {
    let mut text = String::new();
    let mut supplied = false;
    let mut in_string = false;
    let mut escaped = false;
    for part in &body.parts {
        match part {
            WordPart::Literal(literal) => {
                for character in literal.chars() {
                    if escaped {
                        escaped = false;
                    } else if in_string && character == '\\' {
                        escaped = true;
                    } else if character == '"' {
                        in_string = !in_string;
                    }
                }
                text.push_str(literal);
            }
            _ if in_string && !escaped => {
                supplied = true;
                text.push('0');
            }
            _ => return (Force::Unknown, None),
        }
    }
    let Ok(serde_json::Value::Object(fields)) = serde_json::from_str(&text) else {
        return (Force::Unknown, None);
    };
    let force = match fields.get("force") {
        Some(serde_json::Value::Bool(true)) => Force::Yes,
        Some(serde_json::Value::Bool(false)) | None if !supplied => Force::No,
        _ => Force::Unknown,
    };
    let source = fields
        .get("sha")
        .and_then(serde_json::Value::as_str)
        .filter(|_| !supplied)
        .map(str::to_owned);
    (force, source)
}

/// State one hosted ref write as the `git.push_request` a `git push` of that
/// ref would make: exact when its destination and force are known, and a
/// conservative request beside a boundary otherwise.
#[allow(clippy::too_many_arguments)]
fn ref_write_request(
    builder: &mut PlanBuilder,
    method: &Method,
    force: &Force,
    destination: Option<String>,
    source: Option<String>,
    node: ProvenanceRef,
    arg: ProvenanceRef,
    detail: &str,
) {
    let mut attrs = Attrs::new();
    for (key, value) in [
        ("push", true),
        ("active", true),
        ("abort", false),
        ("dry_run", false),
        ("controls_complete", true),
        ("destination_complete", destination.is_some()),
        ("lease_requested", false),
        ("all_refs_lease", false),
        ("mirror", false),
        ("all", false),
        ("prune", false),
    ] {
        attrs.insert(key.into(), AttrValue::Bool(value));
    }
    let (deleted, forced) = match (method, force) {
        // Git states every deletion as forced, from an empty source.
        (Method::Delete, _) => (Some(true), Some(true)),
        (Method::Update, Force::Yes) => (Some(false), Some(true)),
        (Method::Update, Force::No) => (Some(false), Some(false)),
        (Method::Update, Force::Unknown) => (Some(false), None),
        (Method::Symbolic, _) => (None, None),
    };
    if let Some(destination) = &destination {
        // A ref write names one destination and takes no lease.
        let destinations = [super::git::git_push::PushedRef {
            destination: Some(super::git::git_push::normalize_push_ref(destination)),
            source: if deleted == Some(true) {
                Some("")
            } else {
                source.as_deref()
            },
            forced,
            deleted,
            certain: true,
        }];
        super::git::git_push::push_destination_lists(
            &mut attrs,
            &destinations,
            Some((false, &[])),
            true,
            true,
        );
    }
    if let Some(deleted) = deleted {
        attrs.insert("delete".into(), AttrValue::Bool(deleted));
    }
    if let Some(forced) = forced {
        attrs.insert("force".into(), AttrValue::Bool(forced));
        attrs.insert(
            "explicit_force".into(),
            AttrValue::Bool(forced && !deleted.unwrap()),
        );
    }
    let exact = destination.is_some() && forced.is_some();
    if destination.is_none() || matches!((method, force), (Method::Update, Force::Unknown)) {
        builder.boundary(Boundary {
            reason: BoundaryReason::UNMODELED_DYNAMIC,
            class: BoundaryClass::Unmodeled,
            scope: BoundaryScope::Invocation,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("git")],
            provenance: vec![node],
            limit: None,
            detail: Some(detail.into()),
        });
    }
    builder.effect(Effect {
        request_assurance: if exact {
            RequestAssurance::Exact
        } else {
            RequestAssurance::Conservative
        },
        id: Default::default(),
        operation: Operation::new("git.push_request"),
        // A hosted repository has no local Git identity.
        resource: unresolved_resource("git"),
        attributes: attrs,
        modality: if exact {
            Modality::MustOnSuccess
        } else {
            Modality::May
        },
        realm: ExecutionRealm::Host,
        condition: None,
        execution: ExecutionNodeRef(0),
        provenance: vec![arg, node],
    });
}

/// The ref a `repos/{owner}/{repo}/git/refs/{ref}` route names, `None` inside
/// when the ref is symbolic or carries a query, fragment or escape; `None`
/// for any other route. gh sends an absolute URL as written; only the REST
/// roots gh itself uses for GitHub (`https://api.github.com/`) and for the
/// `--hostname` Enterprise host (`https://{host}/api/v3/`) are its API.
fn ref_route(word: &Word, hostname: Option<&Word>) -> Option<Option<String>> {
    let prefix = word.literal_prefix();
    let path = if prefix.contains("://") {
        let (host, path) = prefix.strip_prefix("https://")?.split_once('/')?;
        if host.eq_ignore_ascii_case("api.github.com") {
            path
        } else if hostname
            .and_then(Word::as_literal)
            .is_some_and(|hostname| hostname.eq_ignore_ascii_case(host))
        {
            path.strip_prefix("api/v3/")?
        } else {
            return None;
        }
    } else {
        prefix.strip_prefix('/').unwrap_or(prefix)
    };
    let parts = path.splitn(6, '/').collect::<Vec<_>>();
    let [repos, owner, repo, git, refs, name] = parts.as_slice() else {
        return None;
    };
    if *repos != "repos" || owner.is_empty() || repo.is_empty() || *git != "git" || *refs != "refs"
    {
        return None;
    }
    if word.as_literal().is_none() {
        return Some(None);
    }
    if name.is_empty() || name.split('/').any(str::is_empty) {
        return None;
    }
    Some((!name.contains(['?', '#', '%'])).then(|| format!("refs/{name}")))
}
