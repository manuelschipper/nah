use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, ProvenanceRef, ResourceExpr,
};

use super::datastore_effects::{
    datastore_effect, datastore_host_port, datastore_table_resource, datastore_text_attrs,
};
use crate::builder::PlanBuilder;
use crate::models::InvocationCtx;
use crate::models::common::{arg_node, boundary};
use crate::value::unresolved_resource;
use crate::word::{Word, WordPart};

/// State the data a POST to an Elasticsearch or OpenSearch REST route
/// removes. `<index>/_delete_by_query` deletes the documents its `query`
/// selects, and `_aliases` deletes each index a `remove_index` action
/// names. Both route names are the search API's own, so the effect is
/// stated on any host, but only a host or port that names the service
/// establishes that the server implements them. `body` is the request's
/// one data body, `None` when curl reads it from a file or joins several.
/// Every other route states nothing here.
pub(in crate::models) fn elasticsearch_post_delete(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    (url_index, url): (u32, &Word),
    body: Option<&Word>,
) {
    let Some(url) = search_url_text(url) else {
        return;
    };
    let SearchUrl {
        host,
        search_service,
        segments,
        query,
    } = search_url(&url);
    let body = body
        .and_then(Word::as_literal)
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok());
    let (operation, targets, attributes, unread) = match segments[..] {
        [target, "_delete_by_query"] => {
            // `q=` selects documents from the URL, where `*` and `*:*`
            // select them all, and `max_docs` caps how many are deleted.
            let mut pairs = query.split('&');
            let url_query = pairs.clone().find_map(|pair| pair.strip_prefix("q="));
            let capped = pairs.any(|pair| pair.starts_with("max_docs="))
                || body
                    .as_ref()
                    .is_some_and(|body| body.get("max_docs").is_some());
            let filtered = match url_query {
                _ if capped => None,
                Some("*" | "*:*" | "*%3A*" | "*%3a*") => Some(false),
                Some(_) => None,
                None => body
                    .as_ref()
                    .and_then(|body| body.get("query"))
                    .map(|query| !elasticsearch_matches_all(query)),
            };
            let mut attributes = datastore_text_attrs(&[("action", "delete")]);
            if let Some(filtered) = filtered {
                attributes.insert("filtered".into(), AttrValue::Bool(filtered));
            }
            let targets = target.split(',').map(str::to_string).collect::<Vec<_>>();
            let unread = filtered
                .is_none()
                .then_some("Elasticsearch delete-by-query selection is not established");
            ("database.write", targets, attributes, unread)
        }
        ["_aliases"] => {
            let actions = body
                .as_ref()
                .and_then(|body| body.get("actions"))
                .and_then(serde_json::Value::as_array);
            let targets = actions.map(|actions| {
                actions
                    .iter()
                    .filter_map(|action| action.get("remove_index"))
                    .flat_map(|remove| {
                        let names = [remove.get("index"), remove.get("indices")];
                        names.into_iter().flatten().flat_map(|names| match names {
                            serde_json::Value::Array(names) => names.clone(),
                            name => vec![name.clone()],
                        })
                    })
                    .map(|name| name.as_str().unwrap_or_default().to_string())
                    .collect::<Vec<_>>()
            });
            let unread = targets
                .is_none()
                .then_some("Elasticsearch alias actions are not a literal body");
            (
                "database.schema_drop",
                targets.unwrap_or_default(),
                // An index holds its documents, as a collection does.
                datastore_text_attrs(&[("object_kind", "collection")]),
                unread,
            )
        }
        _ => return,
    };
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    let provenance = vec![node, arg_node(builder, ctx, url_index)];
    for target in targets {
        datastore_effect(
            builder,
            provenance.clone(),
            operation,
            search_index(&host, &target),
            attributes.clone(),
        );
    }
    let unestablished = (!search_service)
        .then_some("the host is not established as an Elasticsearch or OpenSearch service");
    for detail in unread.into_iter().chain(unestablished) {
        boundary(
            builder,
            node,
            BoundaryReason::PARTIAL_ANALYSIS,
            BoundaryClass::Unresolved,
            &["database"],
            detail,
        );
    }
}

/// State the indices a DELETE of `<index>[,<index>…]` removes on an
/// Elasticsearch or OpenSearch server. A bare DELETE of one path segment
/// names no API of its own, so it is read only where the host or port names
/// the service; a longer path (`<index>/_doc/<id>`) or an `_`-prefixed API
/// other than `_all` is not an index.
pub(in crate::models) fn elasticsearch_index_delete(
    builder: &mut PlanBuilder,
    ctx: &InvocationCtx,
    node: ProvenanceRef,
    (url_index, url): (u32, &Word),
) {
    let Some(url) = search_url_text(url) else {
        return;
    };
    let SearchUrl {
        host,
        search_service: true,
        segments,
        ..
    } = search_url(&url)
    else {
        return;
    };
    let [targets] = segments[..] else {
        return;
    };
    if targets.starts_with('_') && targets != "_all" {
        return;
    }
    builder.declare_coverage(Domain::new("database"), CoverageLevel::Full);
    let provenance = vec![node, arg_node(builder, ctx, url_index)];
    for target in targets.split(',') {
        datastore_effect(
            builder,
            provenance.clone(),
            "database.schema_drop",
            search_index(&host, target),
            datastore_text_attrs(&[("object_kind", "collection")]),
        );
    }
}

/// A search request URL, `[scheme://][user@]host[:port]/path[?query]`.
struct SearchUrl<'a> {
    host: String,
    /// The host or port names Elasticsearch, OpenSearch or Elastic Cloud.
    search_service: bool,
    segments: Vec<&'a str>,
    query: &'a str,
}

/// The text curl is given for a URL word. An unquoted `?` or `*` in a URL
/// (`…/users?pretty`) is a shell pattern that matches no file, so it
/// reaches curl as written.
fn search_url_text(url: &Word) -> Option<String> {
    url.parts
        .iter()
        .all(|part| matches!(part, WordPart::Literal(_) | WordPart::Glob(_)))
        .then(|| url.render_raw())
}

fn search_url(url: &str) -> SearchUrl<'_> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let (host, port) = datastore_host_port(authority.rsplit('@').next().unwrap_or(authority));
    // The default HTTP ports of Elasticsearch, OpenSearch and Elastic Cloud,
    // or a host named for the service (the managed AWS domains included).
    let search_service = matches!(port, Some(9200 | 9243)) || {
        let host = host.to_ascii_lowercase();
        [
            "elastic",
            "opensearch",
            ".es.amazonaws.com",
            ".aoss.amazonaws.com",
        ]
        .iter()
        .any(|name| host.contains(name))
    };
    SearchUrl {
        host,
        search_service,
        segments: path.split('/').filter(|part| !part.is_empty()).collect(),
        query,
    }
}

/// An index a request names outright; a pattern, a list entry that excludes,
/// or `_all` names no one index.
fn search_index(host: &str, name: &str) -> ResourceExpr {
    if name.is_empty() || name == "_all" || name.starts_with(['-', '+', '<']) || name.contains('*')
    {
        unresolved_resource("db")
    } else {
        datastore_table_resource(Some(host.to_string()), None, None, name.to_string())
    }
}

/// Whether an Elasticsearch query selects every document. `match_all` does,
/// as do an `exists` on `_id`, which every document has, a `query_string`
/// of `*:*`, and a `bool` whose only clauses are `must` and `filter` of such
/// queries. A `query_string` of a bare `*` tests that the fields it
/// searches exist: every field under the default
/// `index.query.default_field`, so it selects everything unless
/// `default_field` or `fields` narrows it.
fn elasticsearch_matches_all(query: &serde_json::Value) -> bool {
    let Some(query) = query.as_object().filter(|query| query.len() == 1) else {
        return false;
    };
    if query.contains_key("match_all") {
        return true;
    }
    if let Some(clause) = query.get("query_string") {
        return match clause.get("query").and_then(serde_json::Value::as_str) {
            Some("*:*") => true,
            Some("*") => clause
                .get("default_field")
                .or(clause.get("fields"))
                .is_none(),
            _ => false,
        };
    }
    if let Some(clause) = query.get("exists") {
        return clause.get("field").and_then(serde_json::Value::as_str) == Some("_id");
    }
    let Some(serde_json::Value::Object(clauses)) = query.get("bool") else {
        return false;
    };
    clauses.iter().all(|(kind, clause)| {
        matches!(kind.as_str(), "must" | "filter")
            && match clause {
                serde_json::Value::Array(clauses) => clauses.iter().all(elasticsearch_matches_all),
                clause => elasticsearch_matches_all(clause),
            }
    })
}
