//! The names a call uses, for the facts export's `names`: each host, URL,
//! bucket, package and path its plan's effects name, with the terms of the
//! session record (`session_memory::seen`) that spell it.
//!
//! A destination whose tail is computed, such as
//! `gs://bucket/weights/$(date +%Y%m%d)/`, reaches an effect as a join whose
//! first part the engine already made concrete from the leading literal: the
//! bucket, or a host, the literal fixes. That first part is named, marked
//! `rest_unresolved`; a join whose leading literal stops inside the bucket or
//! host (`gs://example-$(x)/k`) has no concrete first part and names nothing.
//! A transfer model may instead state a concrete endpoint for a remote
//! operand whose path is computed (`scp f "host:dir/$(date +%s)"`), dropping
//! the path; the argv word the effect names by its provenance shows it.
//!
//! A folder a call reads recursively to archive, copy or upload it may hold
//! a link the supplied state shows leading out of it. The command never
//! names the link or where it leads, so each is named apart from the paths
//! it does: `link` and `link_target`, both with every read that meets the
//! link (`links`): the folder, the link, its target and whether that read
//! follows links (`nah_effinterp::links_leading_out`).

use nah_proto::ctx::Platform;
use nah_proto::effinterp_proto::{
    AttrValue, Effect, Plan, ProvenanceKind, ResourceExpr, ResourceIdentity,
};
use nah_proto::labels::dependency::{Ecosystem, install_operand};
use serde::Serialize;

use crate::session_memory::seen::{
    FirstSeen, URL_SCHEMES, bucket_term, host_term, package_term, path_terms, url_term,
};

/// One name a call uses, and where the session first saw it.
#[derive(Serialize)]
pub(super) struct Name {
    /// `host`, `url`, `bucket`, `package`, `path`, `link` or `link_target`.
    pub(super) kind: &'static str,
    pub(super) name: String,
    /// Some effect names this only as the first part of a resource whose
    /// rest Nah could not resolve, so the name is not the whole destination.
    pub(super) rest_unresolved: bool,
    /// The terms any of which is a sighting: a path's spellings from each
    /// folder above it, anything else its one term.
    #[serde(skip)]
    pub(super) terms: Vec<String>,
    pub(super) first_seen: Option<FirstSeen>,
    /// For a `link` or `link_target`, each distinct reading of the link: one
    /// per folder, target and follow mode the call's reads meet it with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) links: Vec<Link>,
}

/// A link inside a folder a call reads recursively that leads out of it.
#[derive(Clone, PartialEq, Serialize)]
pub(super) struct Link {
    folder: String,
    link: String,
    leads_to: String,
    /// The read follows links; otherwise it keeps the link as a link.
    follows_links: bool,
}

/// The names `plan` uses, each once, in the order its effects name them; a
/// path below `home` may be spelled from it. A program's own executable is
/// not a name the call uses. `listing` answers for the links below a folder.
pub(super) fn names(
    plan: &Plan,
    home: &str,
    listing: &nah_effinterp::FolderLinks,
    platform: Platform,
) -> Vec<Name> {
    let mut names: Vec<Name> = Vec::new();
    let mut add = |kind: &'static str,
                   name: &str,
                   terms: Vec<String>,
                   rest_unresolved: bool,
                   link: Option<&Link>| match names
        .iter_mut()
        .find(|known| known.kind == kind && known.name == name)
    {
        Some(known) => {
            known.rest_unresolved |= rest_unresolved;
            if let Some(link) = link.filter(|link| !known.links.contains(link)) {
                known.links.push(link.clone());
            }
        }
        None => names.push(Name {
            kind,
            name: name.to_owned(),
            rest_unresolved,
            terms,
            first_seen: None,
            links: link.into_iter().cloned().collect(),
        }),
    };
    for effect in &plan.effects {
        let computed = computed_argument(plan, effect);
        match &effect.resource {
            ResourceExpr::Join { parts } => match parts.first() {
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, .. },
                }) => add("host", host, vec![host_term(host)], true, None),
                Some(ResourceExpr::Concrete {
                    identity: ResourceIdentity::ObjectStore { bucket, .. },
                }) => add("bucket", bucket, vec![bucket_term(bucket)], true, None),
                _ => {}
            },
            ResourceExpr::Concrete {
                identity:
                    ResourceIdentity::NetworkEndpoint {
                        host,
                        scheme,
                        port,
                        path,
                    },
            } => {
                add("host", host, vec![host_term(host)], computed, None);
                if let Some(scheme) = scheme
                    .as_deref()
                    .filter(|scheme| URL_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()))
                {
                    let port = port.map(|port| port.to_string());
                    let path = path.as_deref().unwrap_or("/");
                    let term = url_term(scheme, host, port.as_deref(), path);
                    let url = term.strip_prefix("U:").unwrap_or(&term).to_owned();
                    add("url", &url, vec![term], computed, None);
                }
            }
            ResourceExpr::Concrete {
                identity: ResourceIdentity::ObjectStore { bucket, .. },
            } => add("bucket", bucket, vec![bucket_term(bucket)], computed, None),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if effect.operation.as_str() != "process.exec" => {
                add("path", path, path_terms(path, home), false, None);
            }
            _ => {}
        }
        for out in nah_effinterp::links_leading_out(plan, effect, listing, platform) {
            let link = Link {
                folder: out.folder,
                link: out.link,
                leads_to: out.leads_to,
                follows_links: out.follows_links,
            };
            for (kind, name) in [("link", &link.link), ("link_target", &link.leads_to)] {
                add(kind, name, path_terms(name, home), false, Some(&link));
            }
        }
        let (Some(AttrValue::String(ecosystem)), Some(AttrValue::List(operands))) = (
            effect.attributes.get("package_ecosystem"),
            effect.attributes.get("requested_packages"),
        ) else {
            continue;
        };
        let Some(ecosystem) = Ecosystem::from_attribute(ecosystem) else {
            continue;
        };
        for operand in operands {
            if let AttrValue::String(operand) = operand
                && let Some(requirement) = install_operand(ecosystem, operand)
            {
                add(
                    "package",
                    &requirement.name,
                    vec![package_term(ecosystem, &requirement.name)],
                    false,
                    None,
                );
            }
        }
    }
    names
}

/// Whether an argv word `effect` names by its provenance is computed: a word
/// of the one program its execution runs that is not wholly literal.
fn computed_argument(plan: &Plan, effect: &Effect) -> bool {
    let mut runs = plan.effects.iter().filter(|run| {
        run.execution == effect.execution && run.operation.as_str() == "process.exec"
    });
    let (
        Some(Effect {
            resource:
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::Process { argv, .. },
                },
            ..
        }),
        None,
    ) = (runs.next(), runs.next())
    else {
        return false;
    };
    effect.provenance.iter().any(|reference| {
        // An argument's index counts the program's name, which `argv` leaves out.
        matches!(
            plan.provenance.get(reference.0 as usize).map(|node| &node.kind),
            Some(ProvenanceKind::Argument { index })
                if (*index as usize).checked_sub(1).and_then(|index| argv.get(index))
                    .is_some_and(|word| !matches!(word, ResourceExpr::Literal { .. }))
        )
    })
}
