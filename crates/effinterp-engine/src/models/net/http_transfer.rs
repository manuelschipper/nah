use effinterp_proto::{CoverageLevel, Domain, ResourceExpr, ResourceIdentity};

use crate::builder::PlanBuilder;
use crate::resource_transfer::TransferBinding;
use crate::value::{parse_url_endpoint, unresolved_resource};
use crate::word::Word;

use super::network_endpoint::parse_network_endpoint_operand;

/// A curl or wget URL operand can contain a scheme-less single-label hostname
/// such as `intranet`.
fn http_transfer_endpoint(url: &str) -> Option<ResourceIdentity> {
    parse_network_endpoint_operand(url).or_else(|| {
        if url.contains("://") {
            return None;
        }
        let identity = parse_url_endpoint(url)?;
        let ResourceIdentity::NetworkEndpoint { host, .. } = &identity else {
            return None;
        };
        (host.as_bytes()[0].is_ascii_alphanumeric()
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then_some(identity)
    })
}

/// An output option names standard output with either `-` or `/dev/stdout`.
pub(super) fn names_stdout(value: Option<&str>) -> bool {
    matches!(value, Some("-" | "/dev/stdout"))
}

/// A curl or wget endpoint stays unresolved when the operand is symbolic.
pub(super) fn http_transfer_endpoint_expr(word: &Word) -> ResourceExpr {
    match word.as_literal().and_then(http_transfer_endpoint) {
        Some(identity) => ResourceExpr::Concrete { identity },
        None => unresolved_resource("network"),
    }
}

/// For the URL basename, drop the prefix through the first `://` if present,
/// take the text after the final slash, then cut it at the first `?` or `#`.
pub(super) fn url_basename(word: &Word) -> Option<String> {
    let text = word.as_literal()?;
    let rest = text.split_once("://").map_or(text, |(_, r)| r);
    let name = rest
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty() && *n != rest)?;
    Some(name.split(['?', '#']).next().unwrap_or(name).to_string())
}

/// Declare full network coverage before recording any invocation-specific gaps.
pub(super) fn declare_full_network_coverage(builder: &mut PlanBuilder) {
    builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
}

/// Record one source-to-destination transfer pairing when both endpoint
/// effects were retained.
pub(super) fn record_http_transfer(
    builder: &mut PlanBuilder,
    source: Option<u32>,
    destination: Option<u32>,
    assurance: effinterp_proto::CausalAssurance,
) {
    if let (Some(source), Some(destination)) = (source, destination) {
        builder.transfer_binding(if assurance == effinterp_proto::CausalAssurance::Exact {
            TransferBinding::exact(source, destination)
        } else {
            TransferBinding::new(source, destination)
        });
    }
}
