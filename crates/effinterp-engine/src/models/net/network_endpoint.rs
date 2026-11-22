use effinterp_proto::ResourceIdentity;

use crate::value::parse_url_endpoint;

/// Parse a literal endpoint operand. A scheme-less URL needs a dotted host or
/// `localhost`. SCP-style `user@host:path` operands have their own syntax.
pub(in crate::models) fn parse_network_endpoint_operand(text: &str) -> Option<ResourceIdentity> {
    let (scheme, rest) = match text.split_once("://") {
        Some((s, r)) => (Some(s.to_string()), r),
        None => (None, text),
    };
    let scp_style = scheme.is_none()
        && rest
            .split_once(':')
            .is_some_and(|(authority, path)| authority.contains('@') && !path.is_empty());
    if scp_style {
        let (authority, path) = rest.split_once(':').unwrap();
        let host = authority.rsplit('@').next().unwrap_or(authority);
        if host.is_empty() {
            return None;
        }
        return Some(ResourceIdentity::NetworkEndpoint {
            host: host.to_string(),
            scheme,
            port: None,
            path: Some(path.to_string()),
        });
    }
    let identity = parse_url_endpoint(text)?;
    let ResourceIdentity::NetworkEndpoint { host, .. } = &identity else {
        unreachable!()
    };
    if scheme.is_none() && !host.contains('.') && host != "localhost" {
        return None;
    }
    Some(identity)
}
