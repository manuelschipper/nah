use super::datastore_effects::datastore_host_port;

/// A `mongodb://` URI, `host[:port]/db`, `host:port`, or a bare database
/// name, as its host and the database it names, if any.
pub(super) fn parse_mongo_address(text: &str) -> (Option<String>, Option<String>) {
    let (hosts, database) = match text
        .split_once("://")
        .filter(|(scheme, _)| matches!(*scheme, "mongodb" | "mongodb+srv"))
    {
        Some((_, rest)) => rest.split_once('/').unwrap_or((rest, "")),
        None => match text.split_once('/') {
            Some(split) => split,
            None if text.contains(':') => (text, ""),
            None => return (None, Some(text.to_string())),
        },
    };
    let database = database.split(['?', '#']).next().unwrap_or_default();
    (
        mongo_host(hosts),
        (!database.is_empty()).then(|| database.to_string()),
    )
}

/// The first host of a `[user@]host[:port][,host...]` list or `rs/host` seed.
pub(super) fn mongo_host(text: &str) -> Option<String> {
    if text.contains("://") {
        return parse_mongo_address(text).0;
    }
    let seeds = text.rsplit_once('/').map_or(text, |(_, seeds)| seeds);
    let first = seeds.split(',').next()?;
    let first = first.rsplit('@').next().unwrap_or(first);
    let host = datastore_host_port(first).0;
    (!host.is_empty()).then_some(host)
}
