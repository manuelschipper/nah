use effinterp_proto::{
    Boundary, BoundaryClass, BoundaryReason, BoundaryScope, Domain, ProvenanceRef, ResourceExpr,
    ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan};
use crate::models::common::{arg_effect, symbolic_expr};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

/// `dig`, `nslookup` and `host`: a DNS lookup sends each name it asks about
/// to the servers it asks.
pub(super) struct DnsLookup;

/// Record types and classes `dig` and `host` accept as bare operands beside
/// the name being looked up.
const DNS_RECORD_WORDS: &[&str] = &[
    "a", "aaaa", "any", "axfr", "caa", "ch", "cname", "dnskey", "ds", "hs", "in", "mx", "naptr",
    "ns", "ptr", "soa", "srv", "txt",
];

/// The `dig` options a DNS lookup is read through; any other leaves it
/// unmodeled.
const DIG_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    value_flags: &["-b", "-c", "-p", "-q", "-t"],
    known_flags: &["-4", "-6", "-m", "-r", "-u"],
    allow_abbreviation: false,
};

/// The `host` options a DNS lookup is read through; any other leaves it
/// unmodeled.
const HOST_FLAG_SPEC: FlagSpec<'static> = FlagSpec {
    value_flags: &["-c", "-N", "-R", "-t", "-W"],
    known_flags: &["-4", "-6", "-a", "-d", "-r", "-s", "-T", "-U", "-v", "-w"],
    allow_abbreviation: false,
};

/// The words of a DNS lookup that leave the machine: each name asked about
/// and each server asked. A lookup's name is itself data sent to whoever
/// serves that zone, so every one is a request endpoint. Options this does
/// not know leave the invocation unmodeled: `dig -f` reads names from a
/// file, `-x` builds a reverse name, `-k`/`-y` load keys.
fn dns_lookup_endpoints(argv: &[Word]) -> Result<Vec<(u32, Word)>, &'static str> {
    let command = argv[0]
        .as_literal()
        .and_then(|name| name.rsplit('/').next());
    let mut endpoints: Vec<(u32, Word)> = if command == Some("nslookup") {
        // Every nslookup option is one `-name[=value]` word; a lone `-`
        // starts the interactive mode, which takes its queries from stdin.
        if argv[1..].iter().any(|word| word.as_literal() == Some("-")) {
            return Err("interactive nslookup reads its queries from stdin");
        }
        argv.iter()
            .enumerate()
            .skip(1)
            .filter(|(_, word)| !word.as_literal().is_some_and(|text| text.starts_with('-')))
            .map(|(index, word)| (index as u32, word.clone()))
            .collect()
    } else {
        let dig = command == Some("dig");
        let parsed = scan(argv, if dig { &DIG_FLAG_SPEC } else { &HOST_FLAG_SPEC });
        if !parsed.unknown_flags.is_empty() {
            return Err("DNS lookup options are unmodeled");
        }
        let mut endpoints: Vec<(u32, Word)> = parsed
            .flags
            .iter()
            .filter(|flag| dig && flag.name == "-q")
            .filter_map(|flag| Some((flag.index, flag.value.clone()?)))
            .collect();
        endpoints.extend(
            parsed
                .operands
                .iter()
                // `+short` and its kin are dig query options.
                .filter(|(_, word)| !(dig && word.as_literal().is_some_and(|t| t.starts_with('+'))))
                .map(|(index, word)| (*index, (*word).clone())),
        );
        endpoints
    };
    endpoints.retain(|(_, word)| {
        !word
            .as_literal()
            .is_some_and(|text| DNS_RECORD_WORDS.contains(&text.to_ascii_lowercase().as_str()))
    });
    if endpoints.is_empty() {
        return Err("DNS lookup names no query");
    }
    Ok(endpoints)
}

impl CommandModel for DnsLookup {
    fn domains(&self) -> &'static [&'static str] {
        &["network", "process"]
    }
    fn id(&self) -> &'static str {
        "network/dns-lookup@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["dig", "nslookup", "host"]
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let endpoints = match dns_lookup_endpoints(ctx.argv) {
            Ok(endpoints) => endpoints,
            Err(detail) => {
                builder.boundary(Boundary {
                    reason: BoundaryReason::UNRECOGNIZED_ARGUMENTS,
                    class: BoundaryClass::Unmodeled,
                    scope: BoundaryScope::Invocation,
                    affected_resource: None,
                    callee: None,
                    domains: vec![Domain::new("network"), Domain::new("process")],
                    provenance: vec![model_node],
                    limit: None,
                    detail: Some(detail.into()),
                });
                return;
            }
        };
        for (index, word) in endpoints {
            let endpoint = match word.as_literal() {
                // dig spells the server to ask as `@server`.
                Some(text) => ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint {
                        host: text.trim_start_matches('@').to_string(),
                        scheme: None,
                        port: None,
                        path: None,
                    },
                },
                None => symbolic_expr(&word, "network"),
            };
            arg_effect(
                builder,
                ctx,
                model_node,
                index,
                "network.request",
                endpoint,
                Default::default(),
            );
        }
        // The lookup also goes to the host's configured resolver, and
        // resolv.conf and `~/.digrc` are not read.
        builder.boundary(Boundary {
            reason: BoundaryReason::ENVIRONMENT_CONFIGURATION,
            class: BoundaryClass::Unresolved,
            scope: BoundaryScope::Environment,
            affected_resource: None,
            callee: None,
            domains: vec![Domain::new("network")],
            provenance: vec![model_node],
            limit: None,
            detail: Some("resolver configuration is not read".to_string()),
        });
    }
}
