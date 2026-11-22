use std::collections::BTreeMap;

use effinterp_proto::{
    AttrValue, Boundary, BoundaryClass, BoundaryReason, BoundaryScope, CoverageLevel, Domain,
    ProvenanceRef, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::args::{FlagSpec, scan_with_value_indices};
use crate::models::common::{arg_effect, arg_node};
use crate::models::{CommandModel, InvocationCtx};
use crate::value::unresolved_resource;
use crate::word::Word;

use super::socket_handler::{analyze_socket_handler, socket_handler_boundary};

/// Netcat and Ncat effects remain possible where supported dialects disagree.
pub(super) struct Netcat;

struct SocketSession {
    index: u32,
    endpoint: ResourceExpr,
    port: u16,
    protocol: &'static str,
    listen: bool,
    receive: bool,
    send: bool,
    handler: Option<(u32, bool, Word)>,
}

// nc implementations disagree about what -e names and about listening with
// -p: netcat-traditional and Ncat run the program -e names, while OpenBSD's
// TLS build reads it as a certificate name and rejects -p beside -l. The
// reading that acts is modeled, since its effects are a superset and each
// one stays a `may`.
fn socket_session(argv: &[Word]) -> Result<Option<SocketSession>, &'static str> {
    let ncat = argv
        .first()
        .and_then(Word::as_literal)
        .and_then(|name| name.rsplit('/').next())
        == Some("ncat");
    let flags: &[&str] = if ncat {
        &[
            "-4",
            "-6",
            "-l",
            "--listen",
            "-u",
            "--udp",
            "-v",
            "--verbose",
            "-n",
            "--nodns",
            "-z",
            "--zero",
            "--send-only",
            "--recv-only",
            "-h",
            "--help",
            "--version",
        ]
    } else {
        &["-4", "-6", "-l", "-u", "-v", "-n", "-z", "-d", "-h"]
    };
    // -e hands its value to exec, -c to a shell; Ncat spells both long too.
    let handler_flags: &[&str] = if ncat {
        &["--exec", "-e", "--sh-exec", "-c"]
    } else {
        &["-e", "-c"]
    };
    // -p names the local port; in listen mode it is the port bound when no
    // port operand names one.
    let value_flags: &[&str] = if ncat {
        &["--exec", "-e", "--sh-exec", "-c", "-p", "--source-port"]
    } else {
        &["-e", "-c", "-p"]
    };
    let parsed = scan_with_value_indices(
        argv,
        &FlagSpec {
            value_flags,
            known_flags: flags,
            allow_abbreviation: false,
        },
        true,
    );
    if !parsed.unknown_flags.is_empty()
        || parsed.flags.iter().any(|flag| {
            if value_flags.contains(&flag.name) {
                flag.value.is_none()
            } else {
                argv[flag.index as usize].literal_prefix().contains('=')
            }
        })
    {
        return Err("network socket options or handler dialect are unmodeled");
    }
    if parsed.has(&["-h", "--help", "--version"]) {
        return Ok(None);
    }
    let listen = parsed.has(&["-l", "--listen"]);
    let scan = parsed.has(&["-z", "--zero"]);
    if listen && scan
        || parsed.has(&["-4"]) && parsed.has(&["-6"])
        || parsed.has(&["--send-only"]) && parsed.has(&["--recv-only"])
    {
        return Err("network socket options conflict");
    }
    let handlers: Vec<_> = parsed
        .flags
        .iter()
        .filter(|flag| handler_flags.contains(&flag.name))
        .collect();
    if handlers.len() > 1
        || !handlers.is_empty() && (scan || parsed.has(&["--send-only", "--recv-only"]))
    {
        return Err("Ncat handler options conflict or require unmodeled stream selection");
    }
    let handler = handlers.first().map(|flag| {
        (
            flag.value_index.unwrap_or(flag.index),
            matches!(flag.name, "--sh-exec" | "-c"),
            flag.value.clone().unwrap(),
        )
    });
    let local_port = parsed.value_of(&["-p", "--source-port"]);
    let (index, host, port_word) = match (listen, parsed.operands.as_slice()) {
        (false, [(index, host), (_, port)]) | (true, [(index, host), (_, port)]) => {
            (*index, Some(*host), Some(*port))
        }
        (true, [(index, port)]) => (*index, None, Some(*port)),
        (false, [(index, host)]) if ncat => (*index, Some(*host), None),
        (true, []) if ncat || local_port.is_some() => (0, None, local_port),
        // Given neither a destination host and port nor a listening port,
        // nc prints its usage and exits before opening anything. A literal
        // argv is the whole operand list, so that is settled here.
        _ if argv.iter().all(|word| word.as_literal().is_some()) => return Ok(None),
        _ => return Err("network socket destination or listening port is unresolved"),
    };
    let port = match port_word {
        Some(word) => match word.as_literal().and_then(|text| text.parse::<u16>().ok()) {
            Some(port) if port != 0 => port,
            _ => return Err("network socket service or port range is unmodeled"),
        },
        None => 31337,
    };
    if host.is_some_and(|word| word.as_literal() == Some("")) {
        return Err("network socket host is empty");
    }
    if let Some(host) = host.and_then(Word::as_literal) {
        let address = host.parse::<std::net::IpAddr>();
        if parsed.has(&["-n", "--nodns"]) && address.is_err()
            || parsed.has(&["-4"]) && matches!(address, Ok(std::net::IpAddr::V6(_)))
            || parsed.has(&["-6"]) && matches!(address, Ok(std::net::IpAddr::V4(_)))
        {
            return Err("network socket host conflicts with numeric or address-family options");
        }
    }
    let scheme = if parsed.has(&["-u", "--udp"]) {
        "udp"
    } else {
        "tcp"
    };
    let endpoint = match host {
        Some(host) => match host.as_literal() {
            Some(host) => ResourceExpr::Concrete {
                identity: ResourceIdentity::NetworkEndpoint {
                    host: host.into(),
                    scheme: Some(scheme.into()),
                    port: Some(port),
                    path: None,
                },
            },
            None => ResourceExpr::Join {
                parts: vec![
                    crate::models::common::remote_endpoint(host.parts.clone(), scheme),
                    ResourceExpr::Literal {
                        value: format!(":{port}"),
                    },
                ],
            },
        },
        None => unresolved_resource("network"),
    };
    Ok(Some(SocketSession {
        index,
        endpoint,
        port,
        protocol: scheme,
        handler,
        listen,
        receive: !scan && !parsed.has(&["--send-only"]),
        send: !scan && !parsed.has(&["-d", "--recv-only"]),
    }))
}

impl CommandModel for Netcat {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }
    fn id(&self) -> &'static str {
        "network/netcat@v1"
    }
    fn command_names(&self) -> &'static [&'static str] {
        &["nc", "netcat", "ncat"]
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        use crate::models::{ModelBindingEnd, ModelCausalBinding};
        use effinterp_model_schema::EffectSelection;
        use effinterp_proto::Port;
        let Ok(Some(session)) = socket_session(argv) else {
            return Vec::new();
        };
        if session.handler.is_some() {
            return Vec::new();
        }
        // Plain TCP sessions wire stdin/stdout to their peer. This proves
        // the byte relation, not a successful connection or any bytes sent.
        let assurance =
            if session.protocol == "tcp" && argv.iter().all(|word| word.as_literal().is_some()) {
                effinterp_proto::CausalAssurance::Exact
            } else {
                effinterp_proto::CausalAssurance::Conservative
            };
        let mut bindings = Vec::new();
        if session.receive {
            bindings.push(ModelCausalBinding {
                assurance,
                from: ModelBindingEnd::Effect {
                    operation: "network.download".into(),
                    selection: EffectSelection::All,
                },
                to: ModelBindingEnd::Port(Port::Stdout),
            });
        }
        if session.send {
            bindings.push(ModelCausalBinding {
                assurance,
                from: ModelBindingEnd::Port(Port::Stdin),
                to: ModelBindingEnd::Effect {
                    operation: "network.upload".into(),
                    selection: EffectSelection::All,
                },
            });
        }
        bindings
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        let session = match socket_session(ctx.argv) {
            Ok(Some(session)) => session,
            Ok(None) => return,
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
        let attributes = BTreeMap::from([
            ("listen".into(), AttrValue::Bool(session.listen)),
            ("port".into(), AttrValue::String(session.port.to_string())),
            (
                "protocol".into(),
                AttrValue::String(session.protocol.into()),
            ),
        ]);
        arg_effect(
            builder,
            ctx,
            model_node,
            session.index,
            if session.listen {
                "network.listen"
            } else {
                "network.connect"
            },
            session.endpoint.clone(),
            attributes.clone(),
        );
        // A listener's local bind address does not identify its future peer.
        let peer = if session.listen {
            unresolved_resource("network")
        } else {
            session.endpoint
        };
        let input = session
            .receive
            .then(|| {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    session.index,
                    "network.download",
                    peer.clone(),
                    attributes.clone(),
                )
            })
            .flatten();
        let output = session
            .send
            .then(|| {
                arg_effect(
                    builder,
                    ctx,
                    model_node,
                    session.index,
                    "network.upload",
                    peer,
                    attributes,
                )
            })
            .flatten();
        if let Some((index, shell, command)) = session.handler {
            let argument = arg_node(builder, ctx, index);
            let subject = command.as_literal().and_then(|text| {
                if shell {
                    Some(effinterp_proto::Subject::Shell {
                        source: text.into(),
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                } else {
                    split_ncat_command(text).map(|argv| effinterp_proto::Subject::Exec {
                        argv,
                        cwd: ctx.cwd.map(str::to_string),
                        context: Default::default(),
                    })
                }
            });
            if let Some(subject) = subject {
                analyze_socket_handler(
                    builder,
                    ctx,
                    &[model_node, argument],
                    subject,
                    input,
                    output,
                    [
                        "NCAT_REMOTE_ADDR",
                        "NCAT_REMOTE_PORT",
                        "NCAT_LOCAL_ADDR",
                        "NCAT_LOCAL_PORT",
                        "NCAT_PROTO",
                    ]
                    .into_iter()
                    .map(|name| {
                        let value = if name == "NCAT_PROTO" {
                            ResourceExpr::Literal {
                                value: session.protocol.into(),
                            }
                        } else {
                            unresolved_resource("value")
                        };
                        (name.to_string(), Some(value))
                    })
                    .collect(),
                    false,
                    ctx.runtime_cwd,
                );
            } else {
                socket_handler_boundary(
                    builder,
                    &[model_node, argument],
                    "Ncat handler command is not statically recoverable",
                );
            }
        }
        builder.declare_coverage(Domain::new("network"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
    }
}

// Ncat's POSIX cmdline_split treats quotes literally; only backslashes escape.
fn split_ncat_command(text: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut word = String::new();
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch.is_ascii_whitespace() {
            if !word.is_empty() {
                args.push(std::mem::take(&mut word));
            }
        } else {
            word.push(ch);
        }
    }
    if escaped {
        return None;
    }
    if !word.is_empty() {
        args.push(word);
    }
    (!args.is_empty()).then_some(args)
}
