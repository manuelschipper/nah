//! Hosted developer platform CLIs: Railway, Modal, Kamal and Fastly, and the
//! Wrangler and Supabase deletes their model documents do not model. Each
//! reviewed delete removes one provisioned resource the platform hosts: a
//! project, environment, volume, deployed application or data store. Any
//! other invocation of a tool without a document is an unmodeled subcommand,
//! never a fabricated resource; Wrangler and Supabase fall back to their
//! documents.

use effinterp_proto::{
    BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ProvenanceRef, RequestAssurance, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::common::{arg_node, boundary};
use crate::models::db::{Program, document_sql};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

pub(super) fn platform_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Platform(&RAILWAY)),
        Box::new(Platform(&MODAL)),
        Box::new(Platform(&KAMAL)),
        Box::new(Platform(&FASTLY)),
    ]
}

/// The Wrangler and Supabase documents model their database deletes (D1,
/// projects and branches) and leave the rest of the CLI unmodeled. The other
/// reviewed deletes are read here; anything else continues to the document.
pub(super) fn with_platform_deletes(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    let tool = match owner.id() {
        "p18b/cloud/wrangler@v1" => &WRANGLER,
        "p18b/cloud/supabase@v1" => &SUPABASE,
        _ => return owner,
    };
    Box::new(DocumentedPlatform { owner, tool })
}

/// One platform CLI and the deletes reviewed for it.
struct Tool {
    command: &'static str,
    provider: &'static str,
    /// Options that print help or the version and act on nothing.
    help: &'static [&'static str],
    /// Global options that take a value, and those that do not.
    values: &'static [&'static str],
    switches: &'static [&'static str],
    deletes: &'static [Delete],
}

/// One reviewed delete: its command words, the resource it removes, how the
/// invocation names that resource, and the options it documents.
struct Delete {
    /// Each command word, with its documented aliases.
    words: &'static [&'static [&'static str]],
    service: &'static str,
    kind: &'static str,
    target: DeleteTarget,
    values: &'static [&'static str],
    switches: &'static [&'static str],
    /// Switches with which the CLI reports the delete and performs nothing.
    dry_run: &'static [&'static str],
}

#[derive(Clone, Copy)]
enum DeleteTarget {
    /// The single operand names the resource.
    Operand,
    /// The operand or, instead, one of these options names it.
    OperandOr(&'static [&'static str]),
    /// One of these options names it, and the command takes no operand.
    Named(&'static [&'static str]),
    /// One of these options names it; without one the CLI deletes the
    /// resource the directory is linked to or configured for.
    Linked(&'static [&'static str]),
    /// The operand or one of these options names it; without either the CLI
    /// deletes the resource its configuration names.
    OperandOrLinked(&'static [&'static str]),
}

const RAILWAY_DELETE_SWITCHES: &[&str] = &["--yes", "-y", "--json"];

/// <https://docs.railway.com/cli/delete>, `cli/environment`, `cli/volume`,
/// and `src/commands/{project,service,functions}` in railwayapp/cli. Without
/// `--project` a project delete prompts for the project to delete, and
/// without `--function` a function delete prompts for the function, so only
/// the named forms are reviewed. A service delete without `--service` takes
/// the linked service, which may be none, so it is read only when named too.
const RAILWAY: Tool = Tool {
    command: "railway",
    provider: "railway",
    help: &["--help", "-h", "--version", "-V"],
    values: &["--service", "-s", "--environment", "-e"],
    switches: &[],
    deletes: &[
        // Deleting a project removes its services, deployments and data.
        Delete {
            words: &[&["delete", "rm", "remove"]],
            service: "project",
            kind: "project",
            target: DeleteTarget::Named(&["--project", "-p"]),
            values: &["--project", "-p", "--2fa-code"],
            switches: RAILWAY_DELETE_SWITCHES,
            dry_run: &[],
        },
        // `railway projects` runs `railway project`.
        Delete {
            words: &[&["project", "projects"], &["delete", "rm", "remove"]],
            service: "project",
            kind: "project",
            target: DeleteTarget::Named(&["--project", "-p"]),
            values: &["--project", "-p", "--2fa-code"],
            switches: RAILWAY_DELETE_SWITCHES,
            dry_run: &[],
        },
        // Deleting a service removes it and every deployment it has from
        // the environment.
        Delete {
            words: &[&["service"], &["delete", "remove", "rm"]],
            service: "service",
            kind: "service",
            target: DeleteTarget::Named(&["--service", "-s"]),
            values: &["--project", "-p", "--2fa-code"],
            switches: RAILWAY_DELETE_SWITCHES,
            dry_run: &[],
        },
        Delete {
            words: &[
                &["functions", "function", "func", "fn", "funcs", "fns"],
                &["delete", "remove", "rm"],
            ],
            service: "function",
            kind: "function",
            target: DeleteTarget::Named(&["--function", "-f"]),
            values: &["--function", "-f", "--2fa-code"],
            switches: &["--yes", "-y"],
            dry_run: &[],
        },
        Delete {
            words: &[&["environment"], &["delete", "rm", "remove"]],
            service: "environment",
            kind: "environment",
            target: DeleteTarget::Operand,
            values: &["--2fa-code"],
            switches: RAILWAY_DELETE_SWITCHES,
            dry_run: &[],
        },
        Delete {
            words: &[&["volume", "volumes"], &["delete", "remove", "rm"]],
            service: "volume",
            kind: "volume",
            target: DeleteTarget::Named(&["--volume", "-v"]),
            values: &["--volume", "-v", "--project", "-p", "--2fa-code"],
            switches: RAILWAY_DELETE_SWITCHES,
            dry_run: &[],
        },
    ],
};

const MODAL_OBJECT_SWITCHES: &[&str] = &["--allow-missing", "--yes", "-y"];

/// <https://modal.com/docs/reference/cli/>: `app stop` permanently stops a
/// deployed app; `environment delete` deletes every app in the environment.
const MODAL: Tool = Tool {
    command: "modal",
    provider: "modal",
    help: &["--help"],
    values: &[],
    switches: &[],
    deletes: &[
        Delete {
            words: &[&["app"], &["stop"]],
            service: "app",
            kind: "app",
            target: DeleteTarget::Operand,
            values: &["--env", "-e"],
            switches: &["--yes", "-y"],
            dry_run: &[],
        },
        Delete {
            words: &[&["environment"], &["delete"]],
            service: "environment",
            kind: "environment",
            target: DeleteTarget::Operand,
            values: &[],
            switches: &["--yes", "-y"],
            dry_run: &[],
        },
        Delete {
            words: &[&["volume"], &["delete"]],
            service: "volume",
            kind: "volume",
            target: DeleteTarget::Operand,
            values: &["--env", "-e"],
            switches: MODAL_OBJECT_SWITCHES,
            dry_run: &[],
        },
        Delete {
            words: &[&["dict"], &["delete"]],
            service: "dict",
            kind: "dict",
            target: DeleteTarget::Operand,
            values: &["--env", "-e"],
            switches: MODAL_OBJECT_SWITCHES,
            dry_run: &[],
        },
        Delete {
            words: &[&["queue"], &["delete"]],
            service: "queue",
            kind: "queue",
            target: DeleteTarget::Operand,
            values: &["--env", "-e"],
            switches: MODAL_OBJECT_SWITCHES,
            dry_run: &[],
        },
    ],
};

/// `lib/kamal/cli/{base,main,app,accessory,proxy}.rb`. Thor prints help for
/// `-h` too, which Kamal also declares as `--hosts`, so `-h` stays unread.
/// `kamal remove` removes the app, the proxy and every accessory with its
/// data directory; `accessory remove` removes the accessory's data directory.
const KAMAL: Tool = Tool {
    command: "kamal",
    provider: "kamal",
    help: &["--help", "-?", "-D"],
    values: &[
        "--version",
        "--hosts",
        "--roles",
        "-r",
        "--config-file",
        "-c",
        "--destination",
        "-d",
        "--lock-wait-timeout",
        "--lock-wait-interval",
    ],
    switches: &[
        "--verbose",
        "-v",
        "--quiet",
        "-q",
        "--primary",
        "-p",
        "--skip-hooks",
        "-H",
        "--lock-wait",
    ],
    deletes: &[
        Delete {
            words: &[&["remove"]],
            service: "deployment",
            kind: "deployment",
            target: DeleteTarget::Linked(&[]),
            values: &[],
            switches: &["--confirmed", "-y"],
            dry_run: &[],
        },
        Delete {
            words: &[&["app"], &["remove"]],
            service: "app",
            kind: "app",
            target: DeleteTarget::Linked(&[]),
            values: &[],
            switches: &[],
            dry_run: &[],
        },
        Delete {
            words: &[&["accessory"], &["remove"]],
            service: "accessory",
            kind: "accessory",
            target: DeleteTarget::Operand,
            values: &[],
            switches: &["--confirmed", "-y"],
            dry_run: &[],
        },
        Delete {
            words: &[&["proxy"], &["remove"]],
            service: "proxy",
            kind: "proxy",
            target: DeleteTarget::Linked(&[]),
            values: &[],
            switches: &["--force"],
            dry_run: &[],
        },
    ],
};

/// <https://www.fastly.com/documentation/reference/cli/service/delete/>.
/// Without an option naming it, the service is the one `FASTLY_SERVICE_ID`
/// or `fastly.toml` names. The CLI has no `compute delete`; a Compute
/// service is deleted with `service delete`.
const FASTLY: Tool = Tool {
    command: "fastly",
    provider: "fastly",
    help: &["--help"],
    values: &["--token"],
    switches: &[
        "--accept-defaults",
        "--auto-yes",
        "--debug-mode",
        "--non-interactive",
        "--quiet",
        "--verbose",
    ],
    deletes: &[Delete {
        words: &[&["service"], &["delete", "remove"]],
        service: "service",
        kind: "service",
        target: DeleteTarget::Linked(&["--service-id", "-s", "--service-name"]),
        values: &["--service-id", "-s", "--service-name"],
        switches: &["--force", "-f"],
        dry_run: &[],
    }],
};

/// <https://developers.cloudflare.com/workers/wrangler/commands/>. The
/// operand or `--name` names the Worker `wrangler delete` deletes; without
/// either it deletes the Worker its configuration names.
/// R2 deletes only an empty bucket, and object storage has its own guards.
const WRANGLER: Tool = Tool {
    command: "wrangler",
    provider: "cloudflare",
    help: &["--help", "-h", "--version", "-v"],
    values: &[
        "--config",
        "-c",
        "--env",
        "-e",
        "--cwd",
        "--env-file",
        "--profile",
    ],
    switches: &["--skip-confirmation", "--yes", "-y"],
    deletes: &[
        Delete {
            words: &[&["delete"]],
            service: "workers",
            kind: "worker",
            target: DeleteTarget::OperandOrLinked(&["--name"]),
            values: &["--name"],
            switches: &["--dry-run", "--force"],
            dry_run: &["--dry-run"],
        },
        Delete {
            words: &[&["kv"], &["namespace"], &["delete"]],
            service: "kv",
            kind: "namespace",
            target: DeleteTarget::OperandOr(&["--namespace-id"]),
            values: &["--namespace-id"],
            switches: &["--preview"],
            dry_run: &[],
        },
        Delete {
            words: &[&["queues"], &["delete"]],
            service: "queues",
            kind: "queue",
            target: DeleteTarget::Operand,
            values: &[],
            switches: &[],
            dry_run: &[],
        },
        Delete {
            words: &[&["hyperdrive"], &["delete"]],
            service: "hyperdrive",
            kind: "config",
            target: DeleteTarget::Operand,
            values: &[],
            switches: &[],
            dry_run: &[],
        },
        Delete {
            words: &[&["pages"], &["project"], &["delete"]],
            service: "pages",
            kind: "project",
            target: DeleteTarget::Operand,
            values: &[],
            switches: &[],
            dry_run: &[],
        },
    ],
};

/// <https://supabase.com/docs/reference/cli/supabase-functions-delete>.
const SUPABASE: Tool = Tool {
    command: "supabase",
    provider: "supabase",
    help: &["--help", "-h"],
    values: &[
        "--agent",
        "--dns-resolver",
        "--network-id",
        "--output",
        "-o",
        "--output-format",
        "--profile",
        "--workdir",
        "--project-ref",
    ],
    switches: &["--create-ticket", "--debug", "--experimental", "--yes"],
    deletes: &[Delete {
        words: &[&["functions"], &["delete"]],
        service: "functions",
        kind: "function",
        target: DeleteTarget::Operand,
        values: &[],
        switches: &[],
        dry_run: &[],
    }],
};

/// What a platform invocation requests.
enum Request<'a> {
    /// Help or the version, which act on nothing.
    Help,
    /// A reviewed delete of the resource `id` names, or of the linked one.
    Delete {
        delete: &'a Delete,
        id: Option<String>,
        /// The argv index that names the resource, or the last command word.
        index: usize,
        dry_run: bool,
    },
    /// Anything the reviewed table does not read in full.
    Unreviewed,
}

impl Tool {
    /// Reads `argv` against the reviewed deletes. Every word must be a literal
    /// the tool or the matched delete documents; an option the table does not
    /// know may take a value or change what is deleted, so it leaves the
    /// invocation unreviewed.
    fn request(&self, argv: &[Word]) -> Request<'_> {
        let mut literals = Vec::with_capacity(argv.len());
        for word in argv {
            match word.as_literal() {
                Some(literal) => literals.push(literal),
                None => return Request::Unreviewed,
            }
        }
        let takes_value = |flag: &str| {
            self.values.contains(&flag)
                || self
                    .deletes
                    .iter()
                    .any(|delete| delete.values.contains(&flag))
        };
        let mut positionals = Vec::new();
        // (flag, value, argv index of the value)
        let mut options: Vec<(&str, Option<&str>, usize)> = Vec::new();
        let mut index = 1;
        while index < literals.len() {
            let word = literals[index];
            if self.help.contains(&word) {
                return Request::Help;
            }
            if word == "--" || word == "-" || !word.starts_with('-') {
                if word == "--" {
                    return Request::Unreviewed;
                }
                positionals.push(index);
                index += 1;
                continue;
            }
            match word.split_once('=') {
                Some((flag, value)) if word.starts_with("--") && takes_value(flag) => {
                    options.push((flag, Some(value), index));
                }
                Some(_) => return Request::Unreviewed,
                None if takes_value(word) => {
                    let Some(value) = literals.get(index + 1) else {
                        return Request::Unreviewed;
                    };
                    if value.is_empty() || value.starts_with('-') {
                        return Request::Unreviewed;
                    }
                    options.push((word, Some(value), index + 1));
                    index += 1;
                }
                None => options.push((word, None, index)),
            }
            index += 1;
        }
        let Some(delete) = self.deletes.iter().find(|delete| {
            positionals.len() >= delete.words.len()
                && delete
                    .words
                    .iter()
                    .zip(&positionals)
                    .all(|(aliases, &index)| aliases.contains(&literals[index]))
        }) else {
            return Request::Unreviewed;
        };
        let documented = options.iter().all(|(flag, value, _)| match value {
            Some(_) => self.values.contains(flag) || delete.values.contains(flag),
            None => self.switches.contains(flag) || delete.switches.contains(flag),
        });
        if !documented {
            return Request::Unreviewed;
        }
        let operands = &positionals[delete.words.len()..];
        let named = |flags: &[&str]| {
            options
                .iter()
                .rev()
                .find(|(flag, _, _)| flags.contains(flag))
                .map(|(_, value, index)| (value.map(str::to_string), *index))
        };
        let command_word = positionals[delete.words.len() - 1];
        let (id, index) = match (delete.target, operands) {
            (DeleteTarget::Operand, [operand]) => (Some(literals[*operand].to_string()), *operand),
            (DeleteTarget::OperandOr(flags) | DeleteTarget::OperandOrLinked(flags), [operand])
                if named(flags).is_none() =>
            {
                (Some(literals[*operand].to_string()), *operand)
            }
            (DeleteTarget::OperandOr(flags) | DeleteTarget::Named(flags), []) => match named(flags)
            {
                Some(named) => named,
                None => return Request::Unreviewed,
            },
            (DeleteTarget::Linked(flags) | DeleteTarget::OperandOrLinked(flags), []) => {
                named(flags).unwrap_or((None, command_word))
            }
            _ => return Request::Unreviewed,
        };
        Request::Delete {
            delete,
            // Kamal's accessory `all` names every accessory.
            id: id.filter(|id| !(self.command == "kamal" && id == "all")),
            index,
            dry_run: options
                .iter()
                .any(|(flag, value, _)| value.is_none() && delete.dry_run.contains(flag)),
        }
    }

    /// Emits a reviewed delete. Returns false, emitting nothing, when the
    /// invocation is not one.
    fn apply(
        &self,
        builder: &mut PlanBuilder,
        ctx: &InvocationCtx,
        model_node: ProvenanceRef,
    ) -> bool {
        let request = self.request(ctx.argv);
        if matches!(request, Request::Unreviewed) {
            return false;
        }
        builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
        builder.declare_coverage(Domain::new("cloud"), CoverageLevel::Full);
        let Request::Delete {
            delete,
            id,
            index,
            dry_run: false,
        } = request
        else {
            return true;
        };
        let provenance = vec![arg_node(builder, ctx, index as u32), model_node];
        builder.effect(Effect {
            request_assurance: RequestAssurance::Exact,
            id: Default::default(),
            operation: Operation::new("cloud.resource.delete"),
            resource: ResourceExpr::Concrete {
                identity: ResourceIdentity::CloudResource {
                    scope: Box::new(effinterp_proto::cloud_scope(
                        Some(self.provider),
                        delete.service,
                        delete.kind,
                    )),
                    provider: Some(self.provider.into()),
                    service: delete.service.into(),
                    kind: delete.kind.into(),
                    id,
                },
            },
            attributes: Default::default(),
            modality: Modality::May,
            realm: effinterp_proto::ExecutionRealm::Host,
            condition: None,
            execution: effinterp_proto::ExecutionNodeRef(0),
            provenance,
        });
        true
    }
}

/// A platform CLI no model document covers.
struct Platform(&'static Tool);

impl CommandModel for Platform {
    fn domains(&self) -> &'static [&'static str] {
        &crate::builder::KNOWN_DOMAINS
    }

    fn id(&self) -> &'static str {
        match self.0.command {
            "railway" => "cloud/railway@v0",
            "modal" => "cloud/modal@v0",
            "kamal" => "cloud/kamal@v0",
            _ => "cloud/fastly@v0",
        }
    }

    fn command_names(&self) -> &'static [&'static str] {
        match self.0.command {
            "railway" => &["railway"],
            "modal" => &["modal"],
            "kamal" => &["kamal"],
            _ => &["fastly"],
        }
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        if !self.0.apply(builder, ctx, model_node) {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            boundary(
                builder,
                model_node,
                BoundaryReason::UNMODELED_SUBCOMMAND,
                BoundaryClass::Unmodeled,
                &crate::builder::KNOWN_DOMAINS,
                "only reviewed resource deletes are modeled",
            );
        }
    }
}

struct DocumentedPlatform {
    owner: Box<dyn CommandModel>,
    tool: &'static Tool,
}

impl CommandModel for DocumentedPlatform {
    fn domains(&self) -> &'static [&'static str] {
        self.owner.domains()
    }

    fn id(&self) -> &'static str {
        self.owner.id()
    }

    fn command_names(&self) -> &'static [&'static str] {
        self.owner.command_names()
    }

    fn declaration_digest(&self) -> Option<&str> {
        self.owner.declaration_digest()
    }

    fn matches_subcommand(&self, argv: &[Word], name: &str) -> bool {
        self.owner.matches_subcommand(argv, name)
    }

    fn causal_bindings(&self, argv: &[Word]) -> Vec<crate::models::ModelCausalBinding> {
        self.owner.causal_bindings(argv)
    }

    fn apply(&self, builder: &mut PlanBuilder, ctx: &InvocationCtx, model_node: ProvenanceRef) {
        // Help stays the document's, which already models it.
        if matches!(self.tool.request(ctx.argv), Request::Help) {
            self.owner.apply(builder, ctx, model_node);
        } else if let Some((index, script)) = wrangler_d1_file(ctx.argv) {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            let program = Program::File(Word::literal(script), index);
            document_sql(builder, ctx, model_node, program);
        } else if !self.tool.apply(builder, ctx, model_node) {
            self.owner.apply(builder, ctx, model_node);
        }
    }
}

/// The script `wrangler d1 execute <database> --remote --file <script>` runs
/// against the remote database, and its argv index. The document nests
/// `--command` SQL under the same conditions; a document cannot read a file.
/// None for any other invocation, and for one holding an option this does
/// not read in full, which stays the document's.
fn wrangler_d1_file(argv: &[Word]) -> Option<(usize, &str)> {
    // `--cwd` moves the directory the script resolves against; `--command`
    // beside `--file` is rejected.
    const VALUES: &[&str] = &[
        "--config",
        "-c",
        "--env",
        "-e",
        "--env-file",
        "--profile",
        "--file",
        "--persist-to",
    ];
    const SWITCHES: &[&str] = &[
        "--local",
        "--remote",
        "--preview",
        "--json",
        "--skip-confirmation",
        "--yes",
        "-y",
    ];
    let literals = argv
        .iter()
        .map(Word::as_literal)
        .collect::<Option<Vec<_>>>()?;
    let mut operands = Vec::new();
    // (flag, value, argv index of the value)
    let mut options: Vec<(&str, Option<&str>, usize)> = Vec::new();
    let mut index = 1;
    while index < literals.len() {
        let word = literals[index];
        match word.split_once('=') {
            _ if !word.starts_with('-') => operands.push(word),
            Some((flag, value)) if VALUES.contains(&flag) || SWITCHES.contains(&flag) => {
                options.push((flag, Some(value), index));
            }
            None if VALUES.contains(&word) => {
                index += 1;
                options.push((word, Some(literals.get(index).copied()?), index));
            }
            None if SWITCHES.contains(&word) => options.push((word, None, index)),
            _ => return None,
        }
        index += 1;
    }
    let last = |flag: &str| options.iter().rev().find(|(name, _, _)| *name == flag);
    // Wrangler's switches take `=true` and `=false`.
    let on = |flag: &str| last(flag).is_some_and(|(_, value, _)| *value != Some("false"));
    let remote = matches!(operands[..], ["d1", "execute", _])
        && on("--remote")
        && !on("--local")
        // Wrangler rejects a local state directory with --remote.
        && !last("--persist-to").is_some_and(|(_, path, _)| *path != Some(""));
    let (_, script, index) = last("--file").filter(|_| remote)?;
    Some((*index, (*script)?))
}
