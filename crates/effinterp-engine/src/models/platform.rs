//! Hosted developer platform CLIs: Railway, Modal, Kamal, Fastly and
//! Databricks, and the Wrangler and Supabase deletes their model documents do
//! not model. Each reviewed delete removes one provisioned resource the
//! platform hosts: a project, environment, volume, deployed application, data
//! store or data catalog. Any other invocation of a tool without a document
//! is an unmodeled subcommand, never a fabricated resource; Wrangler and
//! Supabase fall back to their documents.

use effinterp_proto::{
    AttrValue, BoundaryClass, BoundaryReason, CoverageLevel, Domain, Effect, Modality, Operation,
    ProvenanceRef, RequestAssurance, ResourceExpr, ResourceIdentity,
};

use crate::builder::PlanBuilder;
use crate::models::common::{arg_node, boundary};
use crate::models::db::{SqlClientInput, document_sql};
use crate::models::{CommandModel, InvocationCtx};
use crate::word::Word;

pub(super) fn platform_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Platform(&RAILWAY)),
        Box::new(Platform(&MODAL)),
        Box::new(Platform(&KAMAL)),
        Box::new(Platform(&FASTLY)),
        Box::new(Platform(&DATABRICKS)),
    ]
}

/// The Wrangler and Supabase documents model their database deletes (D1,
/// projects and branches) and leave the rest of the CLI unmodeled. The other
/// reviewed deletes are read here, and so is the SQL input a document cannot
/// read (`platform_cli_sql_input`); anything else continues to the document.
pub(super) fn with_platform_deletes(owner: Box<dyn CommandModel>) -> Box<dyn CommandModel> {
    let tool = match owner.id() {
        "p18b/cloud/wrangler@v1" => &WRANGLER,
        "p18b/cloud/supabase@v1" => &SUPABASE,
        "p18b/cloud/turso@v1" => &TURSO,
        "p18b/database/prisma@v1" => &PRISMA,
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

const DATABRICKS_FORCE: &[&str] = &["--force"];

/// <https://docs.databricks.com/aws/en/dev-tools/cli/reference/>
/// `metastores-commands`, `account-metastores-commands`, `catalogs-commands`
/// and `schemas-commands`: deleting a Unity Catalog metastore, catalog or
/// schema. Without `--force` the service deletes only an empty one.
const DATABRICKS: Tool = Tool {
    command: "databricks",
    provider: "databricks",
    help: &["--help", "-h", "--version"],
    values: &[
        "--profile",
        "-p",
        "--output",
        "-o",
        "--target",
        "-t",
        "--log-file",
        "--log-format",
        "--log-level",
        "--progress-format",
    ],
    switches: &["--debug"],
    deletes: &[
        Delete {
            words: &[&["metastores"], &["delete"]],
            service: "unity-catalog",
            kind: "metastore",
            target: DeleteTarget::Operand,
            values: &[],
            switches: DATABRICKS_FORCE,
            dry_run: &[],
        },
        Delete {
            words: &[&["account"], &["metastores"], &["delete"]],
            service: "unity-catalog",
            kind: "metastore",
            target: DeleteTarget::Operand,
            values: &[],
            switches: DATABRICKS_FORCE,
            dry_run: &[],
        },
        Delete {
            words: &[&["catalogs"], &["delete"]],
            service: "unity-catalog",
            kind: "catalog",
            target: DeleteTarget::Operand,
            values: &[],
            switches: DATABRICKS_FORCE,
            dry_run: &[],
        },
        // The operand is the schema's full name, `catalog.schema`.
        Delete {
            words: &[&["schemas"], &["delete"]],
            service: "unity-catalog",
            kind: "schema",
            target: DeleteTarget::Operand,
            values: &[],
            switches: DATABRICKS_FORCE,
            dry_run: &[],
        },
    ],
};

/// Turso and Prisma have no reviewed delete here: their documents model
/// those, and only their SQL input is read natively.
const TURSO: Tool = Tool {
    command: "turso",
    provider: "turso",
    help: &["--help", "-h", "--version", "-v"],
    values: &[],
    switches: &[],
    deletes: &[],
};

const PRISMA: Tool = Tool {
    command: "prisma",
    provider: "prisma",
    help: &["--help", "-h", "--version", "-v"],
    values: &[],
    switches: &[],
    deletes: &[],
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
        /// The service deletes the resource only while it is empty.
        requires_empty: bool,
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
        if self.command == "databricks" {
            return self.cobra_request(&literals);
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
            requires_empty: false,
        }
    }

    /// Reads a Databricks invocation as its Cobra command tree does. Cobra's
    /// `Find` takes the command words first, skipping the word after any flag
    /// it does not know to be a Boolean, then pflag parses the remaining
    /// arguments with the found command's flags:
    /// - a Boolean takes `=value` (Go's `strconv.ParseBool`), and its last
    ///   occurrence wins;
    /// - a value flag takes `=value`, the rest of its shorthand cluster, or
    ///   else the next argument, whatever it is;
    /// - shorthand letters cluster (`-hpprod` is `-h -p prod`), and only a
    ///   Boolean's last letter before `=` takes the assigned value;
    /// - help (`--help`, `-h`) is one such Boolean, read after parsing;
    /// - `--` ends the flags.
    ///
    /// A flag the table does not document leaves the invocation unreviewed.
    /// Every Databricks delete names its resource by its one operand.
    fn cobra_request(&self, literals: &[&str]) -> Request<'_> {
        let matches = |words: &[&[&str]], path: &[&str]| {
            words
                .iter()
                .zip(path)
                .all(|(aliases, word)| aliases.contains(word))
        };
        // While finding the command only the persistent flags are known, so
        // `Find` takes any other flag to consume the word after it.
        let guessed_value = |word: &str| {
            !word.contains('=')
                && (word.starts_with("--") || word.len() == 2 && word.starts_with('-'))
                && !self.switches.contains(&word)
        };
        // Argv indices left for pflag once `Find` removes the command words.
        let mut args: Vec<usize> = (1..literals.len()).collect();
        let mut path = Vec::new();
        loop {
            let mut position = 0;
            let mut next = None;
            while position < args.len() {
                let word = literals[args[position]];
                if word == "--" {
                    break;
                }
                if guessed_value(word) {
                    position += 2;
                    continue;
                }
                if !word.is_empty() && !word.starts_with('-') {
                    next = Some(position);
                    break;
                }
                position += 1;
            }
            let Some(position) = next else { break };
            let word = literals[args[position]];
            let depth = path.len();
            let child = self.deletes.iter().any(|delete| {
                delete.words.len() > depth
                    && matches(delete.words, &path)
                    && delete.words[depth].contains(&word)
            });
            if !child {
                break;
            }
            path.push(word);
            args.remove(position);
        }
        let delete = self
            .deletes
            .iter()
            .find(|delete| delete.words.len() == path.len() && matches(delete.words, &path));
        let values = |flag: &str| {
            self.values.contains(&flag)
                || delete.is_some_and(|delete| delete.values.contains(&flag))
        };
        let switch = |flag: &str| {
            self.switches
                .iter()
                .chain(delete.map_or(&[][..], |delete| delete.switches))
                .copied()
                .find(|switch| *switch == flag)
        };
        // The output flag's setter accepts only `text` or `json`, in any
        // case, and pflag fails on the first value it rejects.
        let rejected = |flag: &str, value: &str| {
            matches!(flag, "--output" | "-o")
                && !["text", "json"]
                    .iter()
                    .any(|format| value.eq_ignore_ascii_case(format))
        };
        let boolean = |value: &str| match value {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
            "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
            _ => None,
        };
        let mut operands = Vec::new();
        // Each Boolean occurrence with the value it sets; `-h` is `--help`.
        let mut switches: Vec<(&str, bool)> = Vec::new();
        let mut index = 0;
        while index < args.len() {
            let word = literals[args[index]];
            index += 1;
            if word == "--" {
                operands.extend(&args[index..]);
                break;
            }
            if word.len() < 2 || !word.starts_with('-') {
                operands.push(args[index - 1]);
                continue;
            }
            if let Some(name) = word.strip_prefix("--") {
                if name.starts_with(['-', '=']) {
                    return Request::Unreviewed;
                }
                let (flag, assigned) = match word.split_once('=') {
                    Some((flag, value)) => (flag, Some(value)),
                    None => (word, None),
                };
                if flag != "--help" && self.help.contains(&flag) {
                    return Request::Help;
                }
                if values(flag) {
                    let value = match assigned {
                        Some(value) => value,
                        None => {
                            let Some(&next) = args.get(index) else {
                                return Request::Unreviewed;
                            };
                            index += 1;
                            literals[next]
                        }
                    };
                    if rejected(flag, value) {
                        return Request::Unreviewed;
                    }
                    continue;
                }
                let Some(flag) = (flag == "--help").then_some("--help").or(switch(flag)) else {
                    return Request::Unreviewed;
                };
                let Some(set) = assigned.map_or(Some(true), boolean) else {
                    return Request::Unreviewed;
                };
                switches.push((flag, set));
                continue;
            }
            let mut cluster = &word[1..];
            while let Some(first) = cluster.chars().next() {
                let (letter, rest) = cluster.split_at(first.len_utf8());
                let flag = format!("-{letter}");
                // `-x=value` assigns only with something after the `=`.
                let assigned = rest.strip_prefix('=').filter(|value| !value.is_empty());
                if let Some(flag) = (letter == "h").then_some("--help").or(switch(&flag)) {
                    let Some(set) = assigned.map_or(Some(true), boolean) else {
                        return Request::Unreviewed;
                    };
                    switches.push((flag, set));
                    cluster = if assigned.is_some() { "" } else { rest };
                } else if values(&flag) {
                    let value = match (assigned, rest) {
                        (Some(value), _) => value,
                        (None, "") => {
                            let Some(&next) = args.get(index) else {
                                return Request::Unreviewed;
                            };
                            index += 1;
                            literals[next]
                        }
                        (None, rest) => rest,
                    };
                    if rejected(&flag, value) {
                        return Request::Unreviewed;
                    }
                    cluster = "";
                } else {
                    return Request::Unreviewed;
                }
            }
        }
        let set = |flag: &str| {
            switches
                .iter()
                .rev()
                .find(|(switch, _)| *switch == flag)
                .is_some_and(|(_, set)| *set)
        };
        if set("--help") {
            return Request::Help;
        }
        let (Some(delete), [operand]) = (delete, &operands[..]) else {
            return Request::Unreviewed;
        };
        Request::Delete {
            delete,
            id: Some(literals[*operand].to_string()),
            index: *operand,
            dry_run: delete.dry_run.iter().any(|flag| set(flag)),
            // Without `--force` Unity Catalog deletes only an empty one.
            requires_empty: !set("--force"),
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
            requires_empty,
        } = request
        else {
            return true;
        };
        let provenance = vec![arg_node(builder, ctx, index as u32), model_node];
        let mut attributes = std::collections::BTreeMap::new();
        if requires_empty {
            attributes.insert("requires_empty".to_string(), AttrValue::Bool(true));
        }
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
            attributes,
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
            "databricks" => "cloud/databricks@v0",
            _ => "cloud/fastly@v0",
        }
    }

    fn command_names(&self) -> &'static [&'static str] {
        match self.0.command {
            "railway" => &["railway"],
            "modal" => &["modal"],
            "kamal" => &["kamal"],
            "databricks" => &["databricks"],
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
        } else if let Some(program) = platform_cli_sql_input(self.tool.command, ctx) {
            builder.declare_coverage(Domain::new("process"), CoverageLevel::Full);
            if self.tool.command == "prisma" {
                boundary(
                    builder,
                    model_node,
                    BoundaryReason::ENVIRONMENT_CONFIGURATION,
                    BoundaryClass::Unmodeled,
                    &["database", "process"],
                    "Prisma reads the target database from the Prisma schema and config",
                );
            }
            document_sql(builder, ctx, model_node, program);
        } else if !self.tool.apply(builder, ctx, model_node) {
            self.owner.apply(builder, ctx, model_node);
        }
    }
}

/// An invocation's operands and options, each with its argv index.
struct ReviewedArguments<'a> {
    operands: Vec<(usize, &'a str)>,
    /// (flag, value, argv index of the value)
    options: Vec<(&'a str, Option<&'a str>, usize)>,
}

impl<'a> ReviewedArguments<'a> {
    /// Reads `argv` when every word is a literal and every option is one of
    /// `values`, which take a value, or `switches`. Any other option may
    /// take a value or change what runs, so the invocation is not read.
    fn reviewed(argv: &'a [Word], values: &[&str], switches: &[&str]) -> Option<Self> {
        let literals = argv
            .iter()
            .map(Word::as_literal)
            .collect::<Option<Vec<_>>>()?;
        let mut arguments = ReviewedArguments {
            operands: Vec::new(),
            options: Vec::new(),
        };
        let mut index = 1;
        while index < literals.len() {
            let word = literals[index];
            match word.split_once('=') {
                _ if !word.starts_with('-') => arguments.operands.push((index, word)),
                Some((flag, value)) if values.contains(&flag) || switches.contains(&flag) => {
                    arguments.options.push((flag, Some(value), index));
                }
                None if values.contains(&word) => {
                    index += 1;
                    let value = literals.get(index).copied()?;
                    arguments.options.push((word, Some(value), index));
                }
                None if switches.contains(&word) => arguments.options.push((word, None, index)),
                _ => return None,
            }
            index += 1;
        }
        Some(arguments)
    }

    /// Whether the operands start with the command words `path`.
    fn runs_command_path(&self, path: &[&str]) -> bool {
        self.operands.len() >= path.len()
            && self
                .operands
                .iter()
                .zip(path)
                .all(|((_, word), name)| word == name)
    }

    /// The value and argv index of the last occurrence of `flag`.
    fn last_option(&self, flag: &str) -> Option<(Option<&'a str>, usize)> {
        let (_, value, index) = self
            .options
            .iter()
            .rev()
            .find(|(name, _, _)| *name == flag)?;
        Some((*value, *index))
    }

    /// Whether a switch is given and not turned off with `=false`.
    fn switch_on(&self, flag: &str) -> bool {
        self.last_option(flag)
            .is_some_and(|(value, _)| value != Some("false"))
    }

    /// A script file an option names, as the program it runs.
    fn script_file_option(&self, flag: &str) -> Option<SqlClientInput> {
        let (path, index) = self.last_option(flag)?;
        Some(SqlClientInput::File(Word::literal(path?), index))
    }
}

/// SQL a documented platform CLI runs where its document cannot read it: a
/// script file an option names, a statement given as an operand, a file on
/// standard input. None for any other invocation, and for one holding an
/// option this does not read in full, which stays the document's.
fn platform_cli_sql_input(command: &str, ctx: &InvocationCtx) -> Option<SqlClientInput> {
    match command {
        // `wrangler d1 execute <database> --remote --file <script>`, under
        // the conditions the document nests `--command` SQL. `--cwd` moves
        // the directory the script resolves against, and `--command` beside
        // `--file` is rejected.
        "wrangler" => {
            let arguments = ReviewedArguments::reviewed(
                ctx.argv,
                &[
                    "--config",
                    "-c",
                    "--env",
                    "-e",
                    "--env-file",
                    "--profile",
                    "--file",
                    "--persist-to",
                ],
                &[
                    "--local",
                    "--remote",
                    "--preview",
                    "--json",
                    "--skip-confirmation",
                    "--yes",
                    "-y",
                ],
            )?;
            let remote = arguments.runs_command_path(&["d1", "execute"])
                && arguments.operands.len() == 3
                && arguments.switch_on("--remote")
                && !arguments.switch_on("--local")
                // Wrangler rejects a local state directory with --remote.
                && arguments
                    .last_option("--persist-to")
                    .is_none_or(|(path, _)| path == Some(""));
            arguments.script_file_option("--file").filter(|_| remote)
        }
        // `turso db shell <database> [sql]`: the statement, or else what is
        // piped in. A dot-command and an interactive shell stay unread.
        "turso" => {
            let arguments = ReviewedArguments::reviewed(
                ctx.argv,
                &["--config-path", "-c", "--instance", "--location", "--proxy"],
                &[],
            )?;
            if !arguments.runs_command_path(&["db", "shell"]) {
                return None;
            }
            match arguments.operands[2..] {
                [_] if ctx.stdin.is_some() => Some(SqlClientInput::Stdin),
                [_, (index, sql)] if !sql.trim_start().starts_with('.') => {
                    Some(SqlClientInput::Sql(Word::literal(sql), index))
                }
                _ => None,
            }
        }
        // `prisma db execute --file <script>`.
        "prisma" => {
            let arguments = ReviewedArguments::reviewed(
                ctx.argv,
                &["--file", "--url", "--schema", "--config"],
                &[],
            )?;
            let executes =
                arguments.runs_command_path(&["db", "execute"]) && arguments.operands.len() == 2;
            arguments.script_file_option("--file").filter(|_| executes)
        }
        _ => None,
    }
}
