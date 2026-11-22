use crate::models::args::FlagSpec;
use crate::word::Word;

use super::aws_request_input::aws_request_shape;
use super::cloud_args::{
    AWS_COMMON_SWITCHES, AWS_COMMON_VALUES, AZ_GLOBAL_VALUE_FLAGS, CLOUD_SCOPE_FLAGS,
    GCLOUD_COMMON_VALUES,
};
use catalog::resource_delete_row;

mod catalog;
mod effects;

pub(super) use effects::{
    aws_resource_delete_by_flag, azure_devops_delete, cloud_resource_delete_effect,
};

/// What a managed-database delete leaves of the resource's automated backups,
/// as its vendor documents it.
#[derive(Clone, Copy)]
enum AutomatedBackups {
    /// A snapshot or backup delete, which removes one recovery point, or a
    /// resource delete whose backup semantics are not claimed.
    NotApplicable,
    /// Removed with the resource and no option keeps them (DocumentDB and
    /// Neptune clusters, Redshift clusters).
    Removed,
    /// Only `--delete-automated-backups` or `--no-delete-automated-backups`
    /// establishes it. An RDS cluster's default keeps them when the account's
    /// AWS Backup policy has a point-in-time rule. An RDS instance's default
    /// removes them, but argv cannot tell a standalone instance from an Aurora
    /// cluster member, whose backups belong to the cluster.
    Explicit,
}

/// A documented fully qualified resource name, which is the whole ID.
#[derive(Clone, Copy)]
enum Qualified {
    None,
    /// gcloud's collection path, e.g. `projects/P/instances/I/databases/D`
    /// for `["projects", "instances", "databases"]`.
    Path(&'static [&'static str]),
    /// An AWS ARN `arn:PARTITION:SERVICE:REGION:ACCOUNT:RESOURCE/NAME`.
    Arn {
        service: &'static str,
        resource: &'static str,
    },
}

impl Qualified {
    fn matches(self, name: &str) -> bool {
        match self {
            Qualified::None => false,
            Qualified::Path(collections) => {
                let parts: Vec<&str> = name.split('/').collect();
                parts.len() == 2 * collections.len()
                    && parts
                        .chunks(2)
                        .zip(collections)
                        .all(|(pair, collection)| pair[0] == *collection && !pair[1].is_empty())
            }
            Qualified::Arn { service, resource } => {
                let parts: Vec<&str> = name.splitn(6, ':').collect();
                matches!(
                    parts[..],
                    ["arn", partition, arn_service, region, account, path]
                        if !partition.is_empty()
                            && arn_service == service
                            && !region.is_empty()
                            && !account.is_empty()
                            && path
                                .strip_prefix(resource)
                                .and_then(|rest| rest.strip_prefix('/'))
                                .is_some_and(|name| !name.is_empty() && !name.contains('/'))
                )
            }
        }
    }
}

/// One documented cloud resource delete verb.
pub(super) struct CloudResourceDelete {
    pub(super) provider: &'static str,
    service: &'static str,
    kind: &'static str,
    /// argv indices of the command words, from the service through the verb.
    path: Vec<usize>,
    /// Options naming the resource; empty when its operand names it.
    id_flags: &'static [&'static str],
    /// Options naming the containing resources, outermost first. The CLI may
    /// take one from its configuration or a fully qualified operand instead.
    parents: &'static [&'static [&'static str]],
    /// Whether several operands each name a resource to delete.
    many: bool,
    /// The switch requesting a final backup (Cloud SQL).
    final_backup: Option<&'static str>,
    /// A switch pair whose effective `true` keeps the resource's data, so the
    /// request deletes no live data (ElastiCache's retained primary).
    keeps_data: Option<(&'static str, &'static str)>,
    /// The vendor's fully qualified form of the name, when one is documented.
    qualified: Qualified,
    /// Whether a name is checked before it becomes an ID: a `/` must form the
    /// fully qualified operand, and a value the CLI reads from a file (AWS
    /// `file://`/`fileb://`, Azure `@file`) is input Nah does not read.
    /// DB-BAK's snapshot and backup verbs keep their literal reading.
    pub(super) strict_names: bool,
    /// Whether a checked name may contain `/` anyway: CloudWatch log groups
    /// and ECR repositories nest names, and some verbs take an ARN whose
    /// resource part does.
    slash_names: bool,
    /// Other command options that take a value.
    values: &'static [&'static str],
    /// Command options without a value.
    switches: &'static [&'static str],
    /// The CLI's global options, accepted after the verb too.
    common_values: &'static [&'static str],
    common_switches: &'static [&'static str],
    /// The CLI's scope options, which take a value wherever they appear.
    scope_values: &'static [&'static str],
    /// The skip-final-snapshot switch and its negation, for resource deletes.
    skip_final: Option<(&'static str, &'static str)>,
    /// The option naming the final snapshot when one is taken.
    final_snapshot: Option<&'static str>,
    backups: AutomatedBackups,
}

/// The provider of the azure-devops extension's deletes, which are hosted
/// requests rather than cloud resource deletes.
pub(super) const AZURE_DEVOPS: &str = "azure-devops";

const GCLOUD_COMMON_SWITCHES: &[&str] = &[
    "--quiet",
    "-q",
    "--log-http",
    "--no-log-http",
    "--user-output-enabled",
    "--no-user-output-enabled",
];
const AZ_COMMON_VALUES: &[&str] = &[
    "--subscription",
    "--output",
    "-o",
    "--query",
    "--change-reference",
];
const AZ_COMMON_SWITCHES: &[&str] = &[
    "--debug",
    "--verbose",
    "--only-show-errors",
    "--acquire-policy-token",
];

/// The managed-database instance, cluster, database, table, snapshot and
/// backup deletes whose options the vendors document, Cloud SQL's user and
/// certificate deletes, and the reviewed deletes of other provisioned
/// resources: compute, networking, edge, identity and account scopes. Other
/// verbs keep their existing handling.
pub(super) fn cloud_resource_delete(argv: &[Word]) -> Option<CloudResourceDelete> {
    let tool = crate::models::args::basename(argv.first()?.as_literal()?);
    let (common_values, common_switches, scope_values) = match tool {
        "aws" => (AWS_COMMON_VALUES, AWS_COMMON_SWITCHES, CLOUD_SCOPE_FLAGS),
        "gcloud" => (
            GCLOUD_COMMON_VALUES,
            GCLOUD_COMMON_SWITCHES,
            CLOUD_SCOPE_FLAGS,
        ),
        "az" => (AZ_COMMON_VALUES, AZ_COMMON_SWITCHES, AZ_GLOBAL_VALUE_FLAGS),
        _ => return None,
    };
    // The command words are found with the same global value options the
    // request is parsed with, plus the scope options that take a value but are
    // refused there (gcloud's --flags-file), so a detached global value is
    // never read as a command word. The CLIs accept global options between
    // command words (`gcloud sql --quiet instances delete x`).
    let global_values: Vec<&str> = common_values.iter().chain(scope_values).copied().collect();
    let words: Vec<usize> = crate::models::args::scan_detached(
        argv,
        &FlagSpec {
            value_flags: &global_values,
            known_flags: &[],
            allow_abbreviation: false,
        },
        false,
    )
    .operands
    .iter()
    .filter(|(_, word)| word.as_literal() != Some("-"))
    .map(|(index, _)| *index as usize)
    .collect();
    let globals = (common_values, common_switches, scope_values);
    // A word after an option the CLI's globals do not include may be that
    // option's value (`gcloud sql --weird d instances delete x`). When the
    // words as read name no verb, the one reading that skips some of those
    // words names it, if exactly one does; the skipped words stay out of the
    // operands. Only words that can precede a verb (at most five command words
    // and three skipped values) are candidates.
    resource_delete_row(argv, tool, &words, globals).or_else(|| {
        let candidates: Vec<(usize, &str)> = (0..words.len().min(8))
            .filter_map(|position| {
                argv[words[position] - 1]
                    .as_literal()
                    .filter(|flag| {
                        flag.starts_with('-')
                            && *flag != "-"
                            && *flag != "--"
                            && !flag.contains('=')
                            && !common_switches.contains(flag)
                    })
                    .map(|flag| (position, flag))
            })
            .collect();
        let readings = (1..1usize << candidates.len()).filter_map(|mask| {
            let skipped: Vec<(usize, &str)> = (0..candidates.len())
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| candidates[bit])
                .collect();
            let reading: Vec<usize> = (0..words.len())
                .filter(|position| !skipped.iter().any(|(skip, _)| skip == position))
                .map(|position| words[position])
                .collect();
            resource_delete_row(argv, tool, &reading, globals)
                .filter(|delete| skipped.iter().all(|(_, flag)| !delete.is_switch(flag)))
        });
        // Readings that skip words after the verb name the same command.
        let mut named: Vec<CloudResourceDelete> = Vec::new();
        for delete in readings {
            if !named.iter().any(|other| other.path == delete.path) {
                named.push(delete);
            }
        }
        (named.len() == 1).then(|| named.remove(0))
    })
}

const AUTOMATED_BACKUP_SWITCHES: [&str; 2] = [
    "--delete-automated-backups",
    "--no-delete-automated-backups",
];

impl CloudResourceDelete {
    /// Every option this verb documents.
    pub(super) fn options(&self) -> impl Iterator<Item = &'static str> + '_ {
        [
            self.common_values,
            self.common_switches,
            self.values,
            self.switches,
            self.id_flags,
            &AUTOMATED_BACKUP_SWITCHES,
        ]
        .into_iter()
        .chain(self.parents.iter().copied())
        .flatten()
        .copied()
        .chain(self.final_snapshot)
        .chain(
            self.skip_final
                .into_iter()
                .flat_map(|(skip, keep)| [skip, keep]),
        )
    }

    fn takes_value(&self, flag: &str) -> bool {
        [self.common_values, self.values, self.id_flags]
            .iter()
            .chain(self.parents)
            .any(|flags| flags.contains(&flag))
            || self.final_snapshot == Some(flag)
    }

    fn is_switch(&self, flag: &str) -> bool {
        self.common_switches.contains(&flag)
            || self.switches.contains(&flag)
            || self
                .skip_final
                .is_some_and(|(skip, keep)| flag == skip || flag == keep)
            || (matches!(self.backups, AutomatedBackups::Explicit)
                && AUTOMATED_BACKUP_SWITCHES.contains(&flag))
    }

    /// The command's options and operands around and between its command
    /// words, when every word is a literal this verb documents. The CLIs parse
    /// options wherever they appear, and a repeated option keeps its last
    /// value, as argparse's store actions do. An option the verb does not
    /// document may still be one the CLI accepts, so it is recorded and the
    /// words around it keep their reading; a scope option keeps its value.
    /// An expansion is read as one operand or value, [`UNSTATED`], that names
    /// a resource Nah cannot. gcloud's `--flags-file`, which supplies
    /// arguments Nah does not read, AWS's `--dry-run`, which these verbs do
    /// not support, or a value option without its value leaves the request
    /// unestablished.
    fn arguments<'a>(&self, argv: &'a [Word]) -> Option<DeleteArguments<'a>> {
        let indices: Vec<usize> = (1..argv.len())
            .filter(|index| !self.path.contains(index))
            .collect();
        let mut arguments = DeleteArguments::default();
        let mut position = 0;
        // The word after an undocumented option may be its value.
        let mut maybe_value = None;
        while let Some(&index) = indices.get(position) {
            position += 1;
            let word = argv[index].as_literal().unwrap_or(UNSTATED);
            // An expansion attached to a long option (`--name="$(…)"`) is
            // that option with a value Nah cannot read.
            let attached_expansion = argv[index]
                .as_literal()
                .is_none()
                .then(|| argv[index].literal_prefix().split_once('='))
                .flatten()
                .filter(|(flag, _)| flag.starts_with("--"))
                .map(|(flag, _)| flag);
            // argparse also reads a short value option's `-nVALUE` and
            // `-n=VALUE` as `-n VALUE`.
            let short = word.get(..2).filter(|flag| {
                !word.starts_with("--")
                    && word.len() > 2
                    && flag.starts_with('-')
                    && self.takes_value(flag)
            });
            let (flag, attached) = if let Some(flag) = attached_expansion {
                (flag, Some(UNSTATED))
            } else {
                match (short, word.split_once('=')) {
                    (Some(flag), _) => (
                        flag,
                        Some(word[2..].strip_prefix('=').unwrap_or(&word[2..])),
                    ),
                    (None, Some((flag, value))) if word.starts_with("--") => (flag, Some(value)),
                    _ => (word, None),
                }
            };
            if attached.is_none() && self.is_switch(flag) {
                arguments.switches.push(flag);
            } else if self.takes_value(flag) {
                let value = match attached {
                    Some(value) => value,
                    None => {
                        let next = *indices.get(position)?;
                        position += 1;
                        if next != index + 1 {
                            return None;
                        }
                        argv[next].as_literal().unwrap_or(UNSTATED)
                    }
                };
                if value.is_empty() || value.starts_with('-') {
                    return None;
                }
                arguments.values.push((flag, value));
            } else if flag == "--flags-file" || (self.provider == "aws" && flag == "--dry-run") {
                return None;
            } else if flag.starts_with('-') {
                arguments.unknown = true;
                if attached.is_none() && self.scope_values.contains(&flag) {
                    let next = *indices.get(position)?;
                    position += 1;
                    if next != index + 1 {
                        return None;
                    }
                } else if attached.is_none() {
                    maybe_value = Some(index + 1);
                }
            } else if maybe_value == Some(index) {
                arguments.ambiguous.push(word);
            } else {
                arguments.operands.push(word);
            }
        }
        Some(arguments)
    }
}

impl CloudResourceDelete {
    /// The request argv states: its arguments, the names of the resources to
    /// delete, each containing resource's name where one is given, and whether
    /// the CLI reads any of those names from a file. A name Nah does not read
    /// is [`UNSTATED`]. `None` when the words do not establish which resources
    /// the request names.
    #[allow(clippy::type_complexity)]
    fn request<'a>(
        &self,
        argv: &'a [Word],
    ) -> Option<(
        DeleteArguments<'a>,
        Vec<&'a str>,
        Vec<Option<&'a str>>,
        bool,
    )> {
        let arguments = self.arguments(argv)?;
        let ids = if self.id_flags.is_empty() {
            match arguments.operands[..] {
                [id] => vec![id],
                [_, _, ..] if self.many => arguments.operands.clone(),
                _ => return None,
            }
        } else if arguments.operands.is_empty() {
            vec![arguments.value(self.id_flags)?]
        } else {
            return None;
        };
        let containers: Vec<Option<&str>> = self
            .parents
            .iter()
            .map(|flags| arguments.value(flags))
            .collect();
        // A name the CLI reads from a file is one Nah does not read. Snapshot and
        // backup verbs keep their literal reading.
        let from_file =
            |name: &&str| (self.strict_names || self.skip_final.is_some()) && self.names_file(name);
        let read_from_file = ids.iter().chain(containers.iter().flatten()).any(from_file);
        let unread = |name| if from_file(&name) { UNSTATED } else { name };
        let ids: Vec<&str> = ids.into_iter().map(unread).collect();
        let containers: Vec<Option<&str>> = containers
            .into_iter()
            .map(|name| name.map(unread))
            .collect();
        // A `/` that does not form the vendor's fully qualified operand is not
        // a name Nah can place.
        if self.strict_names
            && !(ids
                .iter()
                .all(|id| !id.contains('/') || self.qualified.matches(id) || self.slash_names)
                && containers.iter().flatten().all(|name| !name.contains('/')))
        {
            return None;
        }
        Some((arguments, ids, containers, read_from_file))
    }

    /// Whether the CLI reads `name` from a file (AWS `file://`/`fileb://`,
    /// Azure `@file`) instead of taking it as the name.
    fn names_file(&self, name: &str) -> bool {
        match self.provider {
            "aws" => name.starts_with("file://") || name.starts_with("fileb://"),
            "azure" => name.starts_with('@'),
            _ => false,
        }
    }

    /// Whether every word is one this verb documents and every name is
    /// literal, so the request is the one argv states.
    fn stated(
        &self,
        arguments: &DeleteArguments,
        ids: &[&str],
        containers: &[Option<&str>],
    ) -> bool {
        !arguments.unknown
            && arguments.ambiguous.is_empty()
            && !ids
                .iter()
                .chain(containers.iter().flatten())
                .any(|name| *name == UNSTATED)
            && (!containers.contains(&None) || ids.iter().all(|id| self.qualified.matches(id)))
    }

    /// What the request leaves of automated backups, where its switches or
    /// the vendor's documentation establish it.
    fn automated_backups_retained(&self, arguments: &DeleteArguments) -> Option<bool> {
        match self.backups {
            AutomatedBackups::Removed => Some(false),
            AutomatedBackups::Explicit => arguments
                .switch(AUTOMATED_BACKUP_SWITCHES.into())
                .map(|remove| !remove),
            AutomatedBackups::NotApplicable => None,
        }
    }

    /// Whether [`cloud_resource_delete_effect`] emits this delete without a boundary
    /// of its own: every argument was read and the request's backup choices
    /// are established. Only then does the delete close cloud coverage.
    fn resolved(&self, argv: &[Word]) -> bool {
        if self.provider == "aws" && aws_request_shape(argv).is_some() {
            return false;
        }
        let Some((arguments, ids, containers, _)) = self.request(argv) else {
            return false;
        };
        let keeps_data = self
            .keeps_data
            .is_some_and(|pair| arguments.switch(pair) == Some(true));
        let backups_established = match (self.skip_final, self.final_snapshot) {
            (Some(pair), Some(final_snapshot)) => {
                (arguments.switch(pair) == Some(true))
                    != arguments.value(&[final_snapshot]).is_some()
                    && self.automated_backups_retained(&arguments).is_some()
            }
            _ => true,
        };
        // A snapshot or backup verb keeps a file-backed name as written, but
        // the name it deletes is still one Nah did not read.
        let names_read = !ids
            .iter()
            .chain(containers.iter().flatten())
            .any(|name| self.names_file(name));
        self.stated(&arguments, &ids, &containers)
            && names_read
            && !keeps_data
            && backups_established
    }
}

/// A name the invocation gives in a form Nah does not read: an expansion, or
/// a value the CLI reads from a file. No argv word is a NUL.
const UNSTATED: &str = "\0";

#[derive(Default)]
struct DeleteArguments<'a> {
    operands: Vec<&'a str>,
    values: Vec<(&'a str, &'a str)>,
    switches: Vec<&'a str>,
    /// Whether an option the verb does not document was given.
    unknown: bool,
    /// Operands that may instead be such an option's value; never a target.
    ambiguous: Vec<&'a str>,
}

impl<'a> DeleteArguments<'a> {
    /// The last value any of `flags` gave.
    fn value(&self, flags: &[&str]) -> Option<&'a str> {
        self.values
            .iter()
            .rev()
            .find(|(flag, _)| flags.contains(flag))
            .map(|(_, value)| *value)
    }

    /// The boolean a switch pair sets, by its last occurrence: AWS registers
    /// `--x` and `--no-x` as store_true and store_false on one destination.
    fn switch(&self, (on, off): (&str, &str)) -> Option<bool> {
        self.switches.iter().rev().find_map(|flag| {
            (*flag == on)
                .then_some(true)
                .or((*flag == off).then_some(false))
        })
    }
}

/// Whether argv is a reviewed delete that [`cloud_resource_delete_effect`] emits
/// without a boundary of its own.
pub(super) fn cloud_resource_delete_resolved(argv: &[Word]) -> bool {
    cloud_resource_delete(argv).is_some_and(|delete| delete.resolved(argv))
}
