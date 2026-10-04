// Build scripts run on the host at build time: the workspace's pure-crate
// lint rules describe runtime crates, not the generator that feeds them.
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};

use effinterp_model_schema::{
    BehaviorDeclaration, COMPILER_SCHEMA_V2, CallableTargetDeclaration, CommandDeclaration,
    Declaration, DeclarationDocument, LifecycleDeclaration, LifecycleLanguage,
    SubcommandDeclaration, declaration_digest, validate_bundled_document,
};

// Rust-backed command models follow the declaration-backed models in this order.
// The generated lookup and model-set identity are checked against the runtime
// catalog in tests, so changing a model's identity or command ownership requires
// updating this build-time manifest.
const RUST_COMMAND_MODELS: &[(&str, &[&str])] = &[
    ("coreutils/sort@v0", &["sort"]),
    ("coreutils/wc@v0", &["wc"]),
    ("gnu/grep@v0", &["grep", "egrep", "fgrep"]),
    ("util/pager@v0", &["less", "more"]),
    ("coreutils/base64@v0", &["base64", "base32"]),
    ("coreutils/cut@v0", &["cut"]),
    ("posix/awk@v0", &["awk", "gawk", "mawk", "nawk"]),
    (
        "util/inert@v0",
        &[
            "tr", "rev", "tput", "uname", "sleep", "true", "false", "basename", "dirname",
        ],
    ),
    ("openssl/enc@v2", &["openssl"]),
    ("editor/ed@v0", &["ed"]),
    ("editor/ex@v0", &["ex"]),
    ("coreutils/mkfifo@v0", &["mkfifo"]),
    ("coreutils/mknod@v0", &["mknod"]),
    ("coreutils/tee@v0", &["tee"]),
    ("coreutils/head-tail@v0", &["head", "tail"]),
    ("coreutils/sed@v0", &["sed"]),
    ("coreutils/ls@v0", &["ls"]),
    ("coreutils/stat@v0", &["stat"]),
    ("util/patch@v1", &["patch"]),
    ("editor/vim@v1", &["vim", "vi", "nvim"]),
    ("gnu/tar@v1", &["tar"]),
    ("libarchive/bsdtar@v1", &["bsdtar"]),
    ("net/curl@v0", &["curl"]),
    ("net/wget@v0", &["wget"]),
    ("network/netcat@v1", &["nc", "netcat", "ncat"]),
    ("network/socat@v1", &["socat"]),
    ("network/mail@v1", &["mail", "mailx"]),
    ("network/dns-lookup@v1", &["dig", "nslookup", "host"]),
    ("git/git@v0", &["git"]),
    ("git/git-filter-repo@v0", &["git-filter-repo"]),
    ("build/make@v8", &["make", "gmake"]),
    ("build/just@v6", &["just"]),
    ("build/task@v6", &["task", "go-task"]),
    ("build/cargo@v1", &["cargo"]),
    ("build/javac@v1", &["javac"]),
    ("build/maven@v1", &["mvn", "mvnw"]),
    ("build/gradle@v1", &["gradle", "gradlew"]),
    (
        "ci/github-actions@v5",
        &[
            "\0effinterp:github-actions",
            "\0effinterp:github-actions-container",
        ],
    ),
    (
        "posix/shell@v0",
        &["sh", "bash", "dash", "zsh", "ash", "mksh"],
    ),
    ("coreutils/env@v0", &["env"]),
    ("coreutils/printenv@v0", &["printenv"]),
    ("sudo/sudo@v0", &["sudo"]),
    ("openbsd/doas@v0", &["doas"]),
    ("coreutils/nohup@v0", &["nohup"]),
    ("util-linux/setsid@v0", &["setsid"]),
    ("coreutils/nice@v0", &["nice"]),
    ("coreutils/stdbuf@v0", &["stdbuf"]),
    ("util-linux/timeout@v0", &["timeout"]),
    ("coreutils/chroot@v0", &["chroot"]),
    ("findutils/xargs@v0", &["xargs"]),
    ("openssh/ssh@v0", &["ssh"]),
    ("util-linux/su@v0", &["su"]),
    ("util-linux/runuser@v0", &["runuser"]),
    ("posix/command@v0", &["command"]),
    ("ltrace/ltrace@v0", &["ltrace"]),
    ("sshpass/sshpass@v0", &["sshpass"]),
    ("procps/watch@v0", &["watch"]),
    ("util-linux/script@v0", &["script"]),
    ("util-linux/flock@v0", &["flock"]),
    ("systemd/systemd-run@v0", &["systemd-run"]),
    ("util-linux/nsenter@v0", &["nsenter"]),
    ("util-linux/unshare@v0", &["unshare"]),
    ("busybox/busybox@v0", &["busybox", "toybox"]),
    ("tmux/tmux@v0", &["tmux"]),
    ("gnu/parallel@v0", &["parallel"]),
    ("dbus/dbus-run-session@v0", &["dbus-run-session"]),
    ("libeatmydata/eatmydata@v0", &["eatmydata"]),
    ("util-linux/prlimit@v0", &["prlimit"]),
    ("polkit/pkexec@v0", &["pkexec"]),
    ("firejail/firejail@v0", &["firejail"]),
    ("proot/proot@v0", &["proot"]),
    ("shadow/sg@v0", &["sg"]),
    ("gnu/screen@v0", &["screen"]),
    (
        "docker/cli@v6",
        &["docker", "podman", "docker-compose", "podman-compose"],
    ),
    ("cloud/aws@v0", &["aws"]),
    ("cloud/gcloud@v0", &["gcloud"]),
    ("cloud/gsutil@v0", &["gsutil"]),
    ("cloud/az@v0", &["az"]),
    ("cloud/azcopy@v0", &["azcopy"]),
    ("s3tools/s3cmd@v0", &["s3cmd"]),
    ("cloud/railway@v0", &["railway"]),
    ("cloud/modal@v0", &["modal"]),
    ("cloud/kamal@v0", &["kamal"]),
    ("cloud/fastly@v0", &["fastly"]),
    ("infrastructure/terraform@v1", &["terraform"]),
    ("infrastructure/tofu@v1", &["tofu"]),
    ("credential/vault@v0", &["vault"]),
    ("credential/doppler@v0", &["doppler"]),
    ("credential/infisical@v0", &["infisical"]),
    ("credential/op@v0", &["op"]),
    ("credential/security@v0", &["security"]),
    ("credential/bw@v0", &["bw"]),
    ("credential/bws@v0", &["bws"]),
    ("credential/pass@v0", &["pass"]),
    ("credential/gopass@v0", &["gopass"]),
    ("credential/sops@v0", &["sops"]),
    (
        "kafka/cli@v0",
        &[
            "kafka-console-producer",
            "kafka-console-producer.sh",
            "kafka-console-consumer",
            "kafka-console-consumer.sh",
            "kafka-topics",
            "kafka-topics.sh",
        ],
    ),
    ("rabbitmq/rabbitmqctl@v0", &["rabbitmqctl"]),
    ("rabbitmq/rabbitmqadmin@v0", &["rabbitmqadmin"]),
    ("mqtt/mosquitto@v0", &["mosquitto_pub", "mosquitto_sub"]),
    ("nats/cli@v0", &["nats"]),
    (
        "redis/redis-cli@v0",
        &["redis-cli", "valkey-cli", "keydb-cli"],
    ),
    ("postgres/psql@v0", &["psql"]),
    ("mysql/mysql@v0", &["mysql", "mariadb"]),
    ("sqlite/sqlite3@v0", &["sqlite3"]),
    ("duckdb/duckdb@v0", &["duckdb"]),
    ("cockroach/cockroach@v0", &["cockroach"]),
    ("cassandra/cqlsh@v0", &["cqlsh"]),
    ("clickhouse/client@v0", &["clickhouse-client", "clickhouse"]),
    ("mssql/sqlcmd@v0", &["sqlcmd"]),
    ("snowflake/snowsql@v0", &["snowsql"]),
    ("snowflake/snow@v0", &["snow"]),
    ("postgres/dropdb@v0", &["dropdb"]),
    ("mysql/mysqladmin@v0", &["mysqladmin"]),
    ("postgres/pg_restore@v0", &["pg_restore"]),
    ("postgres/pg_dump@v0", &["pg_dump", "pg_dumpall"]),
    ("mysql/mysqldump@v0", &["mysqldump"]),
    ("mongo/mongosh@v0", &["mongo", "mongosh"]),
    ("mongo/mongorestore@v0", &["mongorestore"]),
    ("gcp/bq@v0", &["bq"]),
    ("gcp/cbt@v0", &["cbt"]),
    ("firebase/firebase@v0", &["firebase"]),
    ("perl/perl@v1", &["perl"]),
    ("apple/osascript@v0", &["osascript"]),
    ("coreutils/dd@v0", &["dd"]),
    (
        "util-linux/mkfs@v0",
        &[
            "mkfs",
            "mke2fs",
            "mkswap",
            "mkfs.ext2",
            "mkfs.ext3",
            "mkfs.ext4",
            "mkfs.xfs",
            "mkfs.btrfs",
            "mkfs.vfat",
            "mkfs.fat",
            "mkfs.msdos",
            "mkfs.ntfs",
            "mkfs.exfat",
            "mkfs.f2fs",
            "mkfs.reiserfs",
            "mkfs.minix",
            "mkfs.jfs",
        ],
    ),
    ("util-linux/wipefs@v0", &["wipefs"]),
    ("coreutils/shred@v0", &["shred"]),
    ("util-linux/blkdiscard@v0", &["blkdiscard"]),
    ("hdparm/hdparm@v0", &["hdparm"]),
    ("diskutil/diskutil@v0", &["diskutil"]),
    ("e2fsprogs/badblocks@v0", &["badblocks"]),
    ("lvm/remove@v0", &["lvremove", "vgremove", "pvremove"]),
    ("lvm/lvm@v0", &["lvm"]),
    ("openzfs/zfs@v0", &["zpool", "zfs"]),
    ("btrfs/subvolume@v0", &["btrfs"]),
    (
        "storage/partition@v0",
        &["sgdisk", "fdisk", "gdisk", "parted", "cfdisk", "sfdisk"],
    ),
    ("borg/backup@v1", &["borg"]),
    ("restic/backup@v1", &["restic"]),
    ("velero/backup@v1", &["velero"]),
    ("duplicity/backup@v1", &["duplicity"]),
    ("kopia/snapshot-delete@v1", &["kopia"]),
    ("pgbackrest/expire@v1", &["pgbackrest"]),
    (
        "system/control@v0",
        &[
            "systemctl",
            "service",
            "shutdown",
            "reboot",
            "halt",
            "poweroff",
            "init",
            "telinit",
            "crontab",
            "at",
            "atrm",
            "date",
            "timedatectl",
            "hwclock",
        ],
    ),
    ("sudo/visudo@v0", &["visudo"]),
    ("hashicorp/vagrant@v0", &["vagrant"]),
    ("lima-vm/limactl@v0", &["limactl", "lima"]),
    ("canonical/multipass@v0", &["multipass"]),
    ("cmd/cmd@v0", &["cmd", "cmd.exe"]),
    ("windows/certutil@v0", &["certutil", "certutil.exe"]),
    ("windows/xcopy@v0", &["xcopy", "xcopy.exe"]),
    ("windows/robocopy@v0", &["robocopy", "robocopy.exe"]),
    ("go/verbs@v3", &["go"]),
    ("java/source-file@v0", &["java"]),
    ("rust/script-source@v0", &["rust-script"]),
    ("findutils/find@v0", &["find"]),
    ("util/kill@v0", &["kill", "killall", "pkill"]),
    ("util/mount@v0", &["mount", "umount"]),
    ("archive/zip@v0", &["zip", "unzip", "gzip", "gunzip"]),
    ("util/fileattr@v0", &["chattr", "setfacl"]),
    ("windows/icacls@v0", &["icacls", "icacls.exe"]),
    ("rsync/rsync@v0", &["rsync"]),
    ("openssh/scp@v0", &["scp"]),
    (
        "pkg/manager@v1",
        &[
            "apt", "apt-get", "dnf", "yum", "pip", "pip3", "npm", "pnpm", "pnpx", "yarn", "bun",
        ],
    ),
    ("package/publication@v1", &["twine", "hatch", "flit"]),
    (
        "package/release-tools@v1",
        &[
            "lerna",
            "changeset",
            "semantic-release",
            "np",
            "release-it",
            "pdm",
            "rye",
            "maturin",
        ],
    ),
];

fn collect_models(directory: &Path, directories: &mut Vec<PathBuf>, models: &mut Vec<PathBuf>) {
    directories.push(directory.to_path_buf());
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            collect_models(&path, directories, models);
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            models.push(path);
        } else {
            panic!(
                "promoted model path is not a JSON document: {}",
                path.display()
            );
        }
    }
}

// Keep the schema's serialized shape, but resolve JSON syntax at build time.
// The engine materializes only declarations selected by an invocation.
fn model_value(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "ModelValue::Null".into(),
        Value::Bool(value) => format!("ModelValue::Bool({value})"),
        Value::Number(value) => {
            let (magnitude, negative) = value.as_u64().map_or_else(
                || (value.as_i64().unwrap().unsigned_abs(), true),
                |value| (value, false),
            );
            format!("ModelValue::Number({magnitude}, {negative})")
        }
        Value::String(value) => format!("ModelValue::String({value:?})"),
        Value::Array(values) => format!(
            "ModelValue::Seq(&[{}])",
            values.iter().map(model_value).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => format!(
            "ModelValue::Map(&[{}])",
            values
                .iter()
                .map(|(key, value)| format!("({key:?}, {})", model_value(value)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn subcommand_behaviors(subcommands: &[SubcommandDeclaration]) -> Vec<&BehaviorDeclaration> {
    subcommands
        .iter()
        .flat_map(|subcommand| {
            std::iter::once(&subcommand.behavior)
                .chain(subcommand_behaviors(&subcommand.subcommands))
        })
        .collect()
}

fn behavior_domains(behavior: &BehaviorDeclaration) -> BTreeSet<&str> {
    let mut domains = behavior
        .effects
        .iter()
        .flat_map(|rule| &rule.emit)
        .filter_map(|effect| effect.operation.split('.').next())
        .chain(
            behavior
                .boundaries
                .iter()
                .flat_map(|boundary| boundary.domains.iter().map(String::as_str)),
        )
        .chain(
            behavior
                .unsupported
                .iter()
                .flat_map(|unsupported| unsupported.domains.iter().map(String::as_str)),
        )
        .collect::<BTreeSet<_>>();
    if !behavior.invocations.is_empty() || !behavior.nested_source.is_empty() {
        domains.insert("process");
    }
    if !behavior.nested_source.is_empty() {
        domains.insert("filesystem");
    }
    domains
}

fn command_model(command: &CommandDeclaration, digest: &str) -> String {
    let behaviors = std::iter::once(&command.behavior)
        .chain(subcommand_behaviors(&command.subcommands))
        .chain(command.modes.iter().map(|mode| &mode.behavior))
        .collect::<Vec<_>>();
    let domains = behaviors
        .iter()
        .flat_map(|behavior| behavior_domains(behavior))
        .chain(command.launcher.iter().flat_map(|_| {
            [
                "artifact",
                "filesystem",
                "process",
                "environment",
                "network",
                "database",
                "container",
                "git",
                "cloud",
                "messaging",
                "system",
                "credential",
            ]
        }))
        .collect::<BTreeSet<_>>();
    let mut flags = BTreeMap::new();
    let mut named_value_flags = Vec::new();
    for flag in behaviors.iter().flat_map(|behavior| &behavior.flags) {
        for name in &flag.names {
            if let Some(previous) = flags.insert(name, flag.takes_value) {
                assert_eq!(previous, flag.takes_value, "conflicting flag {name}");
            }
            if flag.named_value {
                named_value_flags.push(name);
            }
        }
    }
    let value_flags = flags
        .iter()
        .filter(|(_, value)| **value)
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    let known_flags = flags
        .iter()
        .filter(|(_, value)| !**value)
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    let case_insensitive_flags = flags.keys().any(|name| {
        name.len() > 2
            && !name.starts_with("--")
            && name.as_bytes().get(1).is_some_and(u8::is_ascii_uppercase)
    });
    let strict_flags = !flags.is_empty()
        || behaviors
            .iter()
            .any(|behavior| behavior.unsupported.is_some() || !behavior.positionals.is_empty());
    let declaration = model_value(&serde_json::to_value(command).unwrap());
    let domains = domains.into_iter().collect::<Vec<_>>();
    format!(
        r#"{{
        static DECLARATION: LazyLock<CommandDeclaration> = LazyLock::new(|| {{
            serde::Deserialize::deserialize(&{declaration}).expect("generated declaration")
        }});
        DeclarativeCommandModel {{
            id: {:?}, command_names: &{:?}, domains: &{domains:?},
            digest: {digest:?}, declaration: CommandData::Builtin(&DECLARATION),
            value_flags: &{value_flags:?}, known_flags: &{known_flags:?},
            case_insensitive_flags: {case_insensitive_flags}, strict_flags: {strict_flags},
            named_value_flags: {named_value_flags:?}.map(|value: &str| value.to_owned()).to_vec(),
        }}
    }}"#,
        command.id, command.commands
    )
}

fn lifecycle(declaration: &LifecycleDeclaration) -> String {
    let lang = match declaration.lang {
        None => "None".into(),
        Some(LifecycleLanguage::Js) => "Some(Lang::Js(SourceDialect::Js))".into(),
        Some(LifecycleLanguage::Ts) => "Some(Lang::Js(SourceDialect::Ts))".into(),
        Some(lang) => format!("Some(Lang::{lang:?})"),
    };
    let sigs = declaration.signatures.iter().map(|sig| {
        let (method, receiver_type, import_path) = match &sig.target {
            CallableTargetDeclaration::Method { name, receiver_type } => (name.as_deref(), receiver_type.as_deref(), None),
            CallableTargetDeclaration::Function { name, import_path } => (Some(name.as_str()), None, import_path.as_deref()),
            CallableTargetDeclaration::Constructor { receiver_type } => (None, Some(receiver_type.as_str()), None),
        };
        format!("LifecycleSig {{ method: {method:?}, receiver_type: {receiver_type:?}, import_path: {import_path:?}, role: effinterp_model_schema::SigRole::{:?}, max_args: {:?}, component: {:?}, evidence: effinterp_model_schema::SigEvidence::{:?}, fields: &{:?}, params: &{:?}, hooks: &{:?}, derive_result: {:?}, result_type: {:?}, field_tags: &{:?} }}",
            sig.role, sig.max_args, sig.component, sig.evidence, sig.fields, sig.params, sig.hooks, sig.derive_result, sig.result_type, sig.field_tags)
    }).collect::<Vec<_>>().join(",");
    format!(
        "FrameworkLifecycle {{ id: {:?}, lang: {lang}, sigs: &[{sigs}] }}",
        declaration.id
    )
}

fn main() {
    let crate_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let model_root = crate_dir.join("models/v1");
    let mut directories = Vec::new();
    let mut models = Vec::new();
    collect_models(&model_root, &mut directories, &mut models);
    directories.sort();
    models.sort();
    for path in directories.iter().chain(&models) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let mut generated = String::from("const PROMOTED_MODEL_SOURCES: &[&str] = &[\n");
    let mut declarations = BTreeMap::new();
    let mut identities = Vec::new();
    for path in models {
        let source = std::fs::read_to_string(&path).unwrap();
        let document: DeclarationDocument = serde_json::from_str(&source)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        validate_bundled_document(&source, &document)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        writeln!(generated, "include_str!({:?}),", path.to_str().unwrap()).unwrap();
        identities.push(document.identity.clone());
        for mut declaration in document.entries {
            // Hash the original declaration, before expanding its fragments.
            let digest = declaration_digest(&document.identity, &declaration);
            if let Declaration::Command(command) = &mut declaration {
                let mut expanded = BehaviorDeclaration::default();
                for fragment in &command.fragments {
                    expanded.extend(document.fragments.get(fragment).expect("known fragment"));
                }
                expanded.extend(&command.behavior);
                command.behavior = expanded;
            }
            assert!(
                declarations
                    .insert(declaration.id().to_string(), (declaration, digest))
                    .is_none(),
                "duplicate declaration ID"
            );
        }
    }
    generated.push_str("];\n");
    identities.sort();
    let mut commands = Vec::new();
    let mut lifecycles = Vec::new();
    let mut apis = Vec::new();
    let mut mcp_tools = Vec::new();
    let mut ownership = BTreeMap::new();
    let mut model_set_entries = Vec::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMPILER_SCHEMA_V2.as_bytes());
    hasher.update(b"\0");
    for (id, (declaration, digest)) in &declarations {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
        hasher.update(b"\0");
        match declaration {
            Declaration::Command(command) => {
                let index = commands.len();
                for name in &command.commands {
                    assert!(
                        ownership.insert(name.clone(), index).is_none(),
                        "duplicate command owner: {name}"
                    );
                }
                if command.id == "p18b/devtools/gh@v1" {
                    model_set_entries.push((
                        "p18b/devtools/gh@v2".to_string(),
                        command.commands.clone(),
                        None,
                    ));
                } else {
                    model_set_entries.push((
                        command.id.clone(),
                        command.commands.clone(),
                        Some(digest.clone()),
                    ));
                }
                commands.push(command_model(command, digest));
            }
            Declaration::Lifecycle(value) => lifecycles.push(lifecycle(value)),
            Declaration::McpTool(tool) => {
                let declaration = model_value(&serde_json::to_value(tool).unwrap());
                mcp_tools.push(format!(
                    "CompiledMcpTool {{ declaration: serde::Deserialize::deserialize(&{declaration}).expect(\"generated MCP tool\"), model: {:?}.into() }}",
                    format!("{id}#blake3:{digest}")
                ));
            }
            Declaration::LibraryApi(api) => {
                for symbol in &api.symbols {
                    let target = match &symbol.target {
                        CallableTargetDeclaration::Method {
                            name,
                            receiver_type,
                        } => [receiver_type.as_deref(), name.as_deref()]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>()
                            .join("."),
                        CallableTargetDeclaration::Function { name, import_path } => import_path
                            .as_ref()
                            .map(|path| format!("{path}.{name}"))
                            .unwrap_or_else(|| name.clone()),
                        CallableTargetDeclaration::Constructor { receiver_type } => {
                            receiver_type.clone()
                        }
                    };
                    let targets = std::iter::once(&target)
                        .chain(&symbol.aliases)
                        .collect::<Vec<_>>();
                    apis.push(format!("CompiledLibraryApi {{ lang: LifecycleLanguage::{:?}, targets: {targets:?}.map(|value: &str| value.to_owned()).to_vec(), operation: {:?}.into(), model: {:?}.into() }}", api.lang, symbol.operation, format!("{}#blake3:{digest}", api.id)));
                }
            }
        }
    }
    let declaration_model_count = commands.len();
    for (offset, (id, names)) in RUST_COMMAND_MODELS.iter().enumerate() {
        let index = declaration_model_count + offset;
        for name in *names {
            assert!(
                ownership.insert((*name).to_string(), index).is_none(),
                "duplicate command owner: {name}"
            );
        }
        model_set_entries.push((
            (*id).to_string(),
            names.iter().map(|name| (*name).to_string()).collect(),
            None,
        ));
    }
    let registry_digest = format!("blake3:{}", hasher.finalize().to_hex());
    model_set_entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut model_set_hasher = blake3::Hasher::new();
    model_set_hasher.update(b"ei-model-set\0v1\0");
    model_set_hasher.update(b"effinterp/plan/v1");
    model_set_hasher.update(b"\0registry\0");
    model_set_hasher.update(registry_digest.as_bytes());
    model_set_hasher.update(b"\0frontends\0");
    for id in ["go", "java", "js", "php", "python", "ruby", "rust", "ts"] {
        model_set_hasher.update(id.as_bytes());
        model_set_hasher.update(b"\0");
    }
    model_set_hasher.update(b"models\0");
    for (id, names, digest) in &model_set_entries {
        model_set_hasher.update(id.as_bytes());
        model_set_hasher.update(b"\x1f");
        for name in names {
            model_set_hasher.update(name.as_bytes());
            model_set_hasher.update(b"\x1e");
        }
        if let Some(digest) = digest {
            model_set_hasher.update(b"\x1d");
            model_set_hasher.update(digest.as_bytes());
        }
        model_set_hasher.update(b"\0");
    }
    writeln!(
        generated,
        "pub(super) const BUILTIN_MODEL_SET_ID: &str = {:?};",
        format!("builtin:blake3:{}", model_set_hasher.finalize().to_hex())
    )
    .unwrap();
    writeln!(
        generated,
        "pub(super) const BUILTIN_REGISTRY_DIGEST: &str = {registry_digest:?};"
    )
    .unwrap();
    generated.push_str(
        "pub(super) fn generated_builtin_model_index(command: &str) -> Option<usize> {\nmatch command {\n",
    );
    for (name, index) in &ownership {
        writeln!(generated, "{name:?} => Some({index}),").unwrap();
    }
    generated.push_str("_ => None,\n}\n}\n");
    generated.push_str(
        "#[cfg(test)]\npub(super) const GENERATED_BUILTIN_COMMAND_INDEX: &[(&str, usize)] = &[\n",
    );
    for (name, index) in &ownership {
        writeln!(generated, "({name:?}, {index}),").unwrap();
    }
    generated.push_str("];\n");
    writeln!(
        generated,
        "fn generated_lifecycles() -> Vec<FrameworkLifecycle> {{ vec![{}] }}",
        lifecycles.join(",")
    )
    .unwrap();
    writeln!(
        generated,
        "fn generated_command_models() -> Vec<DeclarativeCommandModel> {{ vec![{}] }}",
        commands.join(",")
    )
    .unwrap();
    writeln!(
        generated,
        "fn generated_library_apis() -> Vec<CompiledLibraryApi> {{ vec![{}] }}",
        apis.join(",")
    )
    .unwrap();
    writeln!(
        generated,
        "fn generated_mcp_tools() -> Vec<CompiledMcpTool> {{ vec![{}] }}",
        mcp_tools.join(",")
    )
    .unwrap();
    writeln!(
        generated,
        "fn generated_document_identities() -> Vec<String> {{ {identities:?}.map(|value: &str| value.to_owned()).to_vec() }}"
    )
    .unwrap();
    generated.push_str("#[cfg(test)]\nfn generated_registry() -> CompiledRegistry {\n");
    let metadata = declarations
        .iter()
        .map(|(id, (_, digest))| format!("({id:?}.into(), {digest:?}.into())"))
        .collect::<Vec<_>>()
        .join(",");
    writeln!(generated, "CompiledRegistry {{ command_models: generated_command_models(), library_apis: generated_library_apis(), mcp_tools: generated_mcp_tools(), lifecycles: generated_lifecycles(), declaration_digests: BTreeMap::from([{metadata}]), document_identities: generated_document_identities(), model_set_digest: BUILTIN_REGISTRY_DIGEST.into() }}\n}}").unwrap();
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("promoted_models.rs");
    std::fs::write(output, generated).unwrap();
}
