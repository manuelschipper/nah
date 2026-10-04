//! Filesystem/network/environment builtin coverage for the PHP frontend.

use effinterp_engine::Engine;
use effinterp_proto::{Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan};

fn php(code: &str) -> Plan {
    let plan = Engine::new()
        .analyze(&Subject::Source {
            dialect: None,
            language: "php".to_string(),
            source: code.to_string(),
            cwd: Some("/w".to_string()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|e| panic!("invalid plan: {e:?}"));
    plan
}

fn find<'a>(plan: &'a Plan, op: &str) -> &'a effinterp_proto::Effect {
    plan.effects
        .iter()
        .find(|e| e.operation.0 == op)
        .unwrap_or_else(|| panic!("no {op} effect in {:?}", plan.effects))
}

fn fs_path(e: &effinterp_proto::Effect) -> &str {
    match &e.resource {
        ResourceExpr::Concrete {
            identity: ResourceIdentity::FsPath { path },
        } => path,
        other => panic!("not a concrete fs path: {other:?}"),
    }
}

#[test]
fn file_get_contents_path_is_a_read() {
    let plan = php("<?php file_get_contents(\"/path/VERSION\");");
    let e = find(&plan, "filesystem.read");
    assert_eq!(fs_path(e), "/path/VERSION");
    // A content read is not a metadata probe.
    assert!(!e.attributes.contains_key("metadata"));
}

/// Stat-flavored probes (file_exists/filemtime/...) are metadata reads
/// carrying the fsutils `metadata` attribute.
#[test]
fn file_exists_is_a_metadata_read() {
    let plan = php("<?php file_exists(\"/etc/app.conf\");");
    let e = find(&plan, "filesystem.read");
    assert_eq!(fs_path(e), "/etc/app.conf");
    assert_eq!(
        e.attributes.get("metadata"),
        Some(&effinterp_proto::AttrValue::Bool(true))
    );
}

#[test]
fn getenv_is_an_environment_read() {
    let plan = php("<?php getenv(\"HOME\");");
    let e = find(&plan, "environment.read");
    assert!(matches!(
        &e.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "HOME"
    ));

    let empty = php("<?php getenv(\"\");");
    assert!(matches!(
        &find(&empty, "environment.read").resource,
        ResourceExpr::Unresolved { family } if family.0 == "environment"
    ));
}

#[test]
fn file_put_contents_is_a_write() {
    let plan = php("<?php file_put_contents(\"/x\", $d);");
    let e = find(&plan, "filesystem.write");
    assert_eq!(fs_path(e), "/x");
}

#[test]
fn unlink_is_a_delete() {
    let plan = php("<?php unlink($p);");
    assert_eq!(
        find(&plan, "filesystem.delete").operation.0,
        "filesystem.delete"
    );
}

#[test]
fn local_path_values_and_producers_flow_to_filesystem_sinks() {
    let plan = php(r#"<?php
$root = '/srv/app';
$file = $root . '/var/cache/routes.php';
unlink($file);
$path = '/a';
$path .= '/b';
unlink($path);
$dir = __DIR__ . '/../var';
unlink($dir);
$formatted = sprintf('%s/cache/%s', '/srv', 'k');
unlink($formatted);
$home = getenv('HOME');
unlink($home . '/.aws/credentials');"#);
    for path in [
        "/srv/app/var/cache/routes.php",
        "/a/b",
        "/var",
        "/srv/cache/k",
    ] {
        assert!(
            plan.effects.iter().any(|effect| fs_path(effect) == path),
            "missing {path}: {:?}",
            plan.effects
        );
    }
    assert!(plan.effects.iter().any(|effect| {
        effect.operation.0 == "filesystem.delete"
            && matches!(
                &effect.resource,
                ResourceExpr::Join { parts }
                    if matches!(parts.as_slice(), [ResourceExpr::Literal { value }, ResourceExpr::Environment { name }, ..] if value.is_empty() && name == "HOME")
            )
    }));
}

#[test]
fn relative_local_components_are_anchored_only_after_composition() {
    let plan = php(r#"<?php
$name = 'sessions';
unlink('/var/lib/' . $name . '/lock');
$n = 'c';
unlink("/var/$n");
$a = 'x';
$b = 'y';
unlink("var/$a/$b");
$dir = 'cache';
$file = '/srv/app/' . $dir . '/x';
unlink($file);"#);
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(fs_path)
        .collect();
    assert_eq!(
        paths,
        [
            "/var/lib/sessions/lock",
            "/var/c",
            "/w/var/x/y",
            "/srv/app/cache/x",
        ]
    );
}

#[test]
fn textual_concatenation_does_not_insert_path_separators() {
    let plan = php(r#"<?php
$n = 'abc';
unlink("/tmp/pre{$n}post.txt");
unlink('/tmp/pre' . $n . 'post.txt');
$path = '/tmp/x';
$path .= '.log';
unlink($path);
$name = 'app';
unlink(sprintf('/var/log/%s.log', $name));
unlink('/tmp/' . 'ab' . '.txt');"#);
    let paths: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "filesystem.delete")
        .map(fs_path)
        .collect();
    assert_eq!(
        paths,
        [
            "/tmp/preabcpost.txt",
            "/tmp/preabcpost.txt",
            "/tmp/x.log",
            "/var/log/app.log",
            "/tmp/ab.txt",
        ]
    );
}

#[test]
fn poisoned_php_locals_emit_one_dynamic_boundary_at_the_sink() {
    let plan = php("<?php $path = '/a'; if ($flag) { $path = '/b'; } unlink($path);");
    assert!(matches!(
        &find(&plan, "filesystem.delete").resource,
        ResourceExpr::Unresolved { family } if family.0 == "filesystem"
    ));
    assert_eq!(
        plan.boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );

    let unsupported = php("<?php $path = sprintf('%05d', $n); unlink($path);");
    assert_eq!(
        unsupported
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );

    let global = php("<?php function wipe() { $p = '/a'; global $p; unlink($p); } wipe();");
    assert_eq!(
        global
            .boundaries
            .iter()
            .filter(|boundary| boundary.reason.as_str() == "unmodeled_dynamic")
            .count(),
        1
    );
}

#[test]
fn fread_is_a_read() {
    let plan = php("<?php $fp = fopen(\"/x\", \"r\"); fread($fp, 100);");
    // Two reads: fopen("r") and fread on the (unresolved) handle.
    let reads: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "filesystem.read")
        .collect();
    assert_eq!(reads.len(), 2, "{:?}", plan.effects);
}

#[test]
fn fwrite_is_a_write() {
    let plan = php("<?php fwrite($fp, \"data\");");
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.write"),
        "{:?}",
        plan.effects
    );
}

#[test]
fn touch_is_a_write() {
    let plan = php("<?php touch(\"/x\");");
    let e = find(&plan, "filesystem.write");
    assert_eq!(fs_path(e), "/x");
}

#[test]
fn glob_uses_a_pattern_resource() {
    let plan = php("<?php glob(\"/tmp/*.txt\");");
    let e = find(&plan, "filesystem.read");
    assert!(matches!(
        &e.resource,
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/tmp/*.txt"
    ));
    let plan = php("<?php glob(\"*.txt\");");
    assert!(matches!(&find(&plan, "filesystem.read").resource,
        ResourceExpr::Pattern { pattern: effinterp_proto::ResourcePattern::FsPath { glob: pattern, .. } } if pattern == "/w/*.txt"));
}

#[test]
fn scandir_is_a_read() {
    let plan = php("<?php scandir(\"/tmp\");");
    let e = find(&plan, "filesystem.read");
    assert_eq!(fs_path(e), "/tmp");
}

#[test]
fn file_get_contents_url_is_network_not_filesystem() {
    let plan = php("<?php file_get_contents(\"http://example.com/x\");");
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "network.request"),
        "{:?}",
        plan.effects
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0.starts_with("filesystem"))
    );
}

#[test]
fn url_stream_builtins_are_network_not_filesystem_sources() {
    for source in [
        "<?php fopen(\"https://example.com/feed.xml\", \"r\");",
        "<?php file(\"https://example.com/feed.xml\");",
        "<?php readfile(\"https://example.com/feed.xml\");",
        "<?php copy(\"https://example.com/a.tgz\", \"/tmp/a.tgz\");",
    ] {
        let plan = php(source);
        assert!(
            plan.effects.iter().any(|effect| matches!(
                &effect.resource,
                ResourceExpr::Concrete {
                    identity: ResourceIdentity::NetworkEndpoint { host, .. },
                } if effect.operation.0 == "network.request" && host == "example.com"
            )),
            "{source}: {:?}",
            plan.effects
        );
        assert!(
            plan.effects
                .iter()
                .all(|effect| effect.operation.0 != "filesystem.read"),
            "{source}: {:?}",
            plan.effects
        );
    }

    let interpolated = php("<?php file_get_contents(\"https://{$host}/health\");");
    assert!(matches!(
        &find(&interpolated, "network.request").resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));

    let dynamic_path = php("<?php file_get_contents(\"https://example.com/{$path}\");");
    assert!(matches!(
        &find(&dynamic_path, "network.request").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. },
        } if host == "example.com"
    ));
}

#[test]
fn fgets_does_not_read_the_handle_as_a_path() {
    let body = r#"$h = fopen('/var/log/app.log', 'r');
while (($line = fgets($h)) !== false) { echo $line; }
fclose($h);"#;
    for source in [
        format!("<?php {body}"),
        format!("<?php function read_log() {{ {body} }} read_log();"),
    ] {
        let plan = php(&source);
        assert_eq!(plan.effects.len(), 1, "{:?}", plan.effects);
        assert_eq!(fs_path(find(&plan, "filesystem.read")), "/var/log/app.log");
        assert!(
            plan.boundaries
                .iter()
                .all(|boundary| { boundary.reason.as_str() != "unmodeled_dynamic" }),
            "{:?}",
            plan.boundaries
        );
    }
}

#[test]
fn socket_handle_io_is_covered_by_the_connection() {
    let plan = php(
        "<?php $s = stream_socket_client('tcp://10.0.0.5:6379'); fwrite($s, 'FLUSHALL'); fgets($s);",
    );
    let requests: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "network.request")
        .collect();
    assert_eq!(requests.len(), 1, "{:?}", plan.effects);
    assert!(matches!(
        &requests[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, port, .. },
        } if host == "10.0.0.5" && *port == Some(6379)
    ));
    assert!(
        plan.effects
            .iter()
            .all(|effect| !effect.operation.0.starts_with("filesystem.")),
        "{:?}",
        plan.effects
    );
}

#[test]
fn curl_exec_is_a_network_request() {
    let plan = php(
        "<?php $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, \"http://x.test/a\"); curl_exec($ch);",
    );
    let requests: Vec<_> = plan
        .effects
        .iter()
        .filter(|e| e.operation.0 == "network.request")
        .collect();
    assert_eq!(requests.len(), 1, "{:?}", plan.effects);
    assert!(
        requests.iter().any(|e| matches!(
            &e.resource,
            ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "x.test"
        )),
        "{:?}",
        requests
    );
}

#[test]
fn curl_init_url_is_emitted_once_at_exec() {
    let plan = php("<?php $ch = curl_init(\"http://x.test/a\"); curl_exec($ch);");
    assert_eq!(
        plan.effects
            .iter()
            .filter(|effect| effect.operation.0 == "network.request")
            .count(),
        1,
        "{:?}",
        plan.effects
    );
    let e = find(&plan, "network.request");
    assert!(matches!(
        &e.resource,
        ResourceExpr::Concrete { identity: ResourceIdentity::NetworkEndpoint { host, .. } } if host == "x.test"
    ));
}

#[test]
fn backtick_nests_a_shell_command() {
    let plan = php("<?php `rm -rf /tmp/x`;");
    assert!(
        plan.effects.iter().any(|e| e.operation.0 == "process.exec"),
        "{:?}",
        plan.effects
    );
    assert!(
        plan.effects
            .iter()
            .any(|e| e.operation.0 == "filesystem.delete"),
        "{:?}",
        plan.effects
    );
}

#[test]
fn env_superglobal_read_is_an_environment_read() {
    let plan = php("<?php $x = $_ENV['HOME'];");
    let e = find(&plan, "environment.read");
    assert!(matches!(
        &e.resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name }
        } if name == "HOME"
    ));
}

#[test]
fn server_superglobal_write_is_not_a_read() {
    let plan = php("<?php $_SERVER['HTTP_USER_AGENT'] = 'x';");
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| e.operation.0 == "environment.read"),
        "an assignment target must not be reported as a read: {:?}",
        plan.effects
    );
}

#[test]
fn server_request_metadata_is_not_an_environment_read() {
    let plan = php("<?php $referer = $_SERVER['HTTP_REFERER']; $home = $_SERVER['HOME'];");
    let reads: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.0 == "environment.read")
        .collect();
    assert_eq!(reads.len(), 1, "{:?}", plan.effects);
    assert!(matches!(
        &reads[0].resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        } if name == "HOME"
    ));
}

#[test]
fn chmod_is_a_permission_change() {
    let plan = php("<?php chmod(\"/usr/local/bin/tool\", 0);");
    let e = find(&plan, "filesystem.metadata");
    assert_eq!(fs_path(e), "/usr/local/bin/tool");
    assert_eq!(
        e.attributes.get("action"),
        Some(&effinterp_proto::AttrValue::String("chmod".into()))
    );
}

#[test]
fn getenv_paths_take_the_host_environment_value() {
    let php_with_home = |code: &str| {
        let plan = Engine::new()
            .analyze(&Subject::Exec {
                argv: vec!["php".into(), "-r".into(), code.into()],
                cwd: Some("/w".into()),
                context: effinterp_proto::HostContext {
                    env: [("HOME".into(), "/home/test".into())].into(),
                    ..Default::default()
                },
            })
            .unwrap();
        validate_plan(&plan).unwrap();
        plan
    };
    let plan = php_with_home(r#"unlink(getenv("HOME")."/.nah/trust.json");"#);
    assert_eq!(
        fs_path(find(&plan, "filesystem.delete")),
        "/home/test/.nah/trust.json"
    );
    // After the program writes the environment, the host value is stale.
    let plan = php_with_home(r#"putenv("HOME=/tmp"); unlink(getenv("HOME")."/.nah/trust.json");"#);
    assert!(!matches!(
        find(&plan, "filesystem.delete").resource,
        ResourceExpr::Concrete { .. }
    ));
}
