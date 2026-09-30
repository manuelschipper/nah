use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, Effect, Plan, ResourceExpr, ResourceIdentity, Subject, validate_plan,
};

fn analyze(subject: Subject) -> Plan {
    let plan = Engine::new().analyze(&subject).unwrap();
    validate_plan(&plan).unwrap();
    assert!(
        plan.boundaries
            .iter()
            .all(|boundary| boundary.reason.as_str() != "untyped_resource")
    );
    plan
}

fn effect<'a>(plan: &'a Plan, operation: &str) -> &'a Effect {
    let effects: Vec<_> = plan
        .effects
        .iter()
        .filter(|effect| effect.operation.as_str() == operation)
        .collect();
    assert_eq!(effects.len(), 1, "{operation}: {:?}", plan.effects);
    effects[0]
}

fn assert_unresolved_network(subject: Subject) {
    let plan = analyze(subject);
    assert!(matches!(
        &effect(&plan, "network.request").resource,
        ResourceExpr::Unresolved { family } if family.0 == "network"
    ));
}

fn python(source: &str) -> Subject {
    Subject::Source {
        dialect: None,
        language: "python".into(),
        source: source.into(),
        cwd: Some("/w".into()),
        context: Default::default(),
    }
}

fn source(language: &str, source: &str) -> Subject {
    Subject::Source {
        dialect: None,
        language: language.into(),
        source: source.into(),
        cwd: Some("/w".into()),
        context: Default::default(),
    }
}

#[test]
fn python_requests_relative_url_is_unresolved_network() {
    assert_unresolved_network(python("import requests\nrequests.get(\"/api/x\")"));
}

#[test]
fn python_requests_empty_url_is_unresolved_network() {
    assert_unresolved_network(python("import requests\nrequests.get(\"\")"));
}

#[test]
fn python_urlopen_relative_url_is_unresolved_network() {
    assert_unresolved_network(python(
        "from urllib.request import urlopen\nurlopen(\"/x\")",
    ));
}

#[test]
fn python_httpx_client_relative_url_is_unresolved_network() {
    assert_unresolved_network(python(
        "import httpx\nc = httpx.Client(base_url=\"https://api.example.com\")\nc.get(\"/health\")",
    ));
}

#[test]
fn python_unix_socket_path_is_a_unix_network_endpoint() {
    let plan = analyze(python(
        "import socket\ns=socket.socket(socket.AF_UNIX); s.connect(\"/tmp/x.sock\")",
    ));
    assert!(matches!(
        &effect(&plan, "network.request").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint {
                host,
                scheme: Some(scheme),
                port: None,
                path: None,
            },
        } if host == "/tmp/x.sock" && scheme == "unix"
    ));
}

#[test]
fn ruby_net_http_relative_uri_is_unresolved_network() {
    assert_unresolved_network(source(
        "ruby",
        "require \"net/http\"; Net::HTTP.get(URI(\"/x\"))",
    ));
}

#[test]
fn ruby_fileutils_environment_join_preserves_the_environment_value() {
    let plan = analyze(source(
        "ruby",
        "require \"fileutils\"\nFileUtils.rm_rf(File.join(ENV[\"APP_ROOT\"], \"cache\"))",
    ));
    let effect = effect(&plan, "filesystem.delete");
    assert_eq!(
        effect.attributes.get("recursive"),
        Some(&AttrValue::Bool(true))
    );
    assert!(matches!(
        &effect.resource,
        ResourceExpr::Join { parts }
            if parts.len() == 2
                && matches!(&parts[0], ResourceExpr::Environment { name } if name == "APP_ROOT")
                && matches!(
                    &parts[1],
                    ResourceExpr::Concrete {
                        identity: ResourceIdentity::FsPath { path },
                    } if path == "cache"
                )
    ));
}

#[test]
fn ruby_file_exist_environment_value_preserves_both_effect_types() {
    let plan = analyze(source("ruby", "File.exist?(ENV['BUNDLE_GEMFILE'])"));
    assert!(matches!(
        &effect(&plan, "environment.read").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::EnvironmentVariable { name },
        } if name == "BUNDLE_GEMFILE"
    ));
    let filesystem = effect(&plan, "filesystem.read");
    assert!(matches!(
        &filesystem.resource,
        ResourceExpr::Environment { name } if name == "BUNDLE_GEMFILE"
    ));
    assert_eq!(
        filesystem.attributes.get("metadata"),
        Some(&AttrValue::Bool(true))
    );
}

#[test]
fn ruby_open_uri_summary_constant_is_a_network_endpoint() {
    let plan = analyze(source(
        "ruby",
        "require \"open-uri\"\nRELEASE_URL = \"https://e.com/r.tgz\"\ndef fetch(url); URI.open(url) { |io| io.read }; end\nfetch(RELEASE_URL)",
    ));
    assert!(matches!(
        &effect(&plan, "network.request").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::NetworkEndpoint { host, .. }
        } if host == "e.com"
    ));
}

#[test]
fn go_relative_http_url_is_unresolved_network() {
    assert_unresolved_network(source(
        "go",
        "package main\nimport \"net/http\"\nfunc main(){ http.Get(\"/relative\") }",
    ));
}

#[test]
fn rust_git_repository_path_is_a_worktree() {
    let plan = analyze(source(
        "rust",
        "fn main(){ let _ = git2::Repository::open(\"/srv/repo\"); }",
    ));
    assert!(matches!(
        &effect(&plan, "git.read").resource,
        ResourceExpr::Concrete {
            identity: ResourceIdentity::GitRepository {
                worktree: Some(worktree),
                git_dir: None,
                pathspec: None,
            },
        } if matches!(
            worktree.as_ref(),
            ResourceExpr::Concrete {
                identity: ResourceIdentity::FsPath { path },
            } if path == "/srv/repo"
        )
    ));
}
