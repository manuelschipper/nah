mod support;

use nah_actions::finalize;
use nah_proto::action::EffectKind;
use support::{bash_plan, observe};

fn deletes_repository(source: &str) -> bool {
    let plan = bash_plan(source);
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    stream.effects().iter().any(|effect| {
        matches!(effect.kind(), EffectKind::Git { operation }
            if operation.as_str() == "git-remote-delete")
    })
}

#[test]
fn repository_delete_commands_cover_current_explicit_and_confirmed_targets() {
    for source in [
        "gh repo delete",
        "gh repo delete project",
        "gh repo delete owner/project --yes",
        "gh repo delete --confirm github.example.com/owner/project",
        "gh repo delete localhost/owner/project --yes",
        "gh repo delete localhost:9/owner/project --yes",
        "gh repo delete localhost./owner/project --yes",
        "gh repo delete github.example.:443/owner/project --yes",
        "gh repo delete '[::1]/owner/project' --yes",
        "gh repo delete 'bücher.invalid/owner/project' --yes",
        "gh repo delete 'bücher.invalid:9/owner/project' --yes",
        "gh repo delete 'bu\u{308}cher.invalid/owner/project' --yes",
        "gh repo delete 'हिन्दी.invalid/owner/project' --yes",
        "gh repo delete 'শক্তি.invalid/owner/project' --yes",
        "gh repo delete 'தமிழ்.invalid/owner/project' --yes",
        "gh repo delete 'ಕನ್ನಡ.invalid/owner/project' --yes",
        "gh repo delete 'శక్తి.invalid/owner/project' --yes",
        "gh repo delete 'ശക്തി.invalid/owner/project' --yes",
        "gh repo delete 'શક્તિ.invalid/owner/project' --yes",
        "gh repo delete 'ਸ਼ਕਤੀ.invalid/owner/project' --yes",
        "gh repo delete '[::ffff:127.0.0.1]:9/owner/project' --yes",
        "gh repo delete '[fe80::1%25lo]/owner/project' --yes",
        "gh repo delete '[fe80::1%25lo]:9/owner/project' --yes",
        "gh repo delete '[fe80::1%25%6Co]:9/owner/project' --yes",
        "gh repo delete --yes=false owner/project",
        "glab repo delete",
        "glab repo delete project",
        "glab repo delete group/project --yes",
        "glab repo delete -y parent/group/project",
        "glab repo delete -R group/project -y",
        "glab repo delete group/project -yRother/project",
        "glab repo delete --repo=group/project --yes",
        "glab -R parent/group/project repo delete -y",
        "glab -R parent/group/project --help=false repo delete -y",
        "glab project --repo parent/group/project delete --yes",
        "glab project delete group/project",
    ] {
        assert!(deletes_repository(source), "{source}");
    }
}

#[test]
fn confirmation_flags_accept_go_boolean_spellings() {
    for value in [
        "1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False",
    ] {
        for source in [
            format!("gh repo delete owner/project --yes={value}"),
            format!("gh repo delete owner/project --confirm={value}"),
            format!("glab repo delete group/project --yes={value}"),
            format!("glab repo delete group/project -y={value}"),
        ] {
            assert!(deletes_repository(&source), "{source}");
        }
    }
}

#[test]
fn help_boolean_values_preserve_delete_classification() {
    for value in ["0", "f", "F", "FALSE", "false", "False"] {
        for source in [
            format!("gh repo delete owner/project --yes --help={value}"),
            format!("glab repo delete group/project -y --help={value}"),
            format!("glab repo delete group/project -y -h={value}"),
            format!("gh api --help={value} -X DELETE repos/owner/project"),
            format!("glab api --help={value} -X DELETE projects/123"),
            format!("glab api -h={value} -X DELETE projects/123"),
            format!("gh --help={value} repo delete owner/project --yes"),
            format!("glab --help={value} repo delete group/project -y"),
            format!("gh --help={value} api -X DELETE repos/owner/project"),
            format!("glab --help={value} api -X DELETE projects/123"),
            format!("gh repo --help={value} delete owner/project --yes"),
            format!("glab repo --help={value} delete group/project -y"),
            format!("glab project --help={value} delete group/project -y"),
        ] {
            assert!(deletes_repository(&source), "{source}");
        }
    }

    for source in [
        "gh repo delete --help --help=false --yes owner/project",
        "glab repo delete --help -h=0 -y group/project",
        "gh api --help --help=false -X DELETE repos/owner/project",
        "glab api -h --help=False -X DELETE projects/123",
        "gh --help repo delete --help=false --yes owner/project",
        "glab -h api --help=0 -X DELETE projects/123",
        "gh repo --help --help=false delete owner/project --yes",
        "glab project -h --help=0 delete group/project -y",
        "gh --help repo --help=false delete owner/project --yes",
        "glab --help project -h=0 delete group/project -y",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    for value in ["1", "t", "T", "TRUE", "true", "True"] {
        for source in [
            format!("gh repo delete owner/project --yes --help={value}"),
            format!("glab repo delete group/project -y --help={value}"),
            format!("gh api --help={value} -X DELETE repos/owner/project"),
            format!("glab api --help={value} -X DELETE projects/123"),
            format!("gh --help={value} repo delete owner/project --yes"),
            format!("glab --help={value} repo delete group/project -y"),
            format!("gh --help={value} api -X DELETE repos/owner/project"),
            format!("glab --help={value} api -X DELETE projects/123"),
            format!("gh repo --help={value} delete owner/project --yes"),
            format!("glab repo --help={value} delete group/project -y"),
            format!("glab project --help={value} delete group/project -y"),
        ] {
            assert!(!deletes_repository(&source), "{source}");
        }
    }

    for source in [
        "gh repo delete owner/project --yes -h=false",
        "gh api -h=false -X DELETE repos/owner/project",
        "gh repo delete --help=false --help --yes owner/project",
        "glab repo delete -h=0 --help -y group/project",
        "gh api --help=false --help -X DELETE repos/owner/project",
        "glab api --help=False -h -X DELETE projects/123",
        "gh --help=false repo delete --help --yes owner/project",
        "glab -h=0 api --help -X DELETE projects/123",
        "gh repo --help=false --help delete owner/project --yes",
        "glab project -h=0 --help delete group/project -y",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}

#[test]
fn github_api_short_option_forms_preserve_delete_classification() {
    for value in [
        "1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False",
    ] {
        let source = format!("gh api -i={value} -XDELETE repos/owner/project");
        assert!(deletes_repository(&source), "{source}");
    }

    for source in [
        "gh api -iXDELETE repos/owner/project",
        "gh api repos/owner/project -iiX=DELETE",
        "gh api -iX DELETE repos/owner/project",
        "gh api repos/owner/project -iiX delete",
        "gh api -ip corsair -X DELETE repos/owner/project",
        "gh api -iH X-Probe:true -X DELETE repos/owner/project",
        "gh api -ii=false -X DELETE repos/owner/project",
        "gh api -iiiX GET -XDELETE repos/owner/project",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    assert!(!deletes_repository(
        "gh api -XDELETE -iiX GET repos/owner/project"
    ));
}

#[test]
fn gitlab_short_option_clusters_preserve_delete_classification() {
    for source in [
        "glab repo delete group/project -yh=false",
        "glab project delete group/project -yyh=0",
        "glab api -ih=false -X DELETE projects/123",
        "glab api -iXDELETE projects/123",
        "glab api -iiX DELETE projects/123",
        "glab api -iFtrace=true -X DELETE projects/123",
        "glab api -iRother/project -X DELETE projects/123",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    for source in [
        "glab repo delete group/project -yh=true",
        "glab repo delete group/project -hy=false",
        "glab api -ih=true -X DELETE projects/123",
        "glab api -hi=false -X DELETE projects/123",
        "glab api -iXDELETE -iiX GET projects/123",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}

#[test]
fn github_api_paginate_only_allows_delete_when_disabled() {
    for value in ["0", "f", "F", "FALSE", "false", "False"] {
        let source = format!("gh api --paginate={value} -X DELETE repos/owner/project");
        assert!(deletes_repository(&source), "{source}");
    }

    for value in ["1", "t", "T", "TRUE", "true", "True"] {
        let source = format!("gh api --paginate={value} -X DELETE repos/owner/project");
        assert!(!deletes_repository(&source), "{source}");
    }
    assert!(!deletes_repository(
        "gh api --paginate -X DELETE repos/owner/project"
    ));
    assert!(deletes_repository(
        "gh api --paginate --paginate=false -X DELETE repos/owner/project"
    ));
    assert!(!deletes_repository(
        "gh api --paginate=false --paginate -X DELETE repos/owner/project"
    ));
}

#[test]
fn api_preflight_flags_only_allow_delete_when_disabled() {
    for value in ["0", "f", "F", "FALSE", "false", "False"] {
        for source in [
            format!("gh api --slurp={value} -X DELETE repos/owner/project"),
            format!("glab api --paginate={value} -X DELETE projects/123"),
        ] {
            assert!(deletes_repository(&source), "{source}");
        }
    }

    for value in ["1", "t", "T", "TRUE", "true", "True"] {
        for source in [
            format!("gh api --slurp={value} -X DELETE repos/owner/project"),
            format!("glab api --paginate={value} -X DELETE projects/123"),
        ] {
            assert!(!deletes_repository(&source), "{source}");
        }
    }

    for source in [
        "gh api --slurp -X DELETE repos/owner/project",
        "glab api --paginate -X DELETE projects/123",
        "gh api --slurp=false --slurp -X DELETE repos/owner/project",
        "glab api --paginate=false --paginate -X DELETE projects/123",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }

    for source in [
        "gh api --slurp --slurp=false -X DELETE repos/owner/project",
        "glab api --paginate --paginate=false -X DELETE projects/123",
    ] {
        assert!(deletes_repository(source), "{source}");
    }
}

#[test]
fn exact_delete_api_routes_allow_reviewed_options_and_ordering() {
    for source in [
        "gh api repos/owner/project -X DELETE",
        "gh api -Xdelete '/repos/owner/project?archive=false'",
        "gh api --hostname ghe.example --silent --method=DELETE repos/{owner}/{repo}",
        "gh api --hostname bücher.example -X DELETE repos/owner/project",
        "gh api --hostname bu\u{308}cher.example -X DELETE repos/owner/project",
        "gh api --hostname हिन्दी.example -X DELETE repos/owner/project",
        "gh api --hostname শক্তি.example -X DELETE repos/owner/project",
        "gh api --hostname தமிழ்.example -X DELETE repos/owner/project",
        "gh api --hostname ಕನ್ನಡ.example -X DELETE repos/owner/project",
        "gh api --hostname శక్తి.example -X DELETE repos/owner/project",
        "gh api --hostname ശക്തി.example -X DELETE repos/owner/project",
        "gh api --hostname શક્તિ.example -X DELETE repos/owner/project",
        "gh api --hostname ਸ਼ਕਤੀ.example -X DELETE repos/owner/project",
        "glab api --hostname bücher.invalid -X DELETE projects/123",
        "glab api --hostname bu\u{308}cher.invalid -X DELETE projects/123",
        "gh api --hostname ghe.example -X DELETE repos/owner/project -F ref={branch}",
        "gh api --silent=1 --method DELETE repos/owner/project",
        "gh api --silent --silent=false --verbose -X DELETE repos/owner/project",
        "gh api --jq . --silent=false -X DELETE repos/owner/project",
        "gh api --jq= --silent -X DELETE repos/owner/project",
        "gh api --template '' --verbose -X DELETE repos/owner/project",
        "gh api --template '}}' -X DELETE repos/owner/project",
        "gh api --template 'literal }} {{.}}' -X DELETE repos/owner/project",
        "gh api --template '{{range .}}{{break}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{$}}' -X DELETE repos/owner/project",
        "gh api --template '{{$item := .}}{{$item}}' -X DELETE repos/owner/project",
        "gh api --template '{{range $item := .}}{{$item}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | .Field}}' -X DELETE repos/owner/project",
        "gh api --template '{{define \"row\"}}{{.}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{block \"row\" .}}{{.}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{template \"row\" .}}' -X DELETE repos/owner/project",
        r#"gh api --template "{{printf \"%c\" 'a'}}" -X DELETE repos/owner/project"#,
        "gh api --template '{{range $i, $v := .}}{{$v}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{replace \"a\" \"b\" \"a\"}}' -X DELETE repos/owner/project",
        "gh api --template '{{1_000}}' -X DELETE repos/owner/project",
        "gh api --template '{{0x1_f}}' -X DELETE repos/owner/project",
        "gh api --template '{{1e1_0}}' -X DELETE repos/owner/project",
        "gh api --template '{{0b1_0}}' -X DELETE repos/owner/project",
        "gh api --template '{{0o7_7}}' -X DELETE repos/owner/project",
        "gh api --template '{{0x1p2}}' -X DELETE repos/owner/project",
        "gh api --template '{{0x1.fp2}}' -X DELETE repos/owner/project",
        "gh api --template '{{1+2i}}' -X DELETE repos/owner/project",
        "gh api --template '{{.É}}' -X DELETE repos/owner/project",
        "gh api --template '{{$é := .}}{{$é}}' -X DELETE repos/owner/project",
        "gh api -f 'a[]=1' -f 'a[]=2' -X DELETE repos/owner/project",
        "glab api -H X-Probe:true -X DELETE projects/123",
        "glab api -R group/project -X DELETE projects/123",
        "gh api -q '' --silent -X DELETE repos/owner/project",
        "gh api -t '' --verbose -X DELETE repos/owner/project",
        "gh api --jq . --jq= --silent -X DELETE repos/owner/project",
        "gh api --allow-escape-sequences -X DELETE repos/owner/project",
        "gh api --allow-escape-sequences=false -X DELETE repos/owner/project",
        "gh api --method GET -X DELETE repos/owner/project",
        "gh api repos/owner/project --field reason=test --input body.json --method DELETE",
        "gh api -HAccept:application/json -fwhy=test -X=DELETE repos/owner/project",
        "gh api -F audit=true -H X-Probe:true --cache 1s --template '{{.}}' -X DELETE repos/owner/project",
        "gh api --hostname bad/host --hostname ghe.example --template '{{' --template '{{printf \"}}\"}}' -X DELETE repos/owner/project",
        "glab api projects/123 -X DELETE",
        "glab api --method=delete '/projects/group%2Fproject?hard_delete=true'",
        "glab api projects/parent%2Fgroup%2Fproject --hostname gitlab.example --method DELETE",
        "glab api -X DELETE projects/%67itlab-org%2Fcli",
        "glab api -X DELETE projects/gitlab-org%2F%63li",
        "glab api --field audit=true --input body.json -XDELETE projects/:id",
        "glab api --form body=@- -X DELETE projects/123",
        "glab api -F 'data=[\"audit\",true,false,-1.2e3]' -f reason=test -X DELETE projects/123",
        "glab api --silent projects/:fullpath --method DELETE",
        "glab api --method DELETE projects/:namespace%2F:repo",
        "glab api --method DELETE projects/:group%2F:repo",
        "glab api --method DELETE projects/:user%2F:repo",
        "glab api --method DELETE projects/:username%2F:repo",
        "glab api --method DELETE projects/:namespace/:repo",
        "glab api --method DELETE projects/:group/:namespace/:repo",
        "glab api -X DELETE 'projects/123#anything'",
        "gh api -X DELETE 'repos/owner/project#'",
        "gh api -X DELETE 'repos/owner/project#/issues'",
        "gh api -X DELETE repos/%63li/%63li",
        "glab api -X DELETE projects/%32%37%38%39%36%34",
    ] {
        assert!(deletes_repository(source), "{source}");
    }
}

#[test]
fn gitlab_api_form_conflicts_delegate_before_delete() {
    for source in [
        "glab api --form a=b --field c=d -X DELETE projects/123",
        "glab api --field=a=b --form=c=d -X DELETE projects/123",
        "glab api --form a=b -F c=d -X DELETE projects/123",
        "glab api --form a=b --raw-field c=d -X DELETE projects/123",
        "glab api --form a=b -fc=d -X DELETE projects/123",
        "glab api --form a=b --input body.json -X DELETE projects/123",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }

    for source in [
        "glab api --form a=b -X DELETE projects/123",
        "glab api --field a=b --input body.json -X DELETE projects/123",
    ] {
        assert!(deletes_repository(source), "{source}");
    }
}

#[test]
fn gitlab_api_output_requires_a_supported_format() {
    for source in [
        "glab api --output json -X DELETE projects/123",
        "glab api --output=ndjson -X DELETE projects/123",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    for source in [
        "glab api --output yaml -X DELETE projects/123",
        "glab api --output=xml -X DELETE projects/123",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}

#[test]
fn invalid_api_values_and_preflight_conflicts_delegate_before_delete() {
    for source in [
        "glab api --paginate=false --input /dev/null -X DELETE projects/123",
        "glab api --form first=@- --form second=@- -X DELETE projects/123",
        "glab api --hostname bad/host -X DELETE projects/123",
        "gh api --hostname bad/host -X DELETE repos/owner/project",
        "gh api --hostname 'bad#host' -X DELETE repos/owner/project",
        "gh api --hostname 'bad?host' -X DELETE repos/owner/project",
        "gh api --hostname 'bad host' -X DELETE repos/owner/project",
        "gh api --hostname 'local%2Fhost' -X DELETE repos/owner/project",
        "gh api --hostname '\\localhost' -X DELETE repos/owner/project",
        "gh api --hostname ghe.example --hostname 'bad#host' -X DELETE repos/owner/project",
        "gh api -f invalid -X DELETE repos/owner/project",
        "gh api --raw-field invalid -X DELETE repos/owner/project",
        "gh api -F invalid -X DELETE repos/owner/project",
        "gh api --field invalid -X DELETE repos/owner/project",
        "gh api -H invalid -X DELETE repos/owner/project",
        "gh api --header invalid -X DELETE repos/owner/project",
        "gh api --header ': value' -X DELETE repos/owner/project",
        "gh api --header 'bad name: value' -X DELETE repos/owner/project",
        "gh api --cache invalid -X DELETE repos/owner/project",
        "gh api -t '{{' -X DELETE repos/owner/project",
        "gh api --template '{{' -X DELETE repos/owner/project",
        "gh api --template '{{.}}' --template '{{' -X DELETE repos/owner/project",
        "gh api --template '{{break}}' -X DELETE repos/owner/project",
        "gh api --template '{{continue}}' -X DELETE repos/owner/project",
        "gh api --template '{{foo}}' -X DELETE repos/owner/project",
        "gh api --template '{{0xZZ}}' -X DELETE repos/owner/project",
        "gh api --template '{{1__0}}' -X DELETE repos/owner/project",
        "gh api --template '{{1_}}' -X DELETE repos/owner/project",
        "gh api --template '{{1_e2}}' -X DELETE repos/owner/project",
        "gh api --template '{{08}}' -X DELETE repos/owner/project",
        "gh api --template '{{1-}}' -X DELETE repos/owner/project",
        "gh api --template '{{if (}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{$missing}}' -X DELETE repos/owner/project",
        "gh api --template '{{range $item := .}}{{end}}{{$item}}' -X DELETE repos/owner/project",
        "gh api --template '{{| .}}' -X DELETE repos/owner/project",
        "gh api --template '{{if |}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{range |}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | .}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | true}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | \"value\"}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | 1}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | nil}}' -X DELETE repos/owner/project",
        "gh api --template '{{. | | printf}}' -X DELETE repos/owner/project",
        "gh api --template '{{()}}' -X DELETE repos/owner/project",
        "gh api --template '{{define .}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{block . .}}{{end}}' -X DELETE repos/owner/project",
        "gh api --template '{{template .}}' -X DELETE repos/owner/project",
        "gh api --template '{{\"\\x\"}}' -X DELETE repos/owner/project",
        "gh api --template '{{\"\\q\"}}' -X DELETE repos/owner/project",
        "gh api --template '{{\"\\uZZZZ\"}}' -X DELETE repos/owner/project",
        "gh api --template '{{template \"row\" |}}' -X DELETE repos/owner/project",
        r#"gh api --template "{{printf \"%c\" 'ab'}}" -X DELETE repos/owner/project"#,
        "gh api --template '{{range $i, := .}}{{end}}' -X DELETE repos/owner/project",
        "glab api -F 'data={' -X DELETE projects/123",
        "glab api -F 'data={bad}' -X DELETE projects/123",
        "glab api -F 'data=[1,]' -X DELETE projects/123",
        "glab api -f missingequals -X DELETE projects/123",
        "glab api -H invalid -X DELETE projects/123",
        "glab api --header invalid -X DELETE projects/123",
        "glab api -H 'bad name:value' -X DELETE projects/123",
        "glab api -H 'Bad@Name:value' -X DELETE projects/123",
        "glab api -H 'Content-Length:nope' -X DELETE projects/123",
        "gh api -f a=1 -f a=2 -X DELETE repos/owner/project",
        "gh api -f a=1 -F a=2 -X DELETE repos/owner/project",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}

#[test]
fn gitlab_typed_fields_require_valid_delete_query_values() {
    for source in [
        "glab api -F 'data=[\"item\",true,false,-1.2e3]' -X DELETE projects/123",
        "glab api --field 'data=[\"line\\n\",\"\\u0041\"]' -X DELETE projects/123",
        "glab api --field 'data=[]' -X DELETE projects/123",
        "glab api -f 'data={\"audit\":true}' -X DELETE projects/123",
        "glab api -F 'data={\"audit\":true}' -F data=1 -X DELETE projects/123",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    for source in [
        "glab api -F 'data={\"audit\":true}' -X DELETE projects/123",
        "glab api -F 'data=[null]' -X DELETE projects/123",
        "glab api -F 'data=[{\"item\":1}]' -X DELETE projects/123",
        "glab api -F 'data=[[1]]' -X DELETE projects/123",
        "glab api -F data=1 -F 'data={\"audit\":true}' -X DELETE projects/123",
        "glab api -F 'data={\"audit\":true}' -f data=1 -X DELETE projects/123",
        "glab api -F 'data={\"item\":1} trailing' -X DELETE projects/123",
        "glab api -F 'data=[01]' -X DELETE projects/123",
        "glab api -F 'data=[1.]' -X DELETE projects/123",
        "glab api -F 'data=[\"\\x\"]' -X DELETE projects/123",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}

#[test]
fn wrappers_and_reviewed_executable_paths_retain_remote_delete_identity() {
    for source in [
        "sudo gh repo delete owner/project --yes",
        "env glab repo delete group/project -y",
        "timeout 5 gh api -X DELETE repos/owner/project",
        "command /usr/bin/gh repo delete owner/project",
        "/bin/glab api projects/123 --method DELETE",
        "/usr//bin/gh repo delete owner/project --yes",
        "/usr/bin/./gh repo delete owner/project --yes",
        "/usr/bin/../bin/gh api -X DELETE repos/owner/project",
        "/../../usr/bin/gh repo delete owner/project --yes",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    for source in [
        "/tmp/gh repo delete owner/project --yes",
        "./glab repo delete group/project -y",
        "/usr/local/bin/gh api -X DELETE repos/owner/project",
        "/tmp/probe/usr/bin/../../../../usr/bin/gh repo delete owner/project --yes",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}

#[test]
fn adjacent_or_unresolved_operations_do_not_claim_repository_deletion() {
    for source in [
        "gh repo archive owner/project --yes",
        "gh repo rename replacement",
        "gh repo delete owner/project extra",
        "gh repo delete host/owner/project/extra",
        "gh repo delete -host/owner/project --yes",
        "gh repo delete host-/owner/project --yes",
        "gh repo delete host_name/owner/project --yes",
        "gh repo delete localhost../owner/project --yes",
        "gh repo delete localhost:/owner/project --yes",
        "gh repo delete localhost:invalid/owner/project --yes",
        "gh repo delete localhost:65536/owner/project --yes",
        "gh repo delete 'bücher.invalid:/owner/project' --yes",
        "gh repo delete 'bücher.invalid:65536/owner/project' --yes",
        "gh repo delete '[::gg]/owner/project' --yes",
        "gh repo delete '[::ffff:127.0.0.999]/owner/project' --yes",
        "gh repo delete '[::1]extra/owner/project' --yes",
        "gh repo delete '[fe80::1%lo]:9/owner/project' --yes",
        "gh repo delete '[fe80::1%25]:9/owner/project' --yes",
        "gh repo delete '[fe80::1%25lo!]:9/owner/project' --yes",
        "gh repo delete '[fe80::1%25%21]:9/owner/project' --yes",
        "gh repo delete '\u{308}invalid/owner/project' --yes",
        "gh repo delete '\u{94d}invalid/owner/project' --yes",
        "gh repo delete '\u{9cd}invalid/owner/project' --yes",
        "gh repo delete '\u{bcd}invalid/owner/project' --yes",
        "gh repo delete '\u{ccd}invalid/owner/project' --yes",
        "gh repo delete https://github.com/owner/project",
        "gh repo delete \"$REPOSITORY\" --yes",
        "gh repo delete owner/project --unknown",
        "gh repo delete owner/project --yes=maybe",
        "gh repo delete --help owner/project",
        "glab repo archive group/project",
        "glab repo transfer group/project other",
        "glab repo delete https://gitlab.com/group/project",
        "glab repo delete \"$PROJECT\" -y",
        "glab repo delete group/project --force",
        "glab repo delete group/project -y=on",
        "glab repo delete -R https://gitlab.com/group/project -y",
        "glab repo delete -R \"$PROJECT\" -y",
        "gh api -X GET repos/owner/project",
        "gh api repos/owner/project",
        "gh api -f x=y repos/owner/project",
        "gh api -X DELETE repos/owner/project/issues",
        "gh api -X DELETE repos/owner/project/",
        "gh api -X DELETE repos/owner%2Fproject/repository",
        "gh api -X DELETE repos/%2E/%2E%2E",
        "gh api -X DELETE graphql",
        "gh api -X DELETE https://api.github.com/repos/owner/project",
        "gh api -X DELETE \"$ENDPOINT\"",
        "gh api -X DELETE repos/owner/project --unknown",
        "gh api --silent=maybe -X DELETE repos/owner/project",
        "gh api --header * -X DELETE repos/owner/project",
        "glab api --input *.json -X DELETE projects/123",
        "gh api --silent --verbose -X DELETE repos/owner/project",
        "gh api --jq . --template '{{.}}' -X DELETE repos/owner/project",
        "gh api --jq= --jq . --silent -X DELETE repos/owner/project",
        "gh api --template '' --template '{{.}}' --verbose -X DELETE repos/owner/project",
        "gh api -zXDELETE repos/owner/project",
        "gh api -X",
        "gh api -iX",
        "gh api --hostname",
        "gh api --method DELETE --method GET repos/owner/project",
        "glab api -X POST projects/123",
        "glab api projects/123",
        "glab api -X DELETE projects/group/project",
        "glab api -X DELETE projects/group",
        "glab api -X DELETE projects/%63li",
        "glab api -X DELETE projects/%2E%2E",
        "glab api -X DELETE projects/group%2Fproject/issues",
        "glab api -X DELETE projects/group%2F%2E%2E",
        "glab api -X DELETE projects/group%2Fpro%GGject",
        "glab api -X DELETE projects/group%2Fproject%2F",
        "glab api -X DELETE projects/:owner/:repo",
        "glab api -X DELETE projects/:owner%2F:repo",
        "glab api -X DELETE projects/:account%2F:repo",
        "glab api -X DELETE projects/:group/:namespace/:repo/issues",
        "glab api -X DELETE graphql",
        "glab api -X DELETE https://gitlab.com/api/v4/projects/123",
        "glab api -X DELETE \"$ENDPOINT\"",
        "glab api --method",
        "curl -X DELETE https://api.github.com/repos/owner/project",
        "git push origin --delete old",
        "git push origin :old",
    ] {
        assert!(!deletes_repository(source), "{source}");
    }
}
