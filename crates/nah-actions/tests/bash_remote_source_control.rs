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
        "gh repo delete --yes=false owner/project",
        "glab repo delete",
        "glab repo delete project",
        "glab repo delete group/project --yes",
        "glab repo delete -y parent/group/project",
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
            format!("gh repo delete owner/project --yes -h={value}"),
            format!("glab repo delete group/project -y --help={value}"),
            format!("glab repo delete group/project -y -h={value}"),
            format!("gh api --help={value} -X DELETE repos/owner/project"),
            format!("gh api -h={value} -X DELETE repos/owner/project"),
            format!("glab api --help={value} -X DELETE projects/123"),
            format!("glab api -h={value} -X DELETE projects/123"),
        ] {
            assert!(deletes_repository(&source), "{source}");
        }
    }

    for value in ["1", "t", "T", "TRUE", "true", "True"] {
        for source in [
            format!("gh repo delete owner/project --yes --help={value}"),
            format!("glab repo delete group/project -y --help={value}"),
            format!("gh api --help={value} -X DELETE repos/owner/project"),
            format!("glab api --help={value} -X DELETE projects/123"),
        ] {
            assert!(!deletes_repository(&source), "{source}");
        }
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
        "gh api -iiiX GET -XDELETE repos/owner/project",
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    assert!(!deletes_repository(
        "gh api -XDELETE -iiX GET repos/owner/project"
    ));
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
}

#[test]
fn exact_delete_api_routes_allow_reviewed_options_and_ordering() {
    for source in [
        "gh api repos/owner/project -X DELETE",
        "gh api -Xdelete '/repos/owner/project?archive=false'",
        "gh api --hostname ghe.example --silent --method=DELETE repos/{owner}/{repo}",
        "gh api --silent=1 --method DELETE repos/owner/project",
        "gh api --method GET -X DELETE repos/owner/project",
        "gh api repos/owner/project --field reason=test --input body.json --method DELETE",
        "gh api -HAccept:application/json -fwhy=test -X=DELETE repos/owner/project",
        "glab api projects/123 -X DELETE",
        "glab api --method=delete '/projects/group%2Fproject?hard_delete=true'",
        "glab api projects/parent%2Fgroup%2Fproject --hostname gitlab.example --method DELETE",
        "glab api -X DELETE projects/%67itlab-org%2Fcli",
        "glab api -X DELETE projects/gitlab-org%2F%63li",
        "glab api --field audit=true --input body.json -XDELETE projects/:id",
        "glab api --silent projects/:fullpath --method DELETE",
        "glab api --method DELETE projects/:namespace%2F:repo",
        "glab api --method DELETE projects/:namespace/:repo",
        "glab api --method DELETE projects/:group/:namespace/:repo",
        "glab api -X DELETE 'projects/123#anything'",
        "gh api -X DELETE 'repos/owner/project#'",
        "gh api -X DELETE 'repos/owner/project#/issues'",
    ] {
        assert!(deletes_repository(source), "{source}");
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
    ] {
        assert!(deletes_repository(source), "{source}");
    }

    for source in [
        "/tmp/gh repo delete owner/project --yes",
        "./glab repo delete group/project -y",
        "/usr/local/bin/gh api -X DELETE repos/owner/project",
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
        "gh api -X GET repos/owner/project",
        "gh api repos/owner/project",
        "gh api -f x=y repos/owner/project",
        "gh api -X DELETE repos/owner/project/issues",
        "gh api -X DELETE repos/owner/project/",
        "gh api -X DELETE graphql",
        "gh api -X DELETE https://api.github.com/repos/owner/project",
        "gh api -X DELETE \"$ENDPOINT\"",
        "gh api -X DELETE repos/owner/project --unknown",
        "gh api --silent=maybe -X DELETE repos/owner/project",
        "gh api -zXDELETE repos/owner/project",
        "gh api -X",
        "gh api -iX",
        "gh api --hostname",
        "gh api --method DELETE --method GET repos/owner/project",
        "glab api -X POST projects/123",
        "glab api projects/123",
        "glab api -X DELETE projects/group/project",
        "glab api -X DELETE projects/group",
        "glab api -X DELETE projects/group%2Fproject/issues",
        "glab api -X DELETE projects/group%2F%2E%2E",
        "glab api -X DELETE projects/group%2Fpro%GGject",
        "glab api -X DELETE projects/group%2Fproject%2F",
        "glab api -X DELETE projects/:owner/:repo",
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
