mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
use support::{bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn destroys_whole_stack(source: &str) -> bool {
    stream(source).effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation }
                if operation == &SemanticCode::INFRA_IAC_DESTROY
        )
    })
}

#[test]
fn terraform_and_tofu_whole_stack_destroy_forms_are_recognized() {
    for source in [
        "terraform destroy",
        "tofu destroy -auto-approve",
        "terraform apply -destroy",
        "terraform apply --destroy --auto-approve",
        "terraform destroy --auto-approve",
        "tofu apply --destroy --auto-approve",
        "tofu apply -destroy=true -auto-approve=true",
        "terraform -chdir=environments/dev destroy -input=false",
        "tofu -chdir=environments/dev apply -destroy -lock-timeout 30s",
        "terraform destroy -parallelism=4 -var region=local -var-file=dev.tfvars",
        "terraform destroy -parallelism 4",
        "terraform destroy -parallelism=0x4",
        "tofu destroy -parallelism=0x_4",
        "terraform destroy -lock-timeout=1h30m",
        "terraform destroy -destroy=false",
        "tofu destroy -destroy -destroy=false",
        "terraform destroy -no-color -compact-warnings",
        "terraform destroy -minimal-refresh -policies=policy.hcl",
        "terraform destroy -allow-deferral=false",
        "terraform destroy -allow-deferral -allow-deferral=false",
        "terraform apply -refresh-only -refresh-only=false -destroy",
        "tofu destroy -show-sensitive -deprecation=module:none",
        "tofu destroy -concise -consolidate-errors -consolidate-warnings=false",
        "tofu destroy -suppress-forget-errors -json-into=out.json -json -json=false",
        "tofu apply -destroy -lint=all",
        "terraform destroy --",
        "tofu apply -destroy --",
        "/bin/terraform destroy",
        "/sbin/tofu apply -destroy",
        "/usr/bin/terraform destroy",
        "/usr/sbin/tofu destroy",
        "PATH=/tmp /usr/bin/terraform destroy",
    ] {
        assert!(destroys_whole_stack(source), "{source}");
    }
}

#[test]
fn visible_terraform_cli_argument_assignments_are_folded() {
    for source in [
        "TF_CLI_ARGS='-auto-approve -lock=false' terraform destroy",
        "TF_CLI_ARGS_destroy='-parallelism=2' tofu destroy",
        "TF_CLI_ARGS_apply='-destroy -auto-approve' terraform apply",
        "TF_CLI_ARGS_apply='--destroy --auto-approve' terraform apply",
        "TF_CLI_ARGS_destroy='--auto-approve' terraform destroy",
        "TF_CLI_ARGS_apply='--destroy --auto-approve' tofu apply",
        "TF_CLI_ARGS='-destroy' TF_CLI_ARGS_apply='-lock-timeout 5s' tofu apply",
        "TF_CLI_ARGS_apply='-refresh-only' terraform apply -refresh-only=false -destroy",
        "TF_CLI_ARGS='-destroy' TF_CLI_ARGS_apply='-destroy=false' terraform apply",
        "TF_CLI_ARGS=';' terraform destroy",
        "TF_CLI_ARGS='2>/tmp/log' terraform destroy",
        "TF_CLI_ARGS='2foo>/tmp/log' terraform destroy",
        "TF_CLI_ARGS='\"2\">/tmp/log' terraform destroy",
        "TF_CLI_ARGS_destroy='-backup `foo bar`' terraform destroy",
        "TF_CLI_ARGS_destroy='-backup=))' terraform destroy",
        "TF_CLI_ARGS_destroy='-auto-approve' sudo terraform destroy",
        "env TF_CLI_ARGS_apply=-destroy terraform apply",
    ] {
        assert!(destroys_whole_stack(source), "{source}");
    }

    for source in [
        "TF_CLI_ARGS=-target=module.web terraform destroy",
        "TF_CLI_ARGS_destroy='-target module.web' tofu destroy",
        "TF_CLI_ARGS_apply='-destroy -exclude module.keep' tofu apply",
        "TF_CLI_ARGS_destroy='-tar\"\"get module.web' terraform destroy",
        "TF_CLI_ARGS_destroy=\"$ARGS\" terraform destroy",
        "TF_CLI_ARGS_destroy='-var foo(bar)' terraform destroy",
        "TF_CLI_ARGS='-destroy=false' TF_CLI_ARGS_apply='-destroy' terraform apply",
        "TF_CLI_ARGS_destroy='-var -v' terraform destroy",
        "TF_CLI_ARGS='-backup --version' terraform destroy",
        "TF_CLI_ARGS_apply='-var -v -destroy' terraform apply",
        "TF_CLI_ARGS='2</tmp/log' terraform destroy",
        "TF_CLI_ARGS='foo>/tmp/log' terraform destroy",
        "export TF_CLI_ARGS=-target=module.web; terraform destroy",
    ] {
        assert!(!destroys_whole_stack(source), "{source}");
    }
}

#[test]
fn pulumi_whole_stack_destroy_aliases_and_execution_flags_are_recognized() {
    for source in [
        "pulumi destroy",
        "pulumi down -y -f",
        "pulumi dn --yes --skip-preview",
        "pulumi destroy --stack dev",
        "pulumi destroy -s=dev --remove --run-program",
        "pulumi -v 3 destroy",
        "pulumi --memprofilerate=1 destroy",
        "pulumi -C/repo destroy --parallel=4",
        "pulumi destroy --parallel 4",
        "pulumi destroy -sdev",
        "pulumi destroy -p4",
        "pulumi destroy -mmessage",
        "pulumi destroy -cfoo=bar",
        "pulumi -v3 destroy",
        "pulumi destroy -r=false",
        "pulumi destroy -ry",
        "pulumi destroy -yp4",
        "pulumi destroy -yp 4",
        "pulumi -Qv3 destroy",
        "pulumi -Qv 3 destroy",
        "pulumi -Q=false destroy -y=false",
        "pulumi destroy -ysdev",
        "pulumi destroy -ys dev",
        "pulumi destroy --parallel=0x4",
        "pulumi destroy --parallel=0x_4",
        "pulumi -v0x3 destroy",
        "pulumi destroy --preview-only=false --yes",
        "pulumi destroy --exclude-protected=false --yes",
        "pulumi destroy --preview-only --preview-only=false --yes",
        "pulumi destroy --urns --yes",
        "pulumi destroy --ignore-protect --yes",
        "pulumi destroy --target-dependents --yes",
        "pulumi destroy --target-dependents=false --yes",
        "pulumi destroy --help=false --yes",
        "pulumi destroy --help --help=false --yes",
        "pulumi --version=false destroy",
        "pulumi --version --version=false destroy",
        "pulumi destroy --skip-config-validation --skip-plugin-pre-install",
        "pulumi destroy --output=default",
        "pulumi destroy --copilot",
        "pulumi destroy --otel-traces=file:///tmp/traces.json",
        "pulumi destroy --tracing-header=value",
        "pulumi destroy --exec-kind=auto.inline",
        "pulumi destroy --exec-agent=automation-api",
        "pulumi destroy --client=127.0.0.1:1234",
        "pulumi destroy --override-env=dev=prod",
        "pulumi destroy --override-env dev=prod",
        "timeout 5 pulumi destroy -yf",
        "/bin/pulumi destroy",
        "/usr/bin/pulumi down --yes",
        "PATH=/tmp /usr/bin/pulumi destroy --yes",
    ] {
        assert!(destroys_whole_stack(source), "{source}");
    }
}

#[test]
fn targeted_excluded_preview_saved_plan_and_dynamic_forms_remain_outside() {
    for source in [
        "terraform destroy -target module.web",
        "terraform destroy --target module.web",
        "terraform destroy -target=module.web",
        "tofu apply -destroy -exclude module.keep",
        "tofu apply -destroy -exclude-file=keep.txt",
        "tofu destroy -target-file targets.txt",
        "terraform apply -destroy -replace=aws_instance.web",
        "terraform apply -destroy saved.tfplan",
        "terraform apply",
        "terraform plan -destroy",
        "terraform destroy -help",
        "terraform -version destroy",
        "terraform destroy -unknown-selection=value",
        "terraform destroy -parallelism",
        "terraform destroy -parallelism nope",
        "terraform destroy -parallelism=nope",
        "terraform destroy -parallelism=08",
        "terraform destroy -lock-timeout nope",
        "terraform destroy -no-color=false",
        "tofu destroy -compact-warnings=false",
        "terraform destroy -show-sensitive",
        "terraform destroy -deprecation=all",
        "tofu destroy -deprecation=all",
        "terraform destroy -var foo",
        "tofu destroy -var foo",
        "terraform destroy -var 'name =value'",
        "tofu destroy -var 'name =value'",
        "terraform -chdir environments/dev destroy",
        "tofu -chdir environments/dev apply -destroy",
        "terraform -chdir=one -chdir=two destroy",
        "terraform destroy -parallelism=-1",
        "terraform destroy -destroy=true",
        "terraform destroy -destroy",
        "tofu destroy --destroy=true",
        "tofu destroy --destroy",
        "terraform destroy -minimal-refresh -refresh=false",
        "terraform destroy -allow-deferral",
        "tofu destroy -lint=all",
        "tofu destroy -json --json-into=out.json",
        "terraform destroy -var -v",
        "terraform apply -destroy -- saved.tfplan",
        "terraform apply -refresh-only=false -refresh-only -destroy",
        "terraform \"$COMMAND\"",
        "terraform destroy \"$OPTIONS\"",
        "pulumi destroy --target urn:pulumi:dev::project::type::name",
        "pulumi destroy -turn:pulumi:dev::project::type::name",
        "pulumi destroy --exclude urn:pulumi:dev::project::type::name",
        "pulumi destroy -x=urn:pulumi:dev::project::type::name",
        "pulumi destroy --exclude-protected",
        "pulumi destroy --preview-only",
        "pulumi destroy --stack",
        "pulumi destroy --parallel nope",
        "pulumi destroy --parallel=nope",
        "pulumi destroy --parallel=08",
        "pulumi destroy --parallel=0x__4",
        "pulumi -v nope destroy",
        "pulumi --verbose=nope destroy",
        "pulumi --memprofilerate nope destroy",
        "pulumi destroy --refresh=bogus --yes",
        "pulumi --color=bogus destroy --yes",
        "pulumi destroy --exclude-dependents=false --yes",
        "pulumi destroy --exclude-protected=false --ignore-protect",
        "pulumi destroy --json=false --output=default",
        "pulumi destroy -j=false --output=default",
        "pulumi destroy --remote",
        "pulumi destroy --remote --remote-agent-pool-id pool",
        "pulumi destroy --suppress-stream-logs",
        "pulumi destroy --override-env=dev",
        "pulumi destroy -rtrue",
        "pulumi destroy -rfalse",
        "pulumi destroy --help=false --help --yes",
        "pulumi destroy --version",
        "pulumi destroy --unknown-selection=value",
        "pulumi destroy https://github.com/example/project",
        "pulumi destroy one two",
        "pulumi \"$COMMAND\"",
        "pulumi destroy --stack \"$STACK\"",
        "/tmp/terraform destroy",
        "./tofu apply -destroy",
        "/usr/local/bin/pulumi destroy",
    ] {
        assert!(!destroys_whole_stack(source), "{source}");
    }
}

#[test]
fn visible_path_overrides_do_not_gain_infrastructure_tool_identity() {
    for source in [
        "env PATH=/tmp/bin terraform destroy",
        "env PATH=/tmp/bin pulumi destroy --yes",
        "PATH=/tmp; terraform destroy",
        "export PATH=/tmp; terraform destroy",
        "PATH=/tmp sh -c 'terraform destroy'",
        "PATH=/tmp /usr/bin/timeout 1 terraform destroy",
    ] {
        assert!(!destroys_whole_stack(source), "{source}");
    }

    assert!(destroys_whole_stack(
        "PATH=/tmp; /usr/bin/terraform destroy"
    ));
}

#[test]
fn adjacent_infrastructure_tools_and_subcommands_do_not_gain_destroy_evidence() {
    for source in [
        "terragrunt destroy",
        "cdk destroy stack",
        "cdktf destroy stack",
        "aws cloudformation delete-stack --stack-name dev",
        "terraform workspace delete dev",
        "tofu state rm module.web",
        "pulumi preview",
        "pulumi stack rm dev --yes",
    ] {
        assert!(!destroys_whole_stack(source), "{source}");
    }
}
