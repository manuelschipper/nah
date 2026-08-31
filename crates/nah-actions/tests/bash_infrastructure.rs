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
        "tofu apply -destroy=true -auto-approve=true",
        "terraform -chdir=environments/dev destroy -input=false",
        "tofu -chdir environments/dev apply -destroy -lock-timeout 30s",
        "terraform destroy -parallelism=4 -var region=local -var-file=dev.tfvars",
        "/bin/terraform destroy",
        "/sbin/tofu apply -destroy",
        "/usr/bin/terraform destroy",
        "/usr/sbin/tofu destroy",
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
        "TF_CLI_ARGS='-destroy' TF_CLI_ARGS_apply='-lock-timeout 5s' tofu apply",
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
        "pulumi --cwd /repo destroy --parallel=4",
        "pulumi destroy --cwd=/repo --remote --remote-agent-pool-id pool",
        "pulumi destroy https://github.com/example/project",
        "timeout 5 pulumi destroy -yf",
        "/bin/pulumi destroy",
        "/usr/bin/pulumi down --yes",
    ] {
        assert!(destroys_whole_stack(source), "{source}");
    }
}

#[test]
fn targeted_excluded_preview_saved_plan_and_dynamic_forms_remain_outside() {
    for source in [
        "terraform destroy -target module.web",
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
        "terraform \"$COMMAND\"",
        "terraform destroy \"$OPTIONS\"",
        "pulumi destroy --target urn:pulumi:dev::project::type::name",
        "pulumi destroy -turn:pulumi:dev::project::type::name",
        "pulumi destroy --exclude urn:pulumi:dev::project::type::name",
        "pulumi destroy -x=urn:pulumi:dev::project::type::name",
        "pulumi destroy --exclude-protected",
        "pulumi destroy --preview-only",
        "pulumi destroy --stack",
        "pulumi destroy --unknown-selection=value",
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
