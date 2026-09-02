mod support;

use nah_actions::finalize;
use nah_proto::action::{ActionStream, EffectKind, SemanticCode};
use support::{bash_plan, observe};

fn stream(source: &str) -> ActionStream {
    let plan = bash_plan(source);
    finalize(plan.clone(), observe(plan.observation_request(), "echo"))
}

fn destroys_whole_stack(source: &str) -> bool {
    has_system_state(source, &SemanticCode::INFRA_IAC_DESTROY)
}

fn has_system_state(source: &str, expected: &SemanticCode) -> bool {
    stream(source).effects().iter().any(|effect| {
        matches!(
            effect.kind(),
            EffectKind::SystemState { operation }
                if operation == expected
        )
    })
}

fn resets_container_runtime(source: &str) -> bool {
    has_system_state(source, &SemanticCode::INFRA_CONTAINER_RESET)
}

fn deletes_container_volumes(source: &str) -> bool {
    has_system_state(source, &SemanticCode::INFRA_CONTAINER_VOLUME_DELETE)
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
        "TF_CLI_ARGS_destroy='-backup `foo bar`' terraform destroy",
        "TF_CLI_ARGS_destroy='-backup=))' terraform destroy",
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
        "PATH=/tmp command terraform destroy",
        "PATH=/tmp command -- terraform destroy",
        "PATH=/tmp eval 'terraform destroy'",
        "PATH=/tmp time terraform destroy",
    ] {
        assert!(!destroys_whole_stack(source), "{source}");
    }

    for source in [
        "PATH=/tmp; /usr/bin/terraform destroy",
        "command terraform destroy",
        "command -- terraform destroy",
        "PATH=/tmp command -p terraform destroy",
        "eval 'terraform destroy'",
        "time terraform destroy",
    ] {
        assert!(destroys_whole_stack(source), "{source}");
    }
}

#[test]
fn env_clearing_drops_outer_prefix_state_before_wrapped_destroy() {
    for source in [
        "PATH=/tmp /usr/bin/env -i terraform destroy",
        "PATH=/tmp /usr/bin/env --ignore-environment pulumi destroy --yes",
        "PATH=/tmp /usr/bin/env -u PATH tofu apply -destroy",
        "TF_CLI_ARGS=-target=module.web /usr/bin/env -i /usr/bin/terraform destroy",
        "TF_CLI_ARGS_destroy=-target=module.web /usr/bin/env -u TF_CLI_ARGS_destroy /usr/bin/terraform destroy",
        "export TF_CLI_ARGS=-target=module.web; /usr/bin/env -i /usr/bin/terraform destroy",
    ] {
        assert!(destroys_whole_stack(source), "{source}");
    }

    for source in [
        "PATH=/definitely-not-a-real-directory env -i terraform destroy",
        "PATH=/definitely-not-a-real-directory; env -i terraform destroy",
        "PATH=/tmp /usr/bin/env -i PATH=/tmp terraform destroy",
        "TF_CLI_ARGS=-target=module.web /usr/bin/env -i TF_CLI_ARGS=-target=module.web /usr/bin/terraform destroy",
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

#[test]
fn podman_system_reset_is_recognized_independently_of_confirmation() {
    for source in [
        "podman system reset",
        "podman system reset --force",
        "podman system reset --force=false",
        "podman system reset -f=false",
        "printf 'y\\n' | podman system reset",
        "sudo podman system reset -f",
        "timeout 5 podman system reset",
        "env podman system reset",
        "command podman system reset",
        "/bin/podman system reset",
        "/sbin/podman system reset -f",
        "/usr/bin/podman system reset",
        "/usr/sbin/podman system reset",
        "PATH=/tmp /usr/bin/podman system reset",
    ] {
        assert!(resets_container_runtime(source), "{source}");
    }
}

#[test]
fn container_prune_recognizes_only_the_four_broad_volume_forms() {
    for source in [
        "docker volume prune --all",
        "docker volume prune -af",
        "docker volume prune -af=false",
        "docker system prune --volumes",
        "docker system prune --all --volumes --force=false",
        "podman volume prune --all",
        "podman volume prune -fa",
        "podman system prune --volumes",
        "podman system prune --all --build --volumes -f",
        "printf 'y\\n' | docker volume prune --all",
        "sudo podman system prune --volumes",
        "timeout 5 docker system prune --volumes",
        "/bin/docker volume prune --all",
        "/usr/bin/podman system prune --volumes",
    ] {
        assert!(deletes_container_volumes(source), "{source}");
    }
}

#[test]
fn container_connection_options_and_valid_terminators_preserve_classification() {
    for source in [
        "docker --context production volume prune --all",
        "docker -cproduction system prune --volumes",
        "docker -DH=tcp://daemon.example:2376 volume prune -a",
        "docker --host ssh://operator@daemon.example system prune --volumes",
        "docker --tlsverify=false --config=/tmp/docker volume prune --all",
        "podman --connection production system reset",
        "podman -cproduction volume prune --all",
        "podman --url=ssh://operator@host/run/podman.sock system prune --volumes",
        "podman --identity=/tmp/key --remote system reset",
        "podman -rcproduction system reset",
        "docker -- volume prune --all",
        "docker volume prune --all --",
        "podman system reset --",
        "podman volume prune --all --",
        "docker volume --help=false prune --all",
        "podman system reset --help=false",
    ] {
        assert!(
            resets_container_runtime(source) || deletes_container_volumes(source),
            "{source}"
        );
    }
}

#[test]
fn compose_volume_removal_is_recognized_across_entry_points_and_option_positions() {
    for source in [
        "docker compose down -v",
        "podman compose down --volumes",
        "docker-compose rm -v web",
        "podman-compose rm worker --volumes",
        "docker --context production compose --profile app down -v",
        "podman --connection production compose -p demo rm api -v",
        "docker-compose --env-file .env rm -fsv --stop-timeout 30 worker",
        "podman-compose --project-name=demo down --volumes=false -v",
        "docker compose --ansi=never --env-file .env --env-file=.env.local -f compose.yml --file=override.yml --parallel 2 --profile app --profile=worker --progress plain --project-directory . -p demo --project-name=renamed --all-resources --compatibility down --remove-orphans --rmi local --timeout 30 -v",
        "/usr/bin/docker-compose down -v",
    ] {
        assert!(deletes_container_volumes(source), "{source}");
    }
}

#[test]
fn compose_volume_removal_carve_outs_delegate() {
    for source in [
        "docker compose down",
        "podman compose rm app",
        "docker-compose down --volumes=false",
        "podman-compose rm -v --volumes=false app",
        "docker compose --dry-run down -v",
        "podman compose down --dry-run --volumes",
        "docker-compose --help down -v",
        "podman-compose --version rm -v app",
        "docker compose down --help -v",
        "docker compose --unknown value down -v",
        "podman-compose down --unknown -v",
        "docker compose \"$(option)\" down -v",
        "docker compose rm -- -v",
        "PATH=/tmp docker-compose down -v",
    ] {
        assert!(!deletes_container_volumes(source), "{source}");
    }
}

#[test]
fn narrow_filtered_dry_run_dynamic_and_arbitrary_container_forms_stay_outside() {
    for source in [
        "docker volume prune",
        "docker volume prune --all=false",
        "docker volume prune -fa=false",
        "docker system prune",
        "docker system prune --volumes=false",
        "docker volume prune --all --filter label=temporary",
        "docker system prune --volumes --filter=until=24h",
        "podman volume prune",
        "podman volume prune --all --dry-run",
        "podman system prune --volumes --dry-run",
        "podman system prune --volumes --external",
        "podman volume prune --all --filter all=true",
        "podman system reset --help",
        "podman --version system reset",
        "podman system reset --version=false",
        "podman system -v=false reset --force",
        "podman -- system reset --force",
        "podman system -- reset --force",
        "docker volume prune --all -v=false",
        "docker system --version=false prune --volumes",
        "docker -- volume -- prune --all --",
        "docker volume -- prune --all",
        "podman --root /tmp system reset",
        "docker --context volume prune --all",
        "docker volume prune --all extra",
        "docker volume prune \"$SCOPE\"",
        "podman \"$GROUP\" reset",
        "/usr/local/bin/docker volume prune --all",
        "/opt/bin/podman system reset",
        "PATH=/tmp docker volume prune --all",
        "env PATH=/tmp podman system reset",
    ] {
        assert!(!resets_container_runtime(source), "{source}");
        assert!(!deletes_container_volumes(source), "{source}");
    }
}

#[test]
fn adjacent_container_cleanup_and_control_planes_stay_outside() {
    for source in [
        "docker volume rm named-volume",
        "docker container rm -v app",
        "docker image prune --all",
        "docker builder prune --all",
        "docker network prune",
        "podman volume rm --all",
        "podman container rm -v app",
        "podman image prune --all",
        "podman machine reset --force",
        "podman kube down workload.yaml",
        "kubectl delete namespace production",
        "skopeo delete docker://registry.example/image:tag",
    ] {
        assert!(!resets_container_runtime(source), "{source}");
        assert!(!deletes_container_volumes(source), "{source}");
    }
}
