mod support;

use nah_actions::{AnalysisPlan, SelfProtectionProjection, finalize};
use nah_inline::{FindingKind, InlineReport};
use nah_proto::action::{ActionStream, Coverage, EffectKind, InvocationEffect, NahProtectionTier};
use nah_proto::ctx::SchemaVersion;
use nah_proto::observation::{
    EnvObservation, Observation, ObservationFact, ObservationQuery, ObservationValue, Observed,
    PathKind, PathObservation,
};
use support::{Change, absolute, bash_plan, bash_plan_with_self_protection, facts, observe};

fn finalize_with_inline(
    plan: AnalysisPlan,
    observation: Observation,
) -> (ActionStream, InlineReport) {
    let report = plan.inline_report().clone();
    let stream = finalize(plan, observation);
    (stream, report)
}

fn structurally_protected(stream: &ActionStream, report: &InlineReport) -> bool {
    report.contains_conservative(FindingKind::NahTampering)
        || stream.effects().iter().any(|effect| {
            matches!(effect.kind(), EffectKind::Filesystem { effect }
                if effect.operation != nah_proto::action::FilesystemOperation::Read
                    && effect.protection == Some(NahProtectionTier::Critical))
                || matches!(
                        effect.kind(),
                    EffectKind::Invocation {
                        invocation: InvocationEffect::Known { operation, .. }
                    } if operation.as_str() == "critical-mutation"
                )
        })
}

#[test]
fn bash_tags_visible_nah_mutations_without_matching_local_utilities() {
    for command in [
        "nah tui",
        "nah trust /repo",
        "nah untrust /repo",
        "nah guard disable fs-root",
        "sudo nah trust /repo",
        "/usr/bin/nah trust /repo",
        "command -- nah trust /repo",
        "env SAFE=1 nah trust /repo",
        "bash -c 'nah trust /repo'",
        "exec nah trust /repo",
        "exec -cl -- nah trust /repo",
        "exec -aagent nah trust /repo",
        "exec -cla agent nah trust /repo",
        "nice nah trust /repo",
        "nice -n 5 nah trust /repo",
        "nohup nah trust /repo",
        "exec nice -- nohup -- nah trust /repo",
        "(nah trust /repo)",
        "if true; then nah trust /repo; fi",
        "nah hook amp install",
        "nah hook amp uninstall",
        "nah hook antigravity install",
        "nah hook antigravity uninstall",
        "nah hook claude install",
        "nah hook claude uninstall",
        "nah hook cline install",
        "nah hook cline uninstall",
        "nah hook codex install",
        "nah hook codex uninstall",
        "nah hook copilot install",
        "nah hook copilot uninstall",
        "nah hook cursor install",
        "nah hook cursor uninstall",
        "nah hook devin install",
        "nah hook devin uninstall",
        "nah hook droid install",
        "nah hook droid uninstall",
        "nah hook hermes install",
        "nah hook hermes uninstall",
        "nah hook kiro install",
        "nah hook kiro uninstall",
        "nah hook openclaw install",
        "nah hook openclaw uninstall",
        "nah hook opencode install",
        "nah hook opencode uninstall",
        "nah hook pi install",
        "nah hook pi uninstall",
        "nah hook prime-agent install",
        "nah hook prime-agent uninstall",
        "amp plugins remove nah.ts",
        "amp plugins rm nah.ts --target system",
        "agy plugin disable nah",
        "agy plugin uninstall nah",
        "/usr/bin/openclaw plugins uninstall --force nah",
    ] {
        let plan = bash_plan(command);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )),
            "{command}: {:?}",
            stream.effects()
        );
    }
    for command in [
        "nah docs guards",
        "nah hook amp status",
        "echo nah trust /repo",
        "nah \"$COMMAND\" /repo",
        "exec -a nah echo trust /repo",
        "nice --help",
        "nice nah trust-status",
        "nohup echo nah trust /repo",
        "amp plugins add @owner/example",
        "amp plugins update",
        "amp plugins list",
        "amp plugins exec nah.ts tool.call",
        "agy plugin install /tmp/unsafe",
        "agy plugin disable unsafe",
        "agy plugin list",
        "safe() { nah trust /repo; }",
    ] {
        let plan = bash_plan(command);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )),
            "{command}: {:?}",
            stream.effects()
        );
    }
    for command in [
        "nah --help",
        "nah docs security",
        "nah docs guards",
        "nah log --json -n 10",
        "nah why decision-id",
        "nah hook amp status",
    ] {
        let plan = bash_plan(command);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { program, operation, .. }
                } if program == "nah" && operation.as_str() == "inspect"
            )),
            "{command}: {:?}",
            stream.effects()
        );
    }

    let plan = bash_plan("script -qec 'nah nap' /dev/null");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known {
                program,
                operation,
                ..
            }
        } if program == "nah" && operation.as_str() == "permanent-mutation"
    )));

    let plan = bash_plan("mkfifo ~/.nah/nap.json");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.protection == Some(NahProtectionTier::Permanent)
    )));

    let plan = bash_plan("echo x > ~/.nah/trust.json");
    let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Filesystem { effect }
            if effect.protection == Some(NahProtectionTier::Critical)
    )));
}

#[test]
fn cargo_install_blocks_only_a_known_nah_binary_at_a_protected_destination() {
    let critical_mutation = |source: &str, self_protection: SelfProtectionProjection| {
        let plan = bash_plan_with_self_protection(source, self_protection);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        stream.effects().iter().any(|effect| {
            matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )
        })
    };

    for source in [
        "cargo install --path crates/nah-cli --locked --force --root /home/test/.local",
        "cargo install --root ~/.cargo --path crates/nah-cli",
        "cargo +stable --quiet install --root /usr/local nah-cli@1.0.0",
        "cargo install --root=/home/test/.local --bin=nah --path crates/other",
        "cargo install --root /home/test/.local --path crates/nah-cli --bins",
    ] {
        assert!(
            critical_mutation(source, SelfProtectionProjection::default()),
            "{source}"
        );
    }

    for source in [
        "cargo build --path crates/nah-cli",
        "cargo install other --root /home/test/.local",
        "cargo install --path crates/other --root /home/test/.local",
        "cargo install --path crates/nah-cli --bin other --root /home/test/.local",
        "cargo install --path crates/nah-cli --root /tmp/tools",
        "cargo install --path crates/nah-cli --root /home/test/.local --dry-run",
        "cargo install --list",
        "cargo install --path crates/nah-cli --root \"$ROOT\"",
    ] {
        assert!(
            !critical_mutation(source, SelfProtectionProjection::default()),
            "{source}"
        );
    }

    assert!(critical_mutation(
        "cargo install --path crates/nah-cli --root /opt/nah",
        SelfProtectionProjection::new(vec![absolute("/opt/nah/bin/nah")]),
    ));
}

#[test]
fn observed_program_and_arguments_preserve_self_protection() {
    let plan = bash_plan("\"$TOOL\" \"$ACTION\" /repo");
    let observation_facts = facts(plan.observation_request(), "/usr/bin/nah", Change::None)
        .into_iter()
        .map(|fact| {
            if matches!(
                fact.query(),
                ObservationQuery::Env { name, .. } if name == "ACTION"
            ) {
                ObservationFact::new(
                    fact.query().clone(),
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Value {
                                text: "trust".into(),
                            },
                        },
                    },
                )
                .unwrap()
            } else {
                fact
            }
        })
        .collect();
    let observation = Observation::new(
        SchemaVersion::V1,
        plan.observation_request().request_id(),
        observation_facts,
    )
    .unwrap();
    let stream = finalize(plan, observation);

    assert_eq!(stream.coverage(), Coverage::Partial);
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known {
                program,
                operation,
                ..
            }
        } if program == "/usr/bin/nah" && operation.as_str() == "critical-mutation"
    )));

    let plan = bash_plan("nah \"${ACTION}\"ust /repo");
    let observation_facts = facts(plan.observation_request(), "echo", Change::None)
        .into_iter()
        .map(|fact| {
            if matches!(
                fact.query(),
                ObservationQuery::Env { name, .. } if name == "ACTION"
            ) {
                ObservationFact::new(
                    fact.query().clone(),
                    ObservationValue::Env {
                        observed: Observed::Ok {
                            value: EnvObservation::Value { text: "tr".into() },
                        },
                    },
                )
                .unwrap()
            } else {
                fact
            }
        })
        .collect();
    let observation = Observation::new(
        SchemaVersion::V1,
        plan.observation_request().request_id(),
        observation_facts,
    )
    .unwrap();
    let stream = finalize(plan, observation);
    assert!(stream.effects().iter().any(|effect| matches!(
        effect.kind(),
        EffectKind::Invocation {
            invocation: InvocationEffect::Known { operation, .. }
        } if operation.as_str() == "critical-mutation"
    )));
}

#[test]
fn shell_patterns_cannot_hide_self_protection() {
    for source in [
        "nah tr?st /repo",
        "nah tr{u,xx}st /repo",
        "n?h trust /repo",
        "n[ab]h trust /repo",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn exact_interpreter_mutations_of_self_protected_paths_are_structural() {
    let self_protection =
        SelfProtectionProjection::new(vec![absolute("/home/test/.kiro/hooks/nah.json")]);
    for source in [
        r#"python -c 'import os; os.remove(os.path.expanduser("~/.local/bin/nah"))'"#,
        r#"python -c 'from pathlib import Path; (Path.home()/".kiro/hooks/nah.json").unlink()'"#,
        r#"python -c 'from pathlib import Path; Path("/home/test/.kiro/hooks/nah.json").touch()'"#,
        r#"python3 -c 'from pathlib import Path; p=Path("/home/test/.kiro/hooks/nah.json"); q=p.with_name("nah.json.tamper-probe"); p.rename(q); q.rename(p)'"#,
        r#"python3 -c 'from pathlib import Path; P=Path("/home/test/.kiro/hooks/nah.json"); p=Path("/tmp/a"); P.rename("/tmp/b")'"#,
        r#"python3 -c 'import os,stat; p="/home/test/.local/bin/nah"; m=os.stat(p).st_mode; os.chmod(p,0); os.chmod(p,stat.S_IMODE(m))'"#,
        r#"exec 3<<<'import os; os.chmod("/home/test/.local/bin/nah", 0)'; ./.venv/bin/python /dev/fd/3"#,
        r#"python -c 'import os; os.remove("/home/test/.kiro/" + "hooks/nah.json")'"#,
        r#"python -c'import os; os.remove("/home/test/.nah/trust.json")'"#,
        r#"python -Ic'import os; os.remove("/home/test/.nah/trust.json")'"#,
        "python -c $'import os\\nos.remove(\\n\"/home/test/.kiro/hooks/nah.json\"\\n)'",
        r#"python -c 'import os; 1 // (os.remove("/home/test/.kiro/hooks/nah.json") or 1)'"#,
        r#"python -c 'import shutil; shutil.copyfile("/tmp/replacement", "/home/test/.kiro/hooks/nah.json")'"#,
        r#"python -c 'open("/home/test/.nah/trust.json", "w").write("x")'"#,
        r#"python -c 'import subprocess; subprocess.run(["rm","-rf","/home/test/.nah"])'"#,
        r#"python -c 'import os; os.system("rm -rf /home/test/.nah")'"#,
        r#"python -c 'import os; os.open("/home/test/.kiro/hooks/nah.json", os.O_WRONLY | os.O_TRUNC)'"#,
        r#"python -c 'import os; os.chown("/home/test/.kiro/hooks/nah.json", 0, 0)'"#,
        r#"python -c 'import os; getattr(os, "chmod")("/home/test/.local/bin/nah", 0)'"#,
        r#"python -c 'import os; dict(os=1); getattr(os, "chmod")("/home/test/.local/bin/nah", 0)'"#,
        r#"python -c 'import os; getattr(os, "chmod")("/home/test/.local/bin/nah", 0); os=object()'"#,
        r#"python -c 'import io; io.FileIO("/home/test/.local/bin/nah", "w")'"#,
        r#"python -c 'import shutil; shutil.copymode("/tmp/noexec", "/home/test/.local/bin/nah")'"#,
        r#"python -c 'eval("__import__(\"os\").remove(\"/home/test/.nah/trust.json\")")'"#,
        r#"python -c 'exec(compile("import os; os.remove(\"/home/test/.nah/trust.json\")", "<x>", "exec"))'"#,
        r#"python -c 'import os; os.rmdir("/home/test/.nah")'"#,
        r#"python -c 'import os; os.remove(os.getenv("HOME")+"/.nah/trust.json")'"#,
        "python <<'PY'\nimport os\nos.remove(\"/home/test/.nah/trust.json\")\nPY",
        r#"printf '%s' 'import os; os.remove("/home/test/.nah/trust.json")' | python"#,
        r#"printf '%s' 'import os; os.remove("/home/test/.nah/trust.json")' > /tmp/nah-check.py; python /tmp/nah-check.py"#,
        r#"python -c 'import os; os.remove("\x2fhome\x2ftest\x2f.nah\x2ftrust.json")'"#,
        r#"python -c 'import os; os.remove("\u002fhome\u002ftest\u002f.nah\u002ftrust.json")'"#,
        r#"python -c 'from pathlib import Path; Path("/home/test/.nah").rmdir()'"#,
        r#"python2 -c 'import os; os.remove("/home/test/.nah/trust.json")'"#,
        r#"pypy2 -c 'import os; os.remove("/home/test/.nah/trust.json")'"#,
        r#"pypy3 -c 'import os; os.remove("/home/test/.kiro/hooks/nah.json")'"#,
        r#"pypy3.10 -c 'import os; os.remove("/home/test/.nah/trust.json")'"#,
        r#"python3.13t -c 'import os; os.remove("/home/test/.kiro/hooks/nah.json")'"#,
        r#"py -3 -c 'import os; os.remove("/home/test/.nah/trust.json")'"#,
        r#"perl -e 'unlink "$ENV{HOME}/.local/bin/nah"'"#,
        r#"perl -e'unlink "/home/test/.nah/trust.json"'"#,
        r#"perl -we'unlink "/home/test/.nah/trust.json"'"#,
        r#"perl5.38.2 -e 'unlink "/home/test/.nah/trust.json"'"#,
        r#"perl -e 'unlink $ENV{"HOME"}."/.nah/trust.json"'"#,
        r#"perl -e 'unlink "\x2fhome\x2ftest\x2f.nah\x2ftrust.json"'"#,
        r#"perl -e 'unlink "\x{2f}home\x{2f}test\x{2f}.nah\x{2f}trust.json"'"#,
        r#"perl -MFile::Copy -e 'copy("/tmp/replacement", "$ENV{HOME}/.local/bin/nah")'"#,
        r#"perl -MFile::Path -e 'remove_tree("$ENV{HOME}/.nah")'"#,
        r#"perl -e 'undef // unlink "$ENV{HOME}/.local/bin/nah"'"#,
        r#"perl -e 'eval("unlink \"/home/test/.nah/trust.json\"")'"#,
        r#"perl -MFcntl=:DEFAULT -e 'sysopen(my $fh, "$ENV{HOME}/.nah/trust.json", O_WRONLY|O_TRUNC)'"#,
        r#"node -e 'require("fs").rmSync(process.env.HOME+"/.kiro/hooks/nah.json")'"#,
        r#"node -e 'require("fs").copyFileSync("/tmp/replacement", process.env.HOME+"/.kiro/hooks/nah.json")'"#,
        r#"node -e 'require("fs").createWriteStream(process.env.HOME+"/.kiro/hooks/nah.json")'"#,
        r#"node -e 'eval("require(\"fs\").rmSync(process.env.HOME+\"/.nah/trust.json\")")'"#,
        r#"node -e 'require("fs").openSync(process.env.HOME+"/.kiro/hooks/nah.json", "w")'"#,
        r#"node --eval 'require("fs").rmSync(process.env.HOME+"/.nah/trust.json")'"#,
        r#"node --eval='require("fs").rmSync(process.env.HOME+"/.nah/trust.json")'"#,
        r#"node --print 'require("fs").rmSync(process.env.HOME+"/.nah/trust.json")'"#,
        r#"node --eval 'require("fs").rmSync(process.env.HOME+"/\u{2e}nah/trust.json")'"#,
        r#"ruby -e 'IO.write(File.join(ENV["HOME"], ".nah/trust.json"), "x")'"#,
        r#"ruby -e'File.unlink("/home/test/.nah/trust.json")'"#,
        r#"ruby -e 'File.unlink(ENV.fetch("HOME")+"/.nah/trust.json")'"#,
        r#"ruby -e 'File.unlink("/home/test/\u{2e}nah/trust.json")'"#,
        r#"ruby -e 'eval("File.unlink(\"/home/test/.nah/trust.json\")")'"#,
        r#"ruby -e 'File.truncate("/home/test/.nah/trust.json", 0)'"#,
        r#"ruby -e 'File.unlink(File.join(ENV["HOME"], ".nah/trust.json"))'"#,
        r#"ruby -e 'FileUtils.cp("/tmp/replacement", "/home/test/.nah/trust.json")'"#,
        r#"pwsh -Command 'Remove-Item "$HOME/.kiro/hooks/nah.json"'"#,
        r#"pwsh -Com 'Remove-Item "${HOME}/.nah/trust.json"'"#,
        r#"pwsh -Command 'rm "$HOME/.kiro/hooks/nah.json"'"#,
        r#"pwsh -Command 'Set-Content "$HOME/.kiro/hooks/nah.json" "disabled"'"#,
        r#"pwsh -Command 'Clear-Content "$HOME/.kiro/hooks/nah.json"'"#,
        r#"pwsh -Command 'Invoke-Expression "Remove-Item /home/test/.nah/trust.json"'"#,
        r#"php -r 'unlink("/home/test/.nah/trust.json");'"#,
        r#"php -r'unlink("/home/test/.nah/trust.json");'"#,
        r#"php -r 'file_put_contents("/home/test/.kiro/hooks/nah.json", "x");'"#,
        r#"php -r 'copy("/tmp/replacement", "/home/test/.kiro/hooks/nah.json");'"#,
        r#"php -r 'unlink(getenv("HOME")."/.nah/trust.json");'"#,
        r#"php -r 'eval("unlink(\"/home/test/.nah/trust.json\");");'"#,
        r#"lua -e 'os.remove("/home/test/.nah/trust.json")'"#,
        r#"lua -e 'os.remove("/home/test/\046nah/trust.json")'"#,
        r#"lua -e 'os.remove(os.getenv("HOME").."/.nah/trust.json")'"#,
        r#"lua -e 'io.open("/home/test/.nah/trust.json", "w")'"#,
        r#"lua -e 'load("os.remove(\"/home/test/.nah/trust.json\")")()'"#,
        r#"R -e 'file.remove("/home/test/.nah/trust.json")'"#,
        r#"R -e 'unlink("/home/test/.nah/trust.json")'"#,
        r#"Rscript -e'file.remove("/home/test/.nah/trust.json")'"#,
        r#"R -e 'file.remove(file.path(Sys.getenv("HOME"), ".nah", "trust.json"))'"#,
        r#"R -e 'file.copy("/tmp/replacement", "/home/test/.kiro/hooks/nah.json")'"#,
        r#"R -e 'writeLines("x", "/home/test/.kiro/hooks/nah.json")'"#,
        r#"R -e 'eval(parse(text="unlink(\"/home/test/.nah/trust.json\")"))'"#,
        r#"julia -e 'rm("/home/test/.nah/trust.json")'"#,
        r#"julia --eval 'rm("/home/test/.nah/trust.json")'"#,
        r#"julia -e 'rm(joinpath(homedir(), ".nah", "trust.json"))'"#,
        r#"julia -e 'open("/home/test/.nah/trust.json", "w")'"#,
        r#"julia -e 'cp("/tmp/replacement", "/home/test/.kiro/hooks/nah.json", force=true)'"#,
        r#"julia -e 'eval(Meta.parse("rm(\"/home/test/.nah/trust.json\")"))'"#,
        r#"swift -e 'FileManager.default.removeItem(atPath: "/home/test/.nah/trust.json")'"#,
        r#"swift -e 'try FileManager.default.copyItem(atPath: "/tmp/replacement", toPath: "/home/test/.nah/trust.json")'"#,
        r#"cmd /c 'del C:\home\test\.nah\trust.json'"#,
        r#"cmd /Cdel '/home/test/.nah/trust.json'"#,
        "git init /home/test/.nah",
        "git -C /home/test/.nah clean -fdx",
        r#"perl -e 'open my $fh, ">", "$ENV{HOME}/.nah/trust.json"'"#,
        r#"python -c 'import subprocess; subprocess.run(["nah","hook","kiro","uninstall"])'"#,
        r#"python -c 'import os; os.link("/home/test/.kiro/hooks/nah.json", "/tmp/alias")'"#,
        r#"python -c 'import os; os.link("/home/test/.kiro/hooks/../hooks/nah.json", "/tmp/alias")'"#,
        r#"python -c 'import os; os.link(os.path.expanduser("~/.kiro/hooks/../hooks/nah.json"), "/tmp/alias")'"#,
        r#"python -c 'from pathlib import Path; Path("/tmp/alias").hardlink_to("/home/test/.kiro/hooks/nah.json")'"#,
        r#"python.EXE -c 'import os; os.remove("/home/test/.kiro/hooks/nah.json")'"#,
        r#"node -e 'require("fs").linkSync(process.env.HOME+"/.kiro/hooks/nah.json", "/tmp/alias")'"#,
        r#"node -e 'require("fs").linkSync(process.env.HOME+"/.kiro/hooks/../hooks/nah.json", "/tmp/alias")'"#,
        r#"node -e 'require("fs")["chmodSync"]("/home/test/.local/bin/nah", 0)'"#,
        r#"ruby -e 'File.link(File.join(ENV["HOME"], ".kiro/hooks/nah.json"), "/tmp/alias")'"#,
        r#"ruby -e 'File.send(:unlink, "/home/test/.local/bin/nah")'"#,
        r#"perl -e 'link "/home/test/.kiro/hooks/../hooks/nah.json", "/tmp/alias"'"#,
        r#"perl -e 'link "$ENV{HOME}/.kiro/hooks/../hooks/nah.json", "/tmp/alias"'"#,
        r#"pwsh -Command 'New-Item -ItemType HardLink -Path /tmp/alias -Target "$HOME/.kiro/hooks/nah.json"'"#,
        r#"pwsh -Command 'New-Item -ItemType HardLink -Path /tmp/alias -Target "/home/test/.kiro/hooks/../hooks/nah.json"'"#,
        r#"pwsh -Command 'New-Item -ItemType HardLink -Path /tmp/alias -Target "$HOME/.kiro/hooks/../hooks/nah.json"'"#,
        r#"cmd /c 'mklink /H C:\tmp\alias /home/test/.kiro/hooks/nah.json'"#,
        r#"cmd /c 'mklink /H C:\tmp\alias /home/test/.kiro/hooks/../hooks/nah.json'"#,
        r#"php -r 'call_user_func("unlink", "/home/test/.local/bin/nah");'"#,
        r#"python -c 'import subprocess; subprocess.run(["claude","--safe-mode"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["/usr/bin/env","OPENCODE_PURE=1","opencode"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["sh","-c","claude --safe-mode"])'"#,
        r#"perl -e 'system "opencode", "--pure"'"#,
        r#"node -e 'require("child_process").spawn("pi", ["--no-extensions"])'"#,
        r#"python -c 'import subprocess; getattr(subprocess, "run")(["pi", "--no-extensions"])'"#,
        r#"node -e 'require("child_process")["spawn"]("pi", ["--no-extensions"])'"#,
        r#"node -e 'require("child_process").spawn("prime-agent", ["--no-extensions"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["prime-agent", "--no-extensions"])'"#,
        r#"lua -e 'os.execute("claude --safe-mode")'"#,
        r#"pwsh -Command 'Start-Process "claude" -ArgumentList "--safe-mode"'"#,
        r#"pwsh -Command "Start-Process claude -ArgumentList '--safe-mode'""#,
        r#"pwsh -Command 'Start-Process -FilePath claude -ArgumentList "--safe-mode"'"#,
        r#"pwsh -Command 'Start-Process -FilePath "claude" -ArgumentList "--safe-mode"'"#,
        r#"pwsh -Command 'Start-Process -NoNewWindow -FilePath claude -ArgumentList "--safe-mode"'"#,
        r#"pwsh -Command 'Start-Process -ArgumentList "--safe-mode" -FilePath claude'"#,
        r#"pwsh -Command 'Start-Process -ArgumentList "--safe-mode" -FilePath "claude"'"#,
        r#"pwsh -Command 'Start-Process -ArgumentList "--safe-mode" -FilePath "C:\tools\Claude.EXE"'"#,
        r#"pwsh.EXE -Command '& claude --safe-mode'"#,
        r#"pwsh -Command '& claude --safe-mode'"#,
        r#"pwsh -Command '& "claude" --safe-mode'"#,
        r#"cmd /c 'claude --safe-mode'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn runtime_launches_that_skip_active_hooks_are_structural() {
    for source in [
        "PLUGINS=off amp",
        "env PLUGINS=off amp",
        r#"/usr/bin/env -S "CODEX_HOME=/tmp/other codex""#,
        r#"/usr/bin/env -S "-- CODEX_HOME=/tmp/other codex""#,
        r#"/usr/bin/env --split-string="-- CODEX_HOME=/tmp/other codex""#,
        "export PLUGINS=off; amp",
        "claude --safe-mode",
        "/opt/Claude.EXE --safe-mode",
        "nice claude --bare",
        "cline --config /tmp/other",
        "cline --config=/tmp/other",
        "CLINE_DIR=/tmp/other cline",
        "bash -c 'codex --disable hooks'",
        "/opt/codex.cmd --disable hooks",
        "CODEX_HOME=/tmp/other codex",
        "COPILOT_HOME=/tmp/other copilot",
        "devin --config /tmp/other.json",
        "droid --settings=/tmp/other.json",
        "HERMES_HOME=/tmp/other hermes",
        "hermes --ignore-user-config",
        "KIRO_HOME=/tmp/other kiro-cli --v3",
        "OPENCLAW_STATE_DIR=/tmp/other openclaw",
        "OPENCLAW_PROFILE=other openclaw",
        "openclaw --profile other",
        "openclaw --profile=other",
        "openclaw --dev",
        "OPENCODE_PURE=1 opencode",
        "XDG_CONFIG_HOME=/tmp/other opencode",
        "opencode --pure",
        "PI_CODING_AGENT_DIR=/tmp/other pi",
        "pi --no-extensions",
        "PRIME_AGENT_CODING_AGENT_DIR=/tmp/other prime-agent",
        "prime-agent --no-extensions",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn direct_python_decode_to_shell_execution_is_typed() {
    for source in [
        r#"python3 -c "import base64, subprocess; subprocess.run(base64.b64decode('cHJpbnRmIHNhZmU=').decode(), shell=True, check=True)""#,
        r#"python -c 'import base64, subprocess; subprocess.call(args=base64.urlsafe_b64decode(payload), shell=True)'"#,
        r#"python -c 'import base64, subprocess; subprocess.Popen(base64.b64decode(payload), cwd="/tmp", shell=True)'"#,
        r#"python -c 'import base64, subprocess; subprocess.check_call(base64.b64decode(payload), shell=True)'"#,
        r#"python -c 'import base64, subprocess; subprocess.check_output(base64.b64decode(payload), shell=True)'"#,
        r#"python -c 'import base64, subprocess; decoded=base64.b64decode(payload); subprocess.run(decoded, shell=True)'"#,
        r#"python -c 'import base64, os; os.system(base64.b64decode(payload).decode())'"#,
        r#"python -c 'import base64, os; os.popen(base64.b64decode(payload).decode())'"#,
        r#"python -c 'import base64, os; os.system(base64.b64decode(payload).decode(),)'"#,
        r#"python -c 'import base64, subprocess; subprocess.run(base64.b64decode(payload), shell=True,)'"#,
        "python -c 'import base64, subprocess\nsubprocess.run(\nbase64.b64decode(payload),\nshell=True\n)'",
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            report.contains_exact(FindingKind::DecodedExecution),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        r#"python -c 'import base64; print(base64.b64decode(payload).decode())'"#,
        r#"python -c 'import base64, subprocess; subprocess.run(base64.b64decode(payload), shell=False)'"#,
        r#"python -c 'import subprocess; subprocess.run("printf safe", shell=True)'"#,
        r#"python -c 'import base64, subprocess; subprocess.run(base64.b64decode(payload), env={"shell": True})'"#,
        r#"python -c 'print("subprocess.run(base64.b64decode(payload), shell=True)")'"#,
        r#"python -c 'print("""subprocess.run(base64.b64decode(payload), shell=True)""")'"#,
        r#"python -c '# subprocess.run(base64.b64decode(payload), shell=True)'"#,
        r#"python -c 'notsubprocess.run(base64.b64decode(payload), shell=True)'"#,
        r#"python -c 'import base64; subprocess=object(); subprocess.run(base64.b64decode(payload), shell=True)'"#,
    ] {
        let plan = bash_plan(source);
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            !report.contains_exact(FindingKind::DecodedExecution),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn runtime_information_and_permission_modes_do_not_claim_hook_bypass() {
    for source in [
        "PLUGINS=off amp --help",
        "claude --safe-mode --version",
        "codex --disable hooks --help",
        "devin --config /tmp/other.json --help",
        "openclaw --profile default",
        "openclaw --profile=default",
        "openclaw --dev --help",
        "opencode --pure --version",
        "pi --no-extensions --help",
        "prime-agent --no-extensions --help",
        "hermes hooks rm 'nah hook hermes run' --help",
        "openclaw plugins uninstall nah --help",
        "amp plugins remove nah --version",
        "PLUGINS=off; amp",
        r#"CODEX_HOME="$HOME/.codex" codex"#,
        r#"CLINE_DIR="$HOME/.cline" cline"#,
        r#"cline --config "$HOME/.cline""#,
        r#"CODEX_HOME="$HOME/.codex/" codex"#,
        "cline --hooks-dir /tmp/additional",
        r#"devin --config "$HOME/.config/devin/config.json""#,
        r#"droid --settings "$HOME/.factory/settings.json""#,
        r#"OPENCLAW_STATE_DIR="$HOME/.openclaw" openclaw"#,
        "OPENCLAW_PROFILE= openclaw",
        "OPENCLAW_PROFILE=Default openclaw",
        "openclaw --profile=",
        r#"XDG_CONFIG_HOME="$HOME/.config" opencode"#,
        r#"XDG_CONFIG_HOME="$HOME/.config/" opencode"#,
        r#"PI_CODING_AGENT_DIR="$HOME/.pi/agent" pi"#,
        r#"PRIME_AGENT_CODING_AGENT_DIR="$HOME/.prime/agent" prime-agent"#,
        "claude --dangerously-skip-permissions",
        "codex --yolo",
        "copilot --allow-all",
        "cursor-agent --yolo",
        "devin /yolo",
        "droid --skip-permissions-unsafe",
        "hermes /yolo",
        "hermes plugins disable nah",
        "hermes config unset hooks.pre_tool_callback",
        "hermes config unset hooks.pre_tool_calligraphy",
        "openclaw config unset plugins.entries.nahsomething.enabled",
        "git init --help /home/test/.nah",
        "git -C /home/test/.nah clean --dry-run -fdx",
        "git -C /tmp/ordinary clean -fdx",
        "opencode",
    ] {
        let plan = bash_plan(source);
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn new_hardlinks_from_self_protected_paths_are_structural() {
    let self_protection =
        SelfProtectionProjection::new(vec![absolute("/home/test/.kiro/hooks/nah.json")]);
    for source in [
        "ln /home/test/.kiro/hooks/nah.json /tmp/alias",
        "ln -- /home/test/.kiro/hooks/nah.json /tmp/alias",
        "ln /home/test/.kiro/../.kiro/hooks/nah.json /tmp/alias",
        "link /home/test/.kiro/hooks/nah.json /tmp/alias",
        "cp -l /home/test/.kiro/hooks/nah.json /tmp/alias",
        "cp -al /home/test/.kiro/hooks/nah.json /tmp/alias",
        r#"perl -e 'link "/home/test/.kiro/hooks/nah.json", "/tmp/alias"'"#,
        r#"python -c 'import os; os.link("/home/test/.kiro/hooks/nah.json", target)'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "ln -s /home/test/.kiro/hooks/nah.json /tmp/alias",
        "ln /tmp/ordinary /tmp/alias",
        "cp /home/test/.kiro/hooks/nah.json /tmp/copy",
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            !structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn python_hardlinks_use_observed_source_identity() {
    let protected = "/home/test/.kiro/hooks/nah.json";
    let self_protection = SelfProtectionProjection::new(vec![absolute(protected)]);
    for (follow, expected) in [("", true), (", follow_symlinks=False", false)] {
        let source =
            format!(r#"python -c 'import os; os.link("/tmp/source-link", "/tmp/alias"{follow})'"#);
        let plan = bash_plan_with_self_protection(&source, self_protection.clone());
        let observation = Observation::new(
            SchemaVersion::V1,
            plan.observation_request().request_id(),
            facts(plan.observation_request(), "echo", Change::None)
                .into_iter()
                .map(|fact| match fact.query() {
                    ObservationQuery::Path { requested, .. } if requested == "/tmp/source-link" => {
                        ObservationFact::new(
                            fact.query().clone(),
                            ObservationValue::Path {
                                observed: Observed::Ok {
                                    value: PathObservation::new(
                                        absolute("/tmp/source-link"),
                                        Some(absolute(protected)),
                                        PathKind::Symlink,
                                    )
                                    .with_target_kind(PathKind::File),
                                },
                            },
                        )
                        .unwrap()
                    }
                    _ => fact,
                })
                .collect(),
        )
        .unwrap();
        let (stream, report) = finalize_with_inline(plan, observation);
        assert_eq!(
            structurally_protected(&stream, &report),
            expected,
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn python_namespace_replacement_does_not_follow_destination_symlinks() {
    let protected = "/home/test/.kiro/hooks/nah.json";
    let self_protection = SelfProtectionProjection::new(vec![absolute(protected)]);
    for (destination, realpath, expected) in [
        ("/tmp/alias", protected, false),
        (protected, "/tmp/ordinary", true),
    ] {
        let source =
            format!(r#"python -c 'import os; os.replace("/tmp/source", "{destination}")'"#);
        let plan = bash_plan_with_self_protection(&source, self_protection.clone());
        let observation = Observation::new(
            SchemaVersion::V1,
            plan.observation_request().request_id(),
            facts(plan.observation_request(), "echo", Change::None)
                .into_iter()
                .map(|fact| match fact.query() {
                    ObservationQuery::Path { requested, .. } if requested == destination => {
                        ObservationFact::new(
                            fact.query().clone(),
                            ObservationValue::Path {
                                observed: Observed::Ok {
                                    value: PathObservation::new(
                                        absolute(destination),
                                        Some(absolute(realpath)),
                                        PathKind::Symlink,
                                    )
                                    .with_target_kind(PathKind::File),
                                },
                            },
                        )
                        .unwrap()
                    }
                    _ => fact,
                })
                .collect(),
        )
        .unwrap();
        let (stream, report) = finalize_with_inline(plan, observation);
        assert_eq!(
            structurally_protected(&stream, &report),
            expected,
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn namespace_mutations_of_self_protected_path_ancestors_are_structural() {
    let self_protection =
        SelfProtectionProjection::new(vec![absolute("/home/test/.kiro/hooks/nah.json")]);
    for source in [
        r#"python -c 'from pathlib import Path; Path("/home/test/.kiro/hooks").rename("/tmp/hooks")'"#,
        r#"python -c 'from pathlib import Path; hooks=Path("/home/test/.kiro/hooks"); probe=hooks.with_name("hooks.probe"); hooks.rename(probe); probe.rename(hooks)'"#,
        r#"python -c 'import os; os.rename("/home/test/.kiro", "/tmp/kiro")'"#,
        r#"python -c 'import shutil; shutil.rmtree("/home/test/.kiro/hooks")'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        r#"python -c 'from pathlib import Path; print(list(Path("/home/test/.kiro/hooks").iterdir()))'"#,
        r#"python -c 'from pathlib import Path; Path("/home/test/.kiro/hooks").mkdir(exist_ok=True)'"#,
        r#"python -c 'from pathlib import Path; Path("/home/test/.kiro/hooks/other.json").rename("/tmp/other.json")'"#,
        r#"python -c 'from pathlib import Path; parent=Path("/home/test/.kiro/hooks"); Path("/tmp/a").rename("/tmp/b")'"#,
        r#"python -c 'print("/home/test/.kiro/hooks", __import__("os").rename("/tmp/a", "/tmp/b"))'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            !structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }
}

#[test]
fn access_control_mutations_of_self_protected_path_ancestors_are_structural() {
    let self_protection =
        SelfProtectionProjection::new(vec![absolute("/home/test/.kiro/hooks/nah.json")]);
    for source in [
        "chmod 000 /home/test/.kiro/hooks",
        "chown root /home/test/.kiro/hooks",
        "chgrp root /home/test/.kiro/hooks",
        "setfacl -m u::rwx /home/test/.kiro/hooks",
        r#"python -c 'import os; os.chmod("/home/test/.kiro/hooks", 0)'"#,
        r#"python -c 'import os; os.chown("/home/test/.kiro/hooks", 0, 0)'"#,
        r#"python -c 'from pathlib import Path; Path("/home/test/.kiro/hooks").chmod(0)'"#,
        r#"python -c 'import os; parent="/home/test/.local/bin"; os.chmod(parent, 0)'"#,
        r#"python -c 'from pathlib import Path; parent=Path("/home/test/.kiro/hooks"); parent.chmod(0)'"#,
        r#"python -c 'import subprocess; subprocess.run(["chmod", "000", "/home/test/.kiro/hooks"])'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }

    for source in [
        "chmod 000 /tmp/unrelated",
        "chmod --help /home/test/.kiro/hooks",
        "chmod 000 $target",
        "chmod 000 /home/test",
        r#"python -c 'import os; os.chmod("/tmp/unrelated", 0)'"#,
        r#"python -c 'import os; os.chmod(target, 0)'"#,
        r#"python -c 'from pathlib import Path; print(Path("/home/test/.kiro/hooks").stat())'"#,
        r#"python -c 'from pathlib import Path; parent=Path("/home/test/.kiro/hooks"); Path("/tmp/unrelated").chmod(0)'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            !structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let external_self_protection =
        SelfProtectionProjection::new(vec![absolute("/srv/kiro/hooks/nah.json")]);
    for source in [
        "chmod 000 /srv/kiro/hooks",
        r#"python -c 'import os; os.chmod("/srv/kiro", 0)'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, external_self_protection.clone());
        let observation = observe(plan.observation_request(), "echo");
        let (stream, report) = finalize_with_inline(plan, observation);
        assert!(
            structurally_protected(&stream, &report),
            "{source}: {:?}",
            stream.effects()
        );
    }

    let plan = bash_plan_with_self_protection("chmod 000 /srv", external_self_protection);
    let observation = observe(plan.observation_request(), "echo");
    let (stream, report) = finalize_with_inline(plan, observation);
    assert!(
        !structurally_protected(&stream, &report),
        "{:?}",
        stream.effects()
    );
}

#[test]
fn interpreter_mentions_and_read_only_access_do_not_claim_mutation() {
    let self_protection =
        SelfProtectionProjection::new(vec![absolute("/home/test/.kiro/hooks/nah.json")]);
    for source in [
        r#"python -c 'print("os.remove(\"/home/test/.kiro/hooks/nah.json\")")'"#,
        "python -c '# os.remove(\"/home/test/.kiro/hooks/nah.json\")'",
        r#"python -c 'from pathlib import Path; print(Path("/home/test/.kiro/hooks/nah.json").exists())'"#,
        r#"python -c 'from pathlib import Path; print(Path("/home/test/.kiro/hooks/nah.json").read_text())'"#,
        r#"python -c 'import os; os.remove("/tmp/unrelated")'"#,
        r#"python -c 'import os; print("/home/test/.kiro/hooks/nah.json"); os.remove("/tmp/unrelated")'"#,
        r#"python -c 'import os; os.remove("/tmp/unrelated"); print("/home/test/.kiro/hooks/nah.json")'"#,
        r#"python -c 'from pathlib import Path; protected=Path("/home/test/.kiro/hooks/nah.json"); Path("/tmp/a").rename("/tmp/b")'"#,
        r#"python -c 'import os; protected="/home/test/.local/bin/nah"; os.chmod("/tmp/unrelated", 0)'"#,
        r#"python -c 'from pathlib import Path; p=Path("/home/test/.kiro/hooks/nah.json"); P=Path("/tmp/a"); P.rename("/tmp/b")'"#,
        r#"python -c 'import os; os.remove(target)'"#,
        r#"python -c 'import os, shutil; os.remove(shutil.which("nah"))'"#,
        r#"python -c 'import os; os.remove=lambda path: None; os.remove("/home/test/.nah/trust.json")'"#,
        r#"python -c 'import os
def stop(): raise RuntimeError()
stop()
os.remove("/home/test/.nah/trust.json")'"#,
        r#"python -c 'import os; os.remove("/repo/bin/nah")'"#,
        r#"python -c 'print("nah hook kiro uninstall")'"#,
        r#"python -c 'print("unlink /home/test/.local/bin/nah")'"#,
        r#"python -c 'import subprocess; subprocess.run(["echo","claude","--safe-mode"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["env","CODEX_HOME=/home/test/.codex","codex"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["cat","/home/test/.nah/trust.json"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["echo","nah","hook","kiro","uninstall"])'"#,
        r#"python -c 'import subprocess; subprocess.run(["cat","/home/test/.nah/trust.json"], note="rm -rf /home/test/.nah")'"#,
        r#"python -c 'import shutil; shutil.copyfile("/home/test/.nah/trust.json", "/tmp/backup")'"#,
        r#"python -c 'import shutil; shutil.copyfile("/tmp/source", "/tmp/backup", dstuff="/home/test/.nah/trust.json")'"#,
        r#"python -c 'print(open("/home/test/.nah/trust.json", "r").read(), "w")'"#,
        r#"python -c 'open("/home/test/.nah/trust.json"); print("w")'"#,
        r#"perl -MFile::Copy -e 'copy("/home/test/.nah/trust.json", "/tmp/backup")'"#,
        r#"node -e 'require("fs").copyFileSync(process.env.HOME+"/.nah/trust.json", "/tmp/backup")'"#,
        r#"ruby -e 'FileUtils.cp("/home/test/.nah/trust.json", "/tmp/backup")'"#,
        r#"php -r 'copy("/home/test/.nah/trust.json", "/tmp/backup");'"#,
        r#"R -e 'file.copy("/home/test/.nah/trust.json", "/tmp/backup")'"#,
        r#"julia -e 'cp("/home/test/.nah/trust.json", "/tmp/backup")'"#,
        r#"swift -e 'try FileManager.default.copyItem(atPath: "/home/test/.nah/trust.json", toPath: "/tmp/backup")'"#,
        r#"python -c 'print(items.remove("ordinary"), "/home/test/.kiro/hooks/nah.json")'"#,
        r#"python -c 'import os; print(os.remove, "/home/test/.kiro/hooks/nah.json")'"#,
        r#"python -c 'import os; print(getattr(os, "chmod"), "/home/test/.local/bin/nah")'"#,
        r#"python -c 'import os; getattr(os, "stat")("/home/test/.local/bin/nah")'"#,
        r#"python -c 'import os; getattr(os, "delete")("/home/test/.local/bin/nah")'"#,
        r#"python -c 'import subprocess; getattr(subprocess, "echo")(["pi", "--no-extensions"])'"#,
        r#"python -c 'import subprocess; getattr(subprocess, "run")([print("pi"), "--no-extensions"])'"#,
        r#"python -c 'import os, types; os = types.SimpleNamespace(chmod=lambda *args: None); getattr(os, "chmod")("/home/test/.local/bin/nah", 0)'"#,
        r#"python -c 'import os, types; os = types.SimpleNamespace(remove=lambda *args: None); os.remove("/home/test/.local/bin/nah")'"#,
        r#"python -c 'import os; getattr(os, "chmod")([print("/home/test/.local/bin/nah")], 0)'"#,
        r#"python -c 'eval("print(\"/home/test/.nah/trust.json\")")'"#,
        r#"python -c 'print("\x2fhome\x2ftest\x2f.nah\x2ftrust.json")'"#,
        r#"python -c 'import os; os.remove(r"\x2fhome\x2ftest\x2f.nah\x2ftrust.json")'"#,
        r#"printf '%s' 'print("/home/test/.nah/trust.json")' | python"#,
        r#"printf '%s' 'print("/home/test/.nah/trust.json")' > /tmp/nah-check.py; python /tmp/nah-check.py"#,
        r#"python -- -c 'import os; os.remove("/home/test/.nah/trust.json")'"#,
        r#"node -- --eval 'require("fs").rmSync(process.env.HOME+"/.nah/trust.json")'"#,
        r#"ruby -- -e 'File.unlink("/home/test/.nah/trust.json")'"#,
        r#"node -e 'require("child_process"); console.log("pi --no-extensions")'"#,
        r#"node -e 'console.log(require("fs")["chmodSync"], "/home/test/.local/bin/nah")'"#,
        r#"node -e 'require("fs")["delete"]("/home/test/.local/bin/nah")'"#,
        r#"node -e 'require("child_process")["echo"]("pi", ["--no-extensions"])'"#,
        r#"ruby -e 'puts(File.send(:stat, "/home/test/.local/bin/nah"))'"#,
        r#"ruby -e 'File.send(:chmod, "/home/test/.local/bin/nah", 0)'"#,
        r#"php -r 'call_user_func("printf", "/home/test/.local/bin/nah");'"#,
        r#"php -r 'call_user_func("remove", "/home/test/.local/bin/nah");'"#,
        r#"node -e 'eval("console.log(process.env.HOME+\"/.nah/trust.json\")")'"#,
        r#"lua -e 'print([[os.remove("/home/test/.nah/trust.json")]])'"#,
        r#"ruby -e 'puts %q{File.unlink("/home/test/.nah/trust.json")}'"#,
        r#"perl -e 'print q{unlink /home/test/.nah/trust.json}'"#,
        r#"lua -e '-- os.remove("/home/test/.kiro/hooks/nah.json")'"#,
        "lua -e $'--[[\\nos.remove(\"/home/test/.kiro/hooks/nah.json\")\\n]]'",
        "julia -e $'#=\\nrm(\"/home/test/.kiro/hooks/nah.json\")\\n=#'",
        "pwsh -Command $'<#\\nRemove-Item \"$HOME/.kiro/hooks/nah.json\"\\n#>'",
        "ruby -e $'=begin\\nFile.unlink(File.join(ENV[\"HOME\"], \".nah/trust.json\"))\\n=end'",
        "perl -e $'=pod\\nunlink \"$ENV{HOME}/.local/bin/nah\";\\n=cut'",
        "perl -e $'=head1 harmless\\nunlink \"$ENV{HOME}/.local/bin/nah\";\\n=cut'",
        "swift -e $'/* outer /* nested */\\nFileManager.default.removeItem(atPath: \"/home/test/.nah/trust.json\")\\n*/'",
        r#"ruby -e 'puts(File.write, "/home/test/.kiro/hooks/nah.json")'"#,
        r#"pwsh -Command 'Write-Output "claude --safe-mode"'"#,
        r#"pwsh -Command 'Start-Process echo -ArgumentList "claude", "--safe-mode"'"#,
        r#"pwsh -Command 'Start-Process -FilePath echo -ArgumentList "claude", "--safe-mode"'"#,
        r#"pwsh -Command 'Start-Process -ArgumentList "claude", "--safe-mode" -FilePath "echo"'"#,
        r#"pwsh -Command 'Start-Process -ArgumentList "claude", "--safe-mode" -FilePath "C:\tools\echo.exe"'"#,
        r#"cmd /c 'echo claude --safe-mode'"#,
    ] {
        let plan = bash_plan_with_self_protection(source, self_protection.clone());
        let stream = finalize(plan.clone(), observe(plan.observation_request(), "echo"));
        assert!(
            !stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::Known { operation, .. }
                } if operation.as_str() == "critical-mutation"
            )),
            "{source}: {:?}",
            stream.effects()
        );
        assert!(
            stream.effects().iter().any(|effect| matches!(
                effect.kind(),
                EffectKind::Invocation {
                    invocation: InvocationEffect::CodeExecution { .. }
                }
            )),
            "{source}: {:?}",
            stream.effects()
        );
    }
}
