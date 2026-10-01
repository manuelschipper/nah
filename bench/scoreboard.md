# effinterp bench scoreboard

| plane | run | measured | engine | models |
|---|---|---|---|---|
| correctness | `20261001T223852Z-correctness-63712` | 2026-10-01T22:38:52Z | `0.1.0` | `builtin:blake3:6e946ee2386327541fcde865d3b6124dec075f5351efba6fbc1714a9d9815f95` |
| coverage | `20260927T155829Z-coverage-54709` | 2026-09-27T15:58:29Z | `0.1.0` | `builtin:blake3:e4a3aa943d572fb4a6c4ee6fa4eb7d50bafc33cdde32b27864e9d8f1a97b5272` |
| repositories | `20260921T153340Z-repositories-53884` | 2026-09-21T15:33:40Z | `0.1.0` | `builtin:blake3:f4c5b1246f8269fed8c419ed2832d4607967f1357aec6027b0f2bcac2d787f40` |
| performance | `20260921T150325Z-performance-62642` | 2026-09-21T15:03:25Z | `0.1.0` | `builtin:blake3:a73d1a25123b9661020f9e13dbb1528964df754bf91f93b64e2df5b98b703606` |

## 1. Invocation correctness

run `20261001T223852Z-correctness-63712` measured 2026-10-01T22:38:52Z

Independent effect, flow, and uncertainty expectations.

corpus `e7885f6d6e4ecc33d633408561ea540feeef8831c9b6a187cf618e62198cb396`

### Semantic fixtures

352 cases: 352 passed, 0 known gaps, 0 failures.

### Adversarial

| category | sound | boundary_only | silent_miss | wrong_resource | crash | deadline |
|---|---|---|---|---|---|---|
| all | 304 | 22 | 0 | 0 | 0 | 0 |
| bounds | 18 | 0 | 0 | 0 | 0 | 0 |
| controlflow | 22 | 0 | 0 | 0 | 0 | 0 |
| indirection | 70 | 4 | 0 | 0 | 0 | 0 |
| inline | 30 | 4 | 0 | 0 | 0 | 0 |
| modality | 46 | 5 | 0 | 0 | 0 | 0 |
| netsecret | 16 | 4 | 0 | 0 | 0 | 0 |
| path | 21 | 1 | 0 | 0 | 0 | 0 |
| quoting | 40 | 0 | 0 | 0 | 0 | 0 |
| redirection | 24 | 0 | 0 | 0 | 0 | 0 |
| srcinline | 17 | 4 | 0 | 0 | 0 | 0 |

silent drops: 326 rows tested, 71 mutants, 0 drops

### nah parity

nah `24c034ee84e892e6d422ba65d6113d2d9c16d16c` / corpus `063aff88b89df72616863ee25a98b91d8178dab85f36d371f70536c6660b6c8d`

| class | count |
|---|---|
| effect_match | 5149 |
| silent_symbolic_drop | 2 |
| missing_effect | 12 |
| missing_flow | 2 |
| covered | 1427 |
| explained_partial | 1762 |

| file | effect_match | silent_symbolic_drop | missing_effect | missing_flow | covered | explained_partial |
|---|---|---|---|---|---|---|
| code.jsonl | 47 | 0 | 0 | 0 | 15 | 9 |
| compound.jsonl | 196 | 0 | 0 | 0 | 43 | 83 |
| database-services.jsonl | 209 | 0 | 2 | 0 | 32 | 95 |
| database.jsonl | 174 | 0 | 3 | 0 | 141 | 152 |
| execution-flows.jsonl | 527 | 0 | 0 | 0 | 123 | 206 |
| filesystem.jsonl | 721 | 0 | 1 | 0 | 249 | 145 |
| git.jsonl | 791 | 0 | 0 | 0 | 307 | 167 |
| infrastructure.jsonl | 258 | 0 | 0 | 0 | 12 | 135 |
| kubernetes.jsonl | 41 | 0 | 0 | 0 | 1 | 25 |
| local-utilities.jsonl | 4 | 0 | 0 | 0 | 42 | 9 |
| macos.jsonl | 61 | 0 | 0 | 0 | 30 | 16 |
| native.jsonl | 55 | 0 | 0 | 0 | 20 | 4 |
| network.jsonl | 24 | 2 | 1 | 0 | 7 | 6 |
| project.jsonl | 4 | 0 | 0 | 0 | 17 | 1 |
| registry.jsonl | 188 | 0 | 0 | 0 | 6 | 102 |
| secrets.jsonl | 759 | 0 | 3 | 2 | 188 | 205 |
| self-protection.jsonl | 639 | 0 | 2 | 0 | 111 | 286 |
| shell-resolution.jsonl | 183 | 0 | 0 | 0 | 26 | 25 |
| storage.jsonl | 138 | 0 | 0 | 0 | 8 | 51 |
| threat-model.jsonl | 9 | 0 | 0 | 0 | 12 | 6 |
| windows.jsonl | 121 | 0 | 0 | 0 | 37 | 34 |

| guard | effect_match | silent_symbolic_drop | missing_effect | missing_flow | covered | explained_partial |
|---|---|---|---|---|---|---|
| (structural) | 660 | 0 | 2 | 0 | 0 | 166 |
| db-destroy | 374 | 0 | 5 | 0 | 0 | 37 |
| exec-decoded | 55 | 0 | 0 | 0 | 0 | 4 |
| exec-network-shell | 56 | 0 | 0 | 0 | 0 | 1 |
| exec-obfuscated | 49 | 0 | 0 | 0 | 0 | 1 |
| exec-remote | 236 | 0 | 0 | 0 | 0 | 4 |
| fs-auth-identity | 103 | 0 | 0 | 0 | 0 | 2 |
| fs-forkbomb | 24 | 0 | 0 | 0 | 0 | 0 |
| fs-home | 212 | 0 | 1 | 0 | 0 | 8 |
| fs-outside-workspace-delete | 42 | 0 | 0 | 0 | 0 | 0 |
| fs-permission-weaken | 55 | 0 | 0 | 0 | 0 | 0 |
| fs-project-root | 59 | 0 | 0 | 0 | 0 | 0 |
| fs-raw-device | 40 | 0 | 0 | 0 | 0 | 0 |
| fs-shell-profile | 35 | 0 | 0 | 0 | 0 | 0 |
| fs-startup-management | 37 | 0 | 0 | 0 | 0 | 0 |
| fs-startup-persistence | 49 | 0 | 0 | 0 | 0 | 0 |
| fs-system-tree | 553 | 0 | 0 | 0 | 0 | 8 |
| fs-volume-destroy | 34 | 0 | 0 | 0 | 0 | 0 |
| git-clean-force | 53 | 0 | 0 | 0 | 0 | 0 |
| git-force-push | 56 | 0 | 0 | 0 | 0 | 1 |
| git-hard-reset | 42 | 0 | 0 | 0 | 0 | 0 |
| git-history-rewrite | 48 | 0 | 0 | 0 | 0 | 0 |
| git-metadata | 43 | 0 | 0 | 0 | 0 | 0 |
| git-path-discard | 38 | 0 | 0 | 0 | 0 | 0 |
| git-protected-push | 38 | 0 | 0 | 0 | 0 | 0 |
| git-recovery-destroy | 97 | 0 | 0 | 0 | 0 | 0 |
| git-ref-delete | 46 | 0 | 0 | 0 | 0 | 0 |
| git-remote-repo-delete | 189 | 0 | 0 | 0 | 0 | 0 |
| git-remote-resource-delete | 44 | 0 | 0 | 0 | 0 | 0 |
| git-rewrite-force | 43 | 0 | 0 | 0 | 0 | 0 |
| git-worktree-discard | 66 | 0 | 0 | 0 | 0 | 0 |
| infra-cloud-delete | 29 | 0 | 0 | 0 | 0 | 0 |
| infra-container-reset | 37 | 0 | 0 | 0 | 0 | 0 |
| infra-container-volume-delete | 51 | 0 | 0 | 0 | 0 | 0 |
| infra-iac-destroy | 127 | 0 | 0 | 0 | 0 | 0 |
| infra-k8s-delete | 42 | 0 | 0 | 0 | 0 | 0 |
| net-lookalike-host | 24 | 2 | 1 | 0 | 0 | 1 |
| registry-publish | 62 | 0 | 0 | 0 | 0 | 0 |
| registry-unpublish | 127 | 0 | 0 | 0 | 0 | 0 |
| secrets-credentials | 179 | 0 | 0 | 0 | 0 | 6 |
| secrets-env | 119 | 0 | 0 | 0 | 0 | 0 |
| secrets-exfil | 503 | 0 | 3 | 2 | 0 | 3 |
| secrets-store-delete | 40 | 0 | 0 | 0 | 0 | 0 |
| secrets-store-destroy | 61 | 0 | 0 | 0 | 0 | 0 |
| secrets-store-read | 57 | 0 | 0 | 0 | 0 | 0 |
| storage-backup-destroy | 28 | 0 | 0 | 0 | 0 | 0 |
| storage-recursive-delete | 43 | 0 | 0 | 0 | 0 | 0 |
| storage-snapshot-delete | 61 | 0 | 0 | 0 | 0 | 0 |
| sys-power | 34 | 0 | 0 | 0 | 0 | 0 |
| sys-service-stop | 49 | 0 | 0 | 0 | 0 | 0 |

## 2. Invocation coverage

run `20260927T155829Z-coverage-54709` measured 2026-09-27T15:58:29Z

Reported completeness, not independently verified accuracy. Dynamic and unavailable inputs remain separate.

corpus `7fe3b8d3419bcc0de735b0290154360a80fa4d5e39520168d26f6182f1680a03`

### nah

5582 rows, weight 5582

**understood what it could: 68.54%** (3826 rows; complete 60.39%)

| bucket | unique | weighted |
|---|---|---|
| complete | 3371 | 60.39% |
| dynamic | 42 | 0.75% |
| unobservable | 413 | 7.40% |
| gap | 1756 | 31.46% |
| metric | weighted |
|---|---|
| any domain coverage=none | 5.28% |
| all domains coverage=full | 60.39% |
| effects only process.exec | 6.25% |
| failure panic | 0  |
| failure deadline | 0  |
| failure analysis | 0  |
| failure invalid_subject | 0  |
| silent drops | 3371 rows tested, 658 mutants, 0 drops |

| gap class | unique | weighted |
|---|---|---|
| unmodeled | 1213 | 21.73% |
| unresolved | 710 | 12.72% |
| parse_failure | 5 | 0.09% |
| limit | 11 | 0.20% |
| unsupported | 71 | 1.27% |

| kind | rows | complete |
|---|---|---|
| code | 67 | 62.69% |
| shell | 5439 | 59.83% |
| tool | 76 | 98.68% |

| reason | tier | any | unique | sole | top commands |
|---|---|---|---|---|---|
| unrecoverable_source | unobservable | 9.89% | 552 | 2.28% |  |
| environment_configuration | gap | 8.87% | 495 | 4.75% | `python3` 1.56%, `python` 1.50%, `terraform` 1.04%, `git` 0.79%, `npm` 0.70% |
| dynamic_source | dynamic | 5.97% | 333 | 0.41% |  |
| unmodeled_command | gap | 4.68% | 261 | 3.60% | `work` 0.39%, `terraform` 0.13%, `get_source` 0.07%, `prime-agent` 0.07%, `cline` 0.05% |
| unmodeled_hooks | gap | 3.89% | 217 | 3.24% | `git` 3.31%, `cargo` 0.21%, `env` 0.07%, `bash` 0.05%, `sh` 0.04% |
| unrecognized_arguments | gap | 3.82% | 213 | 2.81% | `pwsh` 0.48%, `tar` 0.47%, `git` 0.21%, `pulumi` 0.21%, `gh` 0.20% |
| partial_analysis | gap | 2.99% | 167 | 0.34% | `terraform` 1.00%, `aws` 0.45%, `tofu` 0.45%, `kubectl` 0.25%, `az` 0.18% |
| live_inventory | gap | 2.58% | 144 | 0.82% | `podman` 0.50%, `docker` 0.36%, `borg` 0.32%, `restic` 0.32%, `kubectl` 0.30% |
| daemon_transport | gap | 2.42% | 135 | 1.11% | `docker` 1.11%, `podman` 0.66%, `xargs` 0.20%, `docker-compose` 0.11%, `podman-compose` 0.09% |
| provider_io | gap | 1.85% | 103 | 0.02% | `terraform` 0.97%, `tofu` 0.43%, `env` 0.11%, `command` 0.05%, `--auto-approve` 0.04% |
| unmodeled_subcommand | gap | 1.68% | 94 | 1.07% | `git` 0.27%, `podman` 0.27%, `aws` 0.20%, `az` 0.16%, `gcloud` 0.14% |
| model_coverage | gap | 1.58% | 88 | 0.97% | `find` 0.52%, `npm` 0.34%, `nah` 0.11%, `gh` 0.07%, `borg` 0.05% |
| unmodeled_dynamic | gap | 1.25% | 70 | 0.84% | `pwsh` 0.21%, `openclaw` 0.11%, `droid` 0.07%, `env` 0.07%, `codex` 0.05% |
| cluster_api | gap | 1.22% | 68 | 0.61% | `kubectl` 1.07%, `timeout` 0.04%, `bash` 0.02%, `command` 0.02%, `env` 0.02% |
| input_determined_arguments | dynamic | 0.77% | 43 | 0.30% |  |
| observation_unavailable | gap | 0.63% | 35 | 0.38% | `cargo` 0.34%, `find` 0.29% |
| package_scripts | gap | 0.61% | 34 | 0.13% | `npm` 0.20%, `npx` 0.09%, `pnpm` 0.07%, `bunx` 0.05%, `uv` 0.05% |
| unresolved_source | unobservable | 0.54% | 30 | 0.34% |  |
| frontend_partial | gap | 0.52% | 29 | 0.32% | `python` 0.13% |
| unresolved_command | gap | 0.27% | 15 | 0.20% | `target` 0.04%, `$COND` 0.02%, `ITEMS["${outer:-${target:=0}}"]=value` 0.02%, `ITEMS["${target:=0}"]=value` 0.02%, `env` 0.02% |
| unresolved_call | gap | 0.25% | 14 | 0.18% | `node` 0.07%, `ruby` 0.07%, `python` 0.05%, `await` 0.02%, `deno` 0.02% |
| unsupported_shell_syntax | gap | 0.25% | 14 | 0.16% | `exec` 0.09%, `printf` 0.04%, `set` 0.04%, `<&` 0.02%, `RANDOM))` 0.02% |
| execution_cycle | gap | 0.20% | 11 | 0.18% | `bomb` 0.05%, `f` 0.05%, `first` 0.05%, `:` 0.02%, `bash` 0.02% |
| reviewed_command_surface | gap | 0.18% | 10 | 0.16% | `restic` 0.04%, `aws` 0.02%, `az` 0.02%, `borg` 0.02%, `cargo` 0.02% |
| unresolved_build_target | unobservable | 0.16% | 9 | 0.02% |  |
| unmodeled_import | gap | 0.13% | 7 | 0.00% | `import` 0.07%, `python3` 0.05% |
| dynamic_dispatch | gap | 0.11% | 6 | 0.00% | `python` 0.07%, `python3` 0.04% |
| unresolved_package_script | unobservable | 0.11% | 6 | 0.00% |  |
| external_unmodeled | gap | 0.09% | 5 | 0.00% | `python3` 0.05%, `python` 0.04% |
| parse_error | gap | 0.09% | 5 | 0.04% | `python3` 0.04%, `<(unclosed` 0.02%, `ipython` 0.02%, `unclosed` 0.02% |

| unmodeled exe | any | unique | sole |
|---|---|---|---|
| work | 0.39% | 22 | 0.38% |
| terraform | 0.13% | 7 | 0.00% |
| get_source | 0.07% | 4 | 0.00% |
| prime-agent | 0.07% | 4 | 0.05% |
| cline | 0.05% | 3 | 0.05% |
| ssh-keygen | 0.05% | 3 | 0.05% |
| 1 | 0.04% | 2 | 0.02% |
| count | 0.04% | 2 | 0.04% |
| devin | 0.04% | 2 | 0.04% |
| echo | 0.04% | 2 | 0.02% |
| get_host | 0.04% | 2 | 0.02% |
| herdr | 0.04% | 2 | 0.02% |
| i++ | 0.04% | 2 | 0.04% |
| journalctl | 0.04% | 2 | 0.04% |
| notarealwrapper | 0.04% | 2 | 0.04% |
| rm? | 0.04% | 2 | 0.04% |
| second | 0.04% | 2 | 0.02% |
| some_condition | 0.04% | 2 | 0.00% |
| --help | 0.02% | 1 | 0.00% |
| 1+1 | 0.02% | 1 | 0.02% |
| R.exe | 0.02% | 1 | 0.02% |
| RM | 0.02% | 1 | 0.02% |
| \u{e}2 | 0.02% | 1 | 0.00% |
| aws | 0.02% | 1 | 0.00% |
| blkid | 0.02% | 1 | 0.02% |
| build | 0.02% | 1 | 0.00% |
| condition | 0.02% | 1 | 0.00% |
| disown | 0.02% | 1 | 0.02% |
| env | 0.02% | 1 | 0.00% |
| first | 0.02% | 1 | 0.00% |
| foo | 0.02% | 1 | 0.02% |
| hexdump | 0.02% | 1 | 0.02% |
| icacls | 0.02% | 1 | 0.02% |
| kiro-cli | 0.02% | 1 | 0.02% |
| kubectl | 0.02% | 1 | 0.00% |
| last | 0.02% | 1 | 0.02% |
| let | 0.02% | 1 | 0.00% |
| local.sh | 0.02% | 1 | 0.00% |
| lsblk | 0.02% | 1 | 0.02% |
| lvchange | 0.02% | 1 | 0.02% |

### swe

30052 rows, weight 743963

**understood what it could: 48.40%** (15618 rows; complete 44.79%)

| bucket | unique | weighted |
|---|---|---|
| complete | 14561 | 44.79% |
| dynamic | 286 | 0.64% |
| unobservable | 771 | 2.98% |
| gap | 14434 | 51.60% |
| metric | weighted |
|---|---|
| any domain coverage=none | 18.21% |
| all domains coverage=full | 44.79% |
| effects only process.exec | 16.68% |
| failure panic | 0  |
| failure deadline | 0  |
| failure analysis | 0  |
| failure invalid_subject | 0  |
| silent drops | 0 rows tested, 0 mutants, 0 drops |

| gap class | unique | weighted |
|---|---|---|
| unmodeled | 8031 | 27.24% |
| unresolved | 7593 | 26.50% |
| parse_failure | 258 | 0.54% |
| limit | 13 | 0.02% |
| unsupported | 344 | 0.93% |

| kind | rows | complete |
|---|---|---|
| nebius-swe-agent | 1181 | 30.77% |
| swegym-openhands-sft | 118 | 28.71% |
| swehero-openhands | 5017 | 29.65% |
| swesmith-tool | 1103 | 32.63% |
| tbench2 | 22633 | 48.73% |

| reason | tier | any | unique | sole | top commands |
|---|---|---|---|---|---|
| environment_configuration | gap | 23.77% | 7088 | 1.89% | `python` 14.84%, `python3` 8.27%, `timeout` 0.18%, `nohup` 0.14%, `bash` 0.10% |
| unrecoverable_source | unobservable | 22.43% | 4683 | 0.69% |  |
| dynamic_source | dynamic | 16.12% | 3036 | 0.39% |  |
| unmodeled_command | gap | 16.07% | 3953 | 10.21% | `C-c` 1.57%, `sim` 1.02%, `mailman` 0.69%, `gcc` 0.64%, `g++` 0.54% |
| unresolved_call | gap | 5.48% | 2941 | 0.06% | `python3` 2.71%, `python` 2.57%, `node` 0.07%, `timeout` 0.05%, `python3.12` 0.02% |
| unmodeled_import | gap | 4.48% | 2316 | 0.00% | `python` 2.58%, `python3` 1.78%, `timeout` 0.05%, `python3.11` 0.02%, `python3.12` 0.02% |
| unrecognized_arguments | gap | 4.25% | 1339 | 3.62% | `7z` 1.19%, `ps` 0.58%, `vim` 0.58%, `pytest` 0.24%, `od` 0.22% |
| package_scripts | gap | 3.85% | 1119 | 3.02% | `apt-get` 1.66%, `pip` 1.15%, `pip3` 0.34%, `apt` 0.27%, `python3` 0.24% |
| dynamic_dispatch | gap | 3.24% | 1843 | 0.00% | `python3` 1.84%, `python` 1.30%, `timeout` 0.04%, `python3.11` 0.01%, `bash` 0.01% |
| unresolved_build_target | unobservable | 2.19% | 552 | 0.89% |  |
| unresolved_command | gap | 2.06% | 149 | 1.98% | `$3a` 0.17%, `$3c` 0.15%, `$3b` 0.15%, `$3d` 0.14%, `$3e` 0.14% |
| model_coverage | gap | 1.49% | 943 | 1.38% | `grep` 1.37%, `find` 0.11%, `e.py` 0.00%, `echo` 0.00%, `#` 0.00% |
| external_unmodeled | gap | 1.19% | 706 | 0.00% | `python3` 0.83%, `python` 0.33%, `PRAGMA` 0.01%, `bash` 0.00%, `cd` 0.00% |
| unmodeled_hooks | gap | 0.75% | 193 | 0.45% | `git` 0.61%, `sshpass` 0.08%, `-p` 0.01%, `time` 0.01%, `-i` 0.01% |
| unmodeled_subcommand | gap | 0.66% | 190 | 0.51% | `apt-get` 0.16%, `pip` 0.15%, `git` 0.14%, `apt` 0.05%, `pip3` 0.05% |
| parse_error | gap | 0.54% | 258 | 0.16% | `bash` 0.10%, `for` 0.05%, `python3` 0.05%, `if` 0.05%, `<<'EOF` 0.04% |
| frontend_partial | gap | 0.54% | 340 | 0.00% | `python3` 0.33%, `python` 0.20%, `timeout` 0.01%, `$PYTHON` 0.00%, `su` 0.00% |
| unsupported_sql | gap | 0.31% | 98 | 0.29% | `sqlite3` 0.30%, `v` 0.01%, `echo` 0.00% |
| unsupported_shell_syntax | gap | 0.29% | 132 | 0.14% | `seq` 0.07%, `}` 0.04%, `bash` 0.02%, `cat` 0.02%, `fi` 0.01% |
| input_determined_arguments | dynamic | 0.29% | 181 | 0.25% |  |
| unresolved_source | unobservable | 0.28% | 93 | 0.02% |  |
| unparsed_script | gap | 0.13% | 54 | 0.08% | `sed` 0.07%, `awk` 0.02%, `html` 0.01%, `+chunk-1));` 0.01%, `_dag.csv;` 0.00% |
| unmodeled_dynamic | gap | 0.10% | 61 | 0.00% | `python3` 0.07%, `python` 0.03%, `amp` 0.01%, `python3.11` 0.00%, `$PYTHON` 0.00% |
| no_entry_point | gap | 0.07% | 46 | 0.00% | `python` 0.05%, `python3` 0.02% |
| untyped_resource | gap | 0.06% | 25 | 0.00% | `bash` 0.01%, `x:` 0.01%, `bounds` 0.01%, `attrs_to_remove` 0.01%, `df,` 0.00% |
| unmodeled_inline_code | gap | 0.02% | 11 | 0.00% | `git` 0.02%, `ho` 0.00%, `>&1;` 0.00% |
| limit_saturated | gap | 0.02% | 13 | 0.00% | `bash` 0.00%, `python3` 0.00%, `{1..100000}` 0.00%, `{130000..139999}` 0.00%, `{230000..239999}` 0.00% |
| cross_module | gap | 0.01% | 7 | 0.00% | `python3` 0.01%, `python` 0.00% |
| missing_required_arguments | gap | 0.01% | 2 | 0.00% | `Conte` 0.01% |
| daemon_transport | gap | 0.01% | 5 | 0.00% | `docker` 0.01% |

| unmodeled exe | any | unique | sole |
|---|---|---|---|
| C-c | 1.57% | 7 | 1.57% |
| sim | 1.02% | 120 | 0.00% |
| mailman | 0.69% | 196 | 0.62% |
| gcc | 0.64% | 169 | 0.41% |
| g++ | 0.54% | 71 | 0.45% |
| configure | 0.53% | 141 | 0.00% |
| tesseract | 0.40% | 174 | 0.30% |
| opam | 0.34% | 142 | 0.12% |
| release | 0.33% | 35 | 0.00% |
| nginx | 0.31% | 68 | 0.24% |
| find. | 0.31% | 18 | 0.31% |
| yt-dlp | 0.25% | 94 | 0.21% |
| {keystrokes: | 0.24% | 13 | 0.24% |
| postconf | 0.24% | 96 | 0.20% |
| john | 0.22% | 73 | 0.01% |
| oligotm | 0.21% | 106 | 0.18% |
| postfix | 0.21% | 56 | 0.14% |
| a.out | 0.18% | 48 | 0.00% |
| pmars | 0.17% | 49 | 0.13% |
| povray | 0.16% | 31 | 0.00% |
| qemu-system-i386 | 0.15% | 60 | 0.14% |
| debug | 0.15% | 17 | 0.00% |
| valgrind | 0.15% | 46 | 0.14% |
| pdftotext | 0.15% | 43 | 0.13% |
| ccomp | 0.14% | 40 | 0.00% |
| venv | 0.13% | 41 | 0.00% |
| cd.. | 0.13% | 5 | 0.11% |
| hexdump | 0.13% | 50 | 0.12% |
| apt-cache | 0.13% | 45 | 0.11% |
| C-d | 0.13% | 4 | 0.13% |
| cobc | 0.12% | 37 | 0.08% |
| gdb | 0.12% | 49 | 0.08% |
| readelf | 0.11% | 28 | 0.10% |
| from | 0.11% | 22 | 0.05% |
| objdump | 0.11% | 23 | 0.09% |
| ffmpeg | 0.10% | 48 | 0.09% |
| mkdir.git | 0.10% | 1 | 0.10% |
| convert | 0.10% | 58 | 0.06% |
| useradd | 0.10% | 33 | 0.04% |
| program | 0.10% | 15 | 0.00% |

### wild

7975 rows, weight 7975

**understood what it could: 37.33%** (2977 rows; complete 20.83%)

| bucket | unique | weighted |
|---|---|---|
| complete | 1661 | 20.83% |
| dynamic | 69 | 0.87% |
| unobservable | 1247 | 15.64% |
| gap | 4997 | 62.66% |
| metric | weighted |
|---|---|
| any domain coverage=none | 38.14% |
| all domains coverage=full | 20.83% |
| effects only process.exec | 23.80% |
| failure panic | 0  |
| failure deadline | 1 wild-7721 |
| failure analysis | 0  |
| failure invalid_subject | 0  |
| silent drops | 1661 rows tested, 432 mutants, 7 drops |

| gap class | unique | weighted |
|---|---|---|
| unmodeled | 3894 | 48.83% |
| unresolved | 1808 | 22.67% |
| parse_failure | 134 | 1.68% |
| limit | 11 | 0.14% |
| unsupported | 201 | 2.52% |

| kind | rows | complete |
|---|---|---|
| dockerfile | 797 | 26.35% |
| gha_run | 3432 | 24.94% |
| installer | 22 | 0.00% |
| justfile | 6 | 0.00% |
| makefile | 1757 | 17.59% |
| oneliner | 245 | 38.37% |
| pkgjson | 1392 | 11.14% |
| shscript | 324 | 11.42% |

| reason | tier | any | unique | sole | top commands |
|---|---|---|---|---|---|
| unmodeled_command | gap | 28.44% | 2268 | 13.35% | `breeze` 1.42%, `gulp` 0.94%, `call` 0.82%, `rustup` 0.54%, `next` 0.50% |
| unrecoverable_source | unobservable | 26.02% | 2075 | 0.53% |  |
| unresolved_command | gap | 12.48% | 995 | 7.49% | `${MKDIR_P}` 1.33%, `${MAKE}` 1.17%, `${CC}` 0.73%, `call` 0.66%, `${PYTHON}` 0.59% |
| dynamic_source | dynamic | 11.76% | 938 | 0.50% |  |
| package_scripts | gap | 10.63% | 848 | 3.07% | `uv` 2.08%, `pip` 1.42%, `apt-get` 1.33%, `python3` 1.18%, `sudo` 1.00% |
| unrecognized_arguments | gap | 10.42% | 831 | 4.24% | `uv` 1.72%, `gh` 1.32%, `git` 0.90%, `tar` 0.48%, `deno` 0.44% |
| unmodeled_subcommand | gap | 6.97% | 556 | 4.15% | `openssl` 2.70%, `git` 0.60%, `docker` 0.56%, `brew` 0.46%, `apt-get` 0.44% |
| environment_configuration | gap | 5.94% | 474 | 0.15% | `python3` 2.58%, `python` 2.01%, `uv` 0.41%, `docker` 0.16%, `echo` 0.14% |
| unresolved_package_script | unobservable | 5.83% | 465 | 0.98% |  |
| unresolved_build_target | unobservable | 5.22% | 416 | 2.39% |  |
| daemon_transport | gap | 1.89% | 151 | 0.64% | `docker` 1.76%, `podman` 0.09%, `set` 0.09%, `#` 0.05%, `xargs` 0.04% |
| unresolved_source | unobservable | 1.77% | 141 | 0.06% |  |
| unsupported_shell_syntax | gap | 1.73% | 138 | 0.20% | `seq` 0.13%, `else` 0.09%, `find` 0.09%, `then` 0.09%, `fi` 0.06% |
| parse_error | gap | 1.68% | 134 | 0.18% | `<` 0.56%, `if` 0.16%, `\|` 0.15%, `<<EOT` 0.14%, `for` 0.14% |
| unmodeled_hooks | gap | 1.35% | 108 | 0.10% | `git` 1.29%, `cargo` 0.04%, `!` 0.03%, `env` 0.01%, `eploy` 0.01% |
| input_determined_arguments | dynamic | 1.03% | 82 | 0.15% |  |
| partial_analysis | gap | 0.93% | 74 | 0.38% | `aws` 0.54%, `kubectl` 0.14%, `gcloud` 0.08%, `terraform` 0.06%, `az` 0.04% |
| unparsed_script | gap | 0.90% | 72 | 0.34% | `sed` 0.54%, `set` 0.10%, `xargs` 0.05%, ``g'`;`` 0.04%, `.` 0.03% |
| unresolved_call | gap | 0.78% | 62 | 0.13% | `python3` 0.19%, `node` 0.15%, `python` 0.14%, `echo` 0.08%, `bash` 0.06% |
| model_coverage | gap | 0.65% | 52 | 0.10% | `docker` 0.15%, `gh` 0.15%, `npm` 0.11%, `find` 0.05%, `grep` 0.05% |
| unmodeled_import | gap | 0.40% | 32 | 0.00% | `python` 0.16%, `python3` 0.11%, `echo` 0.04%, `bash` 0.03%, `#` 0.01% |
| external_unmodeled | gap | 0.31% | 25 | 0.00% | `python3` 0.13%, `python` 0.09%, `bash` 0.04%, `SL` 0.03%, `echo` 0.01% |
| remote_command | dynamic | 0.25% | 20 | 0.20% |  |
| unresolved_transfer_target | gap | 0.24% | 19 | 0.04% | `scp` 0.13%, `aws` 0.10%, `rsync` 0.01% |
| untyped_resource | gap | 0.24% | 19 | 0.00% | `docker` 0.05%, `python3` 0.04%, `uv` 0.04%, `aws` 0.03%, `xargs` 0.03% |
| cluster_api | gap | 0.20% | 16 | 0.03% | `kubectl` 0.19%, `!` 0.01%, `bash` 0.01% |
| dynamic_dispatch | gap | 0.19% | 15 | 0.00% | `python3` 0.08%, `python` 0.05%, `bash` 0.04%, `SL` 0.03% |
| limit_saturated | gap | 0.11% | 9 | 0.01% | `echo` 0.03%, `*` 0.01%, `local` 0.01%, `need_cmd` 0.01%, `null` 0.01% |
| reviewed_command_surface | gap | 0.10% | 8 | 0.00% | `bun` 0.10% |
| unmodeled_dynamic | gap | 0.09% | 7 | 0.01% | `gh` 0.05%, `exec` 0.01%, `python` 0.01%, `{` 0.01% |

| unmodeled exe | any | unique | sole |
|---|---|---|---|
| breeze | 1.42% | 113 | 1.34% |
| gulp | 0.94% | 75 | 0.60% |
| call | 0.82% | 65 | 0.00% |
| rustup | 0.54% | 43 | 0.43% |
| next | 0.50% | 40 | 0.36% |
| apk | 0.49% | 39 | 0.38% |
| shell | 0.39% | 31 | 0.01% |
| addprefix | 0.35% | 28 | 0.11% |
| run-jest.sh | 0.33% | 26 | 0.00% |
| ng | 0.31% | 25 | 0.14% |
| concurrently | 0.30% | 24 | 0.14% |
| dpkg | 0.29% | 23 | 0.06% |
| configure | 0.26% | 21 | 0.00% |
| gpg | 0.26% | 21 | 0.06% |
| borp | 0.21% | 17 | 0.18% |
| info | 0.21% | 17 | 0.00% |
| finalize_version_update | 0.20% | 16 | 0.00% |
| compare_dependency_version | 0.19% | 15 | 0.00% |
| jest | 0.19% | 15 | 0.16% |
| useradd | 0.19% | 15 | 0.09% |
| -fo=$^@ | 0.18% | 14 | 0.00% |
| corepack | 0.18% | 14 | 0.03% |
| deemon | 0.18% | 14 | 0.18% |
| umask | 0.18% | 14 | 0.01% |
| venv | 0.18% | 14 | 0.00% |
| buf | 0.16% | 13 | 0.13% |
| rimraf | 0.16% | 13 | 0.04% |
| webpack | 0.16% | 13 | 0.14% |
| zig | 0.16% | 13 | 0.15% |
| New-Item | 0.15% | 12 | 0.03% |
| adduser | 0.15% | 12 | 0.04% |
| log_and_verify_sha256sum | 0.15% | 12 | 0.00% |
| napi | 0.15% | 12 | 0.13% |
| playwright | 0.15% | 12 | 0.06% |
| add-apt-repository | 0.14% | 11 | 0.01% |
| biome | 0.14% | 11 | 0.11% |
| dir | 0.14% | 11 | 0.00% |
| install.sh | 0.14% | 11 | 0.01% |
| mod | 0.14% | 11 | 0.00% |
| npm-run-all2 | 0.14% | 11 | 0.14% |

| drop id | word | operation |
|---|---|---|
| wild-1642 | `https://github.com/github/cli.github.com.git` | network.download |
| wild-2984 | `https://github.com/huggingface/transformers` | network.download |
| wild-2995 | `https://github.com/NVIDIA/apex` | network.download |
| wild-6141 | `https://github.com/bats-core/bats-core.git` | network.download |
| wild-7008 | `https://github.com/hyperium/hyper.git` | network.download |
| wild-7012 | `https://github.com/quinn-rs/quinn.git` | network.download |
| wild-7924 | `https://github.com/org/repo.git` | network.download |

## 3. Repository coverage

run `20260921T153340Z-repositories-53884` measured 2026-09-21T15:33:40Z

Reported completeness over entrypoints; not a whole-repository accuracy score.

corpus `354dda6f5d4676045f3b59762021c9d80700e67327fe58636bf955b25f097961`

**understood what it could: 32.57%** (mean over 87 repositories)

| stratum | value | repos | understood | complete |
|---|---|---|---|---|
| era | post-ai | 21 | 24.38% | 5.33% |
| era | pre-ai | 66 | 35.18% | 6.96% |
| language | go | 11 | 33.67% | 3.33% |
| language | java | 8 | 42.65% | 8.06% |
| language | js | 15 | 20.29% | 2.29% |
| language | php | 7 | 39.33% | 12.40% |
| language | python | 19 | 35.65% | 7.39% |
| language | ruby | 9 | 20.86% | 5.87% |
| language | rust | 10 | 36.29% | 8.48% |
| language | shell | 8 | 39.35% | 8.84% |
| shape | agent-runtime | 13 | 29.42% | 6.67% |
| shape | agent-tooling | 4 | 21.90% | 1.74% |
| shape | artisan | 1 | 37.50% | 12.50% |
| shape | async-client | 1 | 8.79% | 0.00% |
| shape | autoload-include-chain | 1 | 66.00% | 19.00% |
| shape | axum-routes | 1 | 37.58% | 6.94% |
| shape | bin-plus-lib | 1 | 48.93% | 17.02% |
| shape | build-script | 1 | 48.93% | 17.02% |
| shape | build-tool | 1 | 60.00% | 14.00% |
| shape | callbacks | 1 | 25.00% | 0.00% |
| shape | ci | 1 | 24.51% | 8.82% |
| shape | ci-heavy | 2 | 46.90% | 5.65% |
| shape | clap-command-tree | 2 | 53.76% | 1.85% |
| shape | cli | 26 | 31.99% | 6.74% |
| shape | cli-gem | 5 | 31.11% | 8.61% |
| shape | click-command-tree | 1 | 46.75% | 9.09% |
| shape | cobra-command-tree | 8 | 20.89% | 2.33% |
| shape | command-runner | 1 | 48.38% | 12.90% |
| shape | commonjs | 3 | 21.27% | 1.98% |
| shape | composer-app | 3 | 35.04% | 18.44% |
| shape | console-script | 6 | 45.12% | 5.19% |
| shape | cron | 1 | 18.84% | 16.05% |
| shape | curl-download | 3 | 29.03% | 10.24% |
| shape | docker-compose | 2 | 29.76% | 11.91% |
| shape | dsl | 1 | 17.65% | 0.00% |
| shape | dsl-routes | 1 | 0.00% | 0.00% |
| shape | dynamic-import-wrapper | 1 | 13.69% | 2.38% |
| shape | env-manager | 5 | 40.35% | 9.09% |
| shape | esm | 4 | 16.97% | 1.32% |
| shape | exec-dispatch | 2 | 32.26% | 10.22% |
| shape | fastapi-routes | 2 | 29.76% | 11.91% |
| shape | formatter | 2 | 30.22% | 5.74% |
| shape | generated-code | 1 | 72.73% | 0.00% |
| shape | git-subprocess | 3 | 26.24% | 6.36% |
| shape | go | 6 | 47.17% | 5.06% |
| shape | installer | 3 | 54.40% | 6.53% |
| shape | installer-script | 1 | 0.00% | 0.00% |
| shape | interface-dispatch | 1 | 25.39% | 4.76% |
| shape | java | 4 | 27.91% | 5.41% |
| shape | javascript | 1 | 13.69% | 2.38% |
| shape | js | 2 | 22.03% | 0.00% |
| shape | js-ts | 3 | 27.74% | 3.27% |
| shape | laravel-package | 1 | 50.00% | 0.00% |
| shape | laravel-routes | 1 | 37.50% | 12.50% |
| shape | library | 10 | 35.33% | 6.51% |
| shape | macros | 1 | 0.00% | 0.00% |
| shape | main-class | 2 | 33.34% | 5.56% |
| shape | main-demos | 1 | 6.35% | 0.00% |
| shape | maven | 1 | 28.57% | 0.00% |
| shape | maven-multi-module | 5 | 56.03% | 10.78% |
| shape | mcp-client | 1 | 0.00% | 0.00% |
| shape | mcp-server | 3 | 13.97% | 6.11% |
| shape | mixed-language-shell | 4 | 39.39% | 6.95% |
| shape | ml-tooling | 1 | 0.00% | 0.00% |
| shape | monolith | 1 | 0.00% | 0.00% |
| shape | monorepo | 10 | 32.98% | 5.97% |
| shape | multi-crate | 2 | 41.21% | 15.00% |
| shape | multi-language | 1 | 20.00% | 4.62% |
| shape | multi-package | 5 | 54.35% | 4.25% |
| shape | multiple-binaries | 1 | 0.00% | 0.00% |
| shape | nested-includes | 1 | 50.00% | 7.89% |
| shape | network | 1 | 81.48% | 0.00% |
| shape | network-client | 8 | 34.81% | 2.01% |
| shape | network-download | 1 | 12.50% | 0.00% |
| shape | network-server | 1 | 25.00% | 0.00% |
| shape | network-via-git | 1 | 70.00% | 0.00% |
| shape | package-entrypoint | 1 | 53.97% | 5.56% |
| shape | package-manager | 1 | 14.54% | 9.77% |
| shape | package-manager-detect | 1 | 68.75% | 6.25% |
| shape | packaging | 1 | 66.67% | 4.17% |
| shape | php | 2 | 58.00% | 13.45% |
| shape | picocli-command-tree | 1 | 32.46% | 10.53% |
| shape | plugin-hooks | 2 | 32.26% | 10.22% |
| shape | plugin-system | 7 | 36.02% | 12.37% |
| shape | process-exec | 4 | 22.02% | 3.77% |
| shape | process-exec-wrapper | 2 | 18.70% | 2.63% |
| shape | process-manager | 2 | 17.55% | 14.08% |
| shape | python | 7 | 45.79% | 9.15% |
| shape | rails-routes | 1 | 0.00% | 0.00% |
| shape | reflection-dispatch | 1 | 0.00% | 0.00% |
| shape | registered-commands | 2 | 27.57% | 15.38% |
| shape | ruby | 4 | 38.89% | 10.77% |
| shape | rust | 5 | 33.75% | 10.84% |
| shape | shell | 4 | 34.40% | 7.29% |
| shape | shell-scripts | 1 | 0.00% | 0.00% |
| shape | shell-tests | 1 | 12.87% | 5.94% |
| shape | single-script | 2 | 33.25% | 13.89% |
| shape | site-commands | 1 | 16.67% | 16.67% |
| shape | site-generator | 1 | 62.26% | 0.00% |
| shape | spring | 1 | 83.67% | 4.08% |
| shape | spring-routes | 1 | 28.57% | 0.00% |
| shape | src-layout | 6 | 39.49% | 11.84% |
| shape | subprocess | 6 | 45.58% | 4.77% |
| shape | sudo | 2 | 69.38% | 3.13% |
| shape | symfony-console | 3 | 27.78% | 8.19% |
| shape | task-runner | 1 | 17.65% | 0.00% |
| shape | template-generator | 1 | 81.48% | 0.00% |
| shape | thor-command-tree | 3 | 7.41% | 7.41% |
| shape | tool-calls | 6 | 19.39% | 2.98% |
| shape | training-scripts | 1 | 0.00% | 0.00% |
| shape | trait-heavy | 1 | 38.10% | 14.29% |
| shape | tui | 3 | 28.85% | 4.65% |
| shape | uv-workspace | 1 | 78.09% | 22.64% |
| shape | vendored-deps | 1 | 62.79% | 4.65% |
| shape | vscode-extension | 1 | 0.00% | 0.00% |
| shape | web-app | 5 | 25.63% | 5.65% |
| shape | web-framework | 2 | 12.96% | 0.00% |
| shape | workspace | 7 | 32.50% | 5.80% |
| shape | workspaces | 3 | 32.88% | 2.10% |
| shape | yaml-config | 2 | 0.00% | 0.00% |

| repo | status | entrypoints | effects | real entry | understood | complete | dynamic | unobservable | gap | concrete/symbolic/unresolved | wall ms | peak RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Aider-AI/aider | analyzed | 83 | 3386 | no | 12.05% | 2.41% | 0.00% | 9.64% | 87.95% | 731/1159/1496 | 48327 | 272.6 |
| BloopAI/vibe-kanban | analyzed | 173 | 1561 | no | 37.58% | 6.94% | 0.00% | 30.64% | 62.43% | 771/81/709 | 14199 | 266.2 |
| BurntSushi/ripgrep | analyzed | 55 | 295 | yes | 49.09% | 20.00% | 0.00% | 29.09% | 50.91% | 149/52/94 | 6267 | 179.3 |
| Homebrew/brew | analyzed | 440 | 2704 | no | 14.54% | 9.77% | 0.00% | 4.77% | 85.45% | 1884/133/687 | 117534 | 643.1 |
| Homebrew/install | analyzed | 20 | 171 | yes | 70.00% | 0.00% | 0.00% | 70.00% | 30.00% | 104/4/63 | 1863 | 52.4 |
| Kilo-Org/kilocode | analyzed | 463 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0/0/0 | 37736 | 496.2 |
| NousResearch/hermes-agent | analyzed | 671 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0/0/0 | 118419 | 561.6 |
| OpenHands/OpenHands | analyzed | 180 | 1595 | no | 35.00% | 15.00% | 0.00% | 20.00% | 65.00% | 979/98/518 | 12598 | 215.8 |
| PHPCSStandards/PHP_CodeSniffer | analyzed | 100 | 210 | yes | 66.00% | 19.00% | 0.00% | 47.00% | 34.00% | 139/33/38 | 44714 | 145.0 |
| PrefectHQ/fastmcp | analyzed | 73 | 540 | no | 21.92% | 13.70% | 0.00% | 8.22% | 78.08% | 345/54/141 | 12455 | 194.4 |
| QwenLM/qwen-code | analyzed | 1172 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0/0/0 | 67097 | 438.0 |
| Shopify/roast | analyzed | 34 | 25 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 15/6/4 | 2303 | 72.2 |
| Textualize/rich | analyzed | 63 | 1385 | no | 6.35% | 0.00% | 0.00% | 6.35% | 93.65% | 1371/1/13 | 41487 | 161.5 |
| Unitech/pm2 | analyzed | 101 | 2493 | no | 12.87% | 5.94% | 0.00% | 6.93% | 87.13% | 2101/134/258 | 40240 | 179.0 |
| aaif-goose/goose | analyzed | 383 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0/0/0 | 47535 | 600.9 |
| acmesh-official/acme.sh | analyzed | 430 | 1046 | no | 18.84% | 16.05% | 0.00% | 2.79% | 81.16% | 829/67/150 | 34934 | 138.3 |
| anomalyco/opencode | analyzed | 314 | 943 | no | 32.16% | 1.27% | 0.00% | 30.89% | 67.83% | 626/26/291 | 35533 | 488.6 |
| ansible/ansible | timeout | 0 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0/0 | 300045 | 0.0 |
| antfu-collective/ni | analyzed | 35 | 1509 | yes | 11.43% | 0.00% | 0.00% | 11.43% | 88.57% | 1329/1/179 | 1806 | 65.4 |
| apache/maven | analyzed | 50 | 387 | no | 60.00% | 14.00% | 0.00% | 46.00% | 40.00% | 240/47/100 | 103288 | 383.3 |
| apache/maven-wrapper | analyzed | 8 | 338 | yes | 12.50% | 0.00% | 0.00% | 12.50% | 87.50% | 166/40/132 | 2785 | 64.3 |
| asdf-vm/asdf | analyzed | 29 | 558 | yes | 68.96% | 10.34% | 0.00% | 58.62% | 31.03% | 182/22/354 | 9040 | 192.0 |
| astral-sh/uv | analyzed | 593 | 1261 | no | 79.26% | 1.52% | 0.17% | 77.57% | 20.74% | 587/153/521 | 123158 | 740.1 |
| athityakumar/colorls | analyzed | 6 | 11 | yes | 66.67% | 16.67% | 0.00% | 50.00% | 33.33% | 6/4/1 | 999 | 45.9 |
| badlogic/pi-mono | analyzed | 208 | 2018 | no | 18.75% | 0.48% | 0.48% | 17.79% | 81.25% | 944/47/1027 | 34252 | 360.0 |
| casey/just | analyzed | 31 | 252 | yes | 48.38% | 12.90% | 0.00% | 35.48% | 51.61% | 134/41/77 | 6393 | 167.8 |
| changesets/changesets | analyzed | 44 | 338 | yes | 47.73% | 4.55% | 0.00% | 43.18% | 52.27% | 118/2/218 | 2971 | 96.8 |
| charmbracelet/crush | analyzed | 32 | 1247 | no | 25.01% | 6.25% | 3.13% | 15.63% | 75.00% | 586/22/639 | 95799 | 524.8 |
| charmbracelet/glow | analyzed | 5 | 77 | yes | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 20/12/45 | 1971 | 76.0 |
| checkstyle/checkstyle | timeout | 0 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0/0 | 300016 | 0.0 |
| cli/cli | timeout | 0 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0/0 | 300035 | 0.0 |
| composer/composer | analyzed | 38 | 193 | yes | 50.00% | 7.89% | 0.00% | 42.11% | 50.00% | 97/14/82 | 58051 | 239.5 |
| cookiecutter/cookiecutter | analyzed | 27 | 78 | yes | 81.48% | 0.00% | 0.00% | 81.48% | 18.52% | 53/19/6 | 656 | 46.8 |
| ddollar/foreman | analyzed | 9 | 72 | yes | 22.22% | 22.22% | 0.00% | 0.00% | 77.78% | 15/51/6 | 1949 | 61.0 |
| docker/docker-install | analyzed | 16 | 371 | no | 68.75% | 6.25% | 0.00% | 62.50% | 31.25% | 257/12/102 | 7800 | 95.4 |
| drush-ops/drush | analyzed | 18 | 63 | no | 16.67% | 16.67% | 0.00% | 0.00% | 83.33% | 55/1/7 | 5863 | 85.4 |
| expressjs/express | analyzed | 27 | 35 | no | 25.93% | 0.00% | 0.00% | 25.93% | 74.07% | 27/0/8 | 1902 | 67.6 |
| eza-community/eza | analyzed | 21 | 362 | yes | 38.10% | 14.29% | 0.00% | 23.81% | 61.90% | 73/19/270 | 2034 | 99.8 |
| fullstorydev/grpcurl | analyzed | 22 | 123 | yes | 72.73% | 0.00% | 0.00% | 72.73% | 27.27% | 48/24/51 | 3431 | 95.3 |
| github/github-mcp-server | timeout | 0 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0/0 | 300030 | 0.0 |
| gohugoio/hugo | analyzed | 53 | 118 | no | 62.26% | 0.00% | 0.00% | 62.26% | 37.74% | 70/20/28 | 30847 | 472.9 |
| google-gemini/gemini-cli | analyzed | 416 | 2868 | no | 40.39% | 9.86% | 0.00% | 30.53% | 59.62% | 1723/130/1015 | 31155 | 408.9 |
| google/google-java-format | analyzed | 18 | 87 | yes | 66.67% | 11.11% | 0.00% | 55.56% | 33.33% | 44/25/18 | 59071 | 383.3 |
| google/zx | analyzed | 133 | 440 | yes | 24.06% | 5.26% | 0.00% | 18.80% | 75.94% | 323/15/102 | 3909 | 113.1 |
| http-party/http-server | analyzed | 8 | 11 | yes | 25.00% | 0.00% | 0.00% | 25.00% | 75.00% | 11/0/0 | 432 | 39.4 |
| httpie/cli | analyzed | 62 | 183 | yes | 69.35% | 0.00% | 0.00% | 69.35% | 30.65% | 99/15/69 | 2950 | 114.3 |
| jbangdev/jbang | analyzed | 114 | 1119 | yes | 32.46% | 10.53% | 0.00% | 21.93% | 67.54% | 718/105/296 | 79001 | 349.1 |
| jordansissel/fpm | analyzed | 24 | 108 | yes | 66.67% | 4.17% | 0.00% | 62.50% | 33.33% | 80/9/19 | 5344 | 81.5 |
| junegunn/fzf | analyzed | 39 | 684 | yes | 61.54% | 7.69% | 0.00% | 53.85% | 38.46% | 293/48/343 | 61665 | 781.2 |
| karpathy/nanochat | analyzed | 10 | 348 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 204/49/95 | 2120 | 72.2 |
| langchain4j/langchain4j | analyzed | 89 | 490 | no | 57.30% | 24.72% | 0.00% | 32.58% | 42.70% | 366/53/71 | 123209 | 444.4 |
| laravel/laravel | analyzed | 8 | 16 | no | 37.50% | 12.50% | 0.00% | 25.00% | 62.50% | 15/0/1 | 144 | 36.5 |
| mikefarah/yq | analyzed | 79 | 641 | no | 54.43% | 7.59% | 0.00% | 46.84% | 45.57% | 342/116/183 | 104405 | 185.6 |
| modelcontextprotocol/servers | analyzed | 65 | 201 | no | 20.00% | 4.62% | 0.00% | 15.38% | 80.00% | 116/24/61 | 1183 | 61.4 |
| nvm-sh/nvm | analyzed | 128 | 727 | yes | 47.66% | 11.72% | 0.00% | 35.94% | 52.34% | 529/55/143 | 25640 | 103.5 |
| ohmyzsh/ohmyzsh | analyzed | 45 | 974 | yes | 24.44% | 13.33% | 0.00% | 11.11% | 75.56% | 565/49/360 | 12376 | 98.3 |
| open-telemetry/opentelemetry-python | analyzed | 732 | 1012 | no | 57.65% | 1.23% | 0.00% | 56.42% | 42.35% | 590/74/348 | 5754 | 185.9 |
| orhun/git-cliff | analyzed | 60 | 247 | yes | 33.33% | 10.00% | 0.00% | 23.33% | 66.67% | 160/23/64 | 1177 | 87.4 |
| prettier/prettier | analyzed | 336 | 5424 | yes | 13.69% | 2.38% | 0.00% | 11.31% | 86.31% | 5216/27/181 | 46691 | 343.6 |
| prism-php/prism | analyzed | 8 | 28 | no | 50.00% | 0.00% | 0.00% | 50.00% | 50.00% | 22/4/2 | 5979 | 76.5 |
| psf/black | analyzed | 77 | 230 | yes | 46.75% | 9.09% | 0.00% | 37.66% | 53.25% | 126/20/84 | 4633 | 119.6 |
| pydantic/pydantic-ai | analyzed | 826 | 5193 | no | 78.09% | 22.64% | 0.00% | 55.45% | 21.91% | 3802/749/642 | 46386 | 496.3 |
| pyenv/pyenv | analyzed | 93 | 940 | no | 41.94% | 7.53% | 0.00% | 34.41% | 58.06% | 648/38/254 | 7529 | 98.9 |
| pypa/pip | analyzed | 43 | 165 | no | 62.79% | 4.65% | 0.00% | 58.14% | 37.21% | 113/16/36 | 17292 | 266.7 |
| pypa/pipx | analyzed | 36 | 117 | yes | 38.89% | 8.33% | 0.00% | 30.56% | 61.11% | 77/12/28 | 3256 | 95.7 |
| python-poetry/poetry | analyzed | 22 | 169 | yes | 18.18% | 18.18% | 0.00% | 0.00% | 81.82% | 121/12/36 | 5925 | 138.6 |
| python-websockets/websockets | analyzed | 91 | 573 | yes | 8.79% | 0.00% | 0.00% | 8.79% | 91.21% | 484/1/88 | 5828 | 138.8 |
| rbenv/rbenv | analyzed | 31 | 313 | yes | 22.58% | 12.90% | 0.00% | 9.68% | 77.42% | 215/14/84 | 1340 | 50.0 |
| redmine/redmine | analyzed | 101 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0/0/0 | 25445 | 675.1 |
| release-it/release-it | analyzed | 21 | 69 | yes | 19.05% | 0.00% | 0.00% | 19.05% | 80.95% | 38/1/30 | 934 | 51.3 |
| restic/restic | analyzed | 63 | 896 | yes | 25.39% | 4.76% | 0.00% | 20.63% | 74.60% | 267/118/511 | 134151 | 344.2 |
| ruby/rake | analyzed | 17 | 29 | no | 17.65% | 0.00% | 0.00% | 17.65% | 82.35% | 17/6/6 | 1943 | 105.4 |
| rust-lang/cargo | analyzed | 92 | 332 | no | 28.26% | 2.17% | 0.00% | 26.09% | 71.74% | 218/11/103 | 27063 | 621.8 |
| sdkman/sdkman-cli | analyzed | 34 | 115 | yes | 20.59% | 2.94% | 0.00% | 17.65% | 79.41% | 85/2/28 | 364 | 40.2 |
| sharkdp/bat | analyzed | 47 | 376 | yes | 48.93% | 17.02% | 0.00% | 31.91% | 51.06% | 214/29/133 | 3313 | 123.6 |
| sinatra/sinatra | analyzed | 20 | 17 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 15/0/2 | 2857 | 94.5 |
| sindresorhus/execa | analyzed | 30 | 98 | no | 13.33% | 0.00% | 0.00% | 13.33% | 86.67% | 34/2/62 | 32754 | 232.9 |
| spring-projects/spring-ai | analyzed | 49 | 226 | no | 83.67% | 4.08% | 0.00% | 79.59% | 16.33% | 153/16/57 | 58991 | 349.3 |
| spring-projects/spring-petclinic | analyzed | 7 | 102 | no | 28.57% | 0.00% | 0.00% | 28.57% | 71.43% | 61/8/33 | 806 | 45.7 |
| steveyegge/beads | analyzed | 597 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0/0/0 | 49344 | 539.4 |
| symfony/console | analyzed | 6 | 188 | no | 16.67% | 0.00% | 0.00% | 16.67% | 83.33% | 87/20/81 | 57734 | 419.7 |
| tiangolo/full-stack-fastapi-template | analyzed | 102 | 348 | no | 24.51% | 8.82% | 0.00% | 15.69% | 75.49% | 216/56/76 | 1270 | 61.0 |
| tmuxinator/tmuxinator | analyzed | 5 | 48 | yes | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 25/10/13 | 1992 | 56.7 |
| tox-dev/tox | analyzed | 26 | 221 | yes | 61.54% | 30.77% | 0.00% | 30.77% | 38.46% | 109/29/83 | 6156 | 151.0 |
| uutils/coreutils | timeout | 0 | 0 | no | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0/0/0 | 300038 | 0.0 |
| wp-cli/wp-cli | analyzed | 13 | 121 | yes | 38.46% | 30.77% | 0.00% | 7.69% | 61.54% | 85/11/25 | 13404 | 93.0 |
| yt-dlp/yt-dlp | analyzed | 126 | 645 | yes | 53.97% | 5.56% | 0.00% | 48.41% | 46.03% | 465/67/113 | 25302 | 243.5 |

| repo | skipped inputs | failed entrypoints | silent entrypoints |
|---|---|---|---|
| Aider-AI/aider | 6 | 0 | 1 |
| BloopAI/vibe-kanban | 1 | 0 | 0 |
| BurntSushi/ripgrep | 2 | 0 | 2 |
| Homebrew/brew | 8 | 58 | 12 |
| Homebrew/install | 1 | 0 | 0 |
| Kilo-Org/kilocode | 1720 | 463 | 0 |
| NousResearch/hermes-agent | 345 | 671 | 0 |
| OpenHands/OpenHands | 2 | 0 | 5 |
| PHPCSStandards/PHP_CodeSniffer | 2 | 0 | 12 |
| PrefectHQ/fastmcp | 2 | 0 | 0 |
| QwenLM/qwen-code | 4096 | 1172 | 0 |
| Shopify/roast | 2 | 0 | 0 |
| Textualize/rich | 1 | 0 | 0 |
| Unitech/pm2 | 7 | 0 | 14 |
| aaif-goose/goose | 711 | 383 | 0 |
| acmesh-official/acme.sh | 1 | 0 | 307 |
| anomalyco/opencode | 6 | 0 | 3 |
| antfu-collective/ni | 1 | 0 | 0 |
| apache/maven | 7 | 0 | 0 |
| apache/maven-wrapper | 1 | 0 | 0 |
| asdf-vm/asdf | 1 | 0 | 0 |
| astral-sh/uv | 6 | 0 | 5 |
| athityakumar/colorls | 3 | 0 | 0 |
| badlogic/pi-mono | 2 | 0 | 0 |
| casey/just | 3 | 0 | 0 |
| changesets/changesets | 1 | 0 | 1 |
| charmbracelet/crush | 2 | 0 | 0 |
| charmbracelet/glow | 1 | 0 | 0 |
| composer/composer | 3 | 0 | 1 |
| cookiecutter/cookiecutter | 1 | 0 | 0 |
| ddollar/foreman | 1 | 0 | 0 |
| docker/docker-install | 1 | 0 | 0 |
| drush-ops/drush | 1 | 0 | 0 |
| expressjs/express | 1 | 0 | 0 |
| eza-community/eza | 5 | 0 | 0 |
| fullstorydev/grpcurl | 1 | 0 | 0 |
| gohugoio/hugo | 3 | 0 | 2 |
| google-gemini/gemini-cli | 3 | 0 | 1 |
| google/google-java-format | 1 | 0 | 0 |
| google/zx | 1 | 0 | 2 |
| http-party/http-server | 1 | 0 | 1 |
| httpie/cli | 1 | 0 | 0 |
| jbangdev/jbang | 2 | 0 | 2 |
| jordansissel/fpm | 1 | 0 | 1 |
| junegunn/fzf | 2 | 0 | 1 |
| karpathy/nanochat | 2 | 0 | 0 |
| langchain4j/langchain4j | 1 | 0 | 0 |
| laravel/laravel | 1 | 0 | 0 |
| mikefarah/yq | 1 | 0 | 0 |
| modelcontextprotocol/servers | 1 | 0 | 0 |
| nvm-sh/nvm | 7 | 0 | 14 |
| ohmyzsh/ohmyzsh | 1 | 0 | 1 |
| open-telemetry/opentelemetry-python | 1 | 0 | 0 |
| orhun/git-cliff | 2 | 0 | 2 |
| prettier/prettier | 13 | 0 | 9 |
| prism-php/prism | 17 | 0 | 0 |
| psf/black | 4 | 0 | 0 |
| pydantic/pydantic-ai | 55 | 0 | 1 |
| pyenv/pyenv | 9 | 0 | 0 |
| pypa/pip | 2 | 0 | 0 |
| pypa/pipx | 1 | 0 | 0 |
| python-poetry/poetry | 2 | 0 | 0 |
| python-websockets/websockets | 1 | 0 | 0 |
| rbenv/rbenv | 1 | 0 | 0 |
| redmine/redmine | 24 | 101 | 0 |
| release-it/release-it | 1 | 0 | 0 |
| restic/restic | 1 | 0 | 1 |
| ruby/rake | 1 | 0 | 0 |
| rust-lang/cargo | 97 | 0 | 1 |
| sdkman/sdkman-cli | 1 | 0 | 22 |
| sharkdp/bat | 2 | 0 | 0 |
| sinatra/sinatra | 1 | 0 | 5 |
| sindresorhus/execa | 3 | 0 | 3 |
| spring-projects/spring-ai | 1 | 0 | 0 |
| spring-projects/spring-petclinic | 1 | 0 | 0 |
| steveyegge/beads | 1000 | 597 | 0 |
| symfony/console | 1 | 0 | 0 |
| tiangolo/full-stack-fastapi-template | 5 | 0 | 1 |
| tmuxinator/tmuxinator | 1 | 0 | 0 |
| tox-dev/tox | 1 | 0 | 0 |
| wp-cli/wp-cli | 1 | 0 | 0 |
| yt-dlp/yt-dlp | 3 | 0 | 0 |

5 repositories without recorded diagnostics: ansible/ansible, checkstyle/checkstyle, cli/cli, github/github-mcp-server, uutils/coreutils

| repo | boundary reason | count |
|---|---|---|
| Aider-AI/aider | cross_module | 91 |
| Aider-AI/aider | daemon_transport | 4 |
| Aider-AI/aider | dynamic_dispatch | 1392 |
| Aider-AI/aider | dynamic_source | 3 |
| Aider-AI/aider | environment_configuration | 1 |
| Aider-AI/aider | external_unmodeled | 432 |
| Aider-AI/aider | frontend_partial | 174 |
| Aider-AI/aider | lifecycle_unbound | 1 |
| Aider-AI/aider | limit_saturated | 15 |
| Aider-AI/aider | no_entry_point | 3 |
| Aider-AI/aider | package_scripts | 19 |
| Aider-AI/aider | reviewed_command_surface | 9 |
| Aider-AI/aider | uncomposed_subprocess | 3 |
| Aider-AI/aider | unmodeled_command | 27 |
| Aider-AI/aider | unmodeled_dynamic | 31 |
| Aider-AI/aider | unmodeled_hooks | 1 |
| Aider-AI/aider | unmodeled_import | 124 |
| Aider-AI/aider | unmodeled_subcommand | 1 |
| Aider-AI/aider | unrecognized_arguments | 11 |
| Aider-AI/aider | unrecoverable_source | 23 |
| Aider-AI/aider | unresolved_build_target | 1 |
| Aider-AI/aider | unresolved_call | 937 |
| Aider-AI/aider | unresolved_ci_step | 6 |
| Aider-AI/aider | unresolved_command | 4 |
| Aider-AI/aider | unresolved_decorator | 2 |
| Aider-AI/aider | unresolved_package_script | 1 |
| Aider-AI/aider | unresolved_transfer_target | 2 |
| Aider-AI/aider | unsupported_shell_syntax | 1 |
| Aider-AI/aider | untyped_resource | 1 |
| BloopAI/vibe-kanban | cross_module | 98 |
| BloopAI/vibe-kanban | daemon_transport | 5 |
| BloopAI/vibe-kanban | dynamic_source | 10 |
| BloopAI/vibe-kanban | environment_configuration | 1 |
| BloopAI/vibe-kanban | execution_limit | 1 |
| BloopAI/vibe-kanban | external_unmodeled | 127 |
| BloopAI/vibe-kanban | frontend_partial | 19 |
| BloopAI/vibe-kanban | input_determined_arguments | 10 |
| BloopAI/vibe-kanban | limit_saturated | 17 |
| BloopAI/vibe-kanban | model_coverage | 1 |
| BloopAI/vibe-kanban | package_scripts | 11 |
| BloopAI/vibe-kanban | parse_error | 3 |
| BloopAI/vibe-kanban | partial_analysis | 34 |
| BloopAI/vibe-kanban | recursive_call | 5 |
| BloopAI/vibe-kanban | reviewed_command_surface | 46 |
| BloopAI/vibe-kanban | uncomposed_subprocess | 11 |
| BloopAI/vibe-kanban | unmodeled_command | 27 |
| BloopAI/vibe-kanban | unmodeled_dynamic | 43 |
| BloopAI/vibe-kanban | unmodeled_dynamic_code | 22 |
| BloopAI/vibe-kanban | unmodeled_hooks | 9 |
| BloopAI/vibe-kanban | unmodeled_subcommand | 23 |
| BloopAI/vibe-kanban | unmodeled_subprocess | 1 |
| BloopAI/vibe-kanban | unparsed_script | 2 |
| BloopAI/vibe-kanban | unpolled_async | 18 |
| BloopAI/vibe-kanban | unrecognized_arguments | 36 |
| BloopAI/vibe-kanban | unrecoverable_source | 37 |
| BloopAI/vibe-kanban | unresolved_build_target | 58 |
| BloopAI/vibe-kanban | unresolved_call | 1437 |
| BloopAI/vibe-kanban | unresolved_ci_step | 25 |
| BloopAI/vibe-kanban | unresolved_command | 3 |
| BloopAI/vibe-kanban | unresolved_package_script | 27 |
| BloopAI/vibe-kanban | unresolved_source | 3 |
| BloopAI/vibe-kanban | unresolved_transfer_target | 2 |
| BloopAI/vibe-kanban | unsupported_shell_syntax | 10 |
| BloopAI/vibe-kanban | untyped_resource | 18 |
| BurntSushi/ripgrep | cross_module | 5 |
| BurntSushi/ripgrep | daemon_transport | 7 |
| BurntSushi/ripgrep | dynamic_dispatch | 45 |
| BurntSushi/ripgrep | environment_configuration | 6 |
| BurntSushi/ripgrep | external_unmodeled | 24 |
| BurntSushi/ripgrep | frontend_partial | 4 |
| BurntSushi/ripgrep | input_determined_arguments | 1 |
| BurntSushi/ripgrep | limit_saturated | 2 |
| BurntSushi/ripgrep | model_coverage | 4 |
| BurntSushi/ripgrep | package_scripts | 6 |
| BurntSushi/ripgrep | reviewed_command_surface | 12 |
| BurntSushi/ripgrep | unmodeled_command | 30 |
| BurntSushi/ripgrep | unmodeled_dynamic | 4 |
| BurntSushi/ripgrep | unmodeled_subprocess | 1 |
| BurntSushi/ripgrep | unrecognized_arguments | 16 |
| BurntSushi/ripgrep | unrecoverable_source | 5 |
| BurntSushi/ripgrep | unresolved_build_target | 11 |
| BurntSushi/ripgrep | unresolved_call | 263 |
| BurntSushi/ripgrep | unresolved_ci_step | 8 |
| BurntSushi/ripgrep | unresolved_command | 24 |
| BurntSushi/ripgrep | unresolved_source | 1 |
| BurntSushi/ripgrep | unsupported_shell_syntax | 2 |
| Homebrew/brew | cross_module | 25 |
| Homebrew/brew | daemon_transport | 5 |
| Homebrew/brew | dynamic_dispatch | 1 |
| Homebrew/brew | dynamic_source | 2 |
| Homebrew/brew | environment_configuration | 2 |
| Homebrew/brew | external_unmodeled | 43 |
| Homebrew/brew | frontend_partial | 188 |
| Homebrew/brew | limit_saturated | 97 |
| Homebrew/brew | model_coverage | 1 |
| Homebrew/brew | no_entry_point | 99 |
| Homebrew/brew | package_scripts | 34 |
| Homebrew/brew | parse_error | 7 |
| Homebrew/brew | partial_analysis | 403 |
| Homebrew/brew | reviewed_command_surface | 166 |
| Homebrew/brew | unmodeled_command | 44 |
| Homebrew/brew | unmodeled_dynamic | 10 |
| Homebrew/brew | unmodeled_dynamic_code | 6 |
| Homebrew/brew | unmodeled_hooks | 16 |
| Homebrew/brew | unmodeled_import | 398 |
| Homebrew/brew | unmodeled_subcommand | 70 |
| Homebrew/brew | unparsed_script | 4 |
| Homebrew/brew | unrecognized_arguments | 81 |
| Homebrew/brew | unrecoverable_source | 23 |
| Homebrew/brew | unresolved_alias | 1 |
| Homebrew/brew | unresolved_build_target | 4 |
| Homebrew/brew | unresolved_call | 6507 |
| Homebrew/brew | unresolved_ci_step | 19 |
| Homebrew/brew | unresolved_command | 162 |
| Homebrew/brew | unresolved_source | 13 |
| Homebrew/brew | unsupported_shell_syntax | 16 |
| Homebrew/brew | untyped_resource | 1 |
| Homebrew/install | frontend_partial | 1 |
| Homebrew/install | package_scripts | 1 |
| Homebrew/install | parse_error | 2 |
| Homebrew/install | reviewed_command_surface | 2 |
| Homebrew/install | unmodeled_command | 8 |
| Homebrew/install | unmodeled_subcommand | 1 |
| Homebrew/install | unrecognized_arguments | 40 |
| Homebrew/install | unresolved_ci_step | 14 |
| Homebrew/install | unresolved_command | 8 |
| Homebrew/install | unsupported_shell_syntax | 1 |
| OpenHands/OpenHands | daemon_transport | 4 |
| OpenHands/OpenHands | dynamic_dispatch | 107 |
| OpenHands/OpenHands | dynamic_source | 38 |
| OpenHands/OpenHands | environment_configuration | 8 |
| OpenHands/OpenHands | external_unmodeled | 276 |
| OpenHands/OpenHands | frontend_partial | 27 |
| OpenHands/OpenHands | input_determined_arguments | 1 |
| OpenHands/OpenHands | lifecycle_unbound | 2 |
| OpenHands/OpenHands | limit_saturated | 41 |
| OpenHands/OpenHands | model_coverage | 1 |
| OpenHands/OpenHands | no_entry_point | 2 |
| OpenHands/OpenHands | package_scripts | 17 |
| OpenHands/OpenHands | reviewed_command_surface | 35 |
| OpenHands/OpenHands | uncomposed_subprocess | 26 |
| OpenHands/OpenHands | unmodeled_command | 48 |
| OpenHands/OpenHands | unmodeled_dynamic | 7 |
| OpenHands/OpenHands | unmodeled_dynamic_code | 25 |
| OpenHands/OpenHands | unmodeled_hooks | 6 |
| OpenHands/OpenHands | unmodeled_import | 1 |
| OpenHands/OpenHands | unmodeled_subcommand | 12 |
| OpenHands/OpenHands | unparsed_script | 1 |
| OpenHands/OpenHands | unpolled_async | 26 |
| OpenHands/OpenHands | unrecognized_arguments | 25 |
| OpenHands/OpenHands | unrecoverable_source | 104 |
| OpenHands/OpenHands | unresolved_call | 1024 |
| OpenHands/OpenHands | unresolved_ci_step | 13 |
| OpenHands/OpenHands | unresolved_command | 9 |
| OpenHands/OpenHands | unresolved_package_script | 16 |
| OpenHands/OpenHands | unsupported_shell_syntax | 11 |
| OpenHands/OpenHands | untyped_resource | 1 |
| PHPCSStandards/PHP_CodeSniffer | dynamic_class | 1 |
| PHPCSStandards/PHP_CodeSniffer | dynamic_include | 4 |
| PHPCSStandards/PHP_CodeSniffer | dynamic_source | 14 |
| PHPCSStandards/PHP_CodeSniffer | external_unmodeled | 107 |
| PHPCSStandards/PHP_CodeSniffer | frontend_partial | 11 |
| PHPCSStandards/PHP_CodeSniffer | model_coverage | 6 |
| PHPCSStandards/PHP_CodeSniffer | package_scripts | 2 |
| PHPCSStandards/PHP_CodeSniffer | unmodeled_command | 15 |
| PHPCSStandards/PHP_CodeSniffer | unmodeled_dynamic | 8 |
| PHPCSStandards/PHP_CodeSniffer | unmodeled_subcommand | 2 |
| PHPCSStandards/PHP_CodeSniffer | unrecognized_arguments | 8 |
| PHPCSStandards/PHP_CodeSniffer | unrecoverable_source | 371 |
| PHPCSStandards/PHP_CodeSniffer | unresolved_call | 151 |
| PHPCSStandards/PHP_CodeSniffer | unresolved_ci_step | 35 |
| PrefectHQ/fastmcp | cross_module | 44 |
| PrefectHQ/fastmcp | dynamic_dispatch | 294 |
| PrefectHQ/fastmcp | dynamic_source | 6 |
| PrefectHQ/fastmcp | environment_configuration | 4 |
| PrefectHQ/fastmcp | external_unmodeled | 137 |
| PrefectHQ/fastmcp | frontend_partial | 31 |
| PrefectHQ/fastmcp | limit_saturated | 13 |
| PrefectHQ/fastmcp | no_entry_point | 2 |
| PrefectHQ/fastmcp | package_scripts | 21 |
| PrefectHQ/fastmcp | parse_error | 10 |
| PrefectHQ/fastmcp | reviewed_command_surface | 28 |
| PrefectHQ/fastmcp | unmodeled_dynamic | 4 |
| PrefectHQ/fastmcp | unmodeled_dynamic_code | 3 |
| PrefectHQ/fastmcp | unmodeled_import | 30 |
| PrefectHQ/fastmcp | unmodeled_subcommand | 2 |
| PrefectHQ/fastmcp | unpolled_async | 1 |
| PrefectHQ/fastmcp | unrecognized_arguments | 36 |
| PrefectHQ/fastmcp | unrecoverable_source | 35 |
| PrefectHQ/fastmcp | unresolved_build_target | 1 |
| PrefectHQ/fastmcp | unresolved_call | 304 |
| PrefectHQ/fastmcp | unresolved_ci_step | 1 |
| PrefectHQ/fastmcp | unresolved_command | 2 |
| PrefectHQ/fastmcp | unresolved_decorator | 4 |
| PrefectHQ/fastmcp | unresolved_trap_action | 1 |
| PrefectHQ/fastmcp | unsupported_shell_syntax | 4 |
| Shopify/roast | cross_module | 38 |
| Shopify/roast | external_unmodeled | 34 |
| Shopify/roast | frontend_partial | 30 |
| Shopify/roast | package_scripts | 2 |
| Shopify/roast | reviewed_command_surface | 3 |
| Shopify/roast | unmodeled_import | 18 |
| Shopify/roast | unrecognized_arguments | 3 |
| Shopify/roast | unresolved_call | 718 |
| Textualize/rich | cross_module | 38 |
| Textualize/rich | dynamic_dispatch | 3846 |
| Textualize/rich | external_unmodeled | 936 |
| Textualize/rich | frontend_partial | 649 |
| Textualize/rich | limit_saturated | 31 |
| Textualize/rich | no_entry_point | 12 |
| Textualize/rich | package_scripts | 2 |
| Textualize/rich | reexport_cycle | 3 |
| Textualize/rich | reviewed_command_surface | 4 |
| Textualize/rich | unmodeled_command | 5 |
| Textualize/rich | unmodeled_dynamic | 2 |
| Textualize/rich | unmodeled_import | 114 |
| Textualize/rich | unrecognized_arguments | 5 |
| Textualize/rich | unrecoverable_source | 22 |
| Textualize/rich | unresolved_build_target | 3 |
| Textualize/rich | unresolved_call | 1716 |
| Textualize/rich | unresolved_ci_step | 1 |
| Textualize/rich | unresolved_source | 3 |
| Unitech/pm2 | dynamic_source | 104 |
| Unitech/pm2 | environment_configuration | 3 |
| Unitech/pm2 | execution_cycle | 2 |
| Unitech/pm2 | execution_limit | 5 |
| Unitech/pm2 | external_unmodeled | 294 |
| Unitech/pm2 | frontend_partial | 4 |
| Unitech/pm2 | limit_saturated | 45 |
| Unitech/pm2 | model_coverage | 3 |
| Unitech/pm2 | no_entry_point | 17 |
| Unitech/pm2 | package_scripts | 194 |
| Unitech/pm2 | parse_error | 2 |
| Unitech/pm2 | reviewed_command_surface | 182 |
| Unitech/pm2 | unmodeled_command | 746 |
| Unitech/pm2 | unmodeled_dynamic_code | 5 |
| Unitech/pm2 | unmodeled_subcommand | 2 |
| Unitech/pm2 | unmodeled_subprocess | 3 |
| Unitech/pm2 | unparsed_script | 2 |
| Unitech/pm2 | unrecognized_arguments | 6 |
| Unitech/pm2 | unrecoverable_source | 327 |
| Unitech/pm2 | unresolved_build_target | 1 |
| Unitech/pm2 | unresolved_call | 505 |
| Unitech/pm2 | unresolved_ci_step | 1 |
| Unitech/pm2 | unresolved_command | 147 |
| Unitech/pm2 | unresolved_package_script | 3 |
| Unitech/pm2 | unresolved_source | 2 |
| Unitech/pm2 | unsupported_shell_syntax | 16 |
| acmesh-official/acme.sh | daemon_transport | 12 |
| acmesh-official/acme.sh | dynamic_source | 6 |
| acmesh-official/acme.sh | limit_saturated | 1 |
| acmesh-official/acme.sh | package_scripts | 8 |
| acmesh-official/acme.sh | parse_error | 2 |
| acmesh-official/acme.sh | reviewed_command_surface | 4 |
| acmesh-official/acme.sh | unmodeled_command | 58 |
| acmesh-official/acme.sh | unmodeled_hooks | 13 |
| acmesh-official/acme.sh | unmodeled_subcommand | 3 |
| acmesh-official/acme.sh | unrecognized_arguments | 21 |
| acmesh-official/acme.sh | unrecoverable_source | 16 |
| acmesh-official/acme.sh | unresolved_ci_step | 12 |
| acmesh-official/acme.sh | unresolved_command | 9 |
| acmesh-official/acme.sh | unsupported_shell_syntax | 14 |
| anomalyco/opencode | dynamic_source | 2 |
| anomalyco/opencode | environment_configuration | 1 |
| anomalyco/opencode | external_unmodeled | 1212 |
| anomalyco/opencode | frontend_partial | 33 |
| anomalyco/opencode | limit_saturated | 150 |
| anomalyco/opencode | no_entry_point | 1 |
| anomalyco/opencode | package_scripts | 7 |
| anomalyco/opencode | partial_analysis | 1 |
| anomalyco/opencode | reviewed_command_surface | 39 |
| anomalyco/opencode | uncomposed_subprocess | 5 |
| anomalyco/opencode | unmodeled_command | 88 |
| anomalyco/opencode | unmodeled_dynamic | 10 |
| anomalyco/opencode | unmodeled_dynamic_code | 62 |
| anomalyco/opencode | unmodeled_hooks | 4 |
| anomalyco/opencode | unmodeled_subcommand | 22 |
| anomalyco/opencode | unmodeled_subprocess | 1 |
| anomalyco/opencode | unparsed_script | 4 |
| anomalyco/opencode | unpolled_async | 30 |
| anomalyco/opencode | unrecognized_arguments | 21 |
| anomalyco/opencode | unrecoverable_source | 33 |
| anomalyco/opencode | unresolved_call | 2634 |
| anomalyco/opencode | unresolved_ci_step | 60 |
| anomalyco/opencode | unresolved_command | 6 |
| anomalyco/opencode | unresolved_package_script | 57 |
| anomalyco/opencode | unresolved_source | 3 |
| anomalyco/opencode | unresolved_trap_action | 1 |
| anomalyco/opencode | unsupported_shell_syntax | 24 |
| antfu-collective/ni | external_unmodeled | 278 |
| antfu-collective/ni | frontend_partial | 33 |
| antfu-collective/ni | limit_saturated | 44 |
| antfu-collective/ni | package_scripts | 3 |
| antfu-collective/ni | reviewed_command_surface | 4 |
| antfu-collective/ni | uncomposed_subprocess | 20 |
| antfu-collective/ni | unmodeled_command | 9 |
| antfu-collective/ni | unmodeled_dynamic_code | 28 |
| antfu-collective/ni | unpolled_async | 68 |
| antfu-collective/ni | unrecoverable_source | 4 |
| antfu-collective/ni | unresolved_call | 200 |
| antfu-collective/ni | unresolved_package_script | 4 |
| apache/maven | cross_module | 11 |
| apache/maven | dynamic_dispatch | 44 |
| apache/maven | dynamic_source | 2 |
| apache/maven | environment_configuration | 2 |
| apache/maven | external_unmodeled | 140 |
| apache/maven | frontend_partial | 42 |
| apache/maven | limit_saturated | 7 |
| apache/maven | model_coverage | 1 |
| apache/maven | partial_analysis | 1 |
| apache/maven | reviewed_command_surface | 9 |
| apache/maven | unmodeled_command | 4 |
| apache/maven | unmodeled_dynamic | 2 |
| apache/maven | unmodeled_dynamic_code | 1 |
| apache/maven | unmodeled_subprocess | 2 |
| apache/maven | unrecognized_arguments | 18 |
| apache/maven | unrecoverable_source | 26 |
| apache/maven | unresolved_build_target | 25 |
| apache/maven | unresolved_call | 88 |
| apache/maven | unresolved_ci_step | 3 |
| apache/maven | unresolved_command | 7 |
| apache/maven | unresolved_source | 1 |
| apache/maven | unsupported_shell_syntax | 4 |
| apache/maven-wrapper | dynamic_dispatch | 16 |
| apache/maven-wrapper | environment_configuration | 3 |
| apache/maven-wrapper | external_unmodeled | 159 |
| apache/maven-wrapper | frontend_partial | 7 |
| apache/maven-wrapper | input_determined_arguments | 6 |
| apache/maven-wrapper | limit_saturated | 3 |
| apache/maven-wrapper | reviewed_command_surface | 24 |
| apache/maven-wrapper | unmodeled_command | 17 |
| apache/maven-wrapper | unmodeled_dynamic | 4 |
| apache/maven-wrapper | unmodeled_dynamic_code | 2 |
| apache/maven-wrapper | unrecognized_arguments | 29 |
| apache/maven-wrapper | unrecoverable_source | 6 |
| apache/maven-wrapper | unresolved_build_target | 2 |
| apache/maven-wrapper | unresolved_call | 28 |
| apache/maven-wrapper | unresolved_command | 10 |
| apache/maven-wrapper | unresolved_source | 2 |
| apache/maven-wrapper | unsupported_shell_syntax | 12 |
| asdf-vm/asdf | cross_module | 3 |
| asdf-vm/asdf | dynamic_dispatch | 16 |
| asdf-vm/asdf | external_unmodeled | 260 |
| asdf-vm/asdf | frontend_partial | 3 |
| asdf-vm/asdf | package_scripts | 2 |
| asdf-vm/asdf | reviewed_command_surface | 1 |
| asdf-vm/asdf | uncomposed_subprocess | 1 |
| asdf-vm/asdf | unmodeled_command | 4 |
| asdf-vm/asdf | unrecoverable_source | 30 |
| asdf-vm/asdf | unresolved_build_target | 6 |
| asdf-vm/asdf | unresolved_call | 57 |
| asdf-vm/asdf | unresolved_ci_step | 3 |
| asdf-vm/asdf | unresolved_package_script | 2 |
| astral-sh/uv | cross_module | 175 |
| astral-sh/uv | daemon_transport | 2 |
| astral-sh/uv | dynamic_dispatch | 643 |
| astral-sh/uv | dynamic_source | 29 |
| astral-sh/uv | environment_configuration | 18 |
| astral-sh/uv | external_unmodeled | 533 |
| astral-sh/uv | frontend_partial | 49 |
| astral-sh/uv | input_determined_arguments | 3 |
| astral-sh/uv | lifecycle_unbound | 3 |
| astral-sh/uv | limit_saturated | 7 |
| astral-sh/uv | missing_required_arguments | 4 |
| astral-sh/uv | model_coverage | 8 |
| astral-sh/uv | package_scripts | 50 |
| astral-sh/uv | partial_analysis | 4 |
| astral-sh/uv | recursive_call | 12 |
| astral-sh/uv | reviewed_command_surface | 58 |
| astral-sh/uv | uncomposed_subprocess | 13 |
| astral-sh/uv | unmodeled_command | 34 |
| astral-sh/uv | unmodeled_dynamic | 58 |
| astral-sh/uv | unmodeled_hooks | 10 |
| astral-sh/uv | unmodeled_import | 23 |
| astral-sh/uv | unmodeled_subcommand | 4 |
| astral-sh/uv | unmodeled_subprocess | 13 |
| astral-sh/uv | unparsed_script | 3 |
| astral-sh/uv | unpolled_async | 1 |
| astral-sh/uv | unrecognized_arguments | 76 |
| astral-sh/uv | unrecoverable_source | 90 |
| astral-sh/uv | unresolved_build_target | 22 |
| astral-sh/uv | unresolved_call | 2949 |
| astral-sh/uv | unresolved_ci_step | 451 |
| astral-sh/uv | unresolved_command | 72 |
| astral-sh/uv | unresolved_package_script | 2 |
| astral-sh/uv | unsupported_shell_syntax | 10 |
| athityakumar/colorls | cross_module | 1 |
| athityakumar/colorls | external_unmodeled | 7 |
| athityakumar/colorls | frontend_partial | 3 |
| athityakumar/colorls | limit_saturated | 1 |
| athityakumar/colorls | no_entry_point | 1 |
| athityakumar/colorls | partial_analysis | 2 |
| athityakumar/colorls | reviewed_command_surface | 1 |
| athityakumar/colorls | unmodeled_dynamic | 1 |
| athityakumar/colorls | unrecognized_arguments | 1 |
| athityakumar/colorls | unresolved_call | 27 |
| athityakumar/colorls | unresolved_ci_step | 3 |
| badlogic/pi-mono | dynamic_source | 34 |
| badlogic/pi-mono | environment_configuration | 9 |
| badlogic/pi-mono | execution_limit | 2 |
| badlogic/pi-mono | external_unmodeled | 455 |
| badlogic/pi-mono | frontend_partial | 40 |
| badlogic/pi-mono | input_determined_arguments | 2 |
| badlogic/pi-mono | limit_saturated | 181 |
| badlogic/pi-mono | model_coverage | 3 |
| badlogic/pi-mono | no_entry_point | 1 |
| badlogic/pi-mono | package_scripts | 18 |
| badlogic/pi-mono | parse_error | 1 |
| badlogic/pi-mono | partial_analysis | 2 |
| badlogic/pi-mono | reviewed_command_surface | 28 |
| badlogic/pi-mono | uncomposed_subprocess | 33 |
| badlogic/pi-mono | unmodeled_command | 138 |
| badlogic/pi-mono | unmodeled_dynamic | 1 |
| badlogic/pi-mono | unmodeled_dynamic_code | 124 |
| badlogic/pi-mono | unmodeled_hooks | 2 |
| badlogic/pi-mono | unmodeled_subcommand | 7 |
| badlogic/pi-mono | unmodeled_subprocess | 5 |
| badlogic/pi-mono | unpolled_async | 37 |
| badlogic/pi-mono | unrecognized_arguments | 21 |
| badlogic/pi-mono | unrecoverable_source | 132 |
| badlogic/pi-mono | unresolved_alias | 7 |
| badlogic/pi-mono | unresolved_call | 1986 |
| badlogic/pi-mono | unresolved_ci_step | 5 |
| badlogic/pi-mono | unresolved_command | 32 |
| badlogic/pi-mono | unresolved_package_script | 109 |
| badlogic/pi-mono | unsupported_shell_syntax | 4 |
| casey/just | cross_module | 8 |
| casey/just | dynamic_source | 1 |
| casey/just | environment_configuration | 5 |
| casey/just | external_unmodeled | 7 |
| casey/just | frontend_partial | 4 |
| casey/just | limit_saturated | 1 |
| casey/just | package_scripts | 10 |
| casey/just | reviewed_command_surface | 1 |
| casey/just | uncomposed_subprocess | 1 |
| casey/just | unmodeled_command | 28 |
| casey/just | unmodeled_dynamic | 11 |
| casey/just | unmodeled_subprocess | 4 |
| casey/just | unrecognized_arguments | 14 |
| casey/just | unrecoverable_source | 6 |
| casey/just | unresolved_build_target | 19 |
| casey/just | unresolved_call | 224 |
| casey/just | unresolved_ci_step | 1 |
| casey/just | unresolved_source | 1 |
| casey/just | unsupported_shell_syntax | 40 |
| changesets/changesets | external_unmodeled | 183 |
| changesets/changesets | frontend_partial | 4 |
| changesets/changesets | limit_saturated | 6 |
| changesets/changesets | reviewed_command_surface | 5 |
| changesets/changesets | uncomposed_subprocess | 4 |
| changesets/changesets | unmodeled_command | 11 |
| changesets/changesets | unmodeled_dynamic_code | 58 |
| changesets/changesets | unmodeled_subcommand | 1 |
| changesets/changesets | unpolled_async | 10 |
| changesets/changesets | unrecognized_arguments | 1 |
| changesets/changesets | unrecoverable_source | 20 |
| changesets/changesets | unresolved_call | 304 |
| changesets/changesets | unresolved_ci_step | 6 |
| changesets/changesets | unresolved_package_script | 15 |
| charmbracelet/crush | cross_module | 206 |
| charmbracelet/crush | dynamic_dispatch | 77 |
| charmbracelet/crush | dynamic_source | 1 |
| charmbracelet/crush | escaped_callable | 55 |
| charmbracelet/crush | external_unmodeled | 3620 |
| charmbracelet/crush | frontend_partial | 156 |
| charmbracelet/crush | limit_saturated | 3 |
| charmbracelet/crush | registration_context | 17 |
| charmbracelet/crush | uncomposed_subprocess | 20 |
| charmbracelet/crush | unmodeled_command | 1 |
| charmbracelet/crush | unmodeled_dynamic_code | 1 |
| charmbracelet/crush | unmodeled_import | 81 |
| charmbracelet/crush | unrecognized_arguments | 3 |
| charmbracelet/crush | unrecoverable_source | 2 |
| charmbracelet/crush | unresolved_call | 2624 |
| charmbracelet/crush | unresolved_ci_step | 4 |
| charmbracelet/glow | cross_module | 45 |
| charmbracelet/glow | dynamic_dispatch | 1 |
| charmbracelet/glow | external_unmodeled | 549 |
| charmbracelet/glow | frontend_partial | 10 |
| charmbracelet/glow | limit_saturated | 3 |
| charmbracelet/glow | registration_context | 3 |
| charmbracelet/glow | uncomposed_subprocess | 2 |
| charmbracelet/glow | unmodeled_command | 1 |
| charmbracelet/glow | unmodeled_import | 24 |
| charmbracelet/glow | unresolved_call | 181 |
| charmbracelet/glow | unresolved_command | 2 |
| composer/composer | dynamic_call | 14 |
| composer/composer | dynamic_class | 1 |
| composer/composer | dynamic_source | 4 |
| composer/composer | environment_configuration | 2 |
| composer/composer | external_unmodeled | 80 |
| composer/composer | frontend_partial | 12 |
| composer/composer | limit_saturated | 1 |
| composer/composer | model_coverage | 2 |
| composer/composer | reviewed_command_surface | 15 |
| composer/composer | unmodeled_command | 2 |
| composer/composer | unmodeled_dynamic | 13 |
| composer/composer | unmodeled_dynamic_code | 1 |
| composer/composer | unrecognized_arguments | 15 |
| composer/composer | unrecoverable_source | 323 |
| composer/composer | unresolved_call | 280 |
| composer/composer | unresolved_ci_step | 14 |
| composer/composer | unresolved_command | 1 |
| composer/composer | unresolved_include | 2 |
| composer/composer | unresolved_source | 1 |
| composer/composer | unsupported_shell_syntax | 1 |
| cookiecutter/cookiecutter | cross_module | 4 |
| cookiecutter/cookiecutter | dynamic_dispatch | 74 |
| cookiecutter/cookiecutter | external_unmodeled | 59 |
| cookiecutter/cookiecutter | frontend_partial | 5 |
| cookiecutter/cookiecutter | limit_saturated | 4 |
| cookiecutter/cookiecutter | package_scripts | 2 |
| cookiecutter/cookiecutter | reviewed_command_surface | 2 |
| cookiecutter/cookiecutter | unmodeled_import | 2 |
| cookiecutter/cookiecutter | unrecognized_arguments | 1 |
| cookiecutter/cookiecutter | unrecoverable_source | 44 |
| cookiecutter/cookiecutter | unresolved_build_target | 22 |
| cookiecutter/cookiecutter | unresolved_call | 60 |
| ddollar/foreman | cross_module | 1 |
| ddollar/foreman | external_unmodeled | 2 |
| ddollar/foreman | frontend_partial | 10 |
| ddollar/foreman | limit_saturated | 1 |
| ddollar/foreman | partial_analysis | 2 |
| ddollar/foreman | reviewed_command_surface | 1 |
| ddollar/foreman | unmodeled_command | 4 |
| ddollar/foreman | unrecognized_arguments | 1 |
| ddollar/foreman | unrecoverable_source | 3 |
| ddollar/foreman | unresolved_call | 51 |
| ddollar/foreman | unresolved_command | 1 |
| ddollar/foreman | unresolved_source | 1 |
| ddollar/foreman | unsupported_shell_syntax | 3 |
| docker/docker-install | daemon_transport | 1 |
| docker/docker-install | dynamic_source | 46 |
| docker/docker-install | environment_configuration | 2 |
| docker/docker-install | limit_saturated | 1 |
| docker/docker-install | package_scripts | 15 |
| docker/docker-install | reviewed_command_surface | 3 |
| docker/docker-install | unmodeled_command | 20 |
| docker/docker-install | unmodeled_subcommand | 15 |
| docker/docker-install | unmodeled_subprocess | 2 |
| docker/docker-install | unrecognized_arguments | 39 |
| docker/docker-install | unrecoverable_source | 75 |
| docker/docker-install | unresolved_build_target | 11 |
| docker/docker-install | unresolved_command | 33 |
| docker/docker-install | unresolved_source | 4 |
| docker/docker-install | unsupported_shell_syntax | 3 |
| drush-ops/drush | dynamic_include | 1 |
| drush-ops/drush | external_unmodeled | 10 |
| drush-ops/drush | frontend_partial | 5 |
| drush-ops/drush | limit_saturated | 1 |
| drush-ops/drush | package_scripts | 5 |
| drush-ops/drush | reviewed_command_surface | 10 |
| drush-ops/drush | unmodeled_command | 5 |
| drush-ops/drush | unmodeled_hooks | 1 |
| drush-ops/drush | unrecognized_arguments | 10 |
| drush-ops/drush | unrecoverable_source | 80 |
| drush-ops/drush | unresolved_call | 12 |
| drush-ops/drush | unresolved_command | 1 |
| expressjs/express | external_unmodeled | 4 |
| expressjs/express | frontend_partial | 2 |
| expressjs/express | input_determined_arguments | 2 |
| expressjs/express | limit_saturated | 9 |
| expressjs/express | no_entry_point | 3 |
| expressjs/express | package_scripts | 3 |
| expressjs/express | reviewed_command_surface | 2 |
| expressjs/express | unmodeled_command | 6 |
| expressjs/express | unmodeled_subcommand | 2 |
| expressjs/express | unrecognized_arguments | 2 |
| expressjs/express | unrecoverable_source | 3 |
| expressjs/express | unresolved_call | 76 |
| expressjs/express | unresolved_ci_step | 4 |
| expressjs/express | unresolved_package_script | 3 |
| eza-community/eza | cross_module | 3 |
| eza-community/eza | dynamic_dispatch | 1 |
| eza-community/eza | environment_configuration | 5 |
| eza-community/eza | external_unmodeled | 11 |
| eza-community/eza | frontend_partial | 3 |
| eza-community/eza | limit_saturated | 1 |
| eza-community/eza | model_coverage | 1 |
| eza-community/eza | package_scripts | 2 |
| eza-community/eza | unmodeled_command | 15 |
| eza-community/eza | unmodeled_dynamic | 1 |
| eza-community/eza | unmodeled_hooks | 4 |
| eza-community/eza | unmodeled_subprocess | 1 |
| eza-community/eza | unrecognized_arguments | 7 |
| eza-community/eza | unrecoverable_source | 2 |
| eza-community/eza | unresolved_build_target | 3 |
| eza-community/eza | unresolved_call | 106 |
| eza-community/eza | unresolved_ci_step | 4 |
| eza-community/eza | unresolved_command | 3 |
| fullstorydev/grpcurl | cross_module | 24 |
| fullstorydev/grpcurl | dynamic_dispatch | 4 |
| fullstorydev/grpcurl | dynamic_source | 1 |
| fullstorydev/grpcurl | escaped_callable | 4 |
| fullstorydev/grpcurl | external_unmodeled | 502 |
| fullstorydev/grpcurl | frontend_partial | 5 |
| fullstorydev/grpcurl | unmodeled_command | 17 |
| fullstorydev/grpcurl | unmodeled_import | 23 |
| fullstorydev/grpcurl | unrecoverable_source | 32 |
| fullstorydev/grpcurl | unresolved_build_target | 16 |
| fullstorydev/grpcurl | unresolved_call | 367 |
| fullstorydev/grpcurl | unresolved_command | 9 |
| fullstorydev/grpcurl | unsupported_shell_syntax | 12 |
| gohugoio/hugo | cross_module | 11 |
| gohugoio/hugo | dynamic_dispatch | 2 |
| gohugoio/hugo | dynamic_source | 2 |
| gohugoio/hugo | escaped_callable | 3 |
| gohugoio/hugo | external_unmodeled | 105 |
| gohugoio/hugo | frontend_partial | 5 |
| gohugoio/hugo | limit_saturated | 2 |
| gohugoio/hugo | package_scripts | 1 |
| gohugoio/hugo | reviewed_command_surface | 3 |
| gohugoio/hugo | unmodeled_command | 15 |
| gohugoio/hugo | unmodeled_dynamic_code | 3 |
| gohugoio/hugo | unmodeled_hooks | 3 |
| gohugoio/hugo | unmodeled_import | 3 |
| gohugoio/hugo | unrecognized_arguments | 1 |
| gohugoio/hugo | unrecoverable_source | 29 |
| gohugoio/hugo | unresolved_alias | 2 |
| gohugoio/hugo | unresolved_build_target | 16 |
| gohugoio/hugo | unresolved_call | 51 |
| gohugoio/hugo | unresolved_ci_step | 19 |
| gohugoio/hugo | unresolved_command | 2 |
| google-gemini/gemini-cli | cross_module | 19 |
| google-gemini/gemini-cli | daemon_transport | 1 |
| google-gemini/gemini-cli | dynamic_dispatch | 129 |
| google-gemini/gemini-cli | dynamic_source | 73 |
| google-gemini/gemini-cli | environment_configuration | 1 |
| google-gemini/gemini-cli | execution_limit | 1 |
| google-gemini/gemini-cli | external_unmodeled | 480 |
| google-gemini/gemini-cli | frontend_partial | 51 |
| google-gemini/gemini-cli | limit_saturated | 33 |
| google-gemini/gemini-cli | no_entry_point | 1 |
| google-gemini/gemini-cli | package_scripts | 22 |
| google-gemini/gemini-cli | parse_error | 2 |
| google-gemini/gemini-cli | partial_analysis | 5 |
| google-gemini/gemini-cli | reviewed_command_surface | 97 |
| google-gemini/gemini-cli | uncomposed_subprocess | 50 |
| google-gemini/gemini-cli | unmodeled_command | 38 |
| google-gemini/gemini-cli | unmodeled_dynamic | 9 |
| google-gemini/gemini-cli | unmodeled_dynamic_code | 91 |
| google-gemini/gemini-cli | unmodeled_hooks | 10 |
| google-gemini/gemini-cli | unmodeled_import | 16 |
| google-gemini/gemini-cli | unmodeled_subcommand | 53 |
| google-gemini/gemini-cli | unmodeled_subprocess | 1 |
| google-gemini/gemini-cli | unpolled_async | 42 |
| google-gemini/gemini-cli | unrecognized_arguments | 102 |
| google-gemini/gemini-cli | unrecoverable_source | 219 |
| google-gemini/gemini-cli | unresolved_call | 2062 |
| google-gemini/gemini-cli | unresolved_ci_step | 55 |
| google-gemini/gemini-cli | unresolved_command | 26 |
| google-gemini/gemini-cli | unresolved_decorator | 4 |
| google-gemini/gemini-cli | unresolved_package_script | 88 |
| google-gemini/gemini-cli | unsupported_shell_syntax | 12 |
| google/google-java-format | cross_module | 27 |
| google/google-java-format | dynamic_dispatch | 157 |
| google/google-java-format | external_unmodeled | 166 |
| google/google-java-format | frontend_partial | 10 |
| google/google-java-format | input_determined_arguments | 1 |
| google/google-java-format | limit_saturated | 9 |
| google/google-java-format | partial_analysis | 1 |
| google/google-java-format | recursive_call | 3 |
| google/google-java-format | uncomposed_subprocess | 1 |
| google/google-java-format | unmodeled_command | 3 |
| google/google-java-format | unmodeled_dynamic | 1 |
| google/google-java-format | unmodeled_dynamic_code | 2 |
| google/google-java-format | unmodeled_hooks | 2 |
| google/google-java-format | unrecognized_arguments | 1 |
| google/google-java-format | unrecoverable_source | 3 |
| google/google-java-format | unresolved_build_target | 16 |
| google/google-java-format | unresolved_call | 59 |
| google/google-java-format | unresolved_ci_step | 2 |
| google/zx | daemon_transport | 1 |
| google/zx | dynamic_dispatch | 3 |
| google/zx | dynamic_source | 12 |
| google/zx | external_unmodeled | 203 |
| google/zx | frontend_partial | 17 |
| google/zx | limit_saturated | 68 |
| google/zx | model_coverage | 6 |
| google/zx | no_entry_point | 1 |
| google/zx | package_scripts | 9 |
| google/zx | reviewed_command_surface | 15 |
| google/zx | uncomposed_subprocess | 2 |
| google/zx | unmodeled_command | 16 |
| google/zx | unmodeled_dynamic_code | 23 |
| google/zx | unmodeled_subcommand | 16 |
| google/zx | unpolled_async | 7 |
| google/zx | unrecognized_arguments | 3 |
| google/zx | unrecoverable_source | 93 |
| google/zx | unresolved_call | 1484 |
| google/zx | unresolved_ci_step | 1 |
| google/zx | unresolved_command | 2 |
| google/zx | unresolved_package_script | 33 |
| http-party/http-server | limit_saturated | 2 |
| http-party/http-server | no_entry_point | 1 |
| http-party/http-server | unmodeled_command | 2 |
| http-party/http-server | unrecoverable_source | 5 |
| http-party/http-server | unresolved_call | 18 |
| http-party/http-server | unresolved_ci_step | 2 |
| httpie/cli | cross_module | 41 |
| httpie/cli | daemon_transport | 2 |
| httpie/cli | dynamic_dispatch | 755 |
| httpie/cli | dynamic_source | 1 |
| httpie/cli | external_unmodeled | 268 |
| httpie/cli | frontend_partial | 40 |
| httpie/cli | limit_saturated | 3 |
| httpie/cli | package_scripts | 5 |
| httpie/cli | reviewed_command_surface | 4 |
| httpie/cli | unmodeled_command | 9 |
| httpie/cli | unmodeled_dynamic | 6 |
| httpie/cli | unmodeled_import | 17 |
| httpie/cli | unmodeled_subcommand | 1 |
| httpie/cli | unrecognized_arguments | 1 |
| httpie/cli | unrecoverable_source | 92 |
| httpie/cli | unresolved_build_target | 38 |
| httpie/cli | unresolved_call | 277 |
| httpie/cli | unresolved_ci_step | 6 |
| httpie/cli | unresolved_command | 2 |
| httpie/cli | unresolved_decorator | 4 |
| jbangdev/jbang | cross_module | 7 |
| jbangdev/jbang | dynamic_dispatch | 30 |
| jbangdev/jbang | dynamic_source | 36 |
| jbangdev/jbang | environment_configuration | 6 |
| jbangdev/jbang | external_unmodeled | 282 |
| jbangdev/jbang | frontend_partial | 62 |
| jbangdev/jbang | input_determined_arguments | 3 |
| jbangdev/jbang | limit_saturated | 5 |
| jbangdev/jbang | model_coverage | 1 |
| jbangdev/jbang | reviewed_command_surface | 18 |
| jbangdev/jbang | unmodeled_command | 152 |
| jbangdev/jbang | unmodeled_dynamic | 3 |
| jbangdev/jbang | unmodeled_dynamic_code | 4 |
| jbangdev/jbang | unmodeled_hooks | 7 |
| jbangdev/jbang | unmodeled_subcommand | 1 |
| jbangdev/jbang | unrecognized_arguments | 33 |
| jbangdev/jbang | unrecoverable_source | 58 |
| jbangdev/jbang | unresolved_build_target | 10 |
| jbangdev/jbang | unresolved_call | 177 |
| jbangdev/jbang | unresolved_ci_step | 17 |
| jbangdev/jbang | unresolved_command | 67 |
| jbangdev/jbang | unresolved_source | 2 |
| jbangdev/jbang | unsupported_shell_syntax | 25 |
| jbangdev/jbang | untyped_resource | 1 |
| jordansissel/fpm | cross_module | 8 |
| jordansissel/fpm | dynamic_dispatch | 1 |
| jordansissel/fpm | dynamic_source | 4 |
| jordansissel/fpm | external_unmodeled | 52 |
| jordansissel/fpm | frontend_partial | 7 |
| jordansissel/fpm | input_determined_arguments | 8 |
| jordansissel/fpm | limit_saturated | 1 |
| jordansissel/fpm | no_entry_point | 1 |
| jordansissel/fpm | package_scripts | 2 |
| jordansissel/fpm | partial_analysis | 14 |
| jordansissel/fpm | reviewed_command_surface | 2 |
| jordansissel/fpm | unmodeled_command | 15 |
| jordansissel/fpm | unmodeled_dynamic_code | 2 |
| jordansissel/fpm | unmodeled_import | 5 |
| jordansissel/fpm | unrecognized_arguments | 2 |
| jordansissel/fpm | unrecoverable_source | 41 |
| jordansissel/fpm | unresolved_build_target | 10 |
| jordansissel/fpm | unresolved_call | 87 |
| jordansissel/fpm | unresolved_command | 9 |
| jordansissel/fpm | unresolved_source | 4 |
| junegunn/fzf | cross_module | 3 |
| junegunn/fzf | dynamic_dispatch | 9 |
| junegunn/fzf | dynamic_source | 4 |
| junegunn/fzf | environment_configuration | 9 |
| junegunn/fzf | escaped_callable | 10 |
| junegunn/fzf | external_unmodeled | 400 |
| junegunn/fzf | frontend_partial | 15 |
| junegunn/fzf | limit_saturated | 1 |
| junegunn/fzf | model_coverage | 7 |
| junegunn/fzf | package_scripts | 4 |
| junegunn/fzf | reviewed_command_surface | 6 |
| junegunn/fzf | uncomposed_subprocess | 3 |
| junegunn/fzf | unmodeled_command | 73 |
| junegunn/fzf | unmodeled_subprocess | 8 |
| junegunn/fzf | unparsed_script | 6 |
| junegunn/fzf | unrecognized_arguments | 13 |
| junegunn/fzf | unrecoverable_source | 58 |
| junegunn/fzf | unresolved_build_target | 23 |
| junegunn/fzf | unresolved_call | 365 |
| junegunn/fzf | unresolved_command | 3 |
| junegunn/fzf | unsupported_shell_syntax | 18 |
| karpathy/nanochat | cross_module | 28 |
| karpathy/nanochat | dynamic_dispatch | 394 |
| karpathy/nanochat | dynamic_source | 18 |
| karpathy/nanochat | external_unmodeled | 134 |
| karpathy/nanochat | frontend_partial | 16 |
| karpathy/nanochat | limit_saturated | 1 |
| karpathy/nanochat | no_entry_point | 1 |
| karpathy/nanochat | package_scripts | 3 |
| karpathy/nanochat | reviewed_command_surface | 6 |
| karpathy/nanochat | unmodeled_command | 8 |
| karpathy/nanochat | unmodeled_dynamic | 10 |
| karpathy/nanochat | unmodeled_import | 22 |
| karpathy/nanochat | unrecoverable_source | 38 |
| karpathy/nanochat | unresolved_call | 339 |
| karpathy/nanochat | unresolved_decorator | 15 |
| karpathy/nanochat | unresolved_source | 4 |
| karpathy/nanochat | unsupported_shell_syntax | 9 |
| langchain4j/langchain4j | cross_module | 5 |
| langchain4j/langchain4j | daemon_transport | 5 |
| langchain4j/langchain4j | dynamic_dispatch | 42 |
| langchain4j/langchain4j | environment_configuration | 2 |
| langchain4j/langchain4j | external_unmodeled | 59 |
| langchain4j/langchain4j | frontend_partial | 10 |
| langchain4j/langchain4j | input_determined_arguments | 4 |
| langchain4j/langchain4j | limit_saturated | 2 |
| langchain4j/langchain4j | live_inventory | 5 |
| langchain4j/langchain4j | package_scripts | 1 |
| langchain4j/langchain4j | parse_error | 6 |
| langchain4j/langchain4j | reviewed_command_surface | 6 |
| langchain4j/langchain4j | unmodeled_command | 12 |
| langchain4j/langchain4j | unmodeled_hooks | 8 |
| langchain4j/langchain4j | unmodeled_subcommand | 2 |
| langchain4j/langchain4j | unparsed_script | 6 |
| langchain4j/langchain4j | unrecognized_arguments | 17 |
| langchain4j/langchain4j | unrecoverable_source | 30 |
| langchain4j/langchain4j | unresolved_build_target | 51 |
| langchain4j/langchain4j | unresolved_call | 56 |
| langchain4j/langchain4j | unresolved_command | 8 |
| langchain4j/langchain4j | unresolved_package_script | 1 |
| langchain4j/langchain4j | unsupported_shell_syntax | 9 |
| laravel/laravel | dynamic_source | 2 |
| laravel/laravel | external_unmodeled | 6 |
| laravel/laravel | frontend_partial | 2 |
| laravel/laravel | reviewed_command_surface | 3 |
| laravel/laravel | unrecognized_arguments | 1 |
| laravel/laravel | unrecoverable_source | 32 |
| laravel/laravel | unresolved_call | 6 |
| laravel/laravel | unresolved_include | 1 |
| mikefarah/yq | cross_module | 9 |
| mikefarah/yq | daemon_transport | 16 |
| mikefarah/yq | dynamic_dispatch | 9 |
| mikefarah/yq | dynamic_source | 9 |
| mikefarah/yq | environment_configuration | 3 |
| mikefarah/yq | external_unmodeled | 263 |
| mikefarah/yq | frontend_partial | 46 |
| mikefarah/yq | input_determined_arguments | 1 |
| mikefarah/yq | lifecycle_unbound | 2 |
| mikefarah/yq | model_coverage | 1 |
| mikefarah/yq | package_scripts | 1 |
| mikefarah/yq | registration_context | 4 |
| mikefarah/yq | reviewed_command_surface | 3 |
| mikefarah/yq | unmodeled_command | 77 |
| mikefarah/yq | unmodeled_hooks | 2 |
| mikefarah/yq | unmodeled_import | 4 |
| mikefarah/yq | unmodeled_subcommand | 2 |
| mikefarah/yq | unmodeled_subprocess | 3 |
| mikefarah/yq | unparsed_script | 1 |
| mikefarah/yq | unrecognized_arguments | 6 |
| mikefarah/yq | unrecoverable_source | 89 |
| mikefarah/yq | unresolved_build_target | 19 |
| mikefarah/yq | unresolved_call | 231 |
| mikefarah/yq | unresolved_command | 71 |
| mikefarah/yq | unresolved_source | 17 |
| mikefarah/yq | unsupported_shell_syntax | 1 |
| modelcontextprotocol/servers | cross_module | 11 |
| modelcontextprotocol/servers | dynamic_dispatch | 50 |
| modelcontextprotocol/servers | dynamic_source | 3 |
| modelcontextprotocol/servers | environment_configuration | 4 |
| modelcontextprotocol/servers | external_unmodeled | 53 |
| modelcontextprotocol/servers | frontend_partial | 6 |
| modelcontextprotocol/servers | limit_saturated | 6 |
| modelcontextprotocol/servers | model_coverage | 7 |
| modelcontextprotocol/servers | package_scripts | 16 |
| modelcontextprotocol/servers | reviewed_command_surface | 34 |
| modelcontextprotocol/servers | unmodeled_command | 12 |
| modelcontextprotocol/servers | unmodeled_dynamic_code | 1 |
| modelcontextprotocol/servers | unmodeled_hooks | 2 |
| modelcontextprotocol/servers | unmodeled_import | 3 |
| modelcontextprotocol/servers | unmodeled_subcommand | 5 |
| modelcontextprotocol/servers | unpolled_async | 2 |
| modelcontextprotocol/servers | unrecognized_arguments | 11 |
| modelcontextprotocol/servers | unrecoverable_source | 11 |
| modelcontextprotocol/servers | unresolved_call | 237 |
| modelcontextprotocol/servers | unresolved_package_script | 7 |
| nvm-sh/nvm | daemon_transport | 5 |
| nvm-sh/nvm | dynamic_source | 9 |
| nvm-sh/nvm | input_determined_arguments | 1 |
| nvm-sh/nvm | limit_saturated | 2 |
| nvm-sh/nvm | package_scripts | 25 |
| nvm-sh/nvm | parse_error | 2 |
| nvm-sh/nvm | reviewed_command_surface | 21 |
| nvm-sh/nvm | unmodeled_command | 67 |
| nvm-sh/nvm | unmodeled_subcommand | 20 |
| nvm-sh/nvm | unparsed_script | 1 |
| nvm-sh/nvm | unrecognized_arguments | 25 |
| nvm-sh/nvm | unrecoverable_source | 58 |
| nvm-sh/nvm | unresolved_alias | 29 |
| nvm-sh/nvm | unresolved_build_target | 15 |
| nvm-sh/nvm | unresolved_ci_step | 28 |
| nvm-sh/nvm | unresolved_command | 1 |
| nvm-sh/nvm | unresolved_package_script | 9 |
| nvm-sh/nvm | unresolved_source | 8 |
| nvm-sh/nvm | unsupported_shell_syntax | 13 |
| ohmyzsh/ohmyzsh | cross_module | 2 |
| ohmyzsh/ohmyzsh | dynamic_dispatch | 94 |
| ohmyzsh/ohmyzsh | dynamic_source | 4 |
| ohmyzsh/ohmyzsh | execution_cycle | 3 |
| ohmyzsh/ohmyzsh | external_unmodeled | 23 |
| ohmyzsh/ohmyzsh | frontend_partial | 8 |
| ohmyzsh/ohmyzsh | limit_saturated | 2 |
| ohmyzsh/ohmyzsh | package_scripts | 4 |
| ohmyzsh/ohmyzsh | parse_error | 55 |
| ohmyzsh/ohmyzsh | reviewed_command_surface | 34 |
| ohmyzsh/ohmyzsh | unmodeled_command | 143 |
| ohmyzsh/ohmyzsh | unmodeled_dynamic | 5 |
| ohmyzsh/ohmyzsh | unmodeled_hooks | 4 |
| ohmyzsh/ohmyzsh | unmodeled_import | 3 |
| ohmyzsh/ohmyzsh | unmodeled_subcommand | 5 |
| ohmyzsh/ohmyzsh | unparsed_script | 10 |
| ohmyzsh/ohmyzsh | unrecognized_arguments | 51 |
| ohmyzsh/ohmyzsh | unrecoverable_source | 24 |
| ohmyzsh/ohmyzsh | unresolved_alias | 1 |
| ohmyzsh/ohmyzsh | unresolved_build_target | 14 |
| ohmyzsh/ohmyzsh | unresolved_call | 73 |
| ohmyzsh/ohmyzsh | unresolved_ci_step | 2 |
| ohmyzsh/ohmyzsh | unresolved_command | 35 |
| ohmyzsh/ohmyzsh | unresolved_source | 10 |
| ohmyzsh/ohmyzsh | unsupported_shell_syntax | 92 |
| ohmyzsh/ohmyzsh | untyped_resource | 1 |
| open-telemetry/opentelemetry-python | cross_module | 36 |
| open-telemetry/opentelemetry-python | daemon_transport | 2 |
| open-telemetry/opentelemetry-python | dispatch_rounds_exhausted | 112 |
| open-telemetry/opentelemetry-python | dynamic_dispatch | 2443 |
| open-telemetry/opentelemetry-python | dynamic_source | 1 |
| open-telemetry/opentelemetry-python | environment_configuration | 14 |
| open-telemetry/opentelemetry-python | external_unmodeled | 868 |
| open-telemetry/opentelemetry-python | frontend_partial | 9 |
| open-telemetry/opentelemetry-python | lifecycle_unbound | 32 |
| open-telemetry/opentelemetry-python | limit_saturated | 1 |
| open-telemetry/opentelemetry-python | model_coverage | 1 |
| open-telemetry/opentelemetry-python | package_scripts | 259 |
| open-telemetry/opentelemetry-python | reviewed_command_surface | 271 |
| open-telemetry/opentelemetry-python | unmodeled_command | 35 |
| open-telemetry/opentelemetry-python | unmodeled_dynamic | 30 |
| open-telemetry/opentelemetry-python | unmodeled_hooks | 14 |
| open-telemetry/opentelemetry-python | unmodeled_import | 9 |
| open-telemetry/opentelemetry-python | unmodeled_subcommand | 2 |
| open-telemetry/opentelemetry-python | unmodeled_subprocess | 6 |
| open-telemetry/opentelemetry-python | unparsed_script | 5 |
| open-telemetry/opentelemetry-python | unrecognized_arguments | 290 |
| open-telemetry/opentelemetry-python | unrecoverable_source | 33 |
| open-telemetry/opentelemetry-python | unresolved_call | 796 |
| open-telemetry/opentelemetry-python | unresolved_ci_step | 413 |
| open-telemetry/opentelemetry-python | unresolved_command | 1 |
| open-telemetry/opentelemetry-python | unsupported_shell_syntax | 9 |
| orhun/git-cliff | cross_module | 5 |
| orhun/git-cliff | dynamic_source | 3 |
| orhun/git-cliff | environment_configuration | 5 |
| orhun/git-cliff | external_unmodeled | 12 |
| orhun/git-cliff | frontend_partial | 4 |
| orhun/git-cliff | limit_saturated | 1 |
| orhun/git-cliff | model_coverage | 3 |
| orhun/git-cliff | package_scripts | 7 |
| orhun/git-cliff | parse_error | 1 |
| orhun/git-cliff | reviewed_command_surface | 5 |
| orhun/git-cliff | unexpanded_macro | 2 |
| orhun/git-cliff | unmodeled_command | 20 |
| orhun/git-cliff | unmodeled_dynamic | 7 |
| orhun/git-cliff | unmodeled_hooks | 2 |
| orhun/git-cliff | unmodeled_subcommand | 3 |
| orhun/git-cliff | unmodeled_subprocess | 1 |
| orhun/git-cliff | unparsed_script | 3 |
| orhun/git-cliff | unpolled_async | 1 |
| orhun/git-cliff | unrecognized_arguments | 7 |
| orhun/git-cliff | unrecoverable_source | 21 |
| orhun/git-cliff | unresolved_build_target | 22 |
| orhun/git-cliff | unresolved_call | 108 |
| orhun/git-cliff | unresolved_ci_step | 1 |
| orhun/git-cliff | unresolved_package_script | 4 |
| prettier/prettier | dynamic_source | 10 |
| prettier/prettier | environment_configuration | 6 |
| prettier/prettier | external_unmodeled | 784 |
| prettier/prettier | frontend_partial | 266 |
| prettier/prettier | limit_saturated | 84 |
| prettier/prettier | no_entry_point | 82 |
| prettier/prettier | package_scripts | 20 |
| prettier/prettier | reviewed_command_surface | 28 |
| prettier/prettier | unmodeled_command | 20 |
| prettier/prettier | unmodeled_dynamic | 2 |
| prettier/prettier | unmodeled_dynamic_code | 271 |
| prettier/prettier | unmodeled_subcommand | 2 |
| prettier/prettier | unpolled_async | 69 |
| prettier/prettier | unrecognized_arguments | 9 |
| prettier/prettier | unrecoverable_source | 76 |
| prettier/prettier | unresolved_call | 1964 |
| prettier/prettier | unresolved_ci_step | 18 |
| prettier/prettier | unresolved_package_script | 31 |
| prism-php/prism | reviewed_command_surface | 1 |
| prism-php/prism | unmodeled_command | 5 |
| prism-php/prism | unrecoverable_source | 5 |
| prism-php/prism | unresolved_ci_step | 4 |
| psf/black | cross_module | 29 |
| psf/black | daemon_transport | 2 |
| psf/black | dynamic_dispatch | 678 |
| psf/black | dynamic_source | 5 |
| psf/black | external_unmodeled | 150 |
| psf/black | frontend_partial | 24 |
| psf/black | lifecycle_unbound | 1 |
| psf/black | limit_saturated | 11 |
| psf/black | no_entry_point | 1 |
| psf/black | package_scripts | 11 |
| psf/black | parse_error | 2 |
| psf/black | unmodeled_command | 21 |
| psf/black | unmodeled_dynamic | 8 |
| psf/black | unmodeled_hooks | 2 |
| psf/black | unmodeled_import | 29 |
| psf/black | unpolled_async | 1 |
| psf/black | unrecognized_arguments | 5 |
| psf/black | unrecoverable_source | 25 |
| psf/black | unresolved_alias | 1 |
| psf/black | unresolved_call | 349 |
| psf/black | unresolved_ci_step | 24 |
| psf/black | unresolved_command | 4 |
| psf/black | unresolved_decorator | 37 |
| psf/black | unsupported_shell_syntax | 1 |
| pydantic/pydantic-ai | cross_module | 77 |
| pydantic/pydantic-ai | dynamic_dispatch | 949 |
| pydantic/pydantic-ai | dynamic_source | 420 |
| pydantic/pydantic-ai | external_unmodeled | 360 |
| pydantic/pydantic-ai | frontend_partial | 52 |
| pydantic/pydantic-ai | input_determined_arguments | 1 |
| pydantic/pydantic-ai | lifecycle_unbound | 1 |
| pydantic/pydantic-ai | missing_required_arguments | 1 |
| pydantic/pydantic-ai | model_coverage | 1 |
| pydantic/pydantic-ai | no_entry_point | 2 |
| pydantic/pydantic-ai | package_scripts | 95 |
| pydantic/pydantic-ai | parse_error | 7 |
| pydantic/pydantic-ai | reviewed_command_surface | 78 |
| pydantic/pydantic-ai | unmodeled_command | 68 |
| pydantic/pydantic-ai | unmodeled_dynamic | 8 |
| pydantic/pydantic-ai | unmodeled_import | 137 |
| pydantic/pydantic-ai | unmodeled_subcommand | 14 |
| pydantic/pydantic-ai | unpolled_async | 4 |
| pydantic/pydantic-ai | unrecognized_arguments | 100 |
| pydantic/pydantic-ai | unrecoverable_source | 987 |
| pydantic/pydantic-ai | unresolved_alias | 1 |
| pydantic/pydantic-ai | unresolved_build_target | 11 |
| pydantic/pydantic-ai | unresolved_call | 636 |
| pydantic/pydantic-ai | unresolved_ci_step | 46 |
| pydantic/pydantic-ai | unresolved_command | 20 |
| pydantic/pydantic-ai | unresolved_source | 13 |
| pydantic/pydantic-ai | unsupported_shell_syntax | 8 |
| pyenv/pyenv | cross_module | 5 |
| pyenv/pyenv | dynamic_dispatch | 210 |
| pyenv/pyenv | dynamic_source | 18 |
| pyenv/pyenv | environment_configuration | 1 |
| pyenv/pyenv | external_unmodeled | 72 |
| pyenv/pyenv | frontend_partial | 6 |
| pyenv/pyenv | input_determined_arguments | 2 |
| pyenv/pyenv | lifecycle_unbound | 1 |
| pyenv/pyenv | limit_saturated | 1 |
| pyenv/pyenv | package_scripts | 6 |
| pyenv/pyenv | parse_error | 7 |
| pyenv/pyenv | reviewed_command_surface | 14 |
| pyenv/pyenv | unmodeled_command | 168 |
| pyenv/pyenv | unmodeled_dynamic | 4 |
| pyenv/pyenv | unmodeled_import | 9 |
| pyenv/pyenv | unmodeled_subcommand | 6 |
| pyenv/pyenv | unmodeled_subprocess | 1 |
| pyenv/pyenv | unparsed_script | 8 |
| pyenv/pyenv | unrecognized_arguments | 57 |
| pyenv/pyenv | unrecoverable_source | 70 |
| pyenv/pyenv | unresolved_build_target | 8 |
| pyenv/pyenv | unresolved_call | 61 |
| pyenv/pyenv | unresolved_ci_step | 23 |
| pyenv/pyenv | unresolved_command | 38 |
| pyenv/pyenv | unresolved_source | 12 |
| pyenv/pyenv | unresolved_trap_action | 1 |
| pyenv/pyenv | unsupported_shell_syntax | 100 |
| pypa/pip | cross_module | 19 |
| pypa/pip | dynamic_dispatch | 340 |
| pypa/pip | dynamic_source | 7 |
| pypa/pip | external_unmodeled | 172 |
| pypa/pip | frontend_partial | 33 |
| pypa/pip | limit_saturated | 2 |
| pypa/pip | no_entry_point | 1 |
| pypa/pip | package_scripts | 11 |
| pypa/pip | reviewed_command_surface | 2 |
| pypa/pip | uncomposed_subprocess | 2 |
| pypa/pip | unmodeled_dynamic | 3 |
| pypa/pip | unmodeled_hooks | 2 |
| pypa/pip | unmodeled_import | 11 |
| pypa/pip | unmodeled_subcommand | 1 |
| pypa/pip | unrecoverable_source | 30 |
| pypa/pip | unresolved_call | 165 |
| pypa/pip | unresolved_ci_step | 20 |
| pypa/pip | unresolved_command | 4 |
| pypa/pipx | cross_module | 11 |
| pypa/pipx | dynamic_dispatch | 449 |
| pypa/pipx | dynamic_source | 3 |
| pypa/pipx | external_unmodeled | 93 |
| pypa/pipx | frontend_partial | 13 |
| pypa/pipx | lifecycle_unbound | 6 |
| pypa/pipx | model_coverage | 2 |
| pypa/pipx | package_scripts | 8 |
| pypa/pipx | parse_error | 1 |
| pypa/pipx | reviewed_command_surface | 4 |
| pypa/pipx | uncomposed_subprocess | 3 |
| pypa/pipx | unmodeled_command | 9 |
| pypa/pipx | unmodeled_dynamic | 3 |
| pypa/pipx | unmodeled_import | 9 |
| pypa/pipx | unrecognized_arguments | 4 |
| pypa/pipx | unrecoverable_source | 12 |
| pypa/pipx | unresolved_call | 73 |
| pypa/pipx | unresolved_ci_step | 9 |
| python-poetry/poetry | cross_module | 20 |
| python-poetry/poetry | dynamic_dispatch | 237 |
| python-poetry/poetry | dynamic_source | 4 |
| python-poetry/poetry | external_unmodeled | 38 |
| python-poetry/poetry | frontend_partial | 4 |
| python-poetry/poetry | model_coverage | 1 |
| python-poetry/poetry | package_scripts | 5 |
| python-poetry/poetry | reviewed_command_surface | 17 |
| python-poetry/poetry | unmodeled_command | 5 |
| python-poetry/poetry | unmodeled_dynamic | 2 |
| python-poetry/poetry | unmodeled_hooks | 2 |
| python-poetry/poetry | unmodeled_import | 34 |
| python-poetry/poetry | unmodeled_subcommand | 3 |
| python-poetry/poetry | unrecognized_arguments | 12 |
| python-poetry/poetry | unrecoverable_source | 8 |
| python-poetry/poetry | unresolved_call | 36 |
| python-poetry/poetry | unresolved_command | 3 |
| python-poetry/poetry | unresolved_decorator | 2 |
| python-poetry/poetry | unresolved_package_script | 1 |
| python-poetry/poetry | unsupported_shell_syntax | 1 |
| python-websockets/websockets | cross_module | 11 |
| python-websockets/websockets | dynamic_dispatch | 1354 |
| python-websockets/websockets | environment_configuration | 2 |
| python-websockets/websockets | external_unmodeled | 923 |
| python-websockets/websockets | frontend_partial | 78 |
| python-websockets/websockets | model_coverage | 2 |
| python-websockets/websockets | no_entry_point | 5 |
| python-websockets/websockets | package_scripts | 4 |
| python-websockets/websockets | uncomposed_subprocess | 60 |
| python-websockets/websockets | unmodeled_command | 6 |
| python-websockets/websockets | unmodeled_dynamic | 3 |
| python-websockets/websockets | unmodeled_import | 19 |
| python-websockets/websockets | unpolled_async | 9 |
| python-websockets/websockets | unrecoverable_source | 17 |
| python-websockets/websockets | unresolved_build_target | 8 |
| python-websockets/websockets | unresolved_call | 893 |
| rbenv/rbenv | dynamic_source | 5 |
| rbenv/rbenv | frontend_partial | 1 |
| rbenv/rbenv | parse_error | 4 |
| rbenv/rbenv | reviewed_command_surface | 1 |
| rbenv/rbenv | unmodeled_command | 70 |
| rbenv/rbenv | unparsed_script | 5 |
| rbenv/rbenv | unrecognized_arguments | 23 |
| rbenv/rbenv | unrecoverable_source | 27 |
| rbenv/rbenv | unresolved_build_target | 1 |
| rbenv/rbenv | unresolved_call | 31 |
| rbenv/rbenv | unresolved_ci_step | 2 |
| rbenv/rbenv | unresolved_command | 13 |
| rbenv/rbenv | unresolved_source | 5 |
| rbenv/rbenv | unsupported_shell_syntax | 2 |
| release-it/release-it | external_unmodeled | 45 |
| release-it/release-it | frontend_partial | 8 |
| release-it/release-it | limit_saturated | 9 |
| release-it/release-it | no_entry_point | 5 |
| release-it/release-it | package_scripts | 1 |
| release-it/release-it | reviewed_command_surface | 3 |
| release-it/release-it | unmodeled_command | 4 |
| release-it/release-it | unmodeled_dynamic_code | 12 |
| release-it/release-it | unpolled_async | 8 |
| release-it/release-it | unrecoverable_source | 2 |
| release-it/release-it | unresolved_call | 67 |
| release-it/release-it | unresolved_ci_step | 4 |
| restic/restic | cross_module | 324 |
| restic/restic | daemon_transport | 5 |
| restic/restic | dynamic_dispatch | 211 |
| restic/restic | dynamic_registration | 1 |
| restic/restic | environment_configuration | 18 |
| restic/restic | escaped_callable | 292 |
| restic/restic | external_unmodeled | 8712 |
| restic/restic | frontend_partial | 428 |
| restic/restic | input_determined_arguments | 4 |
| restic/restic | lifecycle_unbound | 56 |
| restic/restic | limit_saturated | 1 |
| restic/restic | model_coverage | 1 |
| restic/restic | registration_context | 37 |
| restic/restic | reviewed_command_surface | 1 |
| restic/restic | uncomposed_subprocess | 1 |
| restic/restic | unmodeled_command | 6 |
| restic/restic | unmodeled_import | 96 |
| restic/restic | unmodeled_subcommand | 16 |
| restic/restic | unmodeled_subprocess | 2 |
| restic/restic | unrecognized_arguments | 18 |
| restic/restic | unrecoverable_source | 19 |
| restic/restic | unresolved_alias | 5 |
| restic/restic | unresolved_build_target | 2 |
| restic/restic | unresolved_call | 3094 |
| restic/restic | unresolved_ci_step | 7 |
| restic/restic | unresolved_command | 18 |
| restic/restic | unsupported_shell_syntax | 3 |
| ruby/rake | cross_module | 3 |
| ruby/rake | dynamic_source | 1 |
| ruby/rake | external_unmodeled | 1 |
| ruby/rake | frontend_partial | 24 |
| ruby/rake | model_coverage | 1 |
| ruby/rake | no_entry_point | 2 |
| ruby/rake | package_scripts | 1 |
| ruby/rake | partial_analysis | 13 |
| ruby/rake | reviewed_command_surface | 4 |
| ruby/rake | unmodeled_dynamic | 2 |
| ruby/rake | unmodeled_import | 12 |
| ruby/rake | unrecognized_arguments | 4 |
| ruby/rake | unrecoverable_source | 2 |
| ruby/rake | unresolved_call | 239 |
| ruby/rake | unresolved_ci_step | 2 |
| rust-lang/cargo | cross_module | 47 |
| rust-lang/cargo | dynamic_dispatch | 11 |
| rust-lang/cargo | dynamic_source | 2 |
| rust-lang/cargo | environment_configuration | 7 |
| rust-lang/cargo | external_unmodeled | 106 |
| rust-lang/cargo | frontend_partial | 12 |
| rust-lang/cargo | limit_saturated | 8 |
| rust-lang/cargo | missing_required_arguments | 1 |
| rust-lang/cargo | no_entry_point | 1 |
| rust-lang/cargo | package_scripts | 4 |
| rust-lang/cargo | recursive_call | 2 |
| rust-lang/cargo | reviewed_command_surface | 1 |
| rust-lang/cargo | uncomposed_subprocess | 4 |
| rust-lang/cargo | unexpanded_macro | 3 |
| rust-lang/cargo | unmodeled_command | 52 |
| rust-lang/cargo | unmodeled_dynamic | 33 |
| rust-lang/cargo | unmodeled_dynamic_code | 1 |
| rust-lang/cargo | unmodeled_subprocess | 3 |
| rust-lang/cargo | unrecognized_arguments | 14 |
| rust-lang/cargo | unrecoverable_source | 16 |
| rust-lang/cargo | unresolved_build_target | 28 |
| rust-lang/cargo | unresolved_call | 1044 |
| rust-lang/cargo | unresolved_ci_step | 2 |
| rust-lang/cargo | unresolved_command | 3 |
| sdkman/sdkman-cli | daemon_transport | 1 |
| sdkman/sdkman-cli | dynamic_source | 3 |
| sdkman/sdkman-cli | reviewed_command_surface | 4 |
| sdkman/sdkman-cli | unmodeled_command | 21 |
| sdkman/sdkman-cli | unrecognized_arguments | 5 |
| sdkman/sdkman-cli | unrecoverable_source | 6 |
| sdkman/sdkman-cli | unresolved_build_target | 6 |
| sdkman/sdkman-cli | unresolved_command | 1 |
| sdkman/sdkman-cli | unresolved_source | 2 |
| sdkman/sdkman-cli | unsupported_shell_syntax | 6 |
| sharkdp/bat | cross_module | 20 |
| sharkdp/bat | dynamic_source | 3 |
| sharkdp/bat | environment_configuration | 3 |
| sharkdp/bat | external_unmodeled | 15 |
| sharkdp/bat | frontend_partial | 2 |
| sharkdp/bat | input_determined_arguments | 1 |
| sharkdp/bat | limit_saturated | 2 |
| sharkdp/bat | package_scripts | 4 |
| sharkdp/bat | reviewed_command_surface | 11 |
| sharkdp/bat | uncomposed_subprocess | 19 |
| sharkdp/bat | unmodeled_command | 22 |
| sharkdp/bat | unmodeled_dynamic | 3 |
| sharkdp/bat | unmodeled_subcommand | 1 |
| sharkdp/bat | unmodeled_subprocess | 1 |
| sharkdp/bat | unparsed_script | 1 |
| sharkdp/bat | unrecognized_arguments | 7 |
| sharkdp/bat | unrecoverable_source | 6 |
| sharkdp/bat | unresolved_build_target | 18 |
| sharkdp/bat | unresolved_call | 228 |
| sharkdp/bat | unresolved_ci_step | 1 |
| sharkdp/bat | unresolved_command | 26 |
| sharkdp/bat | unresolved_source | 1 |
| sharkdp/bat | unsupported_shell_syntax | 4 |
| sinatra/sinatra | external_unmodeled | 42 |
| sinatra/sinatra | frontend_partial | 21 |
| sinatra/sinatra | limit_saturated | 1 |
| sinatra/sinatra | no_entry_point | 3 |
| sinatra/sinatra | package_scripts | 2 |
| sinatra/sinatra | partial_analysis | 4 |
| sinatra/sinatra | reexport_ambiguous | 2 |
| sinatra/sinatra | reviewed_command_surface | 10 |
| sinatra/sinatra | unmodeled_dynamic_code | 1 |
| sinatra/sinatra | unmodeled_import | 9 |
| sinatra/sinatra | unrecognized_arguments | 10 |
| sinatra/sinatra | unresolved_call | 33 |
| sindresorhus/execa | dynamic_dispatch | 1 |
| sindresorhus/execa | external_unmodeled | 50 |
| sindresorhus/execa | frontend_partial | 11 |
| sindresorhus/execa | limit_saturated | 1 |
| sindresorhus/execa | no_entry_point | 17 |
| sindresorhus/execa | reviewed_command_surface | 2 |
| sindresorhus/execa | uncomposed_subprocess | 2 |
| sindresorhus/execa | unmodeled_command | 6 |
| sindresorhus/execa | unmodeled_dynamic_code | 14 |
| sindresorhus/execa | unpolled_async | 31 |
| sindresorhus/execa | unresolved_call | 71 |
| sindresorhus/execa | unresolved_ci_step | 4 |
| spring-projects/spring-ai | external_unmodeled | 13 |
| spring-projects/spring-ai | frontend_partial | 1 |
| spring-projects/spring-ai | limit_saturated | 1 |
| spring-projects/spring-ai | recursive_call | 1 |
| spring-projects/spring-ai | reviewed_command_surface | 10 |
| spring-projects/spring-ai | unmodeled_command | 7 |
| spring-projects/spring-ai | unmodeled_hooks | 3 |
| spring-projects/spring-ai | unrecognized_arguments | 16 |
| spring-projects/spring-ai | unrecoverable_source | 2 |
| spring-projects/spring-ai | unresolved_build_target | 4 |
| spring-projects/spring-ai | unresolved_call | 8 |
| spring-projects/spring-ai | unresolved_ci_step | 36 |
| spring-projects/spring-ai | unresolved_command | 3 |
| spring-projects/spring-ai | unresolved_source | 1 |
| spring-projects/spring-ai | unsupported_shell_syntax | 3 |
| spring-projects/spring-petclinic | cluster_api | 3 |
| spring-projects/spring-petclinic | cross_module | 1 |
| spring-projects/spring-petclinic | dynamic_source | 1 |
| spring-projects/spring-petclinic | environment_configuration | 2 |
| spring-projects/spring-petclinic | frontend_partial | 1 |
| spring-projects/spring-petclinic | input_determined_arguments | 2 |
| spring-projects/spring-petclinic | partial_analysis | 5 |
| spring-projects/spring-petclinic | reviewed_command_surface | 9 |
| spring-projects/spring-petclinic | unmodeled_command | 7 |
| spring-projects/spring-petclinic | unrecognized_arguments | 14 |
| spring-projects/spring-petclinic | unrecoverable_source | 2 |
| spring-projects/spring-petclinic | unresolved_build_target | 2 |
| spring-projects/spring-petclinic | unresolved_call | 1 |
| spring-projects/spring-petclinic | unresolved_command | 4 |
| spring-projects/spring-petclinic | unsupported_shell_syntax | 7 |
| symfony/console | daemon_transport | 3 |
| symfony/console | dynamic_call | 56 |
| symfony/console | dynamic_include | 1 |
| symfony/console | dynamic_source | 3 |
| symfony/console | external_unmodeled | 4 |
| symfony/console | frontend_partial | 6 |
| symfony/console | limit_saturated | 2 |
| symfony/console | unmodeled_command | 209 |
| symfony/console | unrecoverable_source | 242 |
| symfony/console | unresolved_call | 2 |
| symfony/console | unresolved_command | 2 |
| symfony/console | unresolved_source | 3 |
| symfony/console | unsupported_shell_syntax | 75 |
| tiangolo/full-stack-fastapi-template | cross_module | 195 |
| tiangolo/full-stack-fastapi-template | daemon_transport | 24 |
| tiangolo/full-stack-fastapi-template | dynamic_dispatch | 316 |
| tiangolo/full-stack-fastapi-template | dynamic_source | 16 |
| tiangolo/full-stack-fastapi-template | environment_configuration | 2 |
| tiangolo/full-stack-fastapi-template | external_unmodeled | 80 |
| tiangolo/full-stack-fastapi-template | frontend_partial | 54 |
| tiangolo/full-stack-fastapi-template | model_coverage | 3 |
| tiangolo/full-stack-fastapi-template | package_scripts | 20 |
| tiangolo/full-stack-fastapi-template | registration_context | 46 |
| tiangolo/full-stack-fastapi-template | reviewed_command_surface | 24 |
| tiangolo/full-stack-fastapi-template | unmodeled_command | 25 |
| tiangolo/full-stack-fastapi-template | unmodeled_hooks | 6 |
| tiangolo/full-stack-fastapi-template | unmodeled_import | 54 |
| tiangolo/full-stack-fastapi-template | unrecognized_arguments | 6 |
| tiangolo/full-stack-fastapi-template | unrecoverable_source | 57 |
| tiangolo/full-stack-fastapi-template | unresolved_call | 150 |
| tiangolo/full-stack-fastapi-template | unresolved_ci_step | 3 |
| tiangolo/full-stack-fastapi-template | unresolved_package_script | 13 |
| tmuxinator/tmuxinator | external_unmodeled | 4 |
| tmuxinator/tmuxinator | frontend_partial | 7 |
| tmuxinator/tmuxinator | limit_saturated | 1 |
| tmuxinator/tmuxinator | partial_analysis | 5 |
| tmuxinator/tmuxinator | reviewed_command_surface | 5 |
| tmuxinator/tmuxinator | unmodeled_dynamic | 2 |
| tmuxinator/tmuxinator | unmodeled_dynamic_code | 2 |
| tmuxinator/tmuxinator | unrecognized_arguments | 5 |
| tmuxinator/tmuxinator | unresolved_call | 65 |
| tox-dev/tox | cross_module | 22 |
| tox-dev/tox | dynamic_dispatch | 295 |
| tox-dev/tox | dynamic_source | 1 |
| tox-dev/tox | external_unmodeled | 165 |
| tox-dev/tox | frontend_partial | 7 |
| tox-dev/tox | model_coverage | 1 |
| tox-dev/tox | no_entry_point | 1 |
| tox-dev/tox | package_scripts | 2 |
| tox-dev/tox | reviewed_command_surface | 2 |
| tox-dev/tox | unmodeled_command | 3 |
| tox-dev/tox | unmodeled_dynamic | 4 |
| tox-dev/tox | unmodeled_hooks | 2 |
| tox-dev/tox | unmodeled_import | 13 |
| tox-dev/tox | unrecognized_arguments | 6 |
| tox-dev/tox | unrecoverable_source | 4 |
| tox-dev/tox | unresolved_call | 166 |
| tox-dev/tox | unresolved_ci_step | 7 |
| tox-dev/tox | unsupported_shell_syntax | 3 |
| wp-cli/wp-cli | dynamic_include | 2 |
| wp-cli/wp-cli | dynamic_source | 2 |
| wp-cli/wp-cli | environment_configuration | 2 |
| wp-cli/wp-cli | frontend_partial | 8 |
| wp-cli/wp-cli | reviewed_command_surface | 10 |
| wp-cli/wp-cli | unmodeled_hooks | 3 |
| wp-cli/wp-cli | unmodeled_subprocess | 1 |
| wp-cli/wp-cli | unparsed_script | 1 |
| wp-cli/wp-cli | unrecognized_arguments | 10 |
| wp-cli/wp-cli | unrecoverable_source | 8 |
| wp-cli/wp-cli | unresolved_call | 30 |
| wp-cli/wp-cli | unresolved_ci_step | 1 |
| wp-cli/wp-cli | unsupported_shell_syntax | 3 |
| yt-dlp/yt-dlp | cross_module | 5 |
| yt-dlp/yt-dlp | dynamic_dispatch | 1040 |
| yt-dlp/yt-dlp | dynamic_source | 33 |
| yt-dlp/yt-dlp | environment_configuration | 7 |
| yt-dlp/yt-dlp | external_unmodeled | 375 |
| yt-dlp/yt-dlp | frontend_partial | 141 |
| yt-dlp/yt-dlp | input_determined_arguments | 1 |
| yt-dlp/yt-dlp | lifecycle_unbound | 3 |
| yt-dlp/yt-dlp | limit_saturated | 4 |
| yt-dlp/yt-dlp | model_coverage | 10 |
| yt-dlp/yt-dlp | no_entry_point | 1 |
| yt-dlp/yt-dlp | package_scripts | 22 |
| yt-dlp/yt-dlp | reviewed_command_surface | 5 |
| yt-dlp/yt-dlp | uncomposed_subprocess | 2 |
| yt-dlp/yt-dlp | unmodeled_command | 22 |
| yt-dlp/yt-dlp | unmodeled_dynamic | 10 |
| yt-dlp/yt-dlp | unmodeled_hooks | 4 |
| yt-dlp/yt-dlp | unmodeled_import | 17 |
| yt-dlp/yt-dlp | unmodeled_subcommand | 10 |
| yt-dlp/yt-dlp | unmodeled_subprocess | 1 |
| yt-dlp/yt-dlp | unparsed_script | 1 |
| yt-dlp/yt-dlp | unrecognized_arguments | 11 |
| yt-dlp/yt-dlp | unrecoverable_source | 218 |
| yt-dlp/yt-dlp | unresolved_build_target | 45 |
| yt-dlp/yt-dlp | unresolved_call | 262 |
| yt-dlp/yt-dlp | unresolved_ci_step | 13 |
| yt-dlp/yt-dlp | unresolved_command | 15 |
| yt-dlp/yt-dlp | unresolved_decorator | 33 |
| yt-dlp/yt-dlp | unresolved_source | 3 |

## 4. Performance

run `20260921T150325Z-performance-62642` measured 2026-09-21T15:03:25Z

### Latency and stress

nah corpus analyze p99: 1913 us (target 5000 us)

nah cold process median: 5321 us
nah cold catalog + first analyze median: 2731 us (target 5000 us)

| engine case | min us | median us | p95 us | max us |
|---|---|---|---|---|
| exec: rm -rf | 634.333 | 1581.250 | 2871.042 | 3757.125 |
| exec: unmodeled cmd | 248.042 | 401.750 | 2205.375 | 2441.708 |
| go: os/exec | 510.542 | 2431.500 | 3631.500 | 4203.916 |
| js: fs/child_process | 1520.667 | 2502.417 | 5605.375 | 6262.208 |
| nested: docker->psql->SQL | 822.083 | 940.458 | 1576.500 | 2325.792 |
| pathological (500 cmds + deep) | 3228416.416 | 3249408.542 | 3316166.916 | 3346537.417 |
| python: os/shutil | 592.834 | 2485.500 | 4237.625 | 18073.375 |
| shell word list (4096 words) | 11186.833 | 11344.417 | 11599.125 | 11761.542 |
| shell: small pipeline | 2505.792 | 2660.459 | 3005.500 | 3291.000 |
| shell: substitution | 714.416 | 768.667 | 951.375 | 1147.000 |

### Invocation host measurements

| source | p50 ms | p99 ms | max ms | max RSS MB |
|---|---|---|---|---|
| adversarial | 0.8 | 130.3 | 10030.1 | 344.7 |
| nah | 0.9 | 9.1 | 39.6 | 158.0 |
| swe | 1.0 | 17.6 | 783.0 | 214.2 |
| wild | 1.1 | 105.5 | 10000.0 | 318.3 |
