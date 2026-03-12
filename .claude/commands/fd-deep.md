---
description: Deep parallel analysis — spawn multiple agents to explore a hard problem from different angles, then synthesize
allowed-tools: Task, Read, Glob, Grep
---

# Deep Analysis

Parallel exploration of a hard problem from multiple angles, inspired by test-time compute scaling. Use when stuck, when the problem is complex enough to benefit from diverse perspectives, or when you need "big brains" on something.

## Argument

Problem description or context: $ARGUMENTS

## Phase 1: Understand the Problem

1. **Parse the argument** — what is the user stuck on? What are they trying to achieve?
2. **Gather context** — read conversation history for what's already been tried or discussed
3. **Check for active FD** — if there's a relevant FD file, read it for design context
4. **Scan the codebase** — do a quick targeted search to understand the relevant code area (key files, architecture, constraints). Keep this brief — the agents will do the deep exploration.

## Phase 2: Design the Exploration

Based on the problem, design **4 exploration angles**. These are NOT redundant — each agent gets a **distinct lens** on the problem.

**Before launching, check orthogonality:** Would two of these angles likely explore the same code paths and reach similar conclusions? If so, reframe one to ensure genuine diversity.

**How to choose angles — infer from the problem type:**

For **performance optimization**:
- Algorithmic: Can the approach itself be fundamentally different?
- Structural: Can the data layout, schema, or architecture reduce work?
- Incremental: Can we avoid redoing work (caching, materialization, deltas)?
- Environmental: Are we fighting the platform? (Snowflake query patterns, Python GIL, network topology)

For **architecture/design decisions**:
- Simplicity: What's the minimal viable approach?
- Scalability: What happens at 10x/100x current load?
- Precedent: How do similar systems/libraries solve this?
- Contrarian: What if the obvious approach is wrong? What's the unconventional path?

For **debugging / "why is this broken"**:
- Symptoms: Trace the failure path precisely — what's the chain of events?
- Environment: What changed? Versions, configs, data, dependencies?
- Assumptions: What are we assuming that might not be true?
- Similar: Has this pattern of failure been seen elsewhere in the codebase or in public?

For **anything else** — choose angles that maximize diversity of insight. Ask: "If these 4 experts were in a room, what different specialties would give me the most useful debate?"

**For each angle, decide:**
- What codebase areas the agent should explore (specific files, directories, patterns)
- What question the agent should answer
- How deep vs. broad the agent should go
- What existing context (if any) to seed the agent with — only what's necessary, avoid anchoring

## Phase 3: Launch Parallel Exploration

**Briefly tell the user** what angles you're exploring (2-3 words each) — then launch immediately. Don't wait for approval. Speed matters when stuck.

Launch **4 Explore agents IN PARALLEL** (single message with 4 Task tool calls). Use `model: "opus"` explicitly on each agent to ensure heavyweight reasoning. Each agent gets:

```
You are exploring a specific angle of a hard problem. Your analysis is input to a multi-agent synthesis — be precise, flag uncertainties, and show your evidence.

## Problem
{problem description}

## Your Angle
{specific lens — what you're looking for, what question you're answering}

## Where to Look (Starting Points)
{specific files, directories, or search patterns to start with}

These are entry points, not the complete scope. Follow evidence wherever it leads — if the trail points to related code outside this list, explore it.

## Key Constraint
You have read-only tools (Glob, Grep, Read). Use them liberally. If you can't verify something exists, don't claim it. Better to say "I couldn't locate a config file for X" than to guess at its name or path.

## Instructions
- Use Glob, Grep, and Read to thoroughly explore the relevant code
- Think deeply about your specific angle — don't try to solve the whole problem
- Look for evidence, patterns, constraints, and opportunities related to your angle
- Note anything surprising or that contradicts assumptions
- Be concrete — reference specific files, functions, line numbers, data flows
- If you find something important outside your angle, note it briefly but stay focused
- Before you finalize: is there evidence that contradicts your recommendation? If yes, address it directly rather than ignore it

## Output
Return a focused analysis (aim for 600-1000 words):

1. **Key findings** — specific observations with evidence. For each finding, cite the file/line or code pattern that shows it's true. Avoid vague claims like "this is slow" — show why.

2. **Implications** — what this means for the problem. For each implication, explain the logical link: if this finding is true, then we should try X because [reason].

3. **Recommendation** — your angle's proposed direction:
   - **Proposed approach:** [specific, actionable idea]
   - **Why this angle suggests it:** [link findings → recommendation]
   - **Tradeoffs:** [what you'd give up]
   - **Key assumptions:** [what has to be true for this to work]
   - **Biggest uncertainty:** [what would most change your mind]
```

## Phase 4: Verify Key Claims

Before synthesizing, two verification passes:

### Pass 1: Contradiction Detection

Scan all 4 agent reports for **opposing claims**. Examples:
- Agent A says "this runs synchronously" while Agent B says "this is async"
- Agent A says "no index on this column" while Agent C assumes an index exists
- Two agents recommend opposite directions

Flag contradictions prominently. **Prioritize verifying contradicted claims first** — these are where the highest-value corrections live.

### Pass 2: Factual Verification

**Cross-check the most important factual claims** from the agents. Agents can hallucinate file paths, function signatures, config options, or behavioral assumptions.

**What to verify:**
- **File paths and function names** — do the files/functions agents referenced actually exist? Spot-check with Glob/Grep.
- **Behavioral claims** — "this function does X" or "this config controls Y" — Read the actual code for the 2-3 most critical claims that the recommendation will hinge on.
- **Performance/complexity claims** — if an agent says "this is O(n²)" or "this query scans the full table," verify against the actual code or query plan.
- **Assumption checks** — if agents assumed something about the system (e.g., "this runs synchronously," "this table has an index on X"), verify the ones that matter most.

**How to verify:**
- Focus on the **top 3-5 claims that would change the recommendation if wrong**. Don't verify everything — verify what matters.
- Use Glob, Grep, and Read directly (no subagents — this should be fast).
- If a claim is wrong, note the correction. If it's right, move on.

**Output:** Note any corrections or confirmations. Flag anything that was wrong — this changes the synthesis.

## Phase 5: Synthesize

After verification, synthesize the agents' findings (with corrections applied) into a single analysis. This is the critical step — don't just concatenate.

**Synthesis structure:**

### 1. Agreements
Where do multiple angles converge? High-confidence insights.

### 2. Tensions
Where do angles disagree or present tradeoffs? These are the real design decisions.

### 3. Surprises
What did agents find that wasn't expected? Novel insights that change the framing.

### 4. Corrections
Any agent claims that were wrong or misleading, and what the truth is. Be transparent — this builds trust in the analysis.

### 5. Recommendation
Your synthesized recommendation. Be opinionated — rank the options, state which direction you'd go and why. Tag each element with confidence (High/Medium/Low) and a one-line justification. Include:
- **Proposed approach** — the synthesized best path forward
- **Key tradeoffs** — what you're giving up
- **Risks** — what could go wrong
- **Key assumptions** — what the recommendation depends on being true
- **First step** — the concrete next action

### 6. Assumption Check
After drafting the recommendation, note what assumptions it hinges on. Verify those specific assumptions with a quick Glob/Grep/Read check. If any fail, flag them and reassess.

### 7. If applicable: FD Update
If there's an active FD related to this problem, propose specific updates to the FD's Solution section based on the analysis. Don't update the file — present the proposed changes for the user to approve.

## Notes

- **Agent count**: Always 4. Four distinct angles. No exceptions.
- **Agent type**: Always use `subagent_type: "Explore"` with `model: "opus"` — read-only research agents on the heaviest model.
- **Thoroughness**: Tell agents to be "very thorough" in their Task descriptions.
- **No anchoring**: Don't give agents each other's angles. They should explore independently.
- **Speed over perfection**: The user is stuck. A good-enough synthesis in 2 minutes beats a perfect one in 10. Don't over-polish the output.
