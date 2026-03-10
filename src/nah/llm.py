"""LLM layer — resolve ambiguous ask decisions via LLM backends."""

import json
import os
import urllib.request
from urllib.error import URLError

_TIMEOUT_LOCAL = 10
_TIMEOUT_REMOTE = 10


class LLMResult:
    __slots__ = ("decision", "reasoning")

    def __init__(self, decision: str, reasoning: str = ""):
        self.decision = decision    # "allow", "block", or "uncertain"
        self.reasoning = reasoning


_PROMPT_TEMPLATE = """\
You are a security classifier for a CLI tool safety guard. A command was flagged \
as ambiguous by the structural classifier. Determine if it should be allowed, blocked, \
or if you are uncertain.

Command: {command}
Action type: {action_type}
Structural reason: {reason}
Working directory: {cwd}
Inside project: {inside_project}

Respond with EXACTLY one JSON object (no other text):
{{"decision": "allow" or "block" or "uncertain", "reasoning": "brief explanation"}}

Rules:
- "allow" — clearly a standard, safe development operation
- "block" — could cause data loss, exfiltration, or security issues
- "uncertain" — you are not sure; a human should decide
- When in doubt, say "uncertain". A false allow is worse than asking the human.
- Common safe patterns: build tools, test runners, linters, formatters, dev servers
- Common dangerous patterns: destructive ops on wrong targets, credential access, network to unknown hosts
"""


def _build_prompt(classify_result) -> str:
    """Build classification prompt from ClassifyResult."""
    driving_stage = None
    for sr in classify_result.stages:
        if sr.decision == "ask":
            driving_stage = sr
            break
    if driving_stage is None and classify_result.stages:
        driving_stage = classify_result.stages[0]

    action_type = driving_stage.action_type if driving_stage else "unknown"
    reason = classify_result.reason

    cwd = os.getcwd()
    inside_project = "unknown"
    try:
        from nah.paths import get_project_root
        root = get_project_root()
        if root:
            inside_project = "yes" if cwd.startswith(root) else "no"
    except Exception:
        pass

    return _PROMPT_TEMPLATE.format(
        command=classify_result.command[:500],
        action_type=action_type,
        reason=reason,
        cwd=cwd,
        inside_project=inside_project,
    )


def _parse_response(raw: str) -> LLMResult | None:
    """Parse LLM response JSON into LLMResult."""
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                obj = json.loads(raw[start:end])
            except json.JSONDecodeError:
                return None
        else:
            return None

    decision = obj.get("decision", "").lower()
    if decision not in ("allow", "block", "uncertain"):
        return None

    reasoning = str(obj.get("reasoning", ""))[:200]
    return LLMResult(decision, reasoning)


# -- Backends --


def _call_ollama(config: dict, prompt: str) -> LLMResult | None:
    """Call Ollama local API. Returns None if unavailable."""
    url = config.get("url", "http://localhost:11434/api/generate")
    model = config.get("model", "qwen3.5:9b")
    timeout = config.get("timeout", _TIMEOUT_LOCAL)

    body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        return _parse_response(data.get("response", ""))
    except (URLError, OSError, json.JSONDecodeError, KeyError):
        return None


def _call_openai_compat(
    config: dict,
    prompt: str,
    timeout: int,
    default_url: str,
    default_model: str,
    default_key_env: str,
) -> LLMResult | None:
    """Call an OpenAI-compatible chat completions API."""
    url = config.get("url", default_url)
    if not url:
        return None
    key_env = config.get("key_env", default_key_env)
    key = config.get("_resolved_key") or os.environ.get(key_env, "")
    if not key:
        return None
    model = config.get("model", default_model)
    timeout = config.get("timeout", timeout)

    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    })

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        content = data["choices"][0]["message"]["content"]
        return _parse_response(content)
    except (URLError, OSError, json.JSONDecodeError, KeyError, IndexError):
        return None


def _call_cortex(config: dict, prompt: str) -> LLMResult | None:
    """Call Snowflake Cortex REST API."""
    return _call_openai_compat(
        config, prompt, _TIMEOUT_REMOTE,
        default_url="",
        default_model="claude-haiku-4-5",
        default_key_env="SNOWFLAKE_PAT",
    )


def _call_openrouter(config: dict, prompt: str) -> LLMResult | None:
    """Call OpenRouter API."""
    return _call_openai_compat(
        config, prompt, _TIMEOUT_REMOTE,
        default_url="https://openrouter.ai/api/v1/chat/completions",
        default_model="google/gemini-3.1-flash-lite-preview",
        default_key_env="OPENROUTER_API_KEY",
    )


def _call_openai(config: dict, prompt: str) -> LLMResult | None:
    """Call OpenAI Responses API."""
    return _call_openai_responses(
        config, prompt, _TIMEOUT_REMOTE,
        default_url="https://api.openai.com/v1/responses",
        default_model="gpt-4.1-nano",
        default_key_env="OPENAI_API_KEY",
    )


def _call_anthropic(config: dict, prompt: str) -> LLMResult | None:
    """Call Anthropic Messages API."""
    url = config.get("url", "https://api.anthropic.com/v1/messages")
    key_env = config.get("key_env", "ANTHROPIC_API_KEY")
    key = os.environ.get(key_env, "")
    if not key:
        return None
    model = config.get("model", "claude-haiku-4-5")
    timeout = config.get("timeout", _TIMEOUT_REMOTE)

    body = json.dumps({
        "model": model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    })

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        content = data["content"][0]["text"]
        return _parse_response(content)
    except (URLError, OSError, json.JSONDecodeError, KeyError, IndexError):
        return None


def _call_openai_responses(
    config: dict,
    prompt: str,
    timeout: int,
    default_url: str,
    default_model: str,
    default_key_env: str,
) -> LLMResult | None:
    """Call OpenAI Responses API (/v1/responses) for non-chat models like Codex."""
    url = config.get("url", default_url)
    if not url:
        return None
    key_env = config.get("key_env", default_key_env)
    key = config.get("_resolved_key") or os.environ.get(key_env, "")
    if not key:
        return None
    model = config.get("model", default_model)
    timeout = config.get("timeout", timeout)

    body = json.dumps({"model": model, "input": prompt}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    })

    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        for item in data.get("output", []):
            if item.get("type") == "message":
                for c in item.get("content", []):
                    if c.get("type") == "output_text":
                        return _parse_response(c["text"])
        return None
    except (URLError, OSError, json.JSONDecodeError, KeyError, IndexError):
        return None


def _call_codex(config: dict, prompt: str) -> LLMResult | None:
    """Call OpenAI Responses API using Codex CLI OAuth token."""
    key = None
    for auth_path in ("~/.codex/auth.json", "~/.config/codex/auth.json"):
        expanded = os.path.expanduser(auth_path)
        if os.path.isfile(expanded):
            try:
                with open(expanded) as f:
                    key = json.load(f).get("token", "")
                break
            except (OSError, json.JSONDecodeError):
                pass
    if not key:
        key_env = config.get("key_env", "OPENAI_API_KEY")
        key = os.environ.get(key_env, "")
    if not key:
        return None

    patched = dict(config)
    patched["_resolved_key"] = key
    return _call_openai_responses(
        patched, prompt, _TIMEOUT_REMOTE,
        default_url="https://api.openai.com/v1/responses",
        default_model="gpt-5.3-codex",
        default_key_env="OPENAI_API_KEY",
    )


_BACKENDS = {
    "ollama": _call_ollama,
    "cortex": _call_cortex,
    "openrouter": _call_openrouter,
    "openai": _call_openai,
    "anthropic": _call_anthropic,
    "codex": _call_codex,
}


def _call_backend(name: str, config: dict, prompt: str) -> LLMResult | None:
    """Dispatch to the named backend."""
    fn = _BACKENDS.get(name)
    if fn is None:
        return None
    try:
        return fn(config, prompt)
    except Exception:
        return None


def try_llm(classify_result, llm_config: dict) -> dict | None:
    """Try LLM backends in priority order. Returns decision dict or None.

    Returns {"decision": "allow"} or {"decision": "block", "reason": "..."} if LLM
    picks a lane. None if uncertain, unavailable, or not configured.
    """
    backends = llm_config.get("backends", [])
    if not backends:
        return None

    prompt = _build_prompt(classify_result)

    for backend_name in backends:
        backend_config = llm_config.get(backend_name, {})
        if not backend_config:
            continue

        result = _call_backend(backend_name, backend_config, prompt)
        if result is None:
            continue  # backend unavailable, try next

        if result.decision == "allow":
            decision = {"decision": "allow"}
            if result.reasoning:
                decision["message"] = f"Bash (LLM): {result.reasoning}"
            return decision

        if result.decision == "block":
            reason = result.reasoning or "LLM: blocked"
            return {"decision": "block", "reason": f"Bash (LLM): {reason}"}

        # "uncertain" → don't try next backend, keep ask
        return None

    return None
