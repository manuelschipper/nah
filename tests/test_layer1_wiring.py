"""Layer-1 hook wiring (nah-982): _apply_layer1_classify end-to-end."""

import pytest

import nah.hook as hook
from nah import taxonomy
from nah.config import NahConfig
from nah.llm import LLMClassification, LLMClassifyResult, ProviderAttempt


def _cfg(**over):
    cfg = NahConfig()
    cfg.llm_mode = "on"
    cfg.llm = {"providers": ["fake"], "fake": {"model": "m"}}
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def _classify_result(action_type, targets, evidence="ev", provider="fake"):
    cls = (
        None if action_type is None
        else LLMClassification(action_type, targets, evidence)
    )
    return LLMClassifyResult(
        classification=cls,
        provider=provider,
        model="m",
        latency_ms=12,
        cascade=[ProviderAttempt(provider, "success", 12, "m")],
    )


def _decision_unknown_ask():
    return {
        "decision": taxonomy.ASK,
        "reason": "Bash: unknown",
        "_meta": {"stages": [{"action_type": taxonomy.UNKNOWN, "decision": "ask"}]},
    }


@pytest.fixture
def _patched(monkeypatch):
    def install(cfg, classify_result):
        monkeypatch.setattr("nah.config.get_config", lambda: cfg)
        monkeypatch.setattr(
            "nah.llm.try_llm_classify_unknown",
            lambda *a, **k: classify_result,
        )
    return install


def test_clean_target_allows(_patched):
    _patched(_cfg(), _classify_result(
        "filesystem_read", [{"kind": "path", "value": "/tmp/notes.txt"}]))
    out = hook._apply_layer1_classify("Bash", {"command": "wc /tmp/notes.txt"},
                                      _decision_unknown_ask())
    # /tmp is outside a project root in test env; either allow or ask is
    # acceptable, but it must not crash and must log the classify pass.
    assert out["decision"] in (taxonomy.ALLOW, taxonomy.ASK)
    passes = out["_meta"]["llm_passes"]
    assert passes[0]["phase"] == "classify"
    assert passes[0]["mapped_type"] == "filesystem_read"
    assert out["_meta"]["action_type_source"] == "llm_classify"


def test_sensitive_target_asks(_patched):
    _patched(_cfg(), _classify_result(
        "filesystem_read", [{"kind": "path", "value": "~/.ssh/id_rsa"}]))
    out = hook._apply_layer1_classify("Bash", {"command": "x"},
                                      _decision_unknown_ask())
    assert out["decision"] in (taxonomy.ASK, taxonomy.BLOCK)
    tgt = out["_meta"]["llm_passes"][0]["targets"][0]
    assert tgt["floor"] in (taxonomy.ASK, taxonomy.BLOCK)


def test_known_host_allows(_patched):
    _patched(_cfg(), _classify_result(
        "network_outbound", [{"kind": "host", "value": "github.com"}]))
    out = hook._apply_layer1_classify("Bash", {"command": "x"},
                                      _decision_unknown_ask())
    assert out["decision"] == taxonomy.ALLOW


def test_unknown_classification_keeps_ask(_patched):
    _patched(_cfg(), _classify_result(taxonomy.UNKNOWN, []))
    out = hook._apply_layer1_classify("Bash", {"command": "zorp"},
                                      _decision_unknown_ask())
    assert out["decision"] == taxonomy.ASK
    # classify pass still logged (audit), but no source override.
    assert out["_meta"]["llm_passes"][0]["mapped_type"] == taxonomy.UNKNOWN
    assert "action_type_source" not in out["_meta"]


def test_none_classification_keeps_ask(_patched):
    _patched(_cfg(), _classify_result(None, []))
    out = hook._apply_layer1_classify("Bash", {"command": "x"},
                                      _decision_unknown_ask())
    assert out["decision"] == taxonomy.ASK


def test_llm_off_is_noop(_patched):
    _patched(_cfg(llm_mode="off"), _classify_result(
        "filesystem_read", [{"kind": "path", "value": "/tmp/x"}]))
    dec = _decision_unknown_ask()
    out = hook._apply_layer1_classify("Bash", {"command": "x"}, dec)
    assert out is dec
    assert "llm_passes" not in out["_meta"]


def test_mapped_type_propagated_to_stage(_patched):
    _patched(_cfg(), _classify_result(
        "network_outbound", [{"kind": "host", "value": "evil.example"}]))
    out = hook._apply_layer1_classify("Bash", {"command": "x"},
                                      _decision_unknown_ask())
    # unknown host -> ask, and the mapped type flows into the stage so Layer-2
    # eligibility + the log see it.
    assert out["decision"] == taxonomy.ASK
    assert out["_meta"]["stages"][0]["action_type"] == "network_outbound"


def test_target_value_redacted(_patched):
    _patched(_cfg(), _classify_result(
        "lang_exec", [{"kind": "unknown", "value": "export TOKEN=supersecret"}]))
    out = hook._apply_layer1_classify("Bash", {"command": "x"},
                                      _decision_unknown_ask())
    logged = out["_meta"]["llm_passes"][0]["targets"][0]["value"]
    assert "supersecret" not in logged
    assert "***" in logged
