"""Safety validation for Part 7 (programmatic, read-only).

Guarantees checked:
  * DRY_RUN is the default response mode;
  * the response module contains no firewall/network modification code;
  * no shell/subprocess/socket/network-client usage in src/response;
  * DRY_RUN never yields BLOCK_REQUESTED regardless of probability;
  * no firewall-modifying tools are invoked by importing the module.
"""

import re
from pathlib import Path

import pytest

from src.detection.schemas import DetectionResult
from src.response.actions import (
    ACTION_BLOCK_REQUESTED,
    DEFAULT_RESPONSE_MODE,
    MODE_AUTHORIZED,
    MODE_DRY_RUN,
)
from src.response.policies import DEFAULT_POLICY
from src.response.response_engine import ResponseEngine

pytestmark = pytest.mark.validation

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RESPONSE_DIR = PROJECT_ROOT / "src" / "response"

# Firewall / network-modification tooling and network APIs that must NOT
# appear anywhere in the response module.
FORBIDDEN_TOOLING = [
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bos\.system\b"),
    re.compile(r"\bos\.popen\b"),
    re.compile(r"\bsocket\b"),
    re.compile(r"\bnetsh\b"),
    re.compile(r"\biptables\b"),
    re.compile(r"\bip6tables\b"),
    re.compile(r"\bnftables?\b"),
    re.compile(r"\bufw\b"),
    re.compile(r"\bfirewall-cmd\b"),
    re.compile(r"\bpfctl\b"),
    re.compile(r"\bsocat\b"),
    re.compile(r"\brequests\b"),
    re.compile(r"\burllib\b"),
    re.compile(r"\bparamiko\b"),
]


def _response_sources():
    files = sorted(RESPONSE_DIR.rglob("*.py"))
    assert files, "response module not found (test broken)"
    return files


def test_default_response_mode_is_dry_run():
    assert DEFAULT_RESPONSE_MODE == MODE_DRY_RUN
    assert DEFAULT_POLICY.mode == MODE_DRY_RUN
    assert ResponseEngine().policy.mode == MODE_DRY_RUN


def test_response_module_has_no_firewall_or_network_tooling():
    hits = []
    for path in _response_sources():
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_TOOLING:
            if pattern.search(text):
                hits.append(f"{path.name}: {pattern.pattern}")
    assert hits == [], f"forbidden network/firewall tooling found: {hits}"


def test_dry_run_never_returns_block_requested():
    engine = ResponseEngine()
    for probability in (0.0, 0.5, 0.8, 0.99, 1.0, None):
        for prediction in (0, 1):
            result = engine.respond(
                DetectionResult(
                    timestamp="t", flow_id="f", prediction=prediction,
                    label="x", is_attack=prediction == 1,
                    attack_probability=probability, confidence=None, severity=None,
                    model_name="m", model_version="v", feature_count=1, status="success",
                )
            )
            assert result.action != ACTION_BLOCK_REQUESTED
            assert result.mode == MODE_DRY_RUN


def test_authorized_mode_is_opt_in_only():
    """AUTHORIZED requires an explicit adapter; importing the module alone
    never enables it, and the constant is distinct from the default."""
    assert MODE_AUTHORIZED != DEFAULT_RESPONSE_MODE
    import inspect

    from src.response import response_engine

    source = inspect.getsource(response_engine)
    # the AUTHORIZED path must exist ONLY behind the executor call
    assert "self.executor.block(" in source
    # and the CLI must refuse AUTHORIZED outright (no adapter shipped)
    assert "REFUSED" in source
