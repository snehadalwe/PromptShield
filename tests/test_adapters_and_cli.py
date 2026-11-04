"""Unit and Integration Tests for Adapters, CLI, and Attack Case Loading.

Tests:
1. GenericRestAdapter validation, error handling (connection failure, timeout), GET/POST, and header masking.
2. OpenAITargetAdapter validation, missing key handling, and key masking.
3. AttackLoader filtering by category and specific attack ID.
4. CLI options and risk threshold gate (--fail-on-risk).
"""

import sys
from pathlib import Path

import pytest
import requests

from promptshield.targets.http_adapter import GenericRestAdapter
from promptshield.targets.openai_adapter import OpenAITargetAdapter
from promptshield.attacks.loader import AttackLoader
from promptshield.attacks.models import Severity
from promptshield.detectors.base import DetectionStatus
from promptshield.scoring.calculator import ScoreCalculator
from promptshield.scoring.models import SingleTestResult
from promptshield.cli import build_parser


# =============================================================================
# 1. GenericRestAdapter Tests
# =============================================================================

def test_http_adapter_url_validation():
    """GenericRestAdapter should reject invalid or non-HTTP protocols."""
    with pytest.raises(ValueError, match="must begin with http:// or https://"):
        GenericRestAdapter(
            name="InvalidProtocol",
            url="ftp://malicious.com/api"
        )

    with pytest.raises(ValueError, match="must begin with http:// or https://"):
        GenericRestAdapter(
            name="InvalidEmpty",
            url="javascript:alert(1)"
        )


def test_http_adapter_header_masking():
    """Sensitive authorization headers should be masked in metadata."""
    headers = {
        "Authorization": "Bearer super-secret-jwt-token-12345",
        "api-key": "secret-api-key-998877",
        "Content-Type": "application/json",
    }

    adapter = GenericRestAdapter(
        name="SecTarget",
        url="http://127.0.0.1:9999/chat",
        headers=headers
    )

    masked = adapter.get_metadata()["headers"]

    assert "***" in masked["Authorization"]
    assert "super-secret" not in masked["Authorization"]
    assert "***" in masked["api-key"]
    assert "998877" not in masked["api-key"]
    assert masked["Content-Type"] == "application/json"


def test_http_adapter_connection_failure(monkeypatch):
    """Connection failures should return a structured error response deterministically."""
    def mock_connection_failure(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Connection refused")

    monkeypatch.setattr(
        "promptshield.targets.http_adapter.requests.post",
        mock_connection_failure
    )

    adapter = GenericRestAdapter(
        name="DownTarget",
        url="http://127.0.0.1:54321/nonexistent",
        timeout=1
    )

    res = adapter.send("Hello test")

    assert "[Connection Error]" in res.text
    assert res.status_code == 503
    assert "connection" in str(res.metadata.get("error", "")).lower()


def test_http_adapter_timeout_failure(monkeypatch):
    """Timeout failures should return a structured 408 timeout error response deterministically."""
    def mock_timeout_failure(*args, **kwargs):
        raise requests.exceptions.Timeout("Request timed out")

    monkeypatch.setattr(
        "promptshield.targets.http_adapter.requests.post",
        mock_timeout_failure
    )

    adapter = GenericRestAdapter(
        name="TimeoutTarget",
        url="http://127.0.0.1:54321/timeout",
        timeout=1
    )

    res = adapter.send("Hello test")

    assert "[Timeout Error]" in res.text
    assert res.status_code == 408
    assert "timeout" in str(res.metadata.get("error", "")).lower()


def test_http_adapter_get_method(monkeypatch):
    """GenericRestAdapter should support GET requests with prompt parameter."""
    class MockResponse:
        status_code = 200
        def json(self):
            return {"response": "GET response success"}

    def mock_get(url, headers, params, timeout):
        assert params.get("message") == "ping"
        return MockResponse()

    monkeypatch.setattr(
        "promptshield.targets.http_adapter.requests.get",
        mock_get
    )

    adapter = GenericRestAdapter(
        name="GetTarget",
        url="http://127.0.0.1:5000/query",
        method="GET"
    )

    res = adapter.send("ping")
    assert res.status_code == 200
    assert res.text == "GET response success"


# =============================================================================
# 2. OpenAITargetAdapter Tests
# =============================================================================

def test_openai_adapter_key_masking():
    """API keys must be masked in adapter metadata."""
    adapter = OpenAITargetAdapter(
        name="OpenAITest",
        api_key="sk-proj-1234567890abcdef123456"
    )

    meta = adapter.get_metadata()

    assert meta["api_key_masked"].startswith("sk-")
    assert "***" in meta["api_key_masked"]
    assert "1234567890abcdef" not in meta["api_key_masked"]


def test_openai_adapter_missing_key():
    """Adapter should report missing API key without unhandled exception."""
    adapter = OpenAITargetAdapter(name="OpenAINoKey", api_key="")
    res = adapter.send("Hello")

    assert "No OpenAI API key provided" in res.text
    assert res.status_code == 401


# =============================================================================
# 3. AttackLoader ID and Category Filtering Tests (Recovered Tests)
# =============================================================================

def test_attack_loader_filter_by_id():
    """AttackLoader should allow filtering by a specific attack ID."""
    loader = AttackLoader()
    cases = loader.load_all(category="POL-004")

    assert len(cases) == 1
    assert cases[0].id == "POL-004"
    assert cases[0].is_control is True


def test_attack_loader_filter_by_category():
    """AttackLoader should load all test cases within a category."""
    loader = AttackLoader()
    cases = loader.load_all(category="policy_bypass")

    assert len(cases) >= 5
    ids = [c.id for c in cases]
    assert "POL-001" in ids
    assert "POL-004" in ids
    assert "POL-005" in ids
    assert "POL-006" in ids


# =============================================================================
# 4. CLI Argument Parser Tests (Recovered Tests)
# =============================================================================

def test_cli_parser_defaults():
    """CLI should default to reports_output and standard parameters."""
    parser = build_parser()
    args = parser.parse_args(["scan", "--target", "demo-weak"])

    assert args.output_dir == "reports_output"
    assert args.attacks == "all"
    assert args.report == "all"
    assert args.threads == 2
    assert args.delay == 0.05


def test_cli_parser_custom_args():
    """CLI should properly parse specific attack and threshold arguments."""
    parser = build_parser()
    args = parser.parse_args([
        "scan",
        "--target", "demo-hardened",
        "--attacks", "POL-004",
        "--output-dir", "custom_dir",
        "--fail-on-risk", "25.0",
        "--agree-authorized",
    ])

    assert args.target == "demo-hardened"
    assert args.attacks == "POL-004"
    assert args.output_dir == "custom_dir"
    assert args.fail_on_risk == 25.0
    assert args.agree_authorized is True
