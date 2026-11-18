"""The Anthropic provider is exercised against a recording fake client: the request shape is what the
Claude API skill prescribes (adaptive thinking implicit, effort in output_config, structured output_format,
server-side fallbacks with its beta header, tool runner for agentic roles)."""

from types import SimpleNamespace

import pytest

from qudisclose.agents.provider import FALLBACK_BETA, AnthropicProvider, ProviderRefusal
from qudisclose.models import TriageResult


class FakeRunner:
    def __init__(self, msg):
        self.msg = msg

    def until_done(self):
        return self.msg


class FakeClient:
    def __init__(self, msg):
        self.calls = []
        beta_msgs = SimpleNamespace(tool_runner=self._tool_runner, parse=self._parse)
        self.beta = SimpleNamespace(messages=beta_msgs)
        self.msg = msg

    def _tool_runner(self, **kw):
        self.calls.append(("tool_runner", kw))
        return FakeRunner(self.msg)

    def _parse(self, **kw):
        self.calls.append(("parse", kw))
        return self.msg


def _triage():
    return TriageResult(is_vulnerability=True, severity="high", cvss_vector="CVSS:4.0/AV:N", cvss_score=7.0, cwe="CWE-22",
                        exploitability="x", affected_components=[], lane="hotfix", rationale="r")


def test_parse_path_request_shape(monkeypatch):
    msg = SimpleNamespace(stop_reason="end_turn", parsed_output=_triage())
    fake = FakeClient(msg)
    p = AnthropicProvider(client=fake, model="claude-opus-5-5")
    out = p.run(role="triage", system="S", user="U", schema=TriageResult, effort="high")
    assert isinstance(out, TriageResult)
    kind, kw = fake.calls[0]
    assert kind == "parse"
    assert kw["model"] == "claude-opus-5-5" and kw["output_format"] is TriageResult
    assert kw["output_config"] == {"effort": "high"} and kw["fallbacks"] == "default" and FALLBACK_BETA in kw["betas"]
    assert "thinking" not in kw  # adaptive thinking is the model default; never send budget_tokens
    assert kw["messages"] == [{"role": "user", "content": "U"}] and kw["system"] == "S"


def test_tool_runner_path_wraps_functions_and_detects_refusal():
    msg = SimpleNamespace(stop_reason="end_turn", parsed_output=_triage())
    fake = FakeClient(msg)
    p = AnthropicProvider(client=fake)

    def read_file(path: str) -> str:
        """Read a file."""
        return "x"

    p.run(role="patcher", system="S", user="U", schema=TriageResult, tools={"read_file": read_file}, effort="xhigh", max_iterations=7)
    kind, kw = fake.calls[0]
    assert kind == "tool_runner" and kw["max_iterations"] == 7
    tool = kw["tools"][0]
    assert tool.to_dict()["name"] == "read_file" and "path" in tool.to_dict()["input_schema"]["properties"]

    refused = FakeClient(SimpleNamespace(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"), parsed_output=None))
    with pytest.raises(ProviderRefusal, match="cyber"):
        AnthropicProvider(client=refused).run(role="triage", system="S", user="U", schema=TriageResult)


def test_cli_provider_local_selects_openai_compat():
    """provider='local' routes the orchestrator to the self-hosted OpenAI-compatible model named in
    `inference` (not Claude, not the scripted stub), so the full pipeline can run on-prem."""
    pytest.importorskip("openai")
    from qudisclose.cli import _provider
    from qudisclose.agents.provider import OpenAICompatProvider
    from qudisclose.config import Config

    cfg = Config(provider="local")
    cfg.inference.base_url = "http://localhost:11434/v1"
    cfg.inference.model = "qwen2.5:7b"
    p = _provider(cfg)
    assert isinstance(p, OpenAICompatProvider)
    assert p.model == "qwen2.5:7b"
    assert str(p.client.base_url).rstrip("/") == "http://localhost:11434/v1"
