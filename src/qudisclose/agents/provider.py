"""Model providers.

`AnthropicProvider` uses Claude through the official SDK: the beta tool runner for agentic roles (tools +
structured final answer) and `beta.messages.parse` for pure-reasoning roles. Server-side refusal fallbacks are
enabled by default (`fallbacks: "default"`), adaptive thinking is on, and effort is set per role.

`ScriptedProvider` runs the same roles without a model: each role maps to a python callable that receives the
prompt and the tool functions. Used by tests and the offline demo."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"

ToolFn = Callable[..., str]


class ProviderRefusal(Exception):
    """The model declined (stop_reason == 'refusal') and no fallback answered."""


class Provider(Protocol):
    def run(self, *, role: str, system: str, user: str, schema: type[T], tools: dict[str, ToolFn] | None = None,
            effort: str = "high", max_iterations: int = 40) -> T: ...


class AnthropicProvider:
    def __init__(self, model: str = DEFAULT_MODEL, client: Any | None = None, max_tokens: int = 16000) -> None:
        import anthropic  # local import keeps the scripted path dependency-free at runtime

        self._anthropic = anthropic
        self.client = client or anthropic.Anthropic()
        self.model = os.environ.get("QUDISCLOSE_MODEL", model)
        self.max_tokens = max_tokens

    def run(self, *, role: str, system: str, user: str, schema: type[T], tools: dict[str, ToolFn] | None = None,
            effort: str = "high", max_iterations: int = 40) -> T:
        common: dict[str, Any] = dict(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
            output_format=schema, output_config={"effort": effort},
            fallbacks="default", betas=[FALLBACK_BETA],
            metadata={"user_id": f"qudisclose-{role}"},
        )
        if tools:
            from anthropic import beta_tool

            runner = self.client.beta.messages.tool_runner(
                tools=[beta_tool(fn, name=name) for name, fn in tools.items()],
                max_iterations=max_iterations, **common,
            )
            message = runner.until_done()
        else:
            message = self.client.beta.messages.parse(**common)
        if message.stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            raise ProviderRefusal(f"{role}: model refused ({getattr(details, 'category', None)})")
        parsed = getattr(message, "parsed_output", None)
        if parsed is None:
            raise ProviderRefusal(f"{role}: no structured output (stop_reason={message.stop_reason})")
        return parsed


class ScriptedProvider:
    """Deterministic stand-in. `scripts[role](user_prompt, tools) -> schema instance | dict`."""

    def __init__(self, scripts: dict[str, Callable[[str, dict[str, ToolFn]], Any]]) -> None:
        self.scripts = scripts
        self.calls: list[tuple[str, str]] = []

    def run(self, *, role: str, system: str, user: str, schema: type[T], tools: dict[str, ToolFn] | None = None,
            effort: str = "high", max_iterations: int = 40) -> T:
        self.calls.append((role, user))
        if role not in self.scripts:
            raise KeyError(f"ScriptedProvider has no script for role {role!r}")
        out = self.scripts[role](user, tools or {})
        return out if isinstance(out, schema) else schema.model_validate(out)


# ----------------------------------------------------------------------------- self-hosted provider

def _json_schema_from_fn(name: str, fn: Any) -> dict[str, Any]:
    """Minimal OpenAI tool spec from a callable's signature and docstring."""
    import inspect

    sig = inspect.signature(fn)
    props: dict[str, Any] = {}
    required: list[str] = []
    _types = {str: "string", int: "integer", float: "number", bool: "boolean"}
    for pname, p in sig.parameters.items():
        props[pname] = {"type": _types.get(p.annotation, "string")}
        if p.default is inspect.Parameter.empty:
            required.append(pname)
    return {"type": "function", "function": {
        "name": name, "description": (fn.__doc__ or name).strip().split("\n")[0],
        "parameters": {"type": "object", "properties": props, "required": required}}}


class OpenAICompatProvider:
    """Provider for a self-hosted, OpenAI-compatible endpoint (Ollama, vLLM, llama.cpp serving GLM/Qwen).

    Deliberately NOT the Anthropic SDK: this is the untrusted, high-volume hunter model, kept on your own
    hardware so source never leaves it. Structured outputs use JSON mode + pydantic validation with one
    repair retry; agentic roles use OpenAI tool-calling, then a final JSON turn."""

    def __init__(self, *, base_url: str, model: str, api_key: str = "ollama", timeout: float = 600.0,
                 temperature: float = 0.2) -> None:
        import openai

        self.client = openai.OpenAI(base_url=base_url, api_key=api_key or "ollama", timeout=timeout)
        self.model = model
        self.temperature = temperature

    def _complete_json(self, messages: list[dict[str, Any]], schema: type[T]) -> T:
        hint = json.dumps(schema.model_json_schema())
        messages = messages + [{"role": "user",
                                "content": f"Return ONLY a JSON object matching this schema, no prose:\n{hint}"}]
        last_err = ""
        for _ in range(2):
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=self.temperature,
                response_format={"type": "json_object"})
            text = resp.choices[0].message.content or "{}"
            try:
                return schema.model_validate_json(text)
            except Exception as e:  # ask the model to repair against the validation error
                last_err = str(e)
                messages = messages + [{"role": "assistant", "content": text},
                                       {"role": "user", "content": f"That failed validation: {last_err}. Return corrected JSON only."}]
        raise ProviderRefusal(f"self-hosted model did not return schema-valid JSON: {last_err}")

    def run(self, *, role: str, system: str, user: str, schema: type[T], tools: dict[str, ToolFn] | None = None,
            effort: str = "high", max_iterations: int = 40) -> T:
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        if tools:
            specs = [_json_schema_from_fn(n, f) for n, f in tools.items()]
            for _ in range(max_iterations):
                resp = self.client.chat.completions.create(
                    model=self.model, messages=messages, tools=specs, tool_choice="auto", temperature=self.temperature)
                msg = resp.choices[0].message
                if not msg.tool_calls:
                    break
                messages.append({"role": "assistant", "content": msg.content or "",
                                 "tool_calls": [{"id": tc.id, "type": "function",
                                                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                                for tc in msg.tool_calls]})
                for tc in msg.tool_calls:
                    fn = tools.get(tc.function.name)
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                        out = fn(**args) if fn else f"ERROR: no such tool {tc.function.name}"
                    except Exception as e:
                        out = f"ERROR: {e}"
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": str(out)[:60_000]})
        return self._complete_json(messages, schema)


# ----------------------------------------------------------------------------- local Claude Code CLI

def _extract_json(text: str) -> Any:
    """Pull the first JSON object/array out of a model reply (tolerates ```json fences and surrounding prose)."""
    s = text.strip()
    if s.startswith("```"):
        s = s.split("```", 2)[1] if s.count("```") >= 2 else s.strip("`")
        if s.lstrip().startswith("json"):
            s = s.lstrip()[4:]
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = s.find(open_c), s.rfind(close_c)
        if 0 <= i < j:
            try:
                return json.loads(s[i:j + 1])
            except Exception:
                continue
    return None


class ClaudeCliProvider:
    """Uses the local Claude Code CLI (`claude -p`) as the model, so runs rely on your existing Claude Code
    login instead of an `ANTHROPIC_API_KEY`. The CLI can't be handed our in-process sandbox tools, so
    tool-using roles drive a JSON action loop (the model replies with {"tool","args"}; we run it and feed
    the output back); the final answer is parsed and validated against the role's schema with repair retries."""

    def __init__(self, model: str | None = None, *, binary: str = "claude", timeout: float = 900.0,
                 on_event: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.model = model          # "opus" | "sonnet" | "haiku" | a full id | None (CLI default)
        self.binary = binary
        self.timeout = timeout
        self.on_event = on_event    # optional sink for live streaming: called with {role, kind, text}

    def _ev(self, role: str, kind: str, text: str) -> None:
        if self.on_event:
            try:
                self.on_event({"role": role, "kind": kind, "text": str(text)[:4000]})
            except Exception:  # noqa: BLE001 — a broken sink must never break a run
                pass

    def _ask(self, system: str, prompt: str) -> str:
        import shutil
        import subprocess
        import tempfile

        exe = shutil.which(self.binary) or self.binary
        cmd = [exe, "-p", "--output-format", "text", "--append-system-prompt", system]
        if self.model:
            cmd += ["--model", self.model]
        try:  # run in a scratch cwd so the CLI's own tools have nothing local to wander into
            r = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                               timeout=self.timeout, cwd=tempfile.gettempdir())
        except FileNotFoundError as exc:
            raise ProviderRefusal(f"claude CLI not found ({self.binary}): {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProviderRefusal(f"claude CLI timed out after {self.timeout}s") from exc
        if r.returncode != 0:
            raise ProviderRefusal(f"claude CLI failed (exit {r.returncode}): {(r.stderr or '').strip()[:300]}")
        return (r.stdout or "").strip()

    def run(self, *, role: str, system: str, user: str, schema: type[T], tools: dict[str, ToolFn] | None = None,
            effort: str = "high", max_iterations: int = 40) -> T:
        hint = json.dumps(schema.model_json_schema())
        convo = [f"<task>\n{user}\n</task>"]
        if tools:
            listing = "\n".join(f"- {n}(...): {(f.__doc__ or n).strip().splitlines()[0]}" for n, f in tools.items())
            convo.append('<tools>\nTo use a tool, reply with ONLY a JSON object {"tool":"<name>","args":{...}} and '
                         "nothing else; I will reply with the tool output. Available tools:\n" + listing + "\n</tools>")
        convo.append(f"When finished, reply with ONLY a JSON object matching this schema (no prose, no fences):\n{hint}")
        self._ev(role, "role_start", f"{role}: thinking…")
        last_err = ""
        for _ in range(max_iterations if tools else 3):
            reply = self._ask(system, "\n\n".join(convo))
            obj = _extract_json(reply)
            if tools and isinstance(obj, dict) and "tool" in obj and set(obj) <= {"tool", "args"}:
                name = obj.get("tool")
                args = obj.get("args") or {}
                fn = tools.get(name)
                self._ev(role, "tool_call", f"{name}({json.dumps(args)[:500]})")
                try:
                    out = fn(**args) if fn else f"ERROR: no such tool {name}"
                except Exception as e:  # noqa: BLE001 — surfaced back to the model as an observation
                    out = f"ERROR: {e}"
                self._ev(role, "tool_output", str(out)[:1500])
                convo.append(f"<you_called>{reply}</you_called>")
                convo.append(f"<tool_output name=\"{name}\">\n{str(out)[:60_000]}\n</tool_output>")
                continue
            try:
                result = schema.model_validate(obj) if obj is not None else schema.model_validate_json(reply)
                self._ev(role, "reply", f"{role}: done")
                return result
            except Exception as e:  # noqa: BLE001 — ask the model to repair against the validation error
                last_err = str(e)
                convo.append(f"<your_reply>{reply}</your_reply>")
                convo.append(f"<error>That failed schema validation: {last_err}. Reply with corrected JSON only "
                             "(or a tool call if you still need one).</error>")
        raise ProviderRefusal(f"{role}: claude CLI did not return schema-valid output: {last_err}")
