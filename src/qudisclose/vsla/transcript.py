"""Per-case transcript capture (VSLA-F-4): every model turn and every sandbox tool call becomes a leaf, in order.

Bodies never enter the leaf, only digests, so the transcript commitment is safe to store and publish. The
`RecordingProvider` wraps any `Provider`; the orchestrator tells it which case the current thread is working on
(stages run on worker threads, one case per thread at a time)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, Iterator, TypeVar

from pydantic import BaseModel

from qudisclose.agents.provider import Provider, ToolFn
from qudisclose.models import canonical_json, sha256_hex

T = TypeVar("T", bound=BaseModel)


def _d(s: Any) -> dict[str, str]:
    data = s if isinstance(s, bytes) else (s.encode() if isinstance(s, str) else canonical_json(s))
    return {"sha256": sha256_hex(data)}


class TranscriptRecorder:
    def __init__(self) -> None:
        self._leaves: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._local = threading.local()

    # -- which case is this thread on
    @contextmanager
    def case(self, report_id: str) -> Iterator[None]:
        prev = getattr(self._local, "case", None)
        self._local.case = report_id
        try:
            yield
        finally:
            self._local.case = prev

    def current(self) -> str | None:
        return getattr(self._local, "case", None)

    # -- leaves
    def append(self, report_id: str | None, leaf: dict[str, Any]) -> None:
        if report_id is None:
            return
        with self._lock:
            leaves = self._leaves.setdefault(report_id, [])
            leaves.append({"seq": len(leaves), **leaf})

    def measure(self, report_id: str, *, harness: dict[str, str], sandbox: dict[str, str] | None) -> None:
        """VSLA-F-14: the first leaf is the measured harness (and sandbox) digest."""
        self.append(report_id, {"kind": "measure", "harness": harness, "sandbox": sandbox})

    def turn(self, report_id: str | None, *, role: str, model: str, system: str, user: str, output: Any) -> None:
        self.append(report_id, {"kind": "turn", "role": role, "model": model, "system": _d(system), "user": _d(user), "output": _d(output)})

    def tool(self, report_id: str | None, *, role: str, name: str, args: Any, output: str, exit_code: int | None = None) -> None:
        leaf: dict[str, Any] = {"kind": "tool", "role": role, "name": name, "input": _d(args), "output": _d(output)}
        if exit_code is not None:
            leaf["exit"] = exit_code
        self.append(report_id, leaf)

    def verify(self, report_id: str, *, what: str, command: str, exit_code: int, security_failure: bool | None, output: str) -> None:
        """The orchestrator's own code-side re-run (VSLA-F-5): the leaf a verifier cares about most. Its fields are the
        ones the reference verifier's E5 compares with the `reproduction` section: what, command, exit, securityFailure,
        output (digest). For `what == "reproduction"` the classification is always recorded as a bool."""
        leaf: dict[str, Any] = {"kind": "verify", "what": what, "command": command, "exit": int(exit_code), "output": _d(output)}
        if security_failure is not None or what == "reproduction":
            leaf["securityFailure"] = bool(security_failure)
        self.append(report_id, leaf)

    def leaves(self, report_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._leaves.get(report_id, []))

    def forget(self, report_id: str) -> None:
        with self._lock:
            self._leaves.pop(report_id, None)


class RecordingProvider:
    """Wraps a Provider: one `turn` leaf per call, one `tool` leaf per tool invocation, attributed to the current case."""

    def __init__(self, inner: Provider, recorder: TranscriptRecorder, *, model_name: str) -> None:
        self.inner, self.recorder, self.model_name = inner, recorder, model_name

    def __getattr__(self, name: str) -> Any:  # scripted providers expose `.calls`, `.scripts`; keep them reachable
        return getattr(self.inner, name)

    def run(self, *, role: str, system: str, user: str, schema: type[T], tools: dict[str, ToolFn] | None = None,
            effort: str = "high", max_iterations: int = 40) -> T:
        rid = self.recorder.current()
        wrapped = {name: self._wrap(rid, role, name, fn) for name, fn in (tools or {}).items()} or None
        out = self.inner.run(role=role, system=system, user=user, schema=schema, tools=wrapped, effort=effort, max_iterations=max_iterations)
        self.recorder.turn(rid, role=role, model=getattr(self.inner, "model", self.model_name) or self.model_name, system=system, user=user,
                           output=out.model_dump() if hasattr(out, "model_dump") else out)
        return out

    def _wrap(self, rid: str | None, role: str, name: str, fn: ToolFn) -> ToolFn:
        def call(*args: Any, **kwargs: Any) -> str:
            result = fn(*args, **kwargs)
            text = result if isinstance(result, str) else str(result)
            exit_code = None
            if name == "run_command" and text.startswith("exit="):
                try:
                    exit_code = int(text[5:].split()[0])
                except ValueError:
                    exit_code = None
            self.recorder.tool(rid, role=role, name=name, args={"args": args, "kwargs": kwargs}, output=text, exit_code=exit_code)
            return result
        call.__name__ = fn.__name__
        call.__doc__ = fn.__doc__
        call.__signature__ = __import__("inspect").signature(fn)  # type: ignore[attr-defined]
        call.__annotations__ = getattr(fn, "__annotations__", {})
        return call
