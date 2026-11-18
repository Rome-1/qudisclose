"""A small, read-only web view of the qudisclose store.

`qudisclose dashboard` serves one page on localhost that lists every case and, for the selected one,
renders its status, event timeline and decoded artifacts (triage / reproduction / patch / review /
release plan / postmortem). It is deliberately read-only: it never writes, never calls an agent and
never touches a sandbox — it just reads the same Postgres (or SQLite) store the pipeline writes to, so
you can watch a run progress instead of reading rows out of psql.

The data shaping lives in pure functions (`report_rows`, `report_detail`) so it is unit-testable without
opening a socket; the HTTP layer is a thin stdlib `http.server` wrapper around them. The page is a small
React app (React + htm over a CDN, no build step) so the client code is still a single served string.
"""

from __future__ import annotations

import importlib.resources as _res
import json
import os
import shutil
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from qudisclose.config import Config
from qudisclose.store import Store

# Claude model aliases the local Claude Code CLI (`claude -p`) accepts; offered when that CLI is installed.
_CLAUDE_MODELS = ("opus", "sonnet", "haiku")

# In-flight / finished run jobs, keyed by report_id: {state: running|done|error, provider, model, error}.
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()

# Live message stream per report_id: a growing list of {t, kind, role, text} the SSE endpoint tails.
_RUN_LOG: dict[str, list[dict[str, Any]]] = {}
_LOG_LOCK = threading.Lock()
# The server reads the store from several request threads (threaded server); serialize that one connection.
_DB_LOCK = threading.Lock()


def _emit(report_id: str, kind: str, text: str, role: str | None = None) -> None:
    """Append a line to a case's live stream (capped) for the SSE console."""
    with _LOG_LOCK:
        buf = _RUN_LOG.setdefault(report_id, [])
        buf.append({"t": time.time(), "kind": kind, "role": role, "text": str(text)[:4000]})
        if len(buf) > 2000:
            del buf[:-2000]

# Artifacts rendered in this order when present; anything else falls back to pretty JSON.
_ARTIFACT_ORDER = ("triage", "reproduction", "patch", "review", "release_plan", "postmortem")


def _load_quokka() -> str:
    """The quokka mark vendored as a package asset."""
    try:
        return (_res.files("qudisclose") / "assets" / "quokka.svg").read_text(encoding="utf-8")
    except Exception:
        return ""


_QUOKKA_SVG = _load_quokka()
# Inner markup between the outer <svg> tags, reused as a <symbol> so the page can <use> it anywhere.
_QUOKKA_INNER = (_QUOKKA_SVG[_QUOKKA_SVG.find(">") + 1:_QUOKKA_SVG.rfind("</svg>")] if _QUOKKA_SVG else "")
_SPRITE = ('<svg width="0" height="0" style="position:absolute" aria-hidden="true">'
           f'<symbol id="quokka" viewBox="0 0 120 120">{_QUOKKA_INNER}</symbol></svg>')


def report_rows(store: Store) -> list[dict[str, Any]]:
    """One compact dict per case for the left-hand list (newest first)."""
    rows = []
    for r in store.list_reports(limit=500):
        rows.append({
            "id": r.id,
            "status": str(r.status),
            "severity": str(r.severity) if r.severity else None,
            "lane": str(r.lane) if r.lane else None,
            "source": str(r.source),
            "repo": r.submission.repo,
            "cwe": r.submission.cwe,
            "title": r.submission.title,
            "received_at": r.received_at.isoformat(),
        })
    rows.sort(key=lambda d: d["received_at"], reverse=True)
    return rows


def report_detail(store: Store, report_id: str) -> dict[str, Any] | None:
    """Full view of one case: the report, its ordered timeline, and decoded artifacts."""
    r = store.get_report(report_id)
    if r is None:
        return None
    events = [{"at": e.at.isoformat(), "kind": e.kind, "actor": e.actor, "data": e.data}
              for e in store.events(report_id)]
    raw = store.artifacts(report_id)
    artifacts = [{"kind": k, "body": raw[k]} for k in _ARTIFACT_ORDER if k in raw]
    artifacts += [{"kind": k, "body": v} for k, v in raw.items() if k not in _ARTIFACT_ORDER]
    return {
        "report": {
            "id": r.id,
            "status": str(r.status),
            "severity": str(r.severity) if r.severity else None,
            "lane": str(r.lane) if r.lane else None,
            "source": str(r.source),
            "title": r.submission.title,
            "repo": r.submission.repo,
            "cwe": r.submission.cwe,
            "received_at": r.received_at.isoformat(),
            "scanner_flags": r.scanner_flags,
        },
        "events": events,
        "artifacts": artifacts,
    }


def available_models(cfg: Config) -> dict[str, Any]:
    """What the run picker offers: self-hosted models pulled live from Ollama, plus Claude when a key is set."""
    local: list[str] = []
    try:
        base = cfg.inference.base_url.rstrip("/")
        if base.endswith("/v1"):
            base = base[:-3]
        with urllib.request.urlopen(base.rstrip("/") + "/api/tags", timeout=2) as resp:
            local = sorted(m["name"] for m in json.loads(resp.read()).get("models", []))
    except Exception:
        local = [cfg.inference.model]
    # Claude via the local CLI uses the user's Claude Code login — no API key needed; offered when installed.
    claude = list(_CLAUDE_MODELS) if shutil.which("claude") else []
    return {"local": local, "claude": claude,
            "default": {"provider": cfg.provider, "model": cfg.model if cfg.provider == "anthropic" else cfg.inference.model}}


def _run_job(cfg: Config, report_id: str, provider: str, model: str | None) -> None:
    """Run the orchestrator for one case on the chosen provider, in a background thread with its own store
    connection (the server's read connection is single-threaded and must not be shared)."""
    from qudisclose.cli import _keys, _orchestrator, _provider_for, _store
    from qudisclose.security import AuditLog

    with _LOG_LOCK:
        _RUN_LOG[report_id] = []
    _emit(report_id, "job", f"starting run on {provider}" + (f" · {model}" if model else ""))
    state, error = "done", None
    try:
        store = _store(cfg)
        _, _, audit_id = _keys(cfg)
        if provider == "claude":  # stream the model's messages + tool calls into the live console
            from qudisclose.agents.provider import ClaudeCliProvider
            prov = ClaudeCliProvider(model=model, on_event=lambda e: _emit(report_id, e["kind"], e["text"], e.get("role")))
        else:
            prov = _provider_for(cfg, provider, model)
        orch = _orchestrator(cfg, store, AuditLog(store.db, audit_id), provider=prov)
        orch.run_case(report_id)
    except Exception as exc:  # noqa: BLE001 — surfaced to the UI, never crashes the server
        state, error = "error", repr(exc)[:500]
    _emit(report_id, "job", f"run {state}" + (f": {error}" if error else ""))
    with _JOBS_LOCK:
        _JOBS[report_id] = {"state": state, "provider": provider, "model": model, "error": error}


class _Handler(BaseHTTPRequestHandler):
    store: Store  # bound per-server (subclass attribute)
    cfg: Config

    def log_message(self, *_: Any) -> None:  # keep the console quiet
        pass

    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(json.dumps(obj, default=str).encode(), "application/json", code)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(_PAGE.replace("<!--SPRITE-->", _SPRITE).encode(), "text/html; charset=utf-8")
        elif path == "/favicon.svg":
            self._send(_QUOKKA_SVG.encode(), "image/svg+xml")
        elif path == "/api/reports":
            with _DB_LOCK:
                rows = report_rows(self.store)
            self._json(rows)
        elif path == "/api/models":
            self._json(available_models(self.cfg))
        elif path == "/api/jobs":
            with _JOBS_LOCK:
                self._json(dict(_JOBS))
        elif path.startswith("/api/stream/"):
            self._stream(path[len("/api/stream/"):])
        elif path.startswith("/api/report/"):
            with _DB_LOCK:
                detail = report_detail(self.store, path[len("/api/report/"):])
            self._json(detail if detail is not None else {"error": "unknown report"}, 200 if detail else 404)
        else:
            self._send(b"not found", "text/plain", 404)

    def _stream(self, report_id: str) -> None:
        """Server-Sent Events: tail this case's timeline events and live agent messages until the run ends.
        Sends existing history first, then live updates; closes once no run is active and history is drained."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(event: str, data: Any) -> None:
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n".encode())
            self.wfile.flush()

        seen_ev, seen_log, start = 0, 0, time.time()
        try:
            while time.time() - start < 3600:
                with _DB_LOCK:
                    events = self.store.events(report_id)
                for e in events[seen_ev:]:
                    emit("stage", {"kind": e.kind, "actor": e.actor, "at": e.at.isoformat(), "data": e.data})
                seen_ev = len(events)
                with _LOG_LOCK:
                    log = list(_RUN_LOG.get(report_id, []))
                for line in log[seen_log:]:
                    emit("msg", line)
                seen_log = len(log)
                with _JOBS_LOCK:
                    job = _JOBS.get(report_id)
                running = bool(job) and job.get("state") == "running"
                if not running:
                    emit("done", job or {"state": "idle"})
                    return
                emit("ping", {"t": time.time()})
                time.sleep(0.7)
        except (BrokenPipeError, ConnectionResetError, ValueError):
            return  # client closed the EventSource

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path.split("?", 1)[0] != "/api/run":
            self._send(b"not found", "text/plain", 404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json({"error": "bad request body"}, 400)
            return
        report_id = body.get("report_id")
        provider = body.get("provider") or "local"
        model = body.get("model") or None
        with _DB_LOCK:
            known = report_id and self.store.get_report(report_id) is not None
        if not known:
            self._json({"error": "unknown report"}, 404)
            return
        if provider == "claude" and not shutil.which("claude"):
            self._json({"error": "claude CLI not found on PATH; cannot run Claude locally"}, 400)
            return
        if provider == "anthropic" and not os.environ.get("ANTHROPIC_API_KEY"):
            self._json({"error": "ANTHROPIC_API_KEY not set; Claude API is unavailable"}, 400)
            return
        with _JOBS_LOCK:
            if _JOBS.get(report_id, {}).get("state") == "running":
                self._json({"error": "a run is already in progress for this case"}, 409)
                return
            _JOBS[report_id] = {"state": "running", "provider": provider, "model": model, "error": None}
        threading.Thread(target=_run_job, args=(self.cfg, report_id, provider, model), daemon=True).start()
        self._json({"ok": True, "report_id": report_id, "provider": provider, "model": model}, 202)


def serve(store: Store, cfg: Config, *, host: str = "127.0.0.1", port: int = 8780) -> None:
    """Serve the dashboard until interrupted. GET requests read the store on this single connection;
    runs launched from the UI execute in their own threads with their own store connection."""

    class _Bound(_Handler):
        pass

    _Bound.store = store
    _Bound.cfg = cfg
    httpd = ThreadingHTTPServer((host, port), _Bound)
    httpd.daemon_threads = True
    print(f"qudisclose dashboard on http://{host}:{port}  (read-only; Ctrl-C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
    finally:
        httpd.server_close()


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>qudisclose</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#f5f6f8; --bg2:#eceef2; --panel:#ffffff; --panel2:#fbfcfd;
    --ink:#10151b; --muted:#6b7480; --faint:#9aa3ae; --line:#e4e8ee;
    --accent:#4263eb; --accent2:#7048e8; --sel:#eef2ff; --ring:rgba(66,99,235,.35);
    --ok:#12b886; --warn:#e8893a; --bad:#e64980; --info:#228be6; --crit:#f03e3e;
    --code:#f4f6f9; --shadow:0 1px 2px rgba(16,21,27,.04),0 8px 24px rgba(16,21,27,.06);
    color-scheme:light;
  }
  :root:not([data-theme="light"]){ @media (prefers-color-scheme: dark){
    --bg:#0d1016; --bg2:#0a0c11; --panel:#161b22; --panel2:#1b212a;
    --ink:#e8ecf1; --muted:#8b95a3; --faint:#5e6773; --line:#242b35;
    --accent:#748ffc; --accent2:#9775fa; --sel:#1b2436; --ring:rgba(116,143,252,.35);
    --ok:#38d9a9; --warn:#ffa94d; --bad:#f783ac; --info:#4dabf7; --crit:#ff6b6b;
    --code:#10151c; --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
    color-scheme:dark;
  }}
  :root[data-theme="dark"]{
    --bg:#0d1016; --bg2:#0a0c11; --panel:#161b22; --panel2:#1b212a;
    --ink:#e8ecf1; --muted:#8b95a3; --faint:#5e6773; --line:#242b35;
    --accent:#748ffc; --accent2:#9775fa; --sel:#1b2436; --ring:rgba(116,143,252,.35);
    --ok:#38d9a9; --warn:#ffa94d; --bad:#f783ac; --info:#4dabf7; --crit:#ff6b6b;
    --code:#10151c; --shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35);
    color-scheme:dark;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    -webkit-font-smoothing:antialiased;font-size:14px;line-height:1.5}
  code,pre,.mono{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
  ::-webkit-scrollbar{width:10px;height:10px}
  ::-webkit-scrollbar-thumb{background:var(--line);border-radius:10px;border:2px solid transparent;background-clip:content-box}
  ::-webkit-scrollbar-thumb:hover{background:var(--faint)}

  .app{display:grid;grid-template-rows:auto 1fr;height:100vh}
  header{display:flex;align-items:center;gap:14px;padding:0 20px;height:60px;
    background:linear-gradient(180deg,var(--panel),var(--panel2));border-bottom:1px solid var(--line);
    position:sticky;top:0;z-index:20}
  .brand{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:-.2px;font-size:16px}
  .brand .mark{width:34px;height:34px;display:block;filter:drop-shadow(0 3px 7px var(--ring))}
  .empty .mascot{width:92px;height:92px;opacity:.9;filter:drop-shadow(0 6px 16px var(--ring));margin-bottom:4px}
  .live{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12.5px;font-weight:500}
  .live .pulse{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 var(--ok);animation:pulse 2s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(18,184,134,.5)}70%{box-shadow:0 0 0 7px rgba(18,184,134,0)}100%{box-shadow:0 0 0 0 rgba(18,184,134,0)}}
  .spacer{flex:1}
  .iconbtn{background:var(--panel);border:1px solid var(--line);color:var(--muted);border-radius:9px;
    height:34px;padding:0 12px;cursor:pointer;font-size:13px;font-weight:500;display:flex;align-items:center;gap:7px;transition:.15s}
  .iconbtn:hover{color:var(--ink);border-color:var(--faint)}

  .body{display:grid;grid-template-columns:330px 1fr;overflow:hidden}
  @media(max-width:860px){.body{grid-template-columns:1fr;grid-template-rows:auto 1fr}}
  aside{border-right:1px solid var(--line);background:var(--panel);overflow-y:auto;padding:12px}
  .listhead{color:var(--faint);font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;padding:6px 8px 10px}
  .toolbar{position:sticky;top:0;z-index:3;background:var(--panel);margin:-12px -12px 10px;padding:12px 16px;border-bottom:1px solid var(--line)}
  .search{position:relative;margin-bottom:9px}
  .search .ic{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--faint);font-size:14px;pointer-events:none}
  .search input{width:100%;height:37px;border:1px solid var(--line);background:var(--bg2);color:var(--ink);
    border-radius:10px;padding:0 12px 0 33px;font-size:13px;outline:none;transition:.15s;font-family:inherit}
  .search input::placeholder{color:var(--faint)}
  .search input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--ring);background:var(--panel)}
  .filterrow{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:9px}
  .fchip{font-size:11px;font-weight:600;padding:4px 9px;border-radius:8px;border:1px solid var(--line);
    background:var(--bg2);color:var(--muted);cursor:pointer;transition:.12s;user-select:none}
  .fchip:hover{color:var(--ink);border-color:var(--faint)}
  .fchip.on{color:#fff;border-color:transparent}
  .fchip.on.all{background:var(--accent)} .fchip.on.crit{background:var(--crit)}
  .fchip.on.bad{background:var(--bad)} .fchip.on.warn{background:var(--warn)} .fchip.on.info{background:var(--info)}
  .reposel{width:100%;height:33px;border:1px solid var(--line);background:var(--bg2);color:var(--ink);
    border-radius:9px;padding:0 10px;font-size:12.5px;outline:none;cursor:pointer;font-family:inherit}
  .reposel:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
  .count{color:var(--faint);font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;padding:0 4px 10px}
  .card .repo{display:flex;align-items:center;gap:5px;color:var(--muted);font-size:11px;margin-top:7px}
  .card .repo svg{width:12px;height:12px;opacity:.7}
  .repolink{color:var(--accent);text-decoration:none;font-weight:600}
  .repolink:hover{text-decoration:underline}
  .card{padding:13px 14px;border:1px solid var(--line);border-radius:13px;margin-bottom:9px;cursor:pointer;
    background:var(--panel);transition:transform .14s,box-shadow .14s,border-color .14s;position:relative;overflow:hidden}
  .card:hover{transform:translateY(-1px);box-shadow:var(--shadow);border-color:var(--faint)}
  .card.sel{border-color:transparent;box-shadow:0 0 0 2px var(--accent),var(--shadow)}
  .card.sel:before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,var(--sel),transparent 60%);pointer-events:none}
  .card .ttl{font-weight:600;line-height:1.35;margin-bottom:7px;position:relative}
  .card .cid{color:var(--faint);font-size:11px;margin-bottom:9px}
  .chips{display:flex;gap:6px;flex-wrap:wrap;position:relative}

  .chip{font-size:11px;font-weight:600;padding:3px 9px;border-radius:999px;letter-spacing:.2px;
    display:inline-flex;align-items:center;gap:5px;border:1px solid transparent}
  .chip .d{width:6px;height:6px;border-radius:50%;background:currentColor}
  .chip.ok{color:var(--ok);background:color-mix(in srgb,var(--ok) 13%,transparent)}
  .chip.warn{color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent)}
  .chip.bad{color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent)}
  .chip.crit{color:var(--crit);background:color-mix(in srgb,var(--crit) 15%,transparent)}
  .chip.info{color:var(--info);background:color-mix(in srgb,var(--info) 13%,transparent)}
  .chip.flat{color:var(--muted);background:var(--bg2);border-color:var(--line)}

  main{overflow-y:auto;padding:26px 30px 60px}
  .empty{display:grid;place-items:center;height:70%;color:var(--faint);gap:10px;text-align:center}
  .fade{animation:fade .35s ease}
  @keyframes fade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

  .hero{display:flex;align-items:flex-start;gap:18px;margin-bottom:22px}
  .hero h1{font-size:23px;font-weight:800;letter-spacing:-.4px;margin:0 0 6px;line-height:1.25}
  .hero .meta{color:var(--muted);font-size:13px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .hero .meta .mono{color:var(--faint)}

  .grid{display:grid;grid-template-columns:1fr 240px;gap:16px;margin-bottom:18px}
  @media(max-width:1040px){.grid{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow)}
  .panel h2{font-size:11px;font-weight:700;letter-spacing:.9px;text-transform:uppercase;color:var(--faint);margin:0 0 16px;display:flex;align-items:center;gap:8px}

  /* pipeline stepper */
  .pipe{display:flex;align-items:flex-start;justify-content:space-between;gap:4px}
  .step{flex:1;display:flex;flex-direction:column;align-items:center;gap:8px;position:relative;min-width:0}
  .step .bar{position:absolute;top:17px;left:50%;width:100%;height:2px;background:var(--line);z-index:0}
  .step:last-child .bar{display:none}
  .step .bar.done{background:linear-gradient(90deg,var(--ok),var(--ok))}
  .step .node{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;z-index:1;
    background:var(--panel);border:2px solid var(--line);color:var(--faint);font-weight:700;font-size:14px;transition:.2s}
  .step.done .node{border-color:var(--ok);color:var(--ok);background:color-mix(in srgb,var(--ok) 12%,var(--panel))}
  .step.active .node{border-color:var(--accent);color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,var(--panel));
    animation:ring 1.6s infinite}
  .step.failed .node{border-color:var(--crit);color:var(--crit);background:color-mix(in srgb,var(--crit) 12%,var(--panel))}
  @keyframes ring{0%{box-shadow:0 0 0 0 var(--ring)}70%{box-shadow:0 0 0 8px transparent}100%{box-shadow:0 0 0 0 transparent}}
  .step .lbl{font-size:11.5px;font-weight:600;color:var(--muted);text-align:center}
  .step.active .lbl{color:var(--accent)} .step.done .lbl{color:var(--ink)} .step.failed .lbl{color:var(--crit)}

  /* cvss gauge */
  .gauge{display:flex;flex-direction:column;align-items:center;gap:6px}
  .gauge .num{font-size:34px;font-weight:800;letter-spacing:-1px;line-height:1}
  .gauge .scale{font-size:11px;color:var(--faint);font-weight:600}
  .gauge svg{display:block}

  /* timeline */
  .tl{display:flex;flex-direction:column}
  .tl .ev{display:grid;grid-template-columns:20px 1fr;gap:12px;padding:0 0 2px}
  .tl .rail{display:flex;flex-direction:column;align-items:center}
  .tl .dot{width:11px;height:11px;border-radius:50%;background:var(--accent);margin-top:5px;box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 20%,transparent)}
  .tl .dot.ok{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 20%,transparent)}
  .tl .dot.bad{background:var(--bad);box-shadow:0 0 0 3px color-mix(in srgb,var(--bad) 20%,transparent)}
  .tl .line{width:2px;flex:1;background:var(--line);margin:3px 0}
  .tl .c{padding-bottom:16px;min-width:0}
  .tl .k{font-weight:600}
  .tl .sub{color:var(--muted);font-size:12.5px;margin-top:1px}
  .tl .ts{color:var(--faint);font-size:11px;margin-top:2px}
  .tl .data{margin-top:6px;font-size:11.5px;color:var(--muted);background:var(--bg2);border:1px solid var(--line);
    border-radius:8px;padding:6px 9px;overflow-x:auto}

  .kv{display:grid;grid-template-columns:auto 1fr;gap:9px 18px;align-items:baseline}
  .kv .k{color:var(--muted);font-size:12.5px;font-weight:500;white-space:nowrap}
  .kv .v{word-break:break-word}
  .tags{display:flex;gap:6px;flex-wrap:wrap}

  pre.block{background:var(--code);border:1px solid var(--line);border-radius:12px;padding:14px 16px;overflow:auto;
    font-size:12px;line-height:1.6;margin:10px 0 0;max-height:420px}
  pre.block.diff .add{color:var(--ok)} pre.block.diff .del{color:var(--bad)}
  pre.block.diff .hunk{color:var(--info);font-weight:500} pre.block.diff .meta{color:var(--faint)}
  .verdict{display:flex;gap:10px;margin-bottom:10px}
  .vbox{flex:1;border:1px solid var(--line);border-radius:12px;padding:12px 14px;text-align:center}
  .vbox .big{font-size:18px;font-weight:800;margin-top:3px}
  .vbox.pass .big{color:var(--ok)} .vbox.fail .big{color:var(--bad)}
  .vbox .cap{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.6px;font-weight:700}

  .cols{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
  @media(max-width:820px){.cols{grid-template-columns:1fr}}
  .cols h4{margin:0 0 8px;font-size:12px;letter-spacing:.3px;display:flex;align-items:center;gap:6px}
  .cols ul{margin:0;padding-left:16px;display:flex;flex-direction:column;gap:5px;font-size:13px}
  .cols .good h4{color:var(--ok)} .cols .bad h4{color:var(--bad)} .cols .act h4{color:var(--info)}
  .skel{height:14px;border-radius:7px;background:linear-gradient(90deg,var(--bg2),var(--line),var(--bg2));
    background-size:200% 100%;animation:sk 1.3s infinite}
  @keyframes sk{0%{background-position:200% 0}100%{background-position:-200% 0}}
  .runbar{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}
  .field{display:flex;flex-direction:column;gap:6px}
  .field label{font-size:10.5px;font-weight:700;color:var(--faint);letter-spacing:.5px;text-transform:uppercase}
  .field select{height:37px;border:1px solid var(--line);background:var(--bg2);color:var(--ink);border-radius:10px;
    padding:0 12px;font-size:13px;font-family:inherit;outline:none;cursor:pointer;min-width:210px}
  .field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
  .runbtn{height:37px;padding:0 20px;border:none;border-radius:10px;color:#fff;font-weight:700;font-size:13px;cursor:pointer;
    display:flex;align-items:center;gap:7px;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 4px 12px var(--ring);transition:.15s}
  .runbtn:hover{filter:brightness(1.08)} .runbtn:disabled{opacity:.5;cursor:not-allowed;box-shadow:none;filter:none}
  .claudeflag{color:var(--warn);font-size:11.5px;margin-top:11px;display:flex;align-items:center;gap:6px}
  .runstate{font-size:12.5px;margin-top:11px;display:flex;align-items:center;gap:8px;font-weight:500}
  .runstate.run{color:var(--accent)} .runstate.done{color:var(--ok)} .runstate.err{color:var(--bad);word-break:break-word}
  .spin{width:13px;height:13px;border:2px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex:none}
  @keyframes spin{to{transform:rotate(360deg)}}
  .tabs{display:flex;gap:2px;margin-bottom:18px;border-bottom:1px solid var(--line)}
  .tab{padding:9px 16px;font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;display:flex;align-items:center}
  .tab:hover{color:var(--ink)} .tab.on{color:var(--accent);border-bottom-color:var(--accent)}
  .dotlive{width:7px;height:7px;border-radius:50%;background:var(--ok);margin-left:7px;animation:pulse 1.6s infinite}
  .conhead{display:flex;align-items:center;gap:9px;margin-bottom:10px}
  .conhead .st{font-size:12px;color:var(--muted);font-weight:500}
  .console{background:#0a0d12;border:1px solid var(--line);border-radius:14px;padding:14px 16px;height:62vh;overflow:auto;
    font:12.5px/1.65 "JetBrains Mono",ui-monospace,Menlo,monospace;color:#c8d0da;box-shadow:var(--shadow)}
  .console .ln{display:flex;gap:11px;padding:2px 0;white-space:pre-wrap;word-break:break-word}
  .console .ts{color:#59626e;flex:none}
  .console .tag{flex:none;font-weight:700;min-width:96px}
  .console .tag.stage{color:#4dabf7} .console .tag.tool_call{color:#ffa94d} .console .tag.tool_output{color:#7d8794}
  .console .tag.reply{color:#38d9a9} .console .tag.role_start{color:#b197fc} .console .tag.job{color:#748ffc}
  .console .txt{flex:1;min-width:0} .console .txt.dim{color:#7d8794}
  .console .empty2{color:#59626e;padding:8px 0}
</style>
</head>
<body>
<!--SPRITE-->
<div id="root"></div>
<script crossorigin src="https://unpkg.com/react@18.3.1/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/htm@3.1.1/dist/htm.umd.js"></script>
<script>
const {useState,useEffect,useRef}=React;
const html=htm.bind(React.createElement);
const root=ReactDOM.createRoot(document.getElementById('root'));

/* ---------- helpers ---------- */
const STAGES=[["received","Received"],["triage","Triage"],["reproduce","Reproduce"],["patch","Patch"],["review","Review"],["release","Release"]];
const statusClass=s=>{s=(s||'').toLowerCase();
  if(/(closed|published|verified|approved|passed)/.test(s))return'ok';
  if(/(failed|rejected|broken|error|unverified)/.test(s))return'bad';
  if(/(patch|reproduc|triag|review|releas|paused|await|pending)/.test(s))return'warn';
  return'info';};
const sevClass=s=>{s=(s||'').toLowerCase();
  if(/crit/.test(s))return'crit'; if(/high/.test(s))return'bad';
  if(/med|mod/.test(s))return'warn'; if(/low/.test(s))return'info'; return'info';};
const titleCase=s=>(s||'').replace(/[_-]/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
const hhmm=iso=>{try{return new Date(iso).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});}catch(e){return iso;}};
const repoUrl=r=>/^[\w.-]+\/[\w.-]+$/.test(r||'')?'https://github.com/'+r:null;
const cweUrl=c=>{const m=/CWE-(\d+)/.exec(c||'');return m?'https://cwe.mitre.org/data/definitions/'+m[1]+'.html':null;};

function Chip({kind,cls,dot=true}){ if(!kind)return null;
  return html`<span class=${'chip '+cls}>${dot&&html`<span class="d"/>`}${titleCase(kind)}</span>`; }

/* ---------- pipeline stepper ---------- */
function pipeState(d){
  const arts=new Set(d.artifacts.map(a=>a.kind));
  const st=(d.report.status||'').toLowerCase();
  const failed=/(failed|rejected)/.test(st);
  const done={received:true,
    triage:arts.has('triage'),
    reproduce:arts.has('reproduction'),
    patch:arts.has('patch'),
    review:arts.has('review'),
    release:arts.has('release_plan')||/(closed|published)/.test(st)};
  const activeMap={triaging:'triage',reproducing:'reproduce',patching:'patch',reviewing:'review',releasing:'release'};
  const active=activeMap[st]||null;
  // the stage that failed = first not-done stage (when the case failed)
  let failStage=null;
  if(failed){ for(const [k] of STAGES){ if(!done[k]){failStage=k;break;} } }
  return STAGES.map(([k,label],i)=>{
    let cls = done[k]?'done':(k===active?'active':(k===failStage?'failed':''));
    const barDone = STAGES.slice(0,i+1).every(([kk])=>done[kk]);
    return {k,label,cls,barDone};
  });
}
function Pipeline({d}){
  const steps=pipeState(d);
  return html`<div class="panel"><h2>Pipeline</h2><div class="pipe">
    ${steps.map((s,i)=>html`<div key=${s.k} class=${'step '+s.cls}>
      <div class=${'bar '+(s.barDone?'done':'')}/>
      <div class="node">${s.cls==='done'?'✓':(s.cls==='failed'?'✕':i+1)}</div>
      <div class="lbl">${s.label}</div>
    </div>`)}
  </div></div>`;
}

/* ---------- cvss gauge ---------- */
function Gauge({score,severity}){
  const v=typeof score==='number'?score:parseFloat(score);
  const has=!isNaN(v);
  const pct=has?Math.max(0,Math.min(1,v/10)):0;
  const R=52,C=2*Math.PI*R, off=C*(1-pct*0.75), gap=C*0.25;
  const color=sevClass(severity);
  const stroke={ok:'var(--ok)',warn:'var(--warn)',bad:'var(--bad)',crit:'var(--crit)',info:'var(--info)'}[color];
  return html`<div class="panel"><h2>CVSS</h2><div class="gauge">
    <svg width="140" height="118" viewBox="0 0 140 130">
      <g transform="rotate(135 70 70)">
        <circle cx="70" cy="70" r=${R} fill="none" stroke="var(--line)" stroke-width="11"
          stroke-linecap="round" stroke-dasharray=${(C*0.75)+' '+C}/>
        <circle cx="70" cy="70" r=${R} fill="none" stroke=${stroke} stroke-width="11"
          stroke-linecap="round" stroke-dasharray=${(C*0.75*pct)+' '+C}
          style=${{transition:'stroke-dasharray .6s ease'}}/>
      </g>
      <text x="70" y="70" text-anchor="middle" dominant-baseline="middle"
        style=${{fontSize:'30px',fontWeight:800,fill:'var(--ink)'}}>${has?v.toFixed(1):'—'}</text>
    </svg>
    <${Chip} kind=${severity||'unknown'} cls=${color}/>
  </div></div>`;
}

/* ---------- timeline ---------- */
function Timeline({events}){
  const last=events.length-1;
  return html`<div class="panel"><h2>Timeline · ${events.length}</h2><div class="tl">
    ${events.map((e,i)=>{
      const cls=/verified|done|published|acknowledged|approved|received/.test(e.kind)?'ok':(/fail|unverified|reject|error|blocked/.test(e.kind)?'bad':'');
      const data=e.data&&Object.keys(e.data).length?JSON.stringify(e.data):'';
      return html`<div key=${i} class="ev">
        <div class="rail"><div class=${'dot '+cls}/>${i!==last&&html`<div class="line"/>`}</div>
        <div class="c">
          <div class="k">${titleCase(e.kind)}</div>
          <div class="sub">${e.actor}</div>
          <div class="ts">${hhmm(e.at)}</div>
          ${data&&html`<div class="data mono">${data}</div>`}
        </div>
      </div>`;
    })}
  </div></div>`;
}

/* ---------- diff viewer ---------- */
function Diff({text}){
  const lines=(text||'').split('\n').map((l,i)=>{
    let c=''; if(l.startsWith('+')&&!l.startsWith('+++'))c='add';
    else if(l.startsWith('-')&&!l.startsWith('---'))c='del';
    else if(l.startsWith('@@'))c='hunk'; else if(/^(diff |index |--- |\+\+\+ )/.test(l))c='meta';
    return html`<div key=${i} class=${c}>${l||' '}</div>`;
  });
  return html`<pre class="block diff mono">${lines}</pre>`;
}

/* ---------- artifact bodies ---------- */
function KV({rows}){ return html`<div class="kv">${rows.filter(([,v])=>v!==undefined&&v!==null&&v!==''&&!(Array.isArray(v)&&!v.length))
  .map(([k,v])=>html`<div class="k" key=${k}>${k}</div><div class="v">${
    Array.isArray(v)?html`<div class="tags">${v.map((x,i)=>html`<span key=${i} class="chip flat">${String(x)}</span>`)}</div>`
    :(typeof v==='boolean'?html`<${Chip} kind=${v?'yes':'no'} cls=${v?'ok':'bad'}/>`:String(v))
  }</div>`)}</div>`; }

function Artifact({a}){
  const b=a.body||{};
  let inner;
  if(a.kind==='triage'){
    inner=html`<${KV} rows=${[['vulnerability',b.is_vulnerability],['severity',b.severity],['CVSS',b.cvss_score],
      ['vector',b.cvss_vector],['CWE',b.cwe],['exploitability',b.exploitability],['lane',b.lane],
      ['duplicate of',b.duplicate_of],['injection suspected',b.injection_suspected],
      ['affected',b.affected_components],['summary',b.summary]]}/>`;
  } else if(a.kind==='reproduction'){
    inner=html`<${KV} rows=${[['fails on vulnerable',b.fails_on_vulnerable],['test path',b.test_path],['command',b.command]]}/>
      ${b.test_source&&html`<pre class="block mono">${b.test_source}</pre>`}`;
  } else if(a.kind==='patch'){
    const p=b.proposal||{};
    inner=html`<div class="verdict">
        <div class=${'vbox '+(b.reproduction_passes?'pass':'fail')}><div class="cap">Reproduction</div><div class="big">${b.reproduction_passes?'PASS':'FAIL'}</div></div>
        <div class=${'vbox '+(b.suite_passes?'pass':'fail')}><div class="cap">Test suite</div><div class="big">${b.suite_passes?'PASS':'FAIL'}</div></div>
        <div class="vbox"><div class="cap">Attempts</div><div class="big">${b.attempts??'—'}</div></div>
      </div>
      ${(p.files_touched&&p.files_touched.length)&&html`<div class="tags" style=${{marginBottom:'8px'}}>${p.files_touched.map((f,i)=>html`<span key=${i} class="chip flat">${f}</span>`)}</div>`}
      ${p.diff&&html`<${Diff} text=${p.diff}/>`}
      ${b.output_excerpt&&html`<pre class="block mono">${b.output_excerpt}</pre>`}`;
  } else if(a.kind==='postmortem'){
    const col=(cls,label,arr)=>html`<div class=${cls}><h4>${label}</h4><ul>${(arr||[]).map((x,i)=>html`<li key=${i}>${x}</li>`)}</ul></div>`;
    inner=html`<div class="cols">${col('good','✓ Went well',b.went_well)}${col('bad','✕ Went badly',b.went_badly)}${col('act','→ Action items',b.action_items)}</div>`;
  } else if(a.kind==='review'){
    inner=html`<${KV} rows=${[['approved',b.approved],['required changes',b.required_changes],['suspicious',b.suspicious],['notes',b.notes]]}/>`;
  } else {
    inner=html`<pre class="block mono">${JSON.stringify(b,null,2)}</pre>`;
  }
  return html`<div class="panel" style=${{marginBottom:'16px'}}><h2>${titleCase(a.kind)}</h2>${inner}</div>`;
}

/* ---------- run panel (launches orchestrator.run_case on a chosen provider) ---------- */
function RunPanel({report,models,job,onRan}){
  const def=models.default||{};
  const localList=models.local||[], claudeList=models.claude||[];
  const [prov,setProv]=useState('local');
  const [model,setModel]=useState('');
  useEffect(()=>{ const l=prov==='claude'?claudeList:localList;
    setModel(l.includes(def.model)?def.model:(l[0]||'')); },[prov,models]);
  const list=prov==='claude'?claudeList:localList;
  const claudeAvail=claudeList.length>0;
  const running=job&&job.state==='running';
  async function run(){
    const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({report_id:report.id,provider:prov,model})});
    if(r.ok){ onRan&&onRan(); }
    else { const e=await r.json().catch(()=>({})); alert(e.error||'run failed'); }
  }
  return html`<div class="panel" style=${{marginBottom:'18px'}}>
    <h2>Run pipeline</h2>
    <div class="runbar">
      <div class="field"><label>Provider</label>
        <select value=${prov} onChange=${e=>setProv(e.target.value)}>
          <option value="local">Local · self-hosted (Ollama)</option>
          <option value="claude" disabled=${!claudeAvail}>Claude · local CLI${claudeAvail?' (Claude Code login)':' · not installed'}</option>
        </select>
      </div>
      <div class="field"><label>Model</label>
        <select value=${model} onChange=${e=>setModel(e.target.value)}>
          ${list.length?list.map(m=>html`<option key=${m} value=${m}>${m}</option>`)
            :html`<option value="">(none found)</option>`}
        </select>
      </div>
      <button class="runbtn" disabled=${running||!model} onClick=${run}>
        ${running?html`<span class="spin"/>Running…`:'▶ Run case'}</button>
    </div>
    ${prov==='claude'&&html`<div class="claudeflag">⚠ Claude runs go through your local Claude Code CLI (claude -p); this repo's code is processed by Claude.</div>`}
    ${job&&html`<div class=${'runstate '+(job.state==='running'?'run':(job.state==='done'?'done':'err'))}>
      ${job.state==='running'?html`<span class="spin"/>running on ${job.provider}${job.model?' · '+job.model:''}…`
        :(job.state==='done'?html`✓ last UI run finished (${job.provider}${job.model?' · '+job.model:''})`
        :html`✕ last run errored: ${job.error}`)}</div>`}
  </div>`;
}

/* ---------- live stream console (SSE) ---------- */
function StreamConsole({reportId,runKey}){
  const [lines,setLines]=useState([]);
  const [status,setStatus]=useState('connecting');
  const box=useRef(null);
  useEffect(()=>{
    setLines([]); setStatus('connecting');
    const es=new EventSource('/api/stream/'+reportId);
    const add=o=>setLines(prev=>[...prev.slice(-1500),o]);
    es.addEventListener('stage',e=>add(Object.assign({t:'stage'},JSON.parse(e.data))));
    es.addEventListener('msg',e=>add(JSON.parse(e.data)));
    es.addEventListener('ping',()=>setStatus('live'));
    es.addEventListener('done',e=>{let j={};try{j=JSON.parse(e.data)}catch(x){}; setStatus((j&&j.state)||'done'); es.close();});
    es.onopen=()=>setStatus('live');
    es.onerror=()=>setStatus(s=>s==='live'?'reconnecting…':s);
    return ()=>es.close();
  },[reportId,runKey]);
  useEffect(()=>{ const el=box.current; if(el) el.scrollTop=el.scrollHeight; },[lines]);
  const tag=l=>l.t==='stage'?'stage':(l.kind||'msg');
  const text=l=>{
    if(l.t==='stage'){ const d=l.data&&Object.keys(l.data).length?' '+JSON.stringify(l.data):''; return titleCase(l.kind)+' ('+l.actor+')'+d; }
    return (l.role?l.role+' · ':'')+(l.text||'');
  };
  const dim=l=>l.t!=='stage'&&(l.kind==='tool_output'||l.kind==='role_start');
  return html`<div>
    <div class="conhead">
      <span class="st">${status==='live'?html`<span class="dotlive" style=${{display:'inline-block'}}/> streaming live`
        :(status==='done'||status==='error'?('stream ended · '+status):status)}</span>
      <span class="st">· ${lines.length} lines</span>
    </div>
    <div class="console" ref=${box}>
      ${lines.length===0&&html`<div class="empty2">Waiting for messages… launch a run above, or watch the current one.</div>`}
      ${lines.map((l,i)=>html`<div class="ln" key=${i}>
        <span class="ts">${new Date((l.t&&l.t*1000)||Date.now()).toLocaleTimeString()}</span>
        <span class=${'tag '+tag(l)}>${tag(l)}</span>
        <span class=${'txt'+(dim(l)?' dim':'')}>${text(l)}</span>
      </div>`)}
    </div>
  </div>`;
}

/* ---------- detail ---------- */
function Detail({d,models,job,onRan}){
  const r=d.report;
  const triage=(d.artifacts.find(a=>a.kind==='triage')||{}).body||{};
  const running=job&&job.state==='running';
  const [view,setView]=useState(running?'live':'overview');
  useEffect(()=>{ if(running) setView('live'); },[running]);
  return html`<div class="fade">
    <div class="hero">
      <div style=${{flex:1,minWidth:0}}>
        <h1>${r.title}</h1>
        <div class="meta">
          <span class="mono">${r.id}</span>
          ${r.repo&&html`<span>· ${repoUrl(r.repo)
            ?html`<a class="repolink" href=${repoUrl(r.repo)} target="_blank" rel="noopener">${r.repo} ↗</a>`
            :r.repo}</span>`}
          ${r.cwe&&html`<span>· ${cweUrl(r.cwe)
            ?html`<a class="repolink" href=${cweUrl(r.cwe)} target="_blank" rel="noopener">${r.cwe} ↗</a>`
            :r.cwe}</span>`}
          <span>·</span>
          <${Chip} kind=${r.status} cls=${statusClass(r.status)}/>
          ${r.severity&&html`<${Chip} kind=${r.severity} cls=${sevClass(r.severity)}/>`}
          ${r.lane&&html`<${Chip} kind=${r.lane} cls='flat' dot=${false}/>`}
          <${Chip} kind=${r.source} cls='flat' dot=${false}/>
          ${(r.scanner_flags||[]).map((f,i)=>html`<${Chip} key=${i} kind=${f} cls='warn'/>`)}
        </div>
      </div>
    </div>
    <div class="tabs">
      <div class=${'tab '+(view==='overview'?'on':'')} onClick=${()=>setView('overview')}>Overview</div>
      <div class=${'tab '+(view==='live'?'on':'')} onClick=${()=>setView('live')}>Live stream${running?html`<span class="dotlive"/>`:''}</div>
    </div>
    <${Pipeline} d=${d}/>
    <${RunPanel} report=${r} models=${models} job=${job} onRan=${onRan}/>
    ${view==='live'
      ?html`<${StreamConsole} reportId=${r.id} runKey=${(job&&job.state)||''}/>`
      :html`<div><div class="grid">
          <${Timeline} events=${d.events}/>
          <${Gauge} score=${triage.cvss_score} severity=${r.severity||triage.severity}/>
        </div>
        ${d.artifacts.map(a=>html`<${Artifact} key=${a.kind} a=${a}/>`)}</div>`}
  </div>`;
}

/* ---------- sidebar ---------- */
const SEV_FILTERS=[['crit','Critical','critical'],['bad','High','high'],['warn','Medium','medium'],['info','Low','low']];
function Sidebar({rows,total,sel,onSel,q,setQ,sevs,toggleSev,repo,setRepo,repoList}){
  return html`<aside>
    <div class="toolbar">
      <div class="search"><span class="ic">⌕</span>
        <input type="search" placeholder="Search title, id, repo, CWE…" value=${q} onInput=${e=>setQ(e.target.value)}/>
      </div>
      <div class="filterrow">
        <span class=${'fchip all '+(sevs.size===0?'on':'')} onClick=${()=>toggleSev(null)}>All</span>
        ${SEV_FILTERS.map(([c,label,key])=>html`<span key=${key}
          class=${'fchip '+c+' '+(sevs.has(key)?'on':'')} onClick=${()=>toggleSev(key)}>${label}</span>`)}
      </div>
      ${repoList.length>1&&html`<select class="reposel" value=${repo} onChange=${e=>setRepo(e.target.value)}>
        <option value="">All repos (${repoList.length})</option>
        ${repoList.map(r=>html`<option key=${r} value=${r}>${r}</option>`)}
      </select>`}
    </div>
    <div class="count">${rows.length===total?total+' cases':rows.length+' of '+total}</div>
    ${total===0&&html`<div style=${{padding:'16px 8px',color:'var(--faint)'}}>No cases yet.</div>`}
    ${total>0&&rows.length===0&&html`<div style=${{padding:'16px 8px',color:'var(--faint)'}}>No matching cases.</div>`}
    ${rows.map(r=>html`<div key=${r.id} class=${'card '+(r.id===sel?'sel':'')} onClick=${()=>onSel(r.id)}>
      <div class="ttl">${r.title}</div>
      <div class="cid mono">${r.id}</div>
      <div class="chips">
        <${Chip} kind=${r.status} cls=${statusClass(r.status)}/>
        ${r.severity&&html`<${Chip} kind=${r.severity} cls=${sevClass(r.severity)}/>`}
        ${r.cwe&&html`<${Chip} kind=${r.cwe} cls='flat' dot=${false}/>`}
      </div>
      ${r.repo&&html`<div class="repo"><svg viewBox="0 0 16 16" fill="currentColor"><path d="M2 2.5A2.5 2.5 0 0 1 4.5 0h8.75a.75.75 0 0 1 .75.75v12.5a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 1 0 0 0-.714 1.7.75.75 0 1 1-1.072 1.05A2.5 2.5 0 0 1 2 11.5Zm10.5-1h-8a1 1 0 0 0-1 1v6.708A2.5 2.5 0 0 1 4.5 9h8ZM5 12.25a.25.25 0 0 1 .25-.25h3.5a.25.25 0 0 1 .25.25v3.25a.25.25 0 0 1-.4.2l-1.45-1.087a.25.25 0 0 0-.3 0L5.4 15.7a.25.25 0 0 1-.4-.2Z"/></svg>${r.repo}</div>`}
    </div>`)}
  </aside>`;
}

/* ---------- app ---------- */
function App(){
  const [rows,setRows]=useState([]);
  const [sel,setSel]=useState(null);
  const [detail,setDetail]=useState(null);
  const [err,setErr]=useState(false);
  const [models,setModels]=useState({local:[],claude:[],default:{}});
  const [jobs,setJobs]=useState({});
  const selRef=useRef(sel); selRef.current=sel;

  async function tick(){
    try{
      const rs=await (await fetch('/api/reports')).json();
      setRows(rs); setErr(false);
      try{ setJobs(await (await fetch('/api/jobs')).json()); }catch(e){}
      let id=selRef.current; if(!id&&rs.length){id=rs[0].id; setSel(id);}
      if(id){ const d=await (await fetch('/api/report/'+id)).json(); if(!d.error) setDetail(d); }
    }catch(e){ setErr(true); }
  }
  useEffect(()=>{ tick(); const t=setInterval(tick,4000); return ()=>clearInterval(t); },[]);
  useEffect(()=>{ fetch('/api/models').then(r=>r.json()).then(setModels).catch(()=>{}); },[]);
  useEffect(()=>{ if(sel) fetch('/api/report/'+sel).then(r=>r.json()).then(d=>{if(!d.error)setDetail(d);}); },[sel]);

  const [theme,setTheme]=useState(()=>{try{return localStorage.getItem('qd-theme')||'';}catch(e){return'';}});
  useEffect(()=>{ if(theme)document.documentElement.setAttribute('data-theme',theme);
    else document.documentElement.removeAttribute('data-theme');
    try{localStorage.setItem('qd-theme',theme);}catch(e){} },[theme]);

  // ---- search + filters (client-side, over the fetched rows) ----
  const [q,setQ]=useState('');
  const [sevs,setSevs]=useState(()=>new Set());
  const [repo,setRepo]=useState('');
  const toggleSev=key=>setSevs(prev=>{ if(key===null) return new Set();
    const n=new Set(prev); n.has(key)?n.delete(key):n.add(key); return n; });
  const repoList=[...new Set(rows.map(r=>r.repo).filter(Boolean))].sort();
  const ql=q.trim().toLowerCase();
  const filtered=rows.filter(r=>{
    if(sevs.size&&!sevs.has((r.severity||'').toLowerCase())) return false;
    if(repo&&r.repo!==repo) return false;
    if(ql){ const hay=[r.title,r.id,r.repo,r.cwe,r.status].join(' ').toLowerCase(); if(!hay.includes(ql)) return false; }
    return true;
  });

  return html`<div class="app">
    <header>
      <div class="brand"><svg class="mark" viewBox="0 0 120 120" aria-hidden="true"><use href="#quokka"/></svg>qudisclose</div>
      <span class="live">${err?html`<span class="pulse" style=${{background:'var(--crit)'}}/>store unreachable`
        :html`<span class="pulse"/>live · ${rows.length} case${rows.length===1?'':'s'} · refresh 4s`}</span>
      <span class="spacer"/>
      <button class="iconbtn" onClick=${()=>setTheme(theme==='dark'?'light':'dark')}>
        ${theme==='dark'?'☀ Light':'☾ Dark'}</button>
    </header>
    <div class="body">
      <${Sidebar} rows=${filtered} total=${rows.length} sel=${sel} onSel=${setSel}
        q=${q} setQ=${setQ} sevs=${sevs} toggleSev=${toggleSev} repo=${repo} setRepo=${setRepo} repoList=${repoList}/>
      <main>${detail?html`<${Detail} d=${detail} models=${models} job=${jobs[detail.report.id]} onRan=${tick}/>`
        :html`<div class="empty"><svg class="mascot" viewBox="0 0 120 120" aria-hidden="true"><use href="#quokka"/></svg><div>Select a case to inspect its pipeline.</div></div>`}</main>
    </div>
  </div>`;
}
root.render(html`<${App}/>`);
</script>
</body>
</html>"""
