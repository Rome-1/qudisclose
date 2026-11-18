# Local inference bridge — keep the model on your hardware, reach it from a sandbox

**Date:** 2026-10-25
**Status:** Implemented (bridge + auth + injection); tunnel step is operator-run
**Author:** Jim Schwoebel + Claude

## Problem

The self-hosted model (Qwen-27B on a Mac Studio, served by Ollama) needs real RAM; a Quome sandbox
VM does not have it. We want to keep the rule **code is generated locally, only code runs in the
sandbox** — i.e. inference always happens on our hardware, and the sandbox only *executes* the code
and tests the model produced.

## Already true: inference is local

The agents (hunter, triage, patcher, reviewer) run in the qudisclose process and call the model
in-process. The sandbox is only ever used through `run(argv)` / `read` / `write`. There is no code
path where the sandbox calls a model. So for today's pipeline, with either sandbox backend, the Mac
Studio does all inference and the low-RAM sandbox only runs the target's tests. **No tunnel is needed
for the current flow.** A test (`test_sandbox_contract_runs_code_only`) locks the `SandboxBackend`
contract to the nine code-execution methods so no inference capability can leak into the sandbox.

## When a tunnel is needed

Only if a consumer *inside* the sandbox needs the model — a future in-sandbox agent, or generated code
that calls the model at runtime. Quome sandboxes have an egress killswitch and east-west guard, so the
sandbox cannot reach local Ollama without an explicit, authenticated egress hop. That hop is this
bridge plus a tunnel.

## Design

**The bridge** (`inference/bridge.py`, served by `qudisclose infer-bridge serve`) is a reverse proxy
in front of local Ollama. Ollama has no auth, so it must never face a tunnel directly; the bridge
requires a token on every request (fail-closed) and forwards authorized traffic to `base_url`.

**Auth prefers OIDC.** When `inference.oidc_issuer` is set, the bearer must be a valid, unexpired,
EdDSA access token issued by that issuer and audienced to `inference.oidc_audience`, verified against
the issuer's JWKS (PyJWT `PyJWKClient`, discovery via `/.well-known/openid-configuration`). This gives
short-lived, single-audience, revocable workload tokens — the in-sandbox consumer gets one via the issuer's
`client_credentials` (or RFC 8693 token-exchange for a delegated agent). A static shared secret
(`static_token_env`) is the fallback when no issuer is configured; with neither, every request is denied.

**The tunnel is operator-run** (ngrok, cloudflared, Tailscale — the bridge is agnostic). Recipe:

```bash
# 1. local model
ollama serve                                   # Qwen-27B on the Mac Studio, :11434

# 2. authenticated bridge in front of it
export QUDISCLOSE_INFERENCE_TOKEN=$(openssl rand -hex 32)   # or configure inference.oidc_issuer
qudisclose infer-bridge serve                  # :8900, fails closed if no auth configured

# 3. expose the bridge (NOT Ollama) through a tunnel
ngrok http 8900                                # -> https://<id>.ngrok.app  == inference.public_url
```

**Injection into the sandbox.** `QuomeSandbox.inject_inference(base_url, token, model)` writes an
OpenAI-compatible client config to `/workspace/.qudisclose/inference.json` so an in-sandbox consumer
points at `{public_url}/v1` with a short-lived token. The model never runs in the sandbox — only the
authenticated hop back to your host does.

## Config (`inference` block)

| Field | Meaning |
|-------|---------|
| `base_url` | local Ollama, OpenAI-compatible (default `http://localhost:11434/v1`) |
| `model` | model id (e.g. `qwen3.8:27b`) |
| `bridge_host` / `bridge_port` | where the bridge listens (default `127.0.0.1:8900`) |
| `public_url` | the tunnel URL fronting the bridge |
| `oidc_issuer` | OIDC issuer; discovery → JWKS. Set this to use issuer tokens |
| `oidc_audience` | required `aud` on bridge tokens (default `qudisclose-inference`) |
| `static_token_env` | env var holding the shared secret used only when `oidc_issuer` is unset |

## Non-goals

- Automating the tunnel. The bridge is tunnel-agnostic; the operator runs ngrok/cloudflared.
- Moving the agents into the sandbox. That is the future case this unblocks, not something built here.
- Exposing Ollama directly. It is always behind the authenticated bridge.
