"""Authenticated bridge in front of the local, self-hosted OpenAI-compatible endpoint (Ollama).

Ollama has no auth of its own, so it must never be exposed through a tunnel (ngrok/cloudflared)
directly. This bridge sits in front of it and requires a token on every request, then reverse-proxies
authorized traffic to `base_url`. It is the one piece that makes "run Ollama on the Mac Studio, reach
it from inside a Quome sandbox" safe: only code runs in the sandbox; the model stays on your hardware
and is reached over an authenticated hop.

Auth is fail-closed and prefers OIDC: the bearer must be a
valid, unexpired, EdDSA access token issued by `oidc_issuer` and audienced to `oidc_audience`,
verified against the issuer's JWKS. When no issuer is configured it falls back to a static shared
secret (`static_token_env`); with neither configured every request is denied.

Run it with `qudisclose infer-bridge serve`, then `ngrok http <bridge_port>` to get `public_url`.
"""

from __future__ import annotations

import hmac
import logging
from functools import lru_cache
from urllib.parse import urlsplit

import httpx2
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from qudisclose.config import InferenceConfig

log = logging.getLogger("qudisclose.inference.bridge")

# Headers that must not be copied verbatim between client<->upstream.
_HOP_BY_HOP = {"host", "authorization", "content-length", "connection", "keep-alive",
               "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization"}


class TokenError(Exception):
    """The presented credential is missing, malformed, expired, or not for this bridge."""


class BridgeAuth:
    """Verifies the `Authorization: Bearer <token>` of an incoming request, fail-closed."""

    def __init__(self, cfg: InferenceConfig, *, static_token: str | None = None) -> None:
        self.cfg = cfg
        self._static = static_token  # resolved from env by the caller; None => static mode unavailable

    @staticmethod
    def _bearer(authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise TokenError("missing bearer token")
        return authorization[7:].strip()

    def verify(self, authorization: str | None) -> None:
        token = self._bearer(authorization)
        if self.cfg.oidc_issuer:
            self._verify_oidc(token)
        elif self._static:
            if not hmac.compare_digest(token, self._static):
                raise TokenError("invalid token")
        else:
            raise TokenError("bridge has no auth configured (set inference.oidc_issuer or the static token)")

    def _verify_oidc(self, token: str) -> None:
        import jwt  # PyJWT, already a dependency

        try:
            signing_key = _jwks_client(self._jwks_uri()).get_signing_key_from_jwt(token)
            jwt.decode(token, signing_key.key, algorithms=["EdDSA"], audience=self.cfg.oidc_audience,
                       issuer=self.cfg.oidc_issuer, options={"require": ["exp", "aud", "iss"]})
        except Exception as exc:  # PyJWT raises many subclasses; all mean "denied"
            raise TokenError(f"token rejected: {type(exc).__name__}") from exc

    def _jwks_uri(self) -> str:
        issuer = (self.cfg.oidc_issuer or "").rstrip("/")
        meta = _discover(f"{issuer}/.well-known/openid-configuration")
        uri = meta.get("jwks_uri")
        if not uri:
            raise TokenError("issuer discovery has no jwks_uri")
        return str(uri)


@lru_cache(maxsize=8)
def _discover(url: str) -> dict:
    return httpx2.get(url, timeout=10).raise_for_status().json()


@lru_cache(maxsize=8)
def _jwks_client(jwks_uri: str):
    import jwt

    return jwt.PyJWKClient(jwks_uri)


def _upstream_origin(base_url: str) -> str:
    """scheme://host[:port] of the Ollama endpoint; the incoming path is forwarded onto it as-is."""
    s = urlsplit(base_url)
    return f"{s.scheme}://{s.netloc}"


def build_app(cfg: InferenceConfig, *, static_token: str | None = None,
              client: httpx2.Client | None = None) -> Starlette:
    """Build the bridge ASGI app. `client` can be injected for tests (MockTransport)."""
    auth = BridgeAuth(cfg, static_token=static_token)
    origin = _upstream_origin(cfg.base_url)
    http = client or httpx2.Client(base_url=origin, timeout=600)

    async def healthz(_req: Request) -> Response:
        return JSONResponse({"ok": True, "upstream": origin})

    async def proxy(req: Request) -> Response:
        try:
            auth.verify(req.headers.get("authorization"))
        except TokenError as exc:
            return JSONResponse({"error": "unauthorized", "detail": str(exc)}, status_code=401)
        body = await req.body()
        fwd = {k: v for k, v in req.headers.items() if k.lower() not in _HOP_BY_HOP}
        try:
            up = http.request(req.method, req.url.path, params=dict(req.query_params), content=body, headers=fwd)
        except httpx2.HTTPError as exc:
            log.warning("upstream error: %s", exc)
            return JSONResponse({"error": "bad_gateway", "detail": str(exc)}, status_code=502)
        resp_headers = {k: v for k, v in up.headers.items() if k.lower() not in _HOP_BY_HOP}
        return Response(content=up.content, status_code=up.status_code, headers=resp_headers,
                        media_type=up.headers.get("content-type"))

    return Starlette(routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/{path:path}", proxy, methods=["GET", "POST", "PUT", "DELETE", "PATCH"]),
    ])


def serve(cfg: InferenceConfig, static_token: str | None = None) -> None:  # pragma: no cover - thin uvicorn wrapper
    import uvicorn

    mode = "oidc" if cfg.oidc_issuer else ("static-token" if static_token else "DENY-ALL (no auth configured)")
    log.info("inference bridge: %s://%s:%s -> %s  [auth: %s]", "http", cfg.bridge_host, cfg.bridge_port,
             _upstream_origin(cfg.base_url), mode)
    uvicorn.run(build_app(cfg, static_token=static_token), host=cfg.bridge_host, port=cfg.bridge_port, log_level="info")
