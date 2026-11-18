"""The authenticated inference bridge: fail-closed auth (static + oidc EdDSA), reverse proxy, and the
architectural invariant that the sandbox contract runs code only — it never does model inference."""

from __future__ import annotations

import time

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.testclient import TestClient

from qudisclose.config import InferenceConfig
from qudisclose.inference.bridge import BridgeAuth, TokenError, build_app


# --------------------------------------------------------------------------- fail-closed auth


def test_no_auth_configured_denies_everything():
    auth = BridgeAuth(InferenceConfig(), static_token=None)
    with pytest.raises(TokenError):
        auth.verify("Bearer anything")
    with pytest.raises(TokenError):
        auth.verify(None)


def test_static_token_mode():
    auth = BridgeAuth(InferenceConfig(), static_token="s3cret")
    auth.verify("Bearer s3cret")  # ok
    for bad in (None, "s3cret", "Bearer wrong", "Basic s3cret", "Bearer "):
        with pytest.raises(TokenError):
            auth.verify(bad)


# --------------------------------------------------------------------------- oidc EdDSA mode


@pytest.fixture
def oidc(monkeypatch):
    """A fake oidc: an Ed25519 key, a JWKS, and discovery — wired into the bridge's httpx2 fetchers."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    from jwt.algorithms import OKPAlgorithm

    jwk = OKPAlgorithm.to_jwk(pub, as_dict=True)
    jwk.update({"kid": "k1", "use": "sig", "alg": "EdDSA"})
    issuer = "https://auth.example"
    jwks = {"keys": [jwk]}
    disco = {"issuer": issuer, "jwks_uri": f"{issuer}/jwks"}

    # the bridge memoizes discovery/JWKS; clear so each test is isolated
    from qudisclose.inference import bridge
    bridge._discover.cache_clear()
    bridge._jwks_client.cache_clear()

    def fake_get(url, timeout=10):
        body = disco if url.endswith("openid-configuration") else jwks
        return httpx2.Response(200, json=body, request=httpx2.Request("GET", url))

    monkeypatch.setattr(bridge.httpx2, "get", fake_get)

    # PyJWKClient fetches the JWKS over the network — feed it from our dict instead
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: jwks)

    def mint(*, aud="qudisclose-inference", iss=issuer, exp_delta=300, extra=None):
        claims = {"iss": iss, "aud": aud, "sub": "agent:sandbox",
                  "iat": int(time.time()), "exp": int(time.time()) + exp_delta}
        claims.update(extra or {})
        return jwt.encode(claims, _pem(key), algorithm="EdDSA", headers={"kid": "k1"})

    return issuer, mint


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def test_oidc_valid_token_accepted(oidc):
    issuer, mint = oidc
    auth = BridgeAuth(InferenceConfig(oidc_issuer=issuer))
    auth.verify(f"Bearer {mint()}")


def test_oidc_wrong_audience_rejected(oidc):
    issuer, mint = oidc
    auth = BridgeAuth(InferenceConfig(oidc_issuer=issuer))
    with pytest.raises(TokenError):
        auth.verify(f"Bearer {mint(aud='some-other-service')}")


def test_oidc_expired_token_rejected(oidc):
    issuer, mint = oidc
    auth = BridgeAuth(InferenceConfig(oidc_issuer=issuer))
    with pytest.raises(TokenError):
        auth.verify(f"Bearer {mint(exp_delta=-10)}")


def test_oidc_wrong_issuer_rejected(oidc):
    issuer, mint = oidc
    auth = BridgeAuth(InferenceConfig(oidc_issuer=issuer))
    with pytest.raises(TokenError):
        auth.verify(f"Bearer {mint(iss='https://evil.example')}")


# --------------------------------------------------------------------------- proxy


def test_proxy_requires_auth_then_forwards():
    captured = {}

    def upstream(request: httpx2.Request) -> httpx2.Response:
        captured["path"] = request.url.path
        captured["auth_forwarded"] = "authorization" in {k.lower() for k in request.headers}
        return httpx2.Response(200, json={"id": "chatcmpl-1"})

    cfg = InferenceConfig(base_url="http://ollama.local:11434/v1")
    client = httpx2.Client(base_url="http://ollama.local:11434", transport=httpx2.MockTransport(upstream))
    app = build_app(cfg, static_token="tok", client=client)
    tc = TestClient(app)

    # unauthorized
    assert tc.post("/v1/chat/completions", json={"model": "x"}).status_code == 401
    # health needs no auth
    assert tc.get("/healthz").json()["ok"] is True
    # authorized → forwarded to upstream, Authorization stripped before upstream
    r = tc.post("/v1/chat/completions", json={"model": "x"}, headers={"Authorization": "Bearer tok"})
    assert r.status_code == 200 and r.json()["id"] == "chatcmpl-1"
    assert captured["path"] == "/v1/chat/completions"
    assert captured["auth_forwarded"] is False


# --------------------------------------------------------------------------- invariant


def test_sandbox_contract_runs_code_only():
    """A sandbox executes code; it must expose no inference/model capability. This is the structural
    guarantee behind 'code is generated locally, only code runs in the sandbox'."""
    from qudisclose.security.sandbox import SandboxBackend

    methods = {m for m in dir(SandboxBackend) if not m.startswith("_")}
    # revision/checkout joined the contract for VSLA-P-4 (re-execute at the subject revision); both are git operations, still code-only
    assert methods == {"create", "destroy", "run", "read", "write", "apply_diff", "commit", "diff", "tree", "revision", "checkout"}
    assert not any(k in m for m in methods for k in ("model", "infer", "complete", "generate", "prompt"))
