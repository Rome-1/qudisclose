"""Environment-pillar adapters (VSLA-F-15..17, VSLA-P-8).

An attestor produces the `environment` section (type, measurement, measures, rootOfTrust, enclaveKey, quote) and the
`enclave:` signature; a verifier checks the quote against a pinned root of trust and asks whether it binds exactly the
`binding` derived from the statement: {enclaveKey, harness, weights[], sandbox}. Shipped here:

  NoEnvironment          declares nothing; the Environment pillar stops at L2 (the honest default).
  SignedQuoteEnvironment the spec's `signed-quote` reference form: the quote is an Ed25519 signature by a pinned root key
                         over `quote_body(env, binding)`. It proves only that the root's key signed these bindings; it
                         stands in for a hardware quote so the procedure can be exercised. two-operator co-signers supply one
                         signature each over the same body, `;`-joined, and MUST be at least two distinct pinned roots.

Hardware adapters (SEV-SNP, TDX, Nitro) are vendor-library integrations and are deliberately NOT claimed here; a
statement naming one of those types verifies no higher than L2 in this verifier. Hardware adapters derive REPORT_DATA /
REPORTDATA / user_data as SHA-256 of `quote_body`."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Protocol

from qudisclose.security.keys import Identity
from qudisclose.vsla.canonical import canonical
from qudisclose.vsla.keyring import Keyring

REQUIRED_MEASURES = ("weights", "harness", "policy", "sandbox", "signingKey")


def quote_body(env: dict[str, Any], binding: dict[str, Any]) -> bytes:
    """Identical to the reference verifier's `quote_body`: what a root of trust signs in the signed-quote form."""
    return canonical({"type": env.get("type"), "measurement": env.get("measurement"), "measures": sorted(env.get("measures", [])),
                      "enclaveKey": binding.get("enclaveKey"), "harness": binding.get("harness"), "weights": sorted(binding.get("weights", [])),
                      "sandbox": binding.get("sandbox")})


class EnvironmentAttestor(Protocol):
    def evidence(self, enclave: Identity, binding: dict[str, Any]) -> dict[str, Any] | None: ...
    def verify(self, env: dict[str, Any], binding: dict[str, Any], roots: Keyring) -> bool: ...


class NoEnvironment:
    def evidence(self, enclave: Identity, binding: dict[str, Any]) -> dict[str, Any] | None:
        return None

    def verify(self, env: dict[str, Any], binding: dict[str, Any], roots: Keyring) -> bool:
        return verify_signed_quote(env, binding, roots)


class SignedQuoteEnvironment:
    """Reads an evidence file: {"type", "measurement", "measures", "rootOfTrust", "rootKey"?: <identity json with the
    root's private key>, "coSigners"?, "quote"?}. With `rootKey` the quote is produced per statement over the exact
    binding (enclave key, harness, weights, sandbox); without it a pre-produced `quote` is carried as-is and will
    verify only if it was made over the same binding. The file is written by whatever attests the host (a launcher,
    a test); qudisclose only carries it."""

    def __init__(self, evidence_path: str | Path) -> None:
        self.path = Path(evidence_path)

    def evidence(self, enclave: Identity, binding: dict[str, Any]) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        spec = json.loads(self.path.read_text())
        if spec.get("type", "none") == "none":
            return None
        env = {k: spec[k] for k in ("type", "measurement", "measures", "rootOfTrust", "coSigners") if k in spec}
        env["enclaveKey"] = f"ed25519:{enclave.public_hex}"
        bound = {**binding, "enclaveKey": enclave.public_hex}
        root_key = spec.get("rootKey")
        if root_key:
            paths = root_key if isinstance(root_key, list) else [root_key]
            keys = [Identity.load((self.path.parent / p) if not Path(p).is_absolute() else p) for p in paths]
            env["quote"] = ";".join(base64.b64encode(k.sign(quote_body(env, bound))).decode() for k in keys)
        elif spec.get("quote"):
            env["quote"] = spec["quote"]
        else:
            return None
        return env

    def verify(self, env: dict[str, Any], binding: dict[str, Any], roots: Keyring) -> bool:
        return verify_signed_quote(env, binding, roots)


def verify_signed_quote(env: dict[str, Any], binding: dict[str, Any], roots: Keyring) -> bool:
    """The reference environment adapter: True iff the pinned root key(s) signed `quote_body(env, binding)`. A two-operator
    quote needs at least two distinct co-signers, or "neither operator alone" is one operator twice."""
    try:
        body = quote_body(env, binding)
        if env.get("type") == "two-operator":
            cos = [str(c) for c in env.get("coSigners", [])]
            if len(cos) < 2 or len(set(cos)) != len(cos):
                return False
            keys = [roots.get(f"root:{c}") for c in cos]
            sigs = [s for s in (env.get("quote") or "").split(";") if s]
        else:
            keys = [roots.get(f"root:{env.get('rootOfTrust')}")]
            sigs = [env.get("quote")]
        if not sigs or not keys or any(k is None for k in keys) or len(sigs) != len(keys):
            return False
        return all(k.verify(base64.b64decode(s), body) for s, k in zip(sigs, keys, strict=True))  # type: ignore[union-attr]
    except Exception:
        return False


def make_signed_quote(*, root: Identity, enclave: Identity, measurement_hex: str, binding: dict[str, Any], env_type: str = "signed-quote",
                      measures: tuple[str, ...] = REQUIRED_MEASURES, root_name: str = "test-root") -> dict[str, Any]:
    """Produce reference-form evidence bound to `binding` ({harness, weights[], sandbox}); used by tests and a two-operator launcher."""
    env = {"type": env_type, "measurement": {"algorithm": "sha384", "value": measurement_hex}, "measures": list(measures), "rootOfTrust": root_name,
           "enclaveKey": f"ed25519:{enclave.public_hex}"}
    env["quote"] = base64.b64encode(root.sign(quote_body(env, {**binding, "enclaveKey": enclave.public_hex}))).decode()
    return env
