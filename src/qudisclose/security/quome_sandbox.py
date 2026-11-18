"""`SandboxBackend` implementation that runs a case inside a Quome sandbox VM, via the official
Quome Python SDK (https://github.com/quome-cloud/quome-sdk-python).

Same nine-method contract as `LocalSandbox`, but the isolation (egress killswitch, east-west guard,
metadata guard, resource limits) is provided by Quome, so this backend carries none of the
`unshare`/`rlimit`/proxy logic. The repo is seeded by tarball upload (the local checkout is tarred,
written into the sandbox and untarred under the case workdir); git operations run *inside* the sandbox
via `run(...)`. See docs/design/2026-10-25-sandbox-backend-seam.md.

Each case gets an isolated workdir `/workspace/qudisclose/<case_id>/<repo_subdir>`, so one long-lived
sandbox (attach mode, `quome_sandbox_id`) can serve many cases without collisions. In create mode the
sandbox is deleted on `destroy()`; in attach mode only the case workdir is removed.
"""

from __future__ import annotations

import base64
import io
import os
import posixpath
import shlex
import tarfile
from pathlib import Path
from typing import Any

from qudisclose.config import SandboxConfig
from qudisclose.security.sandbox import SandboxResult

_GIT = ["git", "-c", "user.name=qudisclose", "-c", "user.email=qudisclose@localhost"]
# Dirs never worth streaming into the sandbox: VCS, virtualenvs, caches, build output, vendored deps
# and documentation. Seeding goes over exec one <10k-char chunk at a time, so a big docs/ tree turns
# into hundreds of round-trips that can swamp the sandbox — and the hunter never targets these anyway.
# Keep this in sync with hunter.SKIP_DIRS so target selection can't pick a file we don't seed.
_SEED_EXCLUDE = {".git", ".venv", "venv", "__pycache__", ".qudisclose-sandboxes", "node_modules",
                 "dist", "build", "target", "vendor", "docs", "doc", "site",
                 ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".idea", ".vscode"}

# Quome's /exec caps the `command` field at 10_000 chars, so any base64 payload bigger than that
# (a real repo tarball, a large file write, a big diff) is streamed to a file in chunks rather than
# inlined in a single command. Headroom below 10_000 covers the `cd <workdir> && (...)` wrapper and
# the `printf %s '<chunk>' >> '<path>'` scaffolding `_put_b64` adds around each chunk.
_EXEC_CHUNK = 8_000


def _build_client(cfg: SandboxConfig) -> Any:
    import quome

    api_key = os.environ.get(cfg.quome_api_key_env)
    if cfg.quome_org_id:
        os.environ.setdefault("QUOME_ORG_ID", cfg.quome_org_id)
    return quome.Quome(api_key=api_key, base_url=cfg.quome_base_url)


class QuomeSandbox:
    def __init__(self, repo: Path, *, case_id: str, config: SandboxConfig, sandbox: Any = None) -> None:
        self.repo = Path(repo).resolve()
        self.case_id = case_id
        self.config = config
        self.workdir = f"/workspace/qudisclose/{case_id}/{config.repo_subdir}"
        self._sbx = sandbox                # an injected quome.Sandbox (tests); else built in create()
        self._created = False              # True if we created it (and so must delete it on destroy)

    # -- lifecycle

    def create(self) -> str:
        if self._sbx is None:
            import quome

            client = _build_client(self.config)
            if self.config.quome_sandbox_id:
                self._sbx = quome.Sandbox.get(self.config.quome_sandbox_id, client=client)
            else:
                self._sbx = quome.Sandbox.create(self.config.quome_template, client=client,
                                                  timeout=self.config.create_timeout_seconds)
                self._created = True
        self._seed_repo()  # _sh wraps every command with `mkdir -p <workdir> && cd <workdir>`
        # Fresh baseline commit so diff()/apply_diff()/commit() work uniformly (mirrors LocalSandbox's
        # non-git path); .git is excluded from the tarball, so history never leaves our host.
        self.run([*_GIT, "init", "-q"])
        # Keep build/test noise (e.g. __pycache__/*.pyc created when the patcher runs pytest) out of git,
        # so diff() never captures binary bytecode that then breaks `git apply` during verification. Uses
        # .git/info/exclude (untracked) so no .gitignore shows up in the diff either.
        self._sh("printf '%s\\n' '__pycache__/' '*.py[cod]' '.pytest_cache/' '.mypy_cache/' '.ruff_cache/' "
                 "'*.egg-info/' '.coverage' '*.so' > .git/info/exclude")
        self.run([*_GIT, "add", "-A"])
        self.run([*_GIT, "commit", "-q", "-m", "baseline", "--no-gpg-sign"])
        return str(self._sbx.id)

    def _seed_repo(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for p in sorted(self.repo.rglob("*")):
                rel = p.relative_to(self.repo)
                if any(part in _SEED_EXCLUDE for part in rel.parts):
                    continue
                if p.is_file() or p.is_dir():
                    tar.add(p, arcname=str(rel), recursive=False)
        # Stream the tarball in over exec (base64 | tar). We go through `run` rather than the SDK's
        # files endpoint because exec is the one capability every deployment supports; the file upload
        # endpoint 400s on some. Fine for ordinary repos; a very large tree may need chunking.
        b64 = base64.b64encode(buf.getvalue()).decode()
        seed = ".qd-seed.tar.b64"  # relative to the workdir (cwd)
        r = self._put_b64(b64, seed)
        if r.returncode == 0:
            r = self._sh(f"base64 -d < {shlex.quote(seed)} | tar -xzf - -C . && rm -f {shlex.quote(seed)}")
        if r.returncode != 0:
            raise RuntimeError(f"seed untar failed: {r.excerpt(500)}")

    def destroy(self) -> None:
        if self._sbx is None:
            return
        try:
            if self._created:
                self._sbx.delete()
            else:  # attached to a shared sandbox — leave it, just drop this case's files
                self.run(["rm", "-rf", f"/workspace/qudisclose/{self.case_id}"])
        finally:
            self._sbx = None

    # -- execution

    def run(self, argv: list[str], *, timeout: int | None = None) -> SandboxResult:
        return self._sh(shlex.join(argv), timeout=timeout)

    def _sh(self, command: str, *, timeout: int | None = None) -> SandboxResult:
        """Run a shell command string in the case workdir and map it to a SandboxResult.

        The command is wrapped so the workdir always exists and is the cwd — we do NOT rely on the
        server honouring `working_dir` (some deployments ignore it and run from /workspace)."""
        from quome import SandboxNotRunningError

        q = shlex.quote(self.workdir)
        wrapped = f"mkdir -p {q} && cd {q} && ( {command} )"
        t = timeout or self.config.exec_timeout_seconds
        try:
            res = self._sbx.run(wrapped, timeout=t, working_dir=self.workdir)
        except TimeoutError:
            return SandboxResult(returncode=-1, stdout="", stderr="timed out", timed_out=True)
        except SandboxNotRunningError as exc:
            return SandboxResult(returncode=-1, stdout="", stderr=f"sandbox not running: {exc}")
        code = res.exit_code if res.exit_code is not None else -1
        return SandboxResult(returncode=code, stdout=(res.stdout or "")[-200_000:],
                             stderr=(res.stderr or "")[-200_000:], timed_out=(code == 124))

    def _put_b64(self, b64: str, dest: str) -> SandboxResult:
        """Write a base64 string to `dest` (a path in the sandbox) over exec, in `_EXEC_CHUNK`-sized
        pieces so no single command exceeds Quome's 10_000-char cap. The first write truncates and the
        rest append, so an empty payload still yields an empty file. The caller decodes `dest`."""
        q = shlex.quote(dest)
        r = self._sh(f": > {q}")  # truncate (also creates the file for an empty payload)
        for i in range(0, len(b64), _EXEC_CHUNK):
            if r.returncode != 0:
                break
            r = self._sh(f"printf %s {shlex.quote(b64[i:i + _EXEC_CHUNK])} >> {q}")
        return r

    # -- file helpers (paths are confined to the case workdir; writes/reads go over exec)

    def _confine(self, rel: str) -> str:
        norm = posixpath.normpath(rel)
        if norm.startswith("/") or norm == ".." or norm.startswith("../"):
            raise PermissionError(f"path escapes sandbox: {rel}")
        return posixpath.join(self.workdir, norm)

    def read(self, rel: str) -> str:
        path = self._confine(rel)  # may raise PermissionError — must not be masked as FileNotFoundError
        r = self._sh(f"cat {shlex.quote(path)}")
        if r.returncode != 0:
            raise FileNotFoundError(rel)
        return r.stdout

    def write(self, rel: str, content: str) -> None:
        path = self._confine(rel)
        b64 = base64.b64encode(content.encode()).decode()
        tmp = f"{path}.qd.b64"
        r = self._sh(f"mkdir -p {shlex.quote(posixpath.dirname(path))}")
        if r.returncode == 0:
            r = self._put_b64(b64, tmp)
        if r.returncode == 0:
            r = self._sh(f"base64 -d < {shlex.quote(tmp)} > {shlex.quote(path)} && rm -f {shlex.quote(tmp)}")
        if r.returncode != 0:
            raise RuntimeError(f"write {rel} failed: {r.excerpt(300)}")

    def apply_diff(self, diff: str) -> SandboxResult:
        b64 = base64.b64encode(diff.encode()).decode()
        patch = ".qd-diff.patch"  # a big diff would also blow the 10_000-char command cap if inlined
        put = self._put_b64(b64, patch)
        if put.returncode != 0:
            return put
        q = shlex.quote(patch)
        self._sh(f"base64 -d < {q} > {q}.decoded")
        r = self._sh(f"git apply --whitespace=nowarn {q}.decoded")
        if r.returncode != 0:
            r = self._sh(f"patch -p1 --forward --batch < {q}.decoded")
        self._sh(f"rm -f {q} {q}.decoded")
        return r

    def commit(self, message: str) -> None:
        self.run([*_GIT, "add", "-A"])
        self.run([*_GIT, "commit", "-q", "--allow-empty", "-m", message, "--no-gpg-sign"])

    def revision(self) -> str:
        """VSLA subject[1]. The tarball is seeded without `.git`, so the sandbox's own baseline commit names nothing
        anyone else can resolve; when the local checkout is a clean git tree the seeded files ARE its HEAD, so that is
        the revision reported. A dirty checkout reports the sandbox baseline (honest: unresolvable by others)."""
        local = self._local_head()
        if local:
            return local
        return self.run(["git", "rev-parse", "HEAD"]).stdout.strip() or "unknown"

    def _local_head(self) -> str | None:
        import subprocess
        if not (self.repo / ".git").exists():
            return None
        head = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True, text=True)
        dirty = subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True)
        if head.returncode != 0 or dirty.stdout.strip():
            return None
        return head.stdout.strip() or None

    def checkout(self, revision: str) -> bool:
        """The sandbox holds no history, so a revision is available only when it is what was seeded: the local
        checkout's clean HEAD. Anything else is `environment-error` for the receipt."""
        local = self._local_head()
        return bool(local) and bool(revision) and local.startswith(revision)

    def diff(self) -> str:
        self.run(["git", "add", "-N", "."])
        return self.run(["git", "diff"]).stdout

    def tree(self, max_files: int = 400) -> list[str]:
        r = self.run(["find", ".", "-type", "f", "-not", "-path", "*/.*"])
        files = [ln[2:] if ln.startswith("./") else ln for ln in r.stdout.splitlines() if ln.strip()]
        return files[:max_files]

    def inject_inference(self, *, base_url: str, token: str, model: str) -> None:
        """Make the self-hosted model reachable from inside the sandbox by writing an OpenAI-compatible
        client config to `<workdir>/.qudisclose/inference.json`. `base_url` is the bridge's tunnel URL
        (…/v1) and `token` a short-lived bridge credential. The model never runs here — only code does;
        this is the authenticated hop back to your host."""
        import json

        self.write(".qudisclose/inference.json",
                   json.dumps({"base_url": base_url, "api_key": token, "model": model}))

    @property
    def sandbox_id(self) -> str | None:
        return str(self._sbx.id) if self._sbx is not None else None
