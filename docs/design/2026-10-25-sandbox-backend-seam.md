# Sandbox backend seam — run qudisclose's execution isolation in a Quome sandbox

**Date:** 2026-10-25
**Status:** Implemented
**Author:** Jim Schwoebel + Claude

## Problem

qudisclose runs untrusted code in two places: the reproducer/patcher agents (orchestrator) and
the always-on hunter. Both go through one class, `security/sandbox.py:Sandbox`, which isolates with
a git worktree, a scrubbed env, `rlimit`s and `unshare -n`. That is fine for a single trusted box,
but it is the weakest link once we run model-written tests and proof-of-concept exploits at volume:
`unshare -n` is Linux-only (a no-op on the macOS dev/Mac-Studio hosts), and there is no VM boundary,
no egress killswitch, no east-west guard.

Quome already provides exactly that isolation as a product: per-tenant sandbox
VMs with an egress killswitch, east-west guard, metadata-token guard, and a git credential broker,
and a self-hosted sandbox-compute path so source never leaves our hardware. We want qudisclose to be
able to run its sandbox step **in a Quome sandbox**, while keeping the zero-dependency local path for
dev and tests.

## Design

### 1. Extract the contract (`SandboxBackend`)

The orchestrator and hunter only ever call nine methods:

```
create() · destroy() · run(argv, timeout=) -> SandboxResult
read(rel) · write(rel, content) · apply_diff(diff) -> SandboxResult
commit(msg) · diff() -> str · tree(max_files=) -> list[str]
```

No caller reaches into `.path` or assumes a local filesystem. These nine become a
`typing.Protocol` named `SandboxBackend`. `SandboxResult` and `is_security_failure()` are unchanged
and shared by every backend.

Today's class is renamed `LocalSandbox` and implements the Protocol with its body unchanged.
`Sandbox = LocalSandbox` stays as an alias so existing imports and tests keep working.

### 2. Factory

```python
make_sandbox(case_id, *, repo_path, config: SandboxConfig | None) -> SandboxBackend
```

`config.backend` selects `"local"` (default) or `"quome"`. The three construction sites
(`orchestrator.py` ×2, `hunter.py` ×1) call the factory instead of `Sandbox(...)` directly. This is
the only behavioural change to existing code; with the default config it is a no-op.

### 3. `QuomeSandbox` (new, behind the Protocol)

`security/quome_sandbox.py` implements the same nine methods over the **official Quome Python SDK**
(`quome`, https://github.com/quome-cloud/quome-sdk-python), an optional dependency (`qudisclose[quome]`):

| Method | How (SDK) |
|--------|-----------|
| `create()` | `quome.Sandbox.create(template)` (or `Sandbox.get(id)` to attach to an existing sandbox), then seed the repo: tar the local checkout, `sbx.files.write(archive, bytes)`, untar into the case workdir with one `run(["tar", ...])`. |
| `run(argv)` | `sbx.run(shlex.join(argv), timeout=, working_dir=)` → `ExecResult{exit_code, stdout, stderr}`, mapped to `SandboxResult`. |
| `write`/`read` | `sbx.files.write` / `sbx.files.read`. |
| `apply_diff`/`commit`/`diff`/`tree` | run `git`/`find` **inside** the sandbox via `run(...)` — the local bodies already shell out, so the logic moves server-side almost verbatim. |
| `destroy()` | `sbx.delete()` when we created it; when attached to a shared sandbox (`quome_sandbox_id`), leave it and just remove the case workdir. |

Each case gets an isolated workdir `/workspace/qudisclose/<case_id>/<repo_subdir>`, so one long-lived
sandbox can serve many cases without collisions. Isolation (egress killswitch, east-west guard,
metadata guard, resource limits) is provided by Quome, so this backend carries none of the
`unshare`/`rlimit`/proxy-poisoning logic.

**Repo seeding = tarball upload** (decided): qudisclose tars the local checkout and writes it in. Works
for any repo including non-git and private checkouts, puts no credentials in the sandbox, and matches
the "source stays on our hardware" model. (Broker-clone is a possible future opt-in, not built here.)

Auth follows the SDK: `QUOME_API_KEY` (env name configurable), optional `QUOME_BASE_URL`/`QUOME_ORG_ID`.

### 4. No Quome platform change needed

An earlier draft of this design assumed `run(argv)` needed a new `POST /sandboxes/{id}/exec` endpoint,
because the only *general* exec I found in the raw API was the `/exec/stream` WebSocket (slated for
sunset). That was wrong: Quome already exposes request/response exec (sync `/exec` and an async
`/exec/{job_id}` job), and the official SDK wraps both — `sbx.run(...)` returns a real `exit_code`. So
`QuomeSandbox` builds on the SDK and needs no server change. The live path only needs credentials.

### 5. Tests

- `LocalSandbox` keeps every existing test (now exercised through the Protocol).
- A backend **contract test** runs `QuomeSandbox` against a fake `quome.Sandbox` backed by a real temp
  directory (create → seed → run → read/write → diff/commit → destroy), exercising real git/tar and
  path confinement, and the create-vs-attach delete behaviour. No live cluster in CI.
- A factory test asserts `"local"` → `LocalSandbox` and `"quome"` → `QuomeSandbox`.
- A live run is opt-in: `QUOME_API_KEY` (+ optionally `sandbox.quome_sandbox_id` to attach).

## Non-goals

- Replacing the local backend. It stays the default and the test path.
- Importing anything from the Quome platform. qudisclose talks to Quome over its public HTTP API only and
  remains standalone.
- Broker-based repo clone, confidential-tier selection, multi-sandbox pooling — future work.
