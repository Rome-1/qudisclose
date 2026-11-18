"""Sandbox-confined tools handed to the reproducer and patcher. Nothing here can reach outside the case's
worktree, and the only executable entry point is a command allowlist (no shell)."""

from __future__ import annotations

import shlex

from qudisclose.security.sandbox import SandboxBackend

ALLOWED_COMMANDS = frozenset({"python", "python3", "pytest", "uv", "npm", "pnpm", "yarn", "node", "go", "cargo",
                              "make", "ruby", "bundle", "mvn", "gradle", "dotnet"})


def sandbox_tools(sb: SandboxBackend, *, allow_write: bool) -> dict:
    def list_files(prefix: str = "") -> str:
        """List files in the repository (relative paths). `prefix` filters by path prefix."""
        files = [f for f in sb.tree() if f.startswith(prefix)]
        return "\n".join(files) or "(no files)"

    def read_file(path: str) -> str:
        """Read a file from the repository by relative path."""
        try:
            return sb.read(path)[:60_000]
        except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
            return f"ERROR: {e}"

    def run_command(command: str) -> str:
        """Run a test or build command inside the sandbox (no shell; first word must be an allowlisted program
        such as pytest, python, npm, go, cargo). Returns exit code and the last part of the output."""
        argv = shlex.split(command)
        if not argv or argv[0].rsplit("/", 1)[-1] not in ALLOWED_COMMANDS:
            return f"ERROR: command not allowed: {argv[:1]}"
        r = sb.run(argv)
        return f"exit={r.returncode} timed_out={r.timed_out}\n{r.excerpt()}"

    tools: dict = {"list_files": list_files, "read_file": read_file, "run_command": run_command}

    if allow_write:
        def write_file(path: str, content: str) -> str:
            """Create or overwrite a file (relative path) inside the repository."""
            try:
                sb.write(path, content)
                return f"wrote {path} ({len(content)} bytes)"
            except PermissionError as e:
                return f"ERROR: {e}"

        def apply_diff(diff: str) -> str:
            """Apply a unified diff (git format, paths relative to repo root) to the repository."""
            r = sb.apply_diff(diff)
            return f"exit={r.returncode}\n{r.excerpt()}"

        def current_diff() -> str:
            """Return the current uncommitted diff of the repository."""
            return sb.diff() or "(no changes)"

        tools.update({"write_file": write_file, "apply_diff": apply_diff, "current_diff": current_diff})
    return tools
