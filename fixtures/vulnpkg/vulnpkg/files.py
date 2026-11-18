"""Serve files from a per-user storage directory."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_path(storage_root: str | os.PathLike[str], user_path: str) -> Path:
    """Map a user-supplied relative path to a location under storage_root."""
    return Path(storage_root) / user_path


def read_user_file(storage_root: str | os.PathLike[str], user_path: str) -> bytes:
    return resolve_path(storage_root, user_path).read_bytes()
