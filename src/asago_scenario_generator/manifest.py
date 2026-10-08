"""Atomic artifact writes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_bytes(path: Path, content: bytes) -> Path:
    """Write bytes to *path* atomically using temp file + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, suffix=".tmp", prefix=path.name
    )
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        # Persist the directory entry as well as file contents.  Without this
        # fsync, a power loss after replace can lose the rename despite a
        # fully flushed temporary file.
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> Path:
    """Write text to *path* atomically using temp file + os.replace."""
    return atomic_write_bytes(path, content.encode(encoding))
