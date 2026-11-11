"""
File-reading tools for the Gap Finder developer agent.
All paths are resolved relative to repo_root.
"""

import os
import subprocess
from pathlib import Path

_repo_root: Path | None = None


def set_repo_root(path: str) -> None:
    global _repo_root
    _repo_root = Path(path).resolve()


def _resolve(path: str) -> Path:
    if _repo_root is None:
        raise RuntimeError("repo_root not set — call set_repo_root() first")
    p = Path(path)
    if p.is_absolute():
        resolved = p
    else:
        resolved = (_repo_root / p).resolve()
    # Security: must stay inside repo_root
    try:
        resolved.relative_to(_repo_root)
    except ValueError:
        raise PermissionError(f"Path escapes repo root: {resolved}")
    return resolved


def read_file(path: str, start_line: int = 1, end_line: int | None = None) -> str:
    """
    Read a file (optionally a line range).
    Returns content with 1-indexed line numbers prefixed.
    """
    p = _resolve(path)
    if not p.exists():
        return f"[read_file] File not found: {path}"
    if not p.is_file():
        return f"[read_file] Not a file: {path}"
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception as e:
        return f"[read_file] Error reading {path}: {e}"

    start = max(1, start_line)
    end = len(lines) if end_line is None else min(end_line, len(lines))
    selected = lines[start - 1 : end]
    output = "\n".join(f"{start + i:>5}: {line}" for i, line in enumerate(selected))
    if len(output) > 20000:
        output = output[:20000] + "\n... [truncated]"
    return output


def list_dir(path: str = ".") -> str:
    """List files and directories in path (non-recursive, relative to repo_root)."""
    p = _resolve(path)
    if not p.exists():
        return f"[list_dir] Path not found: {path}"
    if not p.is_dir():
        return f"[list_dir] Not a directory: {path}"
    entries = []
    for item in sorted(p.iterdir()):
        rel = item.relative_to(_repo_root)
        kind = "dir" if item.is_dir() else "file"
        entries.append(f"{kind}  {rel}")
    return "\n".join(entries) if entries else "(empty directory)"


def search_code(query: str, file_pattern: str = "*.go", path: str = ".") -> str:
    """
    Search for a text pattern in files matching file_pattern under path.
    Uses grep; returns matching lines with file:line references.
    """
    base = _resolve(path)
    try:
        result = subprocess.run(
            ["grep", "-rn", "--include", file_pattern, "-m", "30", query, str(base)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        if not output:
            return f"[search_code] No matches for {query!r} in {path} ({file_pattern})"
        # Make paths relative to repo_root
        lines = []
        for line in output.splitlines():
            if line.startswith(str(base)):
                line = str(Path(line[len(str(base)):]).relative_to("/"))
            lines.append(line)
        return "\n".join(lines[:100])
    except subprocess.TimeoutExpired:
        return "[search_code] Timeout"
    except Exception as e:
        return f"[search_code] Error: {e}"
