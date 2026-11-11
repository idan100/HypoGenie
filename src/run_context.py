"""
Run context — a UUID generated once per process invocation.
Import this module anywhere to get a stable run_id for the current run.

Usage:
    from run_context import run_id
    print(f"Run: {run_id}")   # e.g. "20260111-143022-a3f2"
"""

import uuid
from datetime import datetime

_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
_short = uuid.uuid4().hex[:4]
run_id: str = f"{_ts}-{_short}"
