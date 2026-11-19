"""
Resource Lifecycle Validation — data models.

LifecycleMode:          how the lifecycle experiment is triggered (auto/enabled/disabled)
LifecycleOutcome:       result of the accumulation analysis
LifecycleApplicability: pre-run gate: should we run lifecycle tests for this hypothesis?
LifecycleValidationPlan: structured experiment specification (not an exploit callable)
RetentionSample:        per-scenario/per-batch metric snapshot with 3-phase breakdown
RecoverySample:         time-series sample taken during post-attack recovery window
LifecycleResult:        full result returned to hypogenie.py
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class LifecycleMode(Enum):
    AUTO = "auto"           # assess from hypothesis signals (default)
    ENABLED = "enabled"     # always run lifecycle tests
    DISABLED = "disabled"   # never run lifecycle tests


class LifecycleOutcome(Enum):
    NO_RESOURCE_RETENTION        = "NO_RESOURCE_RETENTION"
    BOUNDED_RETENTION            = "BOUNDED_RETENTION"
    RESOURCE_ACCUMULATION        = "RESOURCE_ACCUMULATION"
    CONFIRMED_RESOURCE_EXHAUSTION = "CONFIRMED_RESOURCE_EXHAUSTION"


@dataclass
class LifecycleApplicability:
    decision: str    # "applicable" | "uncertain" | "not_applicable"
    score: float     # sum of contributing signal weights
    signals: list[str]
    reasoning: str


@dataclass
class LifecycleValidationPlan:
    """
    Structured experiment specification — NOT a generic exploit_fn callable.

    cancel_timing maps scenario id → dict with keys:
      - wait_for_start: bool  — True = wait for backend "STARTED" signal before cancelling
      - cancel_delay: float | None — None = complete normally; 0 = cancel on start signal;
                                     >0 = cancel N seconds after start signal
    E.g.:
      {"A": {"wait_for_start": False, "cancel_delay": None},
       "B": {"wait_for_start": False, "cancel_delay": 0.0},   # cancel before dispatch
       "C": {"wait_for_start": True,  "cancel_delay": 0.0},   # cancel on start signal
       "D": {"wait_for_start": True,  "cancel_delay": 0.3}}   # cancel 300ms after start
    """
    scenarios: list[str]                   # e.g. ["A", "B", "C", "D"]
    primary_metrics: list[str]
    observability_limitations: list[str]
    processing_duration_s: float           # simulated backend work time
    cancel_timing: dict                    # {scenario: {wait_for_start, cancel_delay}}
    ops_per_batch: int
    batch_count: int
    recovery_wait_s: float
    matched_control: str
    lifecycle_port: int
    sidecar_port: int


@dataclass
class RetentionSample:
    """
    One metric snapshot — per-scenario per-batch reading from the backend sidecar.

    Three-phase lifecycle breakdown:
      context_cancelled  — sidecar detected connection drop (context.Done equivalent)
      op_terminated      — work loop exited (operation actually stopped)
      resource_released  — handler returned, resources freed
      outstanding_cleanups — ops currently live (started but not yet released);
                             decrements to 0 as cleanup completes
    """
    batch_num: int
    scenario: str
    # cumulative counters
    cleanup_pending: int          # alias for cancelled; kept for compat
    active_ops: int
    completed_ops: int
    cancelled_ops: int
    context_cancelled: int        # connection drop detected
    op_terminated: int            # work loop stopped
    resource_released: int        # handler returned, cleanup done
    outstanding_cleanups: int     # currently live (not yet released)
    proxy_goroutines: int         # -1 when proxy layer not observable
    timestamp_s: float


@dataclass
class RecoverySample:
    """
    One time-series sample taken during post-attack recovery window.
    Tracks how quickly outstanding operations drain back to baseline.
    """
    elapsed_s: float              # seconds since last attack batch ended
    outstanding_cleanups: int     # ops still live
    active_ops: int
    proxy_goroutines: int         # -1 if unobservable


@dataclass
class LifecycleResult:
    outcome: LifecycleOutcome
    backend_observable: bool          # sidecar always gives full backend visibility
    proxy_observable: bool            # True if pprof goroutine count was readable
    transport_observable: bool        # always False (quic-go internals unobservable)
    observability_limitations: list[str]
    batches: list[RetentionSample]       # attack scenario samples (C + D)
    control_batches: list[RetentionSample]
    recovery_samples: list[RecoverySample]  # time series during recovery window
    cleanup_pending_trend: list[int]     # cleanup_pending per attack batch
    proxy_goroutine_trend: list[int]     # goroutine count per batch (-1 if unobservable)
    recovery_observed: bool
    recovery_wait_s: float
    peak_cleanup_pending: int
    peak_outstanding_cleanups: int       # max concurrent live ops seen
    notes: str
