"""
Lifecycle applicability assessment — multi-signal, mechanism-first. No LLM call.

Scores 7 signals across: dos_class, hypothesis description, assumptions,
suspected_mechanism YAML block, Gap Finder findings, ExploitPlan expected_effect,
and ExploitPlan step frames. dos_class is supporting evidence only, never a gate.

Decision rules:
  score >= 2.0  →  "applicable"   (run lifecycle tests, results are reliable)
  score >= 1.0  →  "uncertain"    (run lifecycle tests, flag limited confidence)
  score <  1.0  →  "not_applicable"

Also builds the LifecycleValidationPlan when decision != "not_applicable".
"""

import re
import socket
from typing import Optional

from lifecycle.model import (
    LifecycleApplicability,
    LifecycleValidationPlan,
    LifecycleMode,
)

# ── keyword patterns ──────────────────────────────────────────────────────────

_ACCUMULATION_RE = re.compile(
    r"\b(retain|accumulate|goroutine|leak|linger|cleanup|cancel|mid.?flight|"
    r"abandon|partial|unreleased|pool|backpressure|outstanding|pending|"
    r"resource.?exhaust|not.?release|never.?free|keep.?alive)\b",
    re.IGNORECASE,
)

_CANCEL_MECHANISM_RE = re.compile(
    r"\b(cancel|reset|abort|mid.?flight|partial|incomplete|abandon|"
    r"RESET_STREAM|RST_STREAM|context.?cancel|context\.Canceled|"
    r"early.?terminat|premature)\b",
    re.IGNORECASE,
)

_CANCEL_FRAME_RE = re.compile(
    r"\b(RESET_STREAM|RST_STREAM|CANCEL|GOAWAY|RST|STOP_SENDING)\b",
    re.IGNORECASE,
)

_RETENTION_EFFECT_RE = re.compile(
    r"\b(retain|goroutine|leak|accumulate|exhaust|hold|unbounded|unlimited|"
    r"never.?release|not.?clean|not.?free|linger|pile.?up|build.?up)\b",
    re.IGNORECASE,
)


# ── public API ────────────────────────────────────────────────────────────────

def assess(ctx, findings: list = None, plan=None) -> LifecycleApplicability:
    """
    Multi-signal applicability assessment.

    ctx     — HypothesisContext (description, dos_class, assumptions, suspected_mechanism)
    findings — list[ComplianceGap | SecurityDesignGap | ImplementationInvariantViolation]
    plan    — ExploitPlan | None
    """
    findings = findings or []
    score = 0.0
    signals: list[str] = []

    # Signal 1 — dos_class: resource_exhaustion or resource_starvation (+1.0)
    if ctx.dos_class in ("resource_exhaustion", "resource_starvation"):
        score += 1.0
        signals.append(f"dos_class={ctx.dos_class!r} indicates resource retention is plausible")

    # Signal 2 — description: accumulation keywords (+1.0)
    desc_matches = _ACCUMULATION_RE.findall(ctx.description)
    if desc_matches:
        score += 1.0
        kws = ", ".join(dict.fromkeys(m.lower() for m in desc_matches[:4]))
        signals.append(f"description contains accumulation keywords ({kws})")

    # Signal 3 — assumptions: cancel/mid-flight patterns (+0.5 each, max 1.0)
    assumption_score = 0.0
    for a in ctx.assumptions:
        if _CANCEL_MECHANISM_RE.search(a.description):
            assumption_score = min(assumption_score + 0.5, 1.0)
            if assumption_score <= 0.5:
                signals.append(
                    f"assumption {a.id!r} describes cancel/mid-flight: "
                    f"{a.description[:70]!r}"
                )
    score += assumption_score

    # Signal 4 — suspected_mechanism: cancel patterns (+0.5 each, max 1.0)
    mech_score = 0.0
    for step in getattr(ctx, "suspected_mechanism", []):
        action = step.get("action", "") if isinstance(step, dict) else str(step)
        if _CANCEL_MECHANISM_RE.search(action):
            mech_score = min(mech_score + 0.5, 1.0)
            if mech_score <= 0.5:
                signals.append(
                    f"suspected_mechanism step {step.get('step', '?') if isinstance(step, dict) else '?'} "
                    f"describes cancel pattern: {action[:70]!r}"
                )
    score += mech_score

    # Signal 5 — Gap Finder findings: retention/cleanup description (+1.0, first match only)
    for f in findings:
        gap_text = ""
        if hasattr(f, "gap_description"):
            gap_text = f.gap_description
        elif hasattr(f, "invariant_description"):
            gap_text = f.invariant_description
        # Also check the RFC requirement dos_mechanism field
        req_text = getattr(getattr(f, "requirement", None), "dos_mechanism", "") or ""
        combined = f"{gap_text} {req_text}"
        if combined.strip() and _ACCUMULATION_RE.search(combined):
            score += 1.0
            signals.append(
                f"{type(f).__name__} finding at {getattr(f, 'code_location', '?')} "
                f"references retention/cleanup: {combined[:70]!r}"
            )
            break

    # Signal 6 — ExploitPlan expected_effect: retention keywords (+1.0)
    if plan:
        effect = plan.expected_effect or ""
        if _RETENTION_EFFECT_RE.search(effect):
            score += 1.0
            signals.append(
                f"exploit expected_effect describes retention: {effect[:70]!r}"
            )

    # Signal 7 — ExploitPlan steps: cancel/reset frames (+0.5, first match only)
    if plan:
        for step in plan.attack_sequence:
            frame = step.quic_frame or ""
            if _CANCEL_FRAME_RE.search(frame):
                score += 0.5
                signals.append(
                    f"exploit step {step.n} uses cancel/reset frame: {frame[:50]!r}"
                )
                break

    # ── decision ──────────────────────────────────────────────────────────────
    if score >= 2.0:
        decision = "applicable"
    elif score >= 1.0:
        decision = "uncertain"
    else:
        decision = "not_applicable"

    reasoning = (
        f"score={score:.1f} from {len(signals)} signal(s) → {decision}. "
        + ("; ".join(signals[:3]) if signals else "No accumulation signals found.")
    )

    return LifecycleApplicability(
        decision=decision,
        score=score,
        signals=signals,
        reasoning=reasoning,
    )


def _find_free_port(retries: int = 10, low: int = 40000, high: int = 59999) -> int:
    """Return an available TCP port in [low, high].

    Uses a bind-and-release approach.  The returned port is free at the time of
    return but may be claimed before the caller binds it (inherent TOCTOU).
    Using a randomised range in the ephemeral zone reduces collision probability
    compared to relying on OS port 0 assignment from a low base.
    Multiple retries handle the rare collision window.
    """
    import random
    for _ in range(retries):
        port = random.randint(low, high)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    # Fallback: let OS pick a port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_plan(
    ctx,
    applicability: LifecycleApplicability,
    lifecycle_port: int = 9444,
    sidecar_port: Optional[int] = None,
) -> LifecycleValidationPlan:
    if sidecar_port is None:
        sidecar_port = _find_free_port()
    """
    Build a LifecycleValidationPlan for a hypothesis that passed the applicability gate.

    processing_duration_s is chosen so cancel scenarios C and D definitely reach the
    backend (Caddy dispatch latency is typically < 20ms, so 0.5s processing gives ample
    margin). batch_count=3 gives enough samples for trend detection without taking too long.
    """
    processing_duration_s = 0.5

    observability_limitations = [
        "Transport layer (quic-go): UNOBSERVABLE from outside — "
        "internal stream/flow-control state cannot be measured.",
        "Proxy layer (Caddy): partially observable via pprof goroutine count "
        "if admin API is reachable on port 2020; falls back to UNOBSERVABLE.",
        "Backend layer: fully observable via instrumented sidecar (cleanup_pending, "
        "active, completed, cancelled counters).",
    ]

    # Event-driven cancel_timing:
    #   wait_for_start=True  → client waits for backend "STARTED" chunk before cancelling
    #   cancel_delay=None    → complete normally (no RESET_STREAM)
    #   cancel_delay=0.0     → cancel immediately on start signal
    #   cancel_delay=0.3     → cancel 300ms after start signal (Scenario D: late cancel)
    #
    # Scenario B uses wait_for_start=False so the cancel fires before Caddy dispatches.
    cancel_timing = {
        "A": {"wait_for_start": False, "cancel_delay": None},   # complete normally
        "B": {"wait_for_start": False, "cancel_delay": 0.0},    # cancel before dispatch
        "C": {"wait_for_start": True,  "cancel_delay": 0.0},    # cancel on start signal
        "D": {"wait_for_start": True,  "cancel_delay": 0.3},    # cancel 300ms after start
    }

    matched_control = (
        "20 ops/batch completing normally (Scenario A: no RESET_STREAM, "
        "full backend processing, event-driven completion)."
    )

    return LifecycleValidationPlan(
        scenarios=["A", "B", "C", "D"],
        primary_metrics=["cleanup_pending", "proxy_goroutines"],
        observability_limitations=observability_limitations,
        processing_duration_s=processing_duration_s,
        cancel_timing=cancel_timing,
        ops_per_batch=20,
        batch_count=3,
        recovery_wait_s=10.0,
        matched_control=matched_control,
        lifecycle_port=lifecycle_port,
        sidecar_port=sidecar_port,
    )
