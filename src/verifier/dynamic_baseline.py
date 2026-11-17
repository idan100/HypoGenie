"""
Dynamic Baseline & Attribution Engine for HypoGenie DoS Verifier.

Implements hypothesis-aware resource attribution to prevent false CONFIRMED_DOS
verdicts caused by ordinary protocol processing, high throughput, transport
overhead, and environmental noise unrelated to the specific vulnerability
hypothesis.

Core principle: CONFIRMED_DOS requires BOTH
  1. Actual service/resource degradation (existing threshold checks).
  2. Causal attribution: the hypothesized behavior causes additional,
     measurable resource consumption compared with a valid, protocol-aware,
     workload-matched benign control.

A CPU spike alone is never sufficient evidence for CONFIRMED_DOS.
"""

from __future__ import annotations

import re
import math
from dataclasses import dataclass, field
from statistics import mean, stdev
from typing import Optional

# ── Attribution status constants ──────────────────────────────────────────────
ATTRIBUTED     = "ATTRIBUTED"
NOT_ATTRIBUTED = "NOT_ATTRIBUTED"
INCONCLUSIVE   = "INCONCLUSIVE"


# ── A. WorkloadProfile ────────────────────────────────────────────────────────

@dataclass
class WorkloadProfile:
    """
    Records the actual workload achieved during an experiment run.

    Fields are Optional so callers can distinguish 'measured zero' from
    'not measured'. Never set a field to 0 as a placeholder for unknown.
    """
    protocol: str = ""
    transport: str = ""
    duration_s: float = 0.0

    # Connection-level
    connections_total: Optional[int]   = None
    connections_per_second: Optional[float] = None
    concurrent_connections: Optional[int]   = None
    handshakes_per_second: Optional[float]  = None

    # Frame / message / operation level
    frames_total: Optional[int]       = None
    frames_per_second: Optional[float] = None
    messages_per_second: Optional[float] = None
    streams_per_second: Optional[float]  = None
    requests_per_second: Optional[float] = None

    # Throughput
    bytes_per_second: Optional[float] = None
    total_bytes: Optional[float]      = None

    # Size distributions
    avg_payload_size_bytes: Optional[float] = None
    avg_frame_size_bytes: Optional[float]   = None

    # Lifecycle
    avg_connection_lifetime_s: Optional[float] = None


# ── B. WorkloadExtractor ──────────────────────────────────────────────────────

class WorkloadExtractor:
    """
    Extracts WorkloadProfile from the metrics dict produced by MetricsCollector
    and exploit script stdout.

    Uses footer fields (_connections_attempted, _avg_lifetime_s, etc.) and
    stdout patterns. Never fabricates values — missing dimensions stay None.
    """

    def extract(self, metrics: dict, duration_s: float, protocol: str = "") -> WorkloadProfile:
        """
        Extract workload profile from metrics.

        Args:
            metrics:    MetricsCollector snapshot + parsed footer fields.
            duration_s: Actual experiment duration.
            protocol:   Protocol identifier (for context).
        """
        dur = max(duration_s, 0.01)
        profile = WorkloadProfile(protocol=protocol, duration_s=dur)

        # ── Connection metrics (from HYPOGENIE footer) ────────────────────────
        conns = metrics.get("_connections_attempted")
        if conns is not None:
            profile.connections_total = int(conns)
            profile.connections_per_second = conns / dur

        avg_life = metrics.get("_avg_lifetime_s")
        if avg_life is not None:
            profile.avg_connection_lifetime_s = float(avg_life)
            if profile.connections_per_second is not None and avg_life > 0:
                profile.concurrent_connections = max(1, int(
                    profile.connections_per_second * avg_life
                ))

        # ── Frame / operation metrics ─────────────────────────────────────────
        frames = metrics.get("exploit_frames_sent")
        if frames is not None and frames >= 0:
            profile.frames_total = int(frames)
            profile.frames_per_second = frames / dur

        # ── Throughput from stdout ────────────────────────────────────────────
        summary = metrics.get("exploit_summary") or ""
        bps = self._parse_bytes_per_second(summary)
        if bps is not None:
            profile.bytes_per_second = bps

        return profile

    @staticmethod
    def _parse_bytes_per_second(summary: str) -> Optional[float]:
        """
        Extract bytes/s from common throughput summary patterns.

        Recognises: "1,112 MB/s", "1.1 GB/s", "512 KB/s", "1024 B/s".
        Returns None when no recognised pattern is found.
        """
        m = re.search(r'([\d,]+\.?\d*)\s*(GB|MB|KB|B)/s', summary, re.IGNORECASE)
        if not m:
            return None
        val = float(m.group(1).replace(",", ""))
        unit = m.group(2).upper()
        return val * {"GB": 1e9, "MB": 1e6, "KB": 1e3, "B": 1.0}.get(unit, 1.0)


# ── C. WorkloadMatchResult + WorkloadMatcher ──────────────────────────────────

@dataclass
class WorkloadMatchResult:
    """Result of comparing two WorkloadProfiles."""
    valid: bool
    matched_dimensions:    list[str]        = field(default_factory=list)
    mismatched_dimensions: list[str]        = field(default_factory=list)
    missing_dimensions:    list[str]        = field(default_factory=list)
    mismatch_ratios:       dict[str, float] = field(default_factory=dict)
    details:               dict             = field(default_factory=dict)
    reason: str = ""


class WorkloadMatcher:
    """
    Validates that two WorkloadProfiles are sufficiently matched.

    A valid comparison requires that workloads differ only in the
    hypothesis-specific dimension — not in overall processing volume.

    Tolerances are intentionally generous to account for the fact that some
    control designs intentionally differ in bytes (e.g., PING frames are much
    smaller than RST_STREAM) while matching at the frame-rate level.
    Only flags cases where mismatch is so large the comparison is invalid.
    """

    _DEFAULT_TOLERANCE = 0.50   # 50 % — allow substantial per-frame size differences

    def match(
        self,
        attack: WorkloadProfile,
        control: WorkloadProfile,
        required_dimensions: Optional[list[str]] = None,
        tolerance: float = _DEFAULT_TOLERANCE,
    ) -> WorkloadMatchResult:
        """
        Compare workloads on the named dimensions.

        Returns WorkloadMatchResult with valid=False only when a measured
        dimension is mismatched beyond tolerance.  Missing (None) dimensions
        are recorded but do NOT make the result invalid.
        """
        if required_dimensions is None:
            required_dimensions = [
                "frames_per_second",
                "connections_per_second",
            ]

        matched: list[str] = []
        mismatched: list[str] = []
        missing: list[str] = []
        ratios: dict[str, float] = {}
        details: dict = {}

        for dim in required_dimensions:
            a_val = getattr(attack, dim, None)
            c_val = getattr(control, dim, None)

            if a_val is None or c_val is None:
                missing.append(dim)
                continue

            if a_val == 0 and c_val == 0:
                matched.append(dim)
                ratios[dim] = 1.0
                details[dim] = {"attack": 0, "control": 0, "ratio": 1.0, "within_tolerance": True}
                continue

            if a_val > 0 and c_val > 0:
                ratio = max(a_val, c_val) / min(a_val, c_val)
            else:
                ratio = float("inf")

            within = ratio <= (1.0 + tolerance) or ratio == float("inf") and (
                a_val == 0 or c_val == 0
            )
            # Treat infinite ratio as mismatch only when one side is truly zero
            if ratio == float("inf"):
                within = False

            ratios[dim] = round(ratio, 3)
            details[dim] = {
                "attack": round(a_val, 3),
                "control": round(c_val, 3),
                "ratio": ratios[dim],
                "within_tolerance": within,
            }

            if within:
                matched.append(dim)
            else:
                mismatched.append(dim)

        valid = len(mismatched) == 0
        if mismatched:
            reason = (
                "Workload mismatch in: "
                + ", ".join(
                    f"{d}(ratio={ratios[d]:.2f})" for d in mismatched
                )
            )
        elif matched:
            reason = "Workload matched on: " + ", ".join(matched)
        else:
            reason = "No workload dimensions were measured for comparison"

        if missing:
            reason += f"; unmeasured dimensions: {', '.join(missing)}"

        return WorkloadMatchResult(
            valid=valid,
            matched_dimensions=matched,
            mismatched_dimensions=mismatched,
            missing_dimensions=missing,
            mismatch_ratios=ratios,
            details=details,
            reason=reason,
        )


# ── D. HypothesisMeasurementContract ─────────────────────────────────────────

@dataclass
class HypothesisMeasurementContract:
    """
    Structured contract describing what the experiment must measure and what
    must remain constant between attack and control.

    Derived from the hypothesis description, dos_class, and protocol —
    not hardcoded per attack type.
    """
    protocol: str = ""
    dos_class: str = ""

    # Dimensions that must match between attack and control
    required_match_dimensions: list[str] = field(default_factory=list)

    # The single dimension that intentionally differs
    hypothesis_variable: str = ""

    # Which resource metric is primarily relevant
    primary_resource: str = "cpu"      # cpu | memory | latency

    # Minimum excess ratio to confirm attribution
    # (attack resource usage must be this many times larger than control)
    min_excess_ratio: float = 2.0

    # Matching tolerance (fraction of attack value)
    workload_tolerance: float = 0.50


def derive_contract(
    protocol: str,
    dos_class: str,
    description: str = "",
) -> HypothesisMeasurementContract:
    """
    Derive a HypothesisMeasurementContract from protocol and dos_class.

    Generic inference rules — not hardcoded per attack.  Any field can be
    overridden via YAML measurement.attribution block (future).
    """
    contract = HypothesisMeasurementContract(
        protocol=protocol,
        dos_class=dos_class,
    )

    # Primary resource follows dos_class
    if dos_class == "memory":
        contract.primary_resource = "memory"
    elif dos_class in ("resource_exhaustion", "resource_starvation"):
        contract.primary_resource = "cpu"
    elif dos_class == "cpu":
        contract.primary_resource = "cpu"
    else:
        contract.primary_resource = "cpu"

    # Required match dimensions by protocol
    if protocol in ("HTTP/2", "gRPC"):
        contract.required_match_dimensions = [
            "connections_per_second",
            "frames_per_second",
        ]
        contract.hypothesis_variable = "frame_type_or_state_transition"
    elif protocol == "QUIC":
        contract.required_match_dimensions = [
            "connections_per_second",
        ]
        contract.hypothesis_variable = "stream_lifecycle_or_header_encoding"
    elif protocol in ("DNS-over-TLS", "DNS/TLS"):
        contract.required_match_dimensions = [
            "connections_per_second",
            "messages_per_second",
        ]
        contract.hypothesis_variable = "query_type_or_recursion"
    else:
        # Generic: match by connection rate and frame rate when available
        contract.required_match_dimensions = [
            "connections_per_second",
            "frames_per_second",
            "bytes_per_second",
        ]
        contract.hypothesis_variable = "protocol_specific_behavior"

    return contract


# ── E. CalibrationPoint + BaselineCalibrator ──────────────────────────────────

@dataclass
class CalibrationPoint:
    """Single measurement: resource consumption at one workload level."""
    workload_value: float    # e.g., MB/s or connections/s
    cpu_pct: float
    mem_mb: float
    duration_s: float


class BaselineCalibrator:
    """
    Builds a workload→resource model from calibration measurements at several
    workload levels.

    Supports nonlinear relationships via piecewise-linear interpolation.
    Never extrapolates beyond the calibrated range.

    Usage:
        cal = BaselineCalibrator()
        cal.add_point(CalibrationPoint(workload_value=100, cpu_pct=8, ...))
        cal.add_point(CalibrationPoint(workload_value=500, cpu_pct=34, ...))
        predicted = cal.predict_cpu(250)   # interpolated
    """

    def __init__(self):
        self._points: list[CalibrationPoint] = []

    def add_point(self, point: CalibrationPoint) -> None:
        self._points.append(point)

    @property
    def point_count(self) -> int:
        return len(self._points)

    def is_calibrated(self) -> bool:
        return len(self._points) >= 2

    def workload_range(self) -> tuple[float, float]:
        if not self._points:
            return (0.0, 0.0)
        values = [p.workload_value for p in self._points]
        return (min(values), max(values))

    def predict_cpu(self, workload_value: float) -> Optional[float]:
        """
        Predict expected CPU% for the given workload level.

        Returns None if:
        - Fewer than 2 calibration points exist.
        - workload_value is outside the calibrated range (no extrapolation).
        """
        if not self.is_calibrated():
            return None

        pts = sorted(self._points, key=lambda p: p.workload_value)
        lo_w = pts[0].workload_value
        hi_w = pts[-1].workload_value

        if workload_value < lo_w or workload_value > hi_w:
            return None   # Out of range — extrapolation not supported

        for i in range(len(pts) - 1):
            lo, hi = pts[i], pts[i + 1]
            if lo.workload_value <= workload_value <= hi.workload_value:
                if hi.workload_value == lo.workload_value:
                    return lo.cpu_pct
                t = (workload_value - lo.workload_value) / (hi.workload_value - lo.workload_value)
                return lo.cpu_pct + t * (hi.cpu_pct - lo.cpu_pct)

        return None

    def predict_mem(self, workload_value: float) -> Optional[float]:
        """Predict expected memory MB at a workload level. Same interpolation."""
        if not self.is_calibrated():
            return None

        pts = sorted(self._points, key=lambda p: p.workload_value)
        lo_w, hi_w = pts[0].workload_value, pts[-1].workload_value

        if workload_value < lo_w or workload_value > hi_w:
            return None

        for i in range(len(pts) - 1):
            lo, hi = pts[i], pts[i + 1]
            if lo.workload_value <= workload_value <= hi.workload_value:
                if hi.workload_value == lo.workload_value:
                    return lo.mem_mb
                t = (workload_value - lo.workload_value) / (hi.workload_value - lo.workload_value)
                return lo.mem_mb + t * (hi.mem_mb - lo.mem_mb)

        return None


# ── F. ControlValidator ───────────────────────────────────────────────────────

class ControlValidator:
    """
    Validates that a control experiment is legitimate before using its
    measurements to influence the attribution verdict.

    A failed control is classified as INCONCLUSIVE — never as evidence that
    the attack caused additional resource consumption.
    """

    def validate(
        self,
        control_metrics: dict,
        attack_metrics: dict,
        protocol: str = "",
        duration_s: float = 30.0,
    ) -> tuple[bool, str]:
        """
        Returns (valid: bool, reason: str).

        The control is invalid when:
        - No CPU measurements were collected.
        - The control script itself was flagged invalid.
        - The control attempted zero connections.
        """
        if not control_metrics.get("cpu_pct"):
            return False, "Control experiment produced no CPU measurements"

        if control_metrics.get("_invalid"):
            reason = control_metrics.get("_invalid_reason", "control script failed")
            return False, f"Control experiment was invalid: {reason}"

        ctrl_conns = control_metrics.get("_connections_attempted")
        if ctrl_conns is not None and int(ctrl_conns) == 0:
            return False, "Control experiment attempted 0 connections — likely a setup failure"

        return True, "Control validated"


# ── G. AttributionResult ──────────────────────────────────────────────────────

@dataclass
class AttributionResult:
    """Structured result of an attribution analysis."""
    status: str = INCONCLUSIVE   # ATTRIBUTED | NOT_ATTRIBUTED | INCONCLUSIVE
    reason: str = ""

    # Computed excess resource consumption (attack - matched_control)
    excess_cpu_pp: Optional[float]  = None
    excess_cpu_pct: Optional[float] = None   # excess as % of attack CPU delta
    excess_mem_mb: Optional[float]  = None

    # Workload comparison
    workload_match: Optional[WorkloadMatchResult] = None

    # Statistical confidence (0.0–1.0)
    confidence: float = 0.0

    # Supporting details for the attribution report
    details: dict = field(default_factory=dict)


# ── H. AttributionEngine ──────────────────────────────────────────────────────

class AttributionEngine:
    """
    Hypothesis-aware resource attribution engine.

    Determines whether observed resource consumption is causally attributable
    to the specific hypothesized behavior, not merely to ordinary protocol
    workload.

    The engine requires a matched control experiment to confirm attribution.
    Without one, it returns INCONCLUSIVE rather than assuming attribution.
    """

    # Protocols for which make_control_fn provides a usable differential control
    _PROTOCOLS_WITH_CONTROLS: frozenset[str] = frozenset({"HTTP/2", "gRPC", "QUIC"})

    def __init__(self):
        self._extractor = WorkloadExtractor()
        self._matcher   = WorkloadMatcher()
        self._validator = ControlValidator()

    # ── Primary method: check whether Phase 3 may confirm ─────────────────────

    def check_control_requirement(
        self,
        protocol: str,
        control_exploit_fn_provided: bool,
        p2c_attribution_ran: bool,
        p2c_diff_attributed: bool,
    ) -> AttributionResult:
        """
        Check whether the available evidence meets the attribution requirement
        before returning CONFIRMED_DOS from Phase 3.

        Decision rules:
        1. Phase 2c ran AND differential attributed     → ATTRIBUTED (strong evidence)
        2. Phase 2c ran AND NOT attributed, but we still reached Phase 3
           (secondary evidence: benign ratio / pprof)  → ATTRIBUTED (secondary evidence)
        3. Phase 2c did NOT run:
           a. No control was provided                  → INCONCLUSIVE
           b. Control provided but Phase 2c incomplete → INCONCLUSIVE

        CONFIRMED_DOS is never issued when no matched control was run.
        """
        if p2c_attribution_ran:
            if p2c_diff_attributed:
                return AttributionResult(
                    status=ATTRIBUTED,
                    reason="Differential control confirmed hypothesis-specific overhead "
                           "(control_delta / attack_delta < confirmation threshold)",
                    confidence=0.9,
                    details={
                        "source":           "differential_control",
                        "diff_attributed":  True,
                    },
                )
            else:
                # Phase 2c ran but diff_attributed=False. We reached Phase 3 because
                # secondary evidence (benign ratio or pprof classification) was available.
                # Trust the existing secondary-evidence logic.
                return AttributionResult(
                    status=ATTRIBUTED,
                    reason="Secondary attribution evidence supported continuation "
                           "(benign_ratio < confirm threshold or pprof application CPU >= threshold)",
                    confidence=0.75,
                    details={
                        "source":          "secondary_evidence",
                        "diff_attributed": False,
                    },
                )

        # Phase 2c did not run
        if not control_exploit_fn_provided:
            has_builtin = protocol in self._PROTOCOLS_WITH_CONTROLS
            reason = (
                f"No matched control experiment was run for protocol '{protocol}'. "
                f"Cannot determine whether the observed CPU/memory consumption is caused "
                f"by the hypothesized behavior or by ordinary protocol workload. "
            )
            if has_builtin:
                reason += (
                    f"Protocol '{protocol}' has built-in control support "
                    f"(make_control_fn) — this is unexpected; check pipeline configuration."
                )
            else:
                reason += (
                    f"Add a hypothesis-matched control for '{protocol}' to establish "
                    f"causal attribution."
                )
            return AttributionResult(
                status=INCONCLUSIVE,
                reason=reason,
                confidence=0.0,
                details={
                    "source":                     "no_control",
                    "protocol":                   protocol,
                    "protocol_has_builtin_control": has_builtin,
                },
            )

        # Control was provided but Phase 2c somehow did not complete
        return AttributionResult(
            status=INCONCLUSIVE,
            reason="Differential control was provided but Phase 2c did not complete — "
                   "attribution evidence is insufficient",
            confidence=0.0,
            details={"source": "p2c_incomplete"},
        )

    # ── Workload validation ────────────────────────────────────────────────────

    def check_workload_match(
        self,
        attack_metrics: dict,
        control_metrics: dict,
        attack_duration_s: float,
        control_duration_s: float,
        protocol: str = "",
        tolerance: float = WorkloadMatcher._DEFAULT_TOLERANCE,
    ) -> Optional[WorkloadMatchResult]:
        """
        Validate that attack and control workloads are sufficiently matched.

        Returns None when insufficient data is available to compare.
        Returns WorkloadMatchResult.valid=False when a critical mismatch is
        detected that would make the differential comparison unreliable.

        High default tolerance (50%) accounts for intentional control designs
        (PING frames are smaller than RST_STREAM, but frame rate matches).
        Only flags extreme mismatches (e.g., attack sends 100× more data).
        """
        a_profile = self._extractor.extract(attack_metrics, attack_duration_s, protocol)
        c_profile = self._extractor.extract(control_metrics, control_duration_s, protocol)

        dims: list[str] = []
        if (a_profile.connections_per_second is not None
                and c_profile.connections_per_second is not None):
            dims.append("connections_per_second")
        if (a_profile.frames_per_second is not None
                and c_profile.frames_per_second is not None):
            dims.append("frames_per_second")

        if not dims:
            return None   # Insufficient workload data

        return self._matcher.match(a_profile, c_profile, dims, tolerance)

    # ── Excess resource computation ────────────────────────────────────────────

    def compute_excess(
        self,
        attack_metrics: dict,
        control_metrics: dict,
        attack_baseline: dict,
        control_baseline: dict,
    ) -> dict:
        """
        Compute excess resource consumption: attack delta minus control delta.

        Each delta is measured against the respective container's own idle
        baseline to eliminate cross-container measurement error.

        Returns a dict with:
          excess_cpu_pp    — absolute CPU excess above control (pp)
          excess_cpu_pct   — excess as a percentage of attack CPU delta
          excess_mem_mb    — excess memory above control (MB)
          ratio            — control_delta / attack_delta (for display)
        """
        def safe_mean(lst):
            vals = [v for v in (lst or []) if v is not None]
            return mean(vals) if vals else 0.0

        ab = safe_mean(attack_baseline.get("cpu_pct", []))
        cb = safe_mean(control_baseline.get("cpu_pct", []))
        a  = safe_mean(attack_metrics.get("cpu_pct", []))
        c  = safe_mean(control_metrics.get("cpu_pct", []))

        a_delta = max(0.0, a - ab)
        c_delta = max(0.0, c - cb)
        excess_cpu = a_delta - c_delta
        excess_pct = (excess_cpu / a_delta * 100.0) if a_delta > 0 else 0.0

        ab_m = safe_mean(attack_baseline.get("mem_mb", []))
        cb_m = safe_mean(control_baseline.get("mem_mb", []))
        a_m  = max(attack_metrics.get("mem_mb") or [ab_m])
        c_m  = max(control_metrics.get("mem_mb") or [cb_m])
        excess_mem = max(0.0, a_m - ab_m) - max(0.0, c_m - cb_m)

        return {
            "attack_cpu_delta_pp":   round(a_delta, 2),
            "control_cpu_delta_pp":  round(c_delta, 2),
            "excess_cpu_pp":         round(excess_cpu, 2),
            "excess_cpu_pct":        round(excess_pct, 1),
            "excess_mem_mb":         round(excess_mem, 2),
            "ratio": round(c_delta / a_delta, 3) if a_delta > 0 else 1.0,
        }

    # ── Multi-run statistical attribution ─────────────────────────────────────

    def compute_statistical_confidence(
        self,
        attack_cpu_deltas: list[float],
        control_cpu_deltas: list[float],
        min_practical_effect_pp: float = 10.0,
    ) -> dict:
        """
        Calculate attribution confidence from multiple paired measurements.

        Args:
            attack_cpu_deltas:  CPU delta (above baseline) for each attack run.
            control_cpu_deltas: CPU delta for each matched control run.
            min_practical_effect_pp: Minimum meaningful difference (pp).

        Returns:
            {
              "mean_excess_pp":    float,
              "median_excess_pp":  float,
              "std_excess_pp":     float | None,
              "run_count":         int,
              "confidence":        float (0.0–1.0),
              "sufficient":        bool,
              "reason":            str,
            }
        """
        if not attack_cpu_deltas or not control_cpu_deltas:
            return {
                "mean_excess_pp": 0.0, "median_excess_pp": 0.0,
                "std_excess_pp": None, "run_count": 0,
                "confidence": 0.0, "sufficient": False,
                "reason": "No measurements provided",
            }

        n = min(len(attack_cpu_deltas), len(control_cpu_deltas))
        excesses = [
            attack_cpu_deltas[i] - control_cpu_deltas[i]
            for i in range(n)
        ]

        m_exc = mean(excesses)
        # Sort for median
        sorted_exc = sorted(excesses)
        med_exc = sorted_exc[n // 2] if n % 2 else (
            (sorted_exc[n // 2 - 1] + sorted_exc[n // 2]) / 2
        )

        std_exc: Optional[float] = stdev(excesses) if n >= 2 else None

        # Confidence: fraction of runs where excess ≥ min_practical_effect_pp
        frac_positive = sum(1 for e in excesses if e >= min_practical_effect_pp) / n

        # Penalise high variance
        cv = (std_exc / abs(m_exc)) if (std_exc is not None and m_exc != 0) else 1.0
        variance_penalty = max(0.0, 1.0 - cv)

        confidence = round(frac_positive * variance_penalty, 3)
        sufficient = (
            n >= 2
            and m_exc >= min_practical_effect_pp
            and frac_positive >= 0.75
        )

        reason = (
            f"{n} paired runs: mean_excess={m_exc:.1f}pp, "
            f"frac_positive={frac_positive:.0%}"
        )
        if std_exc is not None:
            reason += f", std={std_exc:.1f}pp"
        reason += f" → {'sufficient' if sufficient else 'insufficient'} confidence"

        return {
            "mean_excess_pp":   round(m_exc, 2),
            "median_excess_pp": round(med_exc, 2),
            "std_excess_pp":    round(std_exc, 2) if std_exc is not None else None,
            "run_count":        n,
            "confidence":       confidence,
            "sufficient":       sufficient,
            "reason":           reason,
        }

    # ── Environmental consistency check ───────────────────────────────────────

    def check_environmental_stability(
        self,
        attack_baseline_cpu: float,
        control_baseline_cpu: float,
        max_baseline_diff_pp: float = 10.0,
    ) -> tuple[bool, str]:
        """
        Check that background conditions are comparable between experiments.

        A large difference in idle baseline CPU between the attack and control
        containers indicates environmental instability that may invalidate the
        differential comparison.

        Returns (stable: bool, reason: str).
        """
        diff = abs(attack_baseline_cpu - control_baseline_cpu)
        if diff > max_baseline_diff_pp:
            return False, (
                f"Baseline CPU mismatch between attack container "
                f"({attack_baseline_cpu:.1f}%) and control container "
                f"({control_baseline_cpu:.1f}%): diff={diff:.1f}pp "
                f"(threshold={max_baseline_diff_pp}pp). "
                f"Environmental conditions are not sufficiently stable."
            )
        return True, (
            f"Baseline CPUs comparable: attack={attack_baseline_cpu:.1f}%, "
            f"control={control_baseline_cpu:.1f}% (diff={diff:.1f}pp)"
        )
