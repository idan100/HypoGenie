"""
Tests for lifecycle.applicability.assess()

9 cases covering the multi-signal decision logic:
  TC1  resource_exhaustion dos_class alone → uncertain
  TC2  resource_exhaustion + accumulation keywords in description → applicable
  TC3  non-retention dos_class (cpu) + no signals → not_applicable
  TC4  assumption with cancel keywords → partial score → uncertain
  TC5  suspected_mechanism cancel step → partial score
  TC6  gap finder finding with retention keywords → boosts score to applicable
  TC7  exploit plan with RESET_STREAM frame → adds signal
  TC8  exploit plan expected_effect with "goroutine" → adds signal
  TC9  mode=disabled in validation → lifecycle skipped (checked in hypogenie flow)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from processor.models import HypothesisContext, Assumption, RFCSection
from lifecycle.applicability import assess
from lifecycle.model import LifecycleApplicability


# ── helpers ───────────────────────────────────────────────────────────────────

def _ctx(**kwargs) -> HypothesisContext:
    defaults = dict(
        description="A simple hypothesis.",
        dos_class="resource_exhaustion",
        repo_url="https://github.com/caddyserver/caddy",
        version="v2.11.4",
        protocol="QUIC",
        entry_point="localhost:443",
        assumptions=[],
        rfc_sections=[],
        related_work=[],
        docker_image=None,
        server_config="",
        suspected_mechanism=[],
        validation={"resource_lifecycle": {"mode": "auto"}},
    )
    defaults.update(kwargs)
    return HypothesisContext(**defaults)


class _FakeGap:
    def __init__(self, gap_description=""):
        self.gap_description = gap_description
        self.code_location = "foo.go:42"
        self.code_snippet = ""
        from spec_processor.models import SpecRequirement
        self.requirement = SpecRequirement(
            rfc="RFC 9000", section="4.6",
            classification="must_violation",
            requirement_text="",
            dos_mechanism="",
            relevant_to_assumption=None,
        )


class _FakePlan:
    def __init__(self, expected_effect="", frames=None):
        self.expected_effect = expected_effect
        self.attack_sequence = []
        if frames:
            class _Step:
                def __init__(self, n, frame):
                    self.n = n
                    self.quic_frame = frame
            self.attack_sequence = [_Step(i + 1, f) for i, f in enumerate(frames)]


# ── test cases ────────────────────────────────────────────────────────────────

def test_tc1_resource_exhaustion_alone():
    """TC1: dos_class=resource_exhaustion, no other signals → uncertain (score=1.0)."""
    ctx = _ctx(dos_class="resource_exhaustion")
    result = assess(ctx)
    assert result.decision == "uncertain", f"expected uncertain, got {result.decision}"
    assert result.score == 1.0, f"expected score=1.0, got {result.score}"
    assert any("dos_class" in s for s in result.signals)


def test_tc2_resource_exhaustion_plus_description_keywords():
    """TC2: dos_class=resource_exhaustion + 'cancel mid-flight' in description → applicable (score≥2)."""
    ctx = _ctx(
        dos_class="resource_exhaustion",
        description="When a client cancels a request mid-flight, the upstream may retain "
                    "resources, accumulating goroutines over time.",
    )
    result = assess(ctx)
    assert result.decision == "applicable", f"expected applicable, got {result.decision}"
    assert result.score >= 2.0, f"expected score>=2.0, got {result.score}"


def test_tc3_cpu_class_no_signals():
    """TC3: dos_class=cpu, generic description → not_applicable (score<1.0)."""
    ctx = _ctx(
        dos_class="cpu",
        description="A CPU-intensive regex can cause the server to spin indefinitely.",
    )
    result = assess(ctx)
    assert result.decision == "not_applicable", f"expected not_applicable, got {result.decision}"
    assert result.score < 1.0, f"expected score<1.0, got {result.score}"


def test_tc4_assumption_cancel_keywords():
    """TC4: assumption describing cancel pattern → adds 0.5 → total 1.5 → uncertain."""
    ctx = _ctx(
        dos_class="resource_exhaustion",
        assumptions=[
            Assumption(
                id="A1",
                description="The proxy does not cancel in-progress upstream requests when the client aborts.",
                necessity="required",
            )
        ],
    )
    result = assess(ctx)
    # score = 1.0 (dos_class) + 0.5 (assumption) = 1.5 → uncertain
    assert result.decision in ("applicable", "uncertain")
    assert result.score >= 1.5, f"expected score>=1.5, got {result.score}"
    assert any("assumption" in s.lower() for s in result.signals)


def test_tc5_suspected_mechanism_cancel_step():
    """TC5: suspected_mechanism step mentions RESET_STREAM → adds 0.5."""
    ctx = _ctx(
        dos_class="resource_exhaustion",
        suspected_mechanism=[
            {"step": 1, "action": "Client sends RESET_STREAM after upstream dispatch."},
            {"step": 2, "action": "Server retains goroutine for the cancelled request."},
        ],
    )
    result = assess(ctx)
    assert result.score >= 1.5, f"expected score>=1.5, got {result.score}"
    assert any("suspected_mechanism" in s.lower() for s in result.signals)


def test_tc6_gap_finder_retention_finding():
    """TC6: gap finder finding with 'retain' → adds 1.0 → score≥2 → applicable."""
    ctx = _ctx(dos_class="resource_exhaustion")
    finding = _FakeGap(
        gap_description="Upstream request is not cancelled when client disconnects; "
                        "retained goroutines accumulate."
    )
    result = assess(ctx, findings=[finding])
    assert result.decision == "applicable", f"expected applicable, got {result.decision}"
    assert result.score >= 2.0
    assert any("finding" in s.lower() for s in result.signals)


def test_tc7_exploit_plan_cancel_frame():
    """TC7: ExploitPlan step with RESET_STREAM frame → adds 0.5."""
    ctx = _ctx(dos_class="resource_exhaustion")
    plan = _FakePlan(frames=["RESET_STREAM: stream_id=1, error_code=0"])
    result_no_plan = assess(ctx)
    result_with_plan = assess(ctx, plan=plan)
    assert result_with_plan.score > result_no_plan.score
    assert any("frame" in s.lower() for s in result_with_plan.signals)


def test_tc8_exploit_plan_goroutine_effect():
    """TC8: ExploitPlan expected_effect mentions goroutine leak → adds 1.0."""
    ctx = _ctx(dos_class="resource_exhaustion")
    plan = _FakePlan(expected_effect="Goroutine accumulation in Caddy's reverse proxy; "
                                     "each cancelled request leaks a goroutine.")
    result = assess(ctx, plan=plan)
    assert result.score >= 2.0, f"expected score>=2.0, got {result.score}"
    assert result.decision == "applicable"
    assert any("expected_effect" in s.lower() for s in result.signals)


def test_tc9_all_signals_combined():
    """TC9: All signals present → score well above 2.0 → applicable with many signals."""
    ctx = _ctx(
        dos_class="resource_exhaustion",
        description="Client cancels in-flight requests; proxy accumulates goroutines.",
        assumptions=[
            Assumption(
                id="A1",
                description="Server retains resources when client aborts mid-flight.",
                necessity="required",
            )
        ],
        suspected_mechanism=[
            {"step": 1, "action": "RESET_STREAM triggers context.Canceled on the upstream."},
        ],
    )
    finding = _FakeGap(
        gap_description="cleanup is not triggered on context.Canceled; "
                        "outstanding ops are never freed."
    )
    plan = _FakePlan(
        expected_effect="Goroutine and connection pool exhaustion via repeated RESET_STREAM.",
        frames=["RESET_STREAM: stream_id=5"],
    )
    result = assess(ctx, findings=[finding], plan=plan)
    assert result.decision == "applicable"
    assert result.score >= 4.0, f"expected score>=4.0, got {result.score}"
    assert len(result.signals) >= 5, f"expected >=5 signals, got {len(result.signals)}"


# ── runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_tc1_resource_exhaustion_alone,
        test_tc2_resource_exhaustion_plus_description_keywords,
        test_tc3_cpu_class_no_signals,
        test_tc4_assumption_cancel_keywords,
        test_tc5_suspected_mechanism_cancel_step,
        test_tc6_gap_finder_retention_finding,
        test_tc7_exploit_plan_cancel_frame,
        test_tc8_exploit_plan_goroutine_effect,
        test_tc9_all_signals_combined,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{passed + failed} tests passed.")
    if failed:
        sys.exit(1)
