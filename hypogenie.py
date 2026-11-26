#!/usr/bin/env python3
"""
HypoGenie — DoS vulnerability discovery from YAML attack hypotheses.

Usage:
    python hypogenie.py --input <yaml>
    python hypogenie.py --test-suite <dir> --expect <CONFIRMED_DOS|NO_DOS_EFFECT>
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── path setup ────────────────────────────────────────────────────────────────
_SRC = Path(__file__).parent / "src"
_AGENTLIB = _SRC / "agentlib"
sys.path.insert(0, str(_SRC))
sys.path.insert(0, str(_AGENTLIB))

from run_context import run_id
from processor.yaml_parser import parse
from spec_processor.spec_processor import run as spec_run
from gap_finder.gap_finder import run as gap_run
from exploit_planner.exploit_planner import run as plan_run
from exploit_planner.models import ExploitPlan, Step
from assumption_ledger.models import AssumptionLedger
from builder.builder import build, teardown
from exploiter.exploiter import run as exploit_run
from verifier.verifier import run as verify_run, Verdict
from exploiter.exploiter import make_control_fn as _make_control_fn
from exploiter.exploiter import make_benign_fn as _make_benign_fn
from exploiter.exploiter import make_persist_fn as _make_persist_fn
import llm_client as _llm
from lifecycle.applicability import assess as _lc_assess, build_plan as _lc_build_plan
from lifecycle.model import LifecycleMode, LifecycleResult
from lifecycle.scenarios import LifecycleRunner

_PROJECT_ROOT = Path(__file__).parent
_OUTPUT_DIR   = _PROJECT_ROOT / "output"
_CERTS_DIR    = _PROJECT_ROOT / "infra" / "certs"
_WORKSPACE    = _PROJECT_ROOT / "workspace" / "runs"
_VENV_PYTHON  = _PROJECT_ROOT / ".venv" / "bin" / "python"


# ── evidence tiers ────────────────────────────────────────────────────────────

class EvidenceTier:
    """Four ordered levels of confidence — not equivalent; each requires the ones below it."""
    SOURCE_CODE_WEAKNESS          = "source_code_weakness"
    THEORETICALLY_EXPLOITABLE     = "theoretically_exploitable"
    REPRODUCED_RESOURCE_EXHAUSTION = "reproduced_resource_exhaustion"
    AVAILABILITY_IMPACT           = "externally_observable_availability_impact"

    _ORDER = [
        SOURCE_CODE_WEAKNESS,
        THEORETICALLY_EXPLOITABLE,
        REPRODUCED_RESOURCE_EXHAUSTION,
        AVAILABILITY_IMPACT,
    ]


def _derive_evidence_tier(
    findings: list,
    plan,
    verify_result: dict,
    verdicts: list,
) -> dict:
    """
    Returns {"highest": <tier>, "tiers_present": [<tier>, ...]} where tiers_present
    lists every tier the evidence supports, in ascending order.

    Tiers are cumulative: reaching REPRODUCED_RESOURCE_EXHAUSTION implies the two below.
    """
    tiers: list[str] = []

    # Tier 1 — a gap was identified in source code
    if findings:
        tiers.append(EvidenceTier.SOURCE_CODE_WEAKNESS)

    # Tier 2 — the gap is theoretically exploitable (plan + no blocking refuted required assumption)
    if findings and plan and plan.attack_sequence:
        required_refuted = set()
        if verdicts:
            # Need ctx.assumptions, but we only have verdicts here.
            # Use the plan's assumptions_relied_on as a proxy: if any relied-on assumption
            # is "refuted" in the verdicts, the plan rests on a refuted assumption.
            status_map = {v.assumption_id: v.status for v in verdicts}
            required_refuted = {
                a for a in (plan.assumptions_relied_on or [])
                if status_map.get(a) == "refuted"
            }
        if not required_refuted and plan.severity in ("critical", "high", "medium"):
            tiers.append(EvidenceTier.THEORETICALLY_EXPLOITABLE)

    verdict = verify_result.get("verdict", "")

    # Tier 3 — resource exhaustion was measured in a controlled lab run
    if verdict == "CONFIRMED_DOS":
        tiers.append(EvidenceTier.REPRODUCED_RESOURCE_EXHAUSTION)

    # Tier 4 — the service became externally unavailable (latency spike or unreachable threshold)
    if verdict == "CONFIRMED_DOS":
        triggered = verify_result.get("triggered", [])
        phases = verify_result.get("phases", [])
        attack_ph = next((p for p in phases if p.get("phase") == "attack"), {})
        td = attack_ph.get("threshold_details", {})
        latency_triggered = td.get("latency", {}).get("triggered", False)
        unreachable_triggered = td.get("unreachable", {}).get("triggered", False)
        if "unreachable" in triggered or unreachable_triggered or latency_triggered:
            tiers.append(EvidenceTier.AVAILABILITY_IMPACT)

    highest = tiers[-1] if tiers else None
    return {"highest": highest, "tiers_present": tiers}


# ── helpers ───────────────────────────────────────────────────────────────────

def _release_stale_containers() -> None:
    """Stop and remove any leftover hypogenie-* containers before starting a new run."""
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=hypogenie-"],
        capture_output=True, text=True, timeout=10,
    )
    ids = result.stdout.split()
    if not ids:
        return
    print(f"  [hypogenie] releasing {len(ids)} stale container(s): {ids}")
    subprocess.run(["docker", "stop"] + ids, capture_output=True, timeout=30)
    subprocess.run(["docker", "rm"]  + ids, capture_output=True, timeout=30)


def _clone_repo(repo_url: str, version: str, dest: Path) -> str:
    if dest.exists():
        print(f"  [hypogenie:{run_id}] Repo already at {dest}")
        return str(dest)
    print(f"  [hypogenie:{run_id}] Cloning {repo_url} @ {version} ...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", version, repo_url, str(dest)],
        capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        # Shallow clone with branch failed — try without branch (commit SHA)
        result2 = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(dest)],
            capture_output=True, text=True, timeout=120
        )
        if result2.returncode != 0:
            raise RuntimeError(f"Clone failed: {result.stderr.strip()[:200]}")
    print(f"  [hypogenie:{run_id}] Cloned to {dest}")
    return str(dest)


def _port_from_entry_point(entry_point: str) -> int:
    """Extract port number from entry_point string."""
    import re
    m = re.search(r"\b(\d{2,5})\b", entry_point)
    return int(m.group(1)) if m else 443


def _compute_hypothesis_verdict(
    verify_result: dict,
    verdicts: list,
    plan,
    ctx,
    ledger=None,
) -> str:
    """
    Derive a hypothesis-level verdict from measurement result + static analysis signals.

    Decision table:
      DOS_CONFIRMED                  — measurement confirmed a reproducible, causally attributed DoS
      HYPOTHESIS_DISPROVEN           — necessary assumptions falsified (all required refuted +
                                       runtime confirmed no effect, or early INFEASIBLE exit)
      HYPOTHESIS_PARTIALLY_DISPROVEN — one attack path disproven but alternatives remain
                                       (pivot happened, or some required assumptions refuted)
      HYPOTHESIS_INCONCLUSIVE        — insufficient evidence to establish or reject
    """
    meas = verify_result.get("verdict", "UNKNOWN")

    if meas == Verdict.CONFIRMED_DOS:
        return Verdict.DOS_CONFIRMED

    # Operational failures stay as-is — not a hypothesis conclusion.
    # ATTACK_UNREPRESENTABLE and ATTACK_BLOCKED are also not hypothesis conclusions:
    # the former is a client limitation, the latter is server-side mitigation evidence.
    if meas in (Verdict.ENVIRONMENT_ERROR, Verdict.INVALID_TEST,
                Verdict.ATTACK_UNREPRESENTABLE, Verdict.ATTACK_BLOCKED):
        return meas

    # Assess assumption refutation from Gap Finder
    assumptions = getattr(ctx, "assumptions", []) if ctx else []
    all_required = [a.id for a in assumptions if a.necessity == "required"]
    required_refuted = [
        a.id for a in assumptions
        if a.necessity == "required"
        and any(v.assumption_id == a.id and v.status == "refuted" for v in (verdicts or []))
    ]
    all_required_refuted = bool(all_required) and set(required_refuted) == set(all_required)
    some_required_refuted = bool(required_refuted) and not all_required_refuted

    # Pivot: original path was disproven; planner tried alternatives
    has_pivot = plan is not None and plan.pivot_note is not None

    # HYPOTHESIS_DISPROVEN: all required assumptions statically falsified
    if meas == Verdict.INFEASIBLE:
        return Verdict.HYPOTHESIS_DISPROVEN

    # HYPOTHESIS_DISPROVEN: static refutation + runtime confirms no effect
    if all_required_refuted and meas in (Verdict.NO_DOS_EFFECT, Verdict.REJECTED):
        return Verdict.HYPOTHESIS_DISPROVEN

    # HYPOTHESIS_PARTIALLY_DISPROVEN: pivot path tried and failed — alternatives remain untested
    if has_pivot:
        return Verdict.HYPOTHESIS_PARTIALLY_DISPROVEN

    # HYPOTHESIS_PARTIALLY_DISPROVEN: some (not all) required assumptions refuted
    if some_required_refuted and meas in (Verdict.NO_DOS_EFFECT, Verdict.REJECTED, Verdict.INCONCLUSIVE):
        return Verdict.HYPOTHESIS_PARTIALLY_DISPROVEN

    # HYPOTHESIS_INCONCLUSIVE: insufficient evidence to establish or reject
    return Verdict.HYPOTHESIS_INCONCLUSIVE


def _product_from_repo(repo_url: str) -> str:
    """Extract product name from GitHub URL."""
    return repo_url.rstrip("/").split("/")[-1]


def _plan_from_pivot(pivot: dict, base_plan: "ExploitPlan") -> "ExploitPlan":
    """Reconstruct an ExploitPlan from a pivot_candidates entry."""
    steps = [
        Step(n=s.get("n", i+1), action=s.get("action", ""),
             quic_frame=s.get("quic_frame", ""),
             expected_server_response=s.get("expected_server_response", ""),
             rationale=s.get("rationale", ""))
        for i, s in enumerate(pivot.get("attack_sequence", []))
    ]
    return ExploitPlan(
        finding_type=base_plan.finding_type,
        finding_ref=pivot.get("finding_ref") or pivot.get("label", "pivot"),
        assumptions_relied_on=base_plan.assumptions_relied_on,
        attack_sequence=steps,
        expected_effect=pivot.get("expected_effect") or base_plan.expected_effect,
        severity=pivot.get("severity") or base_plan.severity,
        pivot_note=pivot.get("label"),
        protocol=base_plan.protocol,
    )


def _fmt_phase_thresholds(phase_dict: dict) -> list:
    td = phase_dict.get("threshold_details", {})
    out = []
    if "cpu" in td:
        c = td["cpu"]
        icon = "**TRIGGERED** ✓" if c.get("triggered") else "not triggered"
        out.append(
            f"- CPU: {c.get('baseline_mean_pct',0):.1f}% → {c.get('attack_mean_pct',0):.1f}% mean"
            f" (Δ {c.get('delta_pp',0):.1f} pp) | threshold +{c.get('threshold_delta_pp',50)} pp → {icon}"
        )
    if "memory" in td:
        m = td["memory"]
        icon = "**TRIGGERED** ✓" if m.get("triggered") else "not triggered"
        out.append(
            f"- Memory: {m.get('baseline_mean_mb',0):.1f} MB → {m.get('attack_peak_mb',0):.1f} MB peak"
            f" (Δ {m.get('delta_mb',0):.1f} MB) | threshold +{m.get('threshold_delta_mb',100)} MB → {icon}"
        )
    if "latency" in td:
        l = td["latency"]
        icon = "**TRIGGERED** ✓" if l.get("triggered") else "not triggered"
        out.append(
            f"- Latency: {l.get('baseline_mean_ms',0):.1f} ms → {l.get('attack_mean_ms',0):.1f} ms"
            f" ({l.get('ratio',1):.1f}×) | threshold {l.get('threshold_ratio',5)}× → {icon}"
        )
    if "unreachable" in td:
        u = td["unreachable"]
        icon = "**TRIGGERED** ✓" if u.get("triggered") else "not triggered"
        out.append(
            f"- Unreachable: {u.get('max_consecutive_down_s',0)}s consecutive"
            f" | threshold {u.get('threshold_s',3)}s → {icon}"
        )
    return out


def _report_confirmed(lines, ctx, plan, verify_result, verdicts, findings, triggered, phases):
    lines.append("## Weakness Found\n")

    # Finding
    if findings:
        f = findings[0]
        req = f.requirement if hasattr(f, 'requirement') else {}
        lines.append("### Vulnerability")
        lines.append(f"- **Type:** {type(f).__name__} — RFC {getattr(req, 'rfc', '?')} §{getattr(req, 'section', '?')} ({getattr(req, 'classification', '?')})")
        lines.append(f"- **Location:** `{getattr(f, 'code_location', '?')}`")
        desc = getattr(f, 'gap_description', None) or getattr(f, 'invariant_description', None) or getattr(req, 'dos_mechanism', '')
        if desc:
            lines.append(f"- **Description:** {desc}")
        snippet = getattr(f, 'code_snippet', '')
        if snippet:
            lines.append(f"\n```\n{snippet.strip()}\n```")
        lines.append("")

    # Assumptions table
    if verdicts:
        # Build necessity lookup from ctx if available
        necessity_map = {}
        if ctx and hasattr(ctx, "assumptions"):
            for a in ctx.assumptions:
                necessity_map[a.id] = getattr(a, "necessity", "—")
        lines.append("### Assumptions")
        lines.append("")
        lines.append("| ID | Necessity | Status | Evidence |")
        lines.append("|----|-----------|--------|----------|")
        for v in verdicts:
            ev = (v.code_evidence or "").replace("|", "\\|")
            nec = necessity_map.get(v.assumption_id, "—")
            lines.append(f"| {v.assumption_id} | {nec} | {v.status} | {ev} |")
        lines.append("")

    # Find phases
    baseline_ph = next((p for p in phases if p.get("phase") == "baseline"), {})
    attack_ph   = next((p for p in phases if p.get("phase") == "attack"), {})
    control_ph  = next((p for p in phases if p.get("phase") == "control"), {})
    benign_ph   = next((p for p in phases if p.get("phase") == "benign"), {})
    repeat_ph   = next((p for p in phases if p.get("phase") == "repeatability"), {})

    # Exploit summary
    exploit_summary = attack_ph.get("exploit_summary", "")
    if exploit_summary:
        lines.append("### Exploit")
        summary_line = exploit_summary.split("\n")[0]
        lines.append(f"{summary_line}")
        lines.append("")

    lines.append("### Attack Evidence")
    lines.append("")
    lines.append(f"**Phase 2 — Attack ({attack_ph.get('duration_s', 30)}s)**")
    for tl in _fmt_phase_thresholds(attack_ph):
        lines.append(tl)
    lines.append("")

    # Attribution
    if control_ph:
        diff = control_ph.get("differential", {})
        attr = diff.get("attributed", False)
        ratio = diff.get("cpu_ratio", None)
        tls_pp = diff.get("expected_tls_cpu_pp", 0)
        conn_rate = diff.get("attack_conn_rate", 0)
        icon = "**attributed to application layer** ✓" if attr else "NOT attributed (transport overhead)"
        lines.append("**Phase 2c — Differential Attribution**")
        if ratio is not None:
            lines.append(f"- Target CPU delta: +{diff.get('cpu_delta_target',0):.1f} pp | Control CPU delta: +{diff.get('cpu_delta_control',0):.1f} pp")
            lines.append(f"- CPU ratio (control/target): {ratio:.2f} (< 0.50 reject threshold) → {icon}")
        if tls_pp is not None:
            lines.append(f"- TLS overhead: {tls_pp:.1f} pp at {conn_rate:.1f} conn/s — {'negligible' if tls_pp < 5 else 'significant'}")
        lines.append("")

    if benign_ph:
        ratio = benign_ph.get("benign_ratio", None)
        outcome = benign_ph.get("outcome", "")
        if ratio is not None:
            lines.append(f"**Phase 2d — Benign Traffic Comparison:** attack/benign ratio = {ratio:.2f} ({outcome})")
            lines.append("")

    lines.append(f"**Phase 3 — Repeatability**")
    for tl in _fmt_phase_thresholds(repeat_ph):
        lines.append(tl)
    r_outcome = repeat_ph.get("outcome", "confirmed")
    lines.append(f"→ **{r_outcome.upper()}**")
    lines.append("")


def _report_infeasible(lines, ctx, verdicts, findings, notes):
    lines.append("## Why No Weakness\n")
    lines.append("**Stopped at:** Stage 4 — Gap Finder\n")
    lines.append(
        "All required assumptions for the attack were refuted by code analysis. "
        "Exploit execution was skipped.\n"
    )

    if verdicts:
        necessity_map = {}
        if ctx and hasattr(ctx, "assumptions"):
            for a in ctx.assumptions:
                necessity_map[a.id] = getattr(a, "necessity", "—")
        lines.append("### Assumption Analysis")
        lines.append("")
        lines.append("| ID | Necessity | Status | Evidence |")
        lines.append("|----|-----------|--------|----------|")
        for v in verdicts:
            ev = (v.code_evidence or "").replace("|", "\\|")
            nec = necessity_map.get(v.assumption_id, "—")
            lines.append(f"| {v.assumption_id} | {nec} | {v.status} | {ev} |")
        lines.append("")

    lines.append("### Deduction")
    lines.append(
        "The prerequisite conditions for the attack do not hold in this implementation. "
        "The code enforces the invariant(s) the hypothesis assumed were absent. "
        "This is a true negative: the implementation is not vulnerable to this specific attack vector."
    )
    lines.append("")


def _report_no_dos(lines, ctx, plan, verdicts, findings, phases, notes):
    lines.append("## Why No Weakness\n")

    attack_ph = next((p for p in phases if p.get("phase") == "attack"), {})
    escalated = attack_ph.get("escalated", False)

    if attack_ph:
        label = "Phase 2 — Attack (escalated)" if escalated else "Phase 2 — Attack"
        dur = attack_ph.get("escalated_duration_s", attack_ph.get("duration_s", 30))
        lines.append(f"**Stopped at:** {label} ({dur}s) — no thresholds crossed\n")
        lines.append(f"**Exploit summary:** {attack_ph.get('exploit_summary', '').split(chr(10))[0]}\n")
        lines.append(f"**Threshold results:**")
        for tl in _fmt_phase_thresholds(attack_ph):
            lines.append(tl)
        lines.append("")
    else:
        lines.append(f"**Notes:** {notes}\n")

    if findings:
        f = findings[0]
        req = f.requirement if hasattr(f, 'requirement') else {}
        lines.append("### Code Gap")
        lines.append(f"The gap at `{getattr(f, 'code_location', '?')}` exists in the implementation but did not produce measurable resource exhaustion.")
        lines.append("")

    lines.append("### Deduction")
    lines.append(
        "The attack executed successfully but the server absorbed the load without crossing any DoS threshold. "
        "Possible reasons: the gap is mitigated by OS-level scheduling or connection limits; "
        "the attack rate was insufficient; or the vulnerability requires higher concurrency than tested. "
        "This does not prove the code is safe — it means this specific attack parameterization is insufficient."
    )
    lines.append("")


def _report_inconclusive(lines, ctx, plan, verdicts, findings, phases, notes):
    lines.append("## Why Result Is Ambiguous\n")

    attack_ph  = next((p for p in phases if p.get("phase") == "attack"), {})
    control_ph = next((p for p in phases if p.get("phase") == "control"), {})

    if attack_ph:
        lines.append("**Phase 2 — Attack triggered resource increase:**")
        for tl in _fmt_phase_thresholds(attack_ph):
            lines.append(tl)
        lines.append("")

    if control_ph:
        diff = control_ph.get("differential", {})
        ratio = diff.get("cpu_ratio", None)
        transport = diff.get("transport_overhead_confirmed", False)
        lines.append("**Phase 2c — Attribution was ambiguous:**")
        if ratio is not None:
            lines.append(f"- CPU ratio (control/target): {ratio:.2f}")
            if ratio < 0.50:
                lines.append("  → Below 0.50 reject threshold (should be attributed) — check phase notes")
            elif ratio < 0.80:
                lines.append("  → Between 0.50 (reject) and 0.80 (confirm) → **ambiguous zone**")
            else:
                lines.append("  → Above 0.80 confirm threshold → transport overhead confirmed, not the vulnerability")
        if transport:
            lines.append("- Transport overhead confirmed: CPU increase explained by I/O volume, not the specific mechanism")
        lines.append("")

    lines.append(f"**Notes:** {notes}\n")

    lines.append("### Deduction")
    lines.append(
        "The attack causes measurable CPU increase, but the differential test cannot determine whether "
        "it originates from the specific vulnerability mechanism or from generic transport overhead. "
        "To resolve: (1) add a matched benign-load control at the same throughput; "
        "(2) profile with pprof to isolate the hot path; "
        "(3) reduce attack rate until transport overhead is negligible and check if effect persists."
    )
    lines.append("")


def _report_defect(lines, ctx, plan, verdicts, findings, phases, notes):
    lines.append("## Why No Weakness (Attack Not Disproportionate)\n")

    attack_ph  = next((p for p in phases if p.get("phase") == "attack"), {})
    benign_ph  = next((p for p in phases if p.get("phase") == "benign"), {})

    if attack_ph:
        lines.append("**Phase 2 — Attack triggered resource increase:**")
        for tl in _fmt_phase_thresholds(attack_ph):
            lines.append(tl)
        lines.append("")

    if benign_ph:
        a_delta = benign_ph.get("attack_delta_pp", 0)
        b_delta = benign_ph.get("benign_delta_pp", 0)
        ratio   = benign_ph.get("benign_ratio", 0)
        lines.append("**Phase 2d — Benign Comparison (decisive):**")
        lines.append(f"- Attack CPU delta: +{a_delta:.1f} pp")
        lines.append(f"- Benign traffic CPU delta: +{b_delta:.1f} pp")
        lines.append(f"- Benign/attack ratio: {ratio:.2f} (threshold: ≥ 0.80 → not disproportionate)")
        lines.append("")

    lines.append(f"**Notes:** {notes}\n")

    lines.append("### Deduction")
    lines.append(
        "The CPU overhead attributed in Phase 2 is not specific to the attack mechanism — "
        "ordinary well-formed traffic at the same stream rate produces equivalent or greater CPU. "
        "This is a defect in the hypothesis: the QUIC implementation processes resets at similar cost "
        "to normal stream completions, so the stream-cancellation pattern cannot be used as a DoS lever. "
        "Consider: (1) testing at higher concurrency than benign baseline; "
        "(2) targeting state that persists across streams (not per-stream CPU); "
        "(3) revising the hypothesis to focus on memory accumulation rather than CPU."
    )
    lines.append("")


def _report_env_error(lines, notes):
    lines.append("## Pipeline Error\n")
    lines.append(f"**Stopped at:** Environment setup\n")
    lines.append(f"**Error:** {notes}\n")
    lines.append("### Deduction")
    lines.append(
        "The pipeline did not complete due to an infrastructure error (Docker, network, cert, or build failure). "
        "No conclusion about vulnerability presence can be drawn. Fix the environment issue and re-run."
    )
    lines.append("")


def _write_run_report(
    out_dir: Path,
    ctx,
    plan,
    verify_result: dict,
    verdicts: list,
    findings: list,
    pipeline_log: list,
) -> None:
    verdict  = verify_result.get("verdict", "UNKNOWN")
    notes    = verify_result.get("notes", "")
    phases   = verify_result.get("phases", [])
    triggered = verify_result.get("triggered", [])

    hypothesis_verdict = verify_result.get("hypothesis_verdict")

    _meas_emoji = {
        "CONFIRMED_DOS":          "✓",
        "NO_DOS_EFFECT":          "✗",
        "INCONCLUSIVE":           "⚠",
        "INFEASIBLE":             "✗",
        "ENVIRONMENT_ERROR":      "✗",
        "DEFECT":                 "✗",
        "REJECTED":               "✗",
        "ATTACK_UNREPRESENTABLE": "⚠",
        "ATTACK_BLOCKED":         "✗",
    }
    _hyp_emoji = {
        Verdict.DOS_CONFIRMED:                  "✓",
        Verdict.HYPOTHESIS_DISPROVEN:           "✗",
        Verdict.HYPOTHESIS_PARTIALLY_DISPROVEN: "⚠",
        Verdict.HYPOTHESIS_INCONCLUSIVE:        "⚠",
    }
    emoji = _meas_emoji.get(verdict, "?")
    hyp_emoji = _hyp_emoji.get(hypothesis_verdict, "?") if hypothesis_verdict else ""

    et = _derive_evidence_tier(findings, plan, verify_result, verdicts)
    tier_label = {
        EvidenceTier.SOURCE_CODE_WEAKNESS:           "Source-code weakness identified",
        EvidenceTier.THEORETICALLY_EXPLOITABLE:      "Theoretically exploitable",
        EvidenceTier.REPRODUCED_RESOURCE_EXHAUSTION: "Reproduced resource exhaustion",
        EvidenceTier.AVAILABILITY_IMPACT:            "Externally observable availability impact",
    }.get(et["highest"], "No weakness found")

    hyp_line = (
        f"**Hypothesis verdict:** {hypothesis_verdict} {hyp_emoji}"
        if hypothesis_verdict else ""
    )
    lines = [
        "# HypoGenie Run Report", "",
        f"**Run ID:** {run_id}",
        f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Measurement verdict:** {verdict} {emoji}",
    ]
    if hyp_line:
        lines.append(hyp_line)
    lines += [
        f"**Evidence tier:** {tier_label}",
        "", "---", "",
    ]

    if ctx:
        lines += [
            "## Target", "",
            f"- **Repo:** {ctx.repo_url} @ {ctx.version}",
            f"- **Protocol:** {ctx.protocol}",
            f"- **DoS class:** {ctx.dos_class}",
            "", "---", "",
        ]

    # Pipeline table
    lines += ["## Pipeline", "", "| Stage | Status | Detail |", "|-------|--------|--------|"]
    for s in pipeline_log:
        icon = {"ok": "✓", "warn": "⚠", "skipped": "—", "failed": "✗"}.get(s["status"], "?")
        lines.append(f"| {s['stage']}. {s['name']} | {icon} {s['status'].upper()} | {s['detail']} |")
    lines += ["", "---", ""]

    if verdict == "CONFIRMED_DOS":
        _report_confirmed(lines, ctx, plan, verify_result, verdicts, findings, triggered, phases)
    elif verdict == "INFEASIBLE":
        _report_infeasible(lines, ctx, verdicts, findings, notes)
    elif verdict == "NO_DOS_EFFECT":
        _report_no_dos(lines, ctx, plan, verdicts, findings, phases, notes)
    elif verdict == "INCONCLUSIVE":
        _report_inconclusive(lines, ctx, plan, verdicts, findings, phases, notes)
    elif verdict in ("DEFECT", "REJECTED"):
        _report_defect(lines, ctx, plan, verdicts, findings, phases, notes)
    else:
        _report_env_error(lines, notes)

    (out_dir / "run_report.md").write_text("\n".join(lines))
    print(f"  [hypogenie:{run_id}] Run report written.")


def _write_disclosure_draft(out_dir: Path, ctx, plan, result: dict) -> None:
    triggered = result.get("triggered", [])
    attack = result.get("attack", {})

    peak_cpu = max(attack.get("cpu_pct", [0]) or [0])
    peak_mem = max(attack.get("mem_mb",  [0]) or [0])
    lats     = [v for v in attack.get("latency_ms", []) if v is not None]
    peak_lat = max(lats) if lats else 0

    steps_md = "\n".join(
        f"{s.n}. {s.action} (`{s.quic_frame}`)" for s in plan.attack_sequence
    )

    draft = f"""# Responsible Disclosure Draft

**Product:** {ctx.repo_url} @ {ctx.version}
**Protocol:** {ctx.protocol}
**DoS class:** {ctx.dos_class}
**Discovered by:** Idan Efraim (Bar-Ilan University / TAU Deepness Lab)
**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}

## Summary

{plan.expected_effect}

## Technical details

{plan.attack_sequence[0].rationale if plan.attack_sequence else ''}

## Attack sequence

{steps_md}

## Evidence

- Peak CPU: {peak_cpu:.1f}%
- Peak memory: {peak_mem:.1f} MB
- Peak latency: {peak_lat:.0f} ms
- Thresholds triggered: {', '.join(triggered)}

## Findings

Finding type: {plan.finding_type}
{plan.finding_ref}

Severity: {plan.severity}

{('Pivot note: ' + plan.pivot_note) if plan.pivot_note else ''}

## Suggested fix

Apply a per-connection rate limit on stream resets / {getattr(plan, 'dos_class', 'resource_exhaustion')} operations
as recommended by the relevant RFC security considerations section.

## Timeline

- Discovered: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
- Draft: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
- Disclosed to vendor: [PENDING]
"""
    (out_dir / "disclosure_draft.md").write_text(draft)
    print(f"  [hypogenie:{run_id}] Disclosure draft written.")


def _serialize_finding(f) -> dict:
    """Convert a Gap Finder finding dataclass to a JSON-serialisable dict."""
    req = f.requirement
    req_dict = {
        "rfc": req.rfc, "section": req.section,
        "classification": req.classification,
        "requirement_text": req.requirement_text,
        "dos_mechanism": req.dos_mechanism,
    }
    base = {
        "type": type(f).__name__,
        "requirement": req_dict,
        "code_location": f.code_location,
        "code_snippet": f.code_snippet,
    }
    if hasattr(f, "gap_description"):
        base["gap_description"] = f.gap_description
    if hasattr(f, "invariant_description"):
        base["invariant_description"] = f.invariant_description
    base["cwes"] = getattr(f, "cwes", []) or []
    return base


def _serialize_lifecycle(r: "LifecycleResult | None") -> dict | None:
    if r is None:
        return None
    def _sample(s):
        return {
            "batch": s.batch_num, "scenario": s.scenario,
            "cleanup_pending": s.cleanup_pending,
            "active": s.active_ops, "completed": s.completed_ops,
            "cancelled": s.cancelled_ops,
            "context_cancelled": s.context_cancelled,
            "op_terminated": s.op_terminated,
            "resource_released": s.resource_released,
            "outstanding_cleanups": s.outstanding_cleanups,
            "proxy_goroutines": s.proxy_goroutines,
        }

    def _recovery(s):
        return {
            "elapsed_s": s.elapsed_s,
            "outstanding_cleanups": s.outstanding_cleanups,
            "active_ops": s.active_ops,
            "proxy_goroutines": s.proxy_goroutines,
        }

    return {
        "outcome": r.outcome.value,
        "backend_observable": r.backend_observable,
        "proxy_observable": r.proxy_observable,
        "transport_observable": r.transport_observable,
        "observability_limitations": r.observability_limitations,
        "cleanup_pending_trend": r.cleanup_pending_trend,
        "proxy_goroutine_trend": r.proxy_goroutine_trend,
        "recovery_observed": r.recovery_observed,
        "recovery_wait_s": r.recovery_wait_s,
        "peak_cleanup_pending": r.peak_cleanup_pending,
        "peak_outstanding_cleanups": r.peak_outstanding_cleanups,
        "notes": r.notes,
        "batches": [_sample(s) for s in r.batches],
        "control_batches": [_sample(s) for s in r.control_batches],
        "recovery_samples": [_recovery(s) for s in r.recovery_samples],
    }


def _write_outputs(out_dir: Path, ctx, plan, verify_result: dict,
                   verdicts: list, findings: list,
                   lifecycle_result: "LifecycleResult | None" = None,
                   pipeline_log: "list | None" = None,
                   ledger: "AssumptionLedger | None" = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Collect token usage from llm_client accumulator
    token_log = _llm.get_token_log()
    token_log["run_id"] = run_id

    def _clean(d):
        if isinstance(d, dict):
            return {k: _clean(v) for k, v in d.items()}
        if isinstance(d, list):
            return [_clean(v) for v in d]
        return d if d is not None else None

    # ── verdict.json ──────────────────────────────────────────────────────────
    # Assumption verdicts from Gap Finder
    assumption_verdicts = [
        {
            "assumption_id":  v.assumption_id,
            "status":         v.status,
            "reasoning":      v.reasoning,
            "code_evidence":  v.code_evidence,
        }
        for v in (verdicts or [])
    ]

    # Gap Finder findings
    finding_list = [_serialize_finding(f) for f in (findings or [])]

    # Exploit plan steps
    plan_steps = []
    if plan:
        plan_steps = [
            {
                "step":                      s.n,
                "action":                    s.action,
                "frame":                     s.quic_frame,
                "expected_server_response":  s.expected_server_response,
                "rationale":                 s.rationale,
            }
            for s in plan.attack_sequence
        ]

    # Conclusion: how we got to the verdict
    phases = verify_result.get("phases", [])
    triggered = verify_result.get("triggered", [])
    notes = verify_result.get("notes", "")

    reasoning_parts = []
    for ph in phases:
        pname = ph.get("phase", "?")
        if pname == "baseline":
            status = ph.get("outcome", "?")
            reasoning_parts.append(
                f"Phase 1 (baseline, {ph.get('duration_s')}s): {status} — "
                f"cpu={ph.get('cpu_mean_pct')}%, "
                f"lat={ph.get('latency_mean_ms')}ms, "
                f"all_alive={ph.get('all_alive')}"
            )
        elif pname == "attack":
            esc = ph.get("escalated", False)
            trig = ph.get("escalated_triggered", ph.get("triggered", []))
            attr = ph.get("escalated_attributed", ph.get("attributed"))
            reasoning_parts.append(
                f"Phase 2 (attack{' escalated' if esc else ''}, "
                f"{ph.get('escalated_duration_s', ph.get('duration_s'))}s): "
                f"triggered={trig}, attributed={attr}"
            )
        elif pname == "repeatability":
            outcome = ph.get("outcome", "?")
            reasoning_parts.append(
                f"Phase 3 (repeatability): {outcome}, "
                f"triggered={ph.get('triggered', [])}, "
                f"attributed={ph.get('attributed')}"
            )
    conclusion_text = "; ".join(reasoning_parts) + f". Final notes: {notes}"

    evidence_tier = _derive_evidence_tier(findings, plan, verify_result, verdicts)

    verdict_data = {
        "run_id":             run_id,
        "verdict":            verify_result["verdict"],
        "hypothesis_verdict": verify_result.get("hypothesis_verdict"),
        "triggered":          triggered,
        "notes":              notes,
        "evidence_tier":      evidence_tier,

        # target
        "target":    f"{ctx.repo_url}@{ctx.version}" if ctx else "unknown",
        "protocol":  ctx.protocol if ctx else "unknown",
        "dos_class": ctx.dos_class if ctx else "unknown",

        # run config
        "config": {
            "model":     _llm.get_model(_llm.get_provider()),
            "provider":  _llm.get_provider(),
        },

        # conclusion
        "conclusion": {
            "verdict":            verify_result["verdict"],
            "hypothesis_verdict": verify_result.get("hypothesis_verdict"),
            "reasoning":          conclusion_text,
            "phases_run":         [ph.get("phase") for ph in phases],
        },

        # lab tests
        "lab_tests": phases,
        "thresholds_config": verify_result.get("thresholds_config", {}),

        # static analysis
        "assumption_verdicts": assumption_verdicts,
        "assumption_ledger": ledger.to_dict_list() if ledger is not None else None,
        "gap_finder_findings": finding_list,

        # exploit plan
        "exploit_plan": {
            "finding_type":           plan.finding_type if plan else None,
            "finding_ref":            plan.finding_ref if plan else None,
            "severity":               plan.severity if plan else None,
            "expected_effect":        plan.expected_effect if plan else None,
            "assumptions_relied_on":  plan.assumptions_relied_on if plan else [],
            "pivot_note":             plan.pivot_note if plan else None,
            "pivot_candidates":       plan.pivot_candidates if plan else None,
            "attack_steps":           plan_steps,
            "base_attack_steps": [
                {"n": s.n, "action": s.action, "quic_frame": s.quic_frame,
                 "expected_server_response": s.expected_server_response,
                 "rationale": s.rationale}
                for s in plan.base_attack_sequence
            ] if plan and plan.base_attack_sequence else None,
            "amplified_attack_steps": [
                {"n": s.n, "action": s.action, "quic_frame": s.quic_frame,
                 "expected_server_response": s.expected_server_response,
                 "rationale": s.rationale}
                for s in plan.amplified_attack_sequence
            ] if plan and plan.amplified_attack_sequence else None,
            "favorable_assumptions_used": plan.favorable_assumptions_used if plan else [],
        } if plan else None,

        # lifecycle validation
        "lifecycle_validation": _serialize_lifecycle(lifecycle_result),
    }
    (out_dir / "verdict.json").write_text(json.dumps(_clean(verdict_data), indent=2))

    # ── metrics.json ──────────────────────────────────────────────────────────
    metrics_data = {
        "baseline": verify_result.get("baseline", {}),
        "attack":   verify_result.get("attack",   {}),
        "attack2":  verify_result.get("attack2",  {}),
    }
    (out_dir / "metrics.json").write_text(json.dumps(_clean(metrics_data), indent=2))

    # ── token_usage.json ──────────────────────────────────────────────────────
    (out_dir / "token_usage.json").write_text(json.dumps(_clean(token_log), indent=2))

    if verify_result["verdict"] == Verdict.CONFIRMED_DOS:
        _write_disclosure_draft(out_dir, ctx, plan, verify_result)

    _write_run_report(out_dir, ctx, plan, verify_result, verdicts, findings,
                      pipeline_log=pipeline_log or [])

    print(f"  [hypogenie:{run_id}] Outputs in {out_dir}")


# ── single run ────────────────────────────────────────────────────────────────

def run_single(yaml_path: str, run_id_override: str | None = None) -> dict:
    """
    Full pipeline for one hypothesis YAML.
    Returns the verify_result dict (includes 'verdict').
    """
    _id = run_id_override or run_id
    out_dir = _OUTPUT_DIR / _id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"[hypogenie:{_id}] Starting run: {yaml_path}")
    print(f"{'='*60}\n")

    _llm.reset_token_log()
    container_info: dict = {}
    verdicts: list = []
    findings: list = []
    lifecycle_result: "LifecycleResult | None" = None
    pipeline_log: list = []
    _assumptions_refuted_flag: bool = False

    try:
        # ── 1. YAML Parser ─────────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [1/7] YAML Parser ...")
        ctx = parse(yaml_path)
        print(f"  target={ctx.repo_url}@{ctx.version}, protocol={ctx.protocol}")
        pipeline_log.append({"stage": "1/7", "name": "YAML Parser", "status": "ok",
                              "detail": f"{ctx.repo_url}@{ctx.version} | {ctx.protocol}"})

        # ── 2. Clone repo (for Gap Finder) ─────────────────────────────────────
        print(f"[hypogenie:{_id}] [2/7] Clone target repo ...")
        repo_dest = _WORKSPACE / _id / "target"
        repo_dir = _clone_repo(ctx.repo_url, ctx.version, repo_dest)
        pipeline_log.append({"stage": "2/7", "name": "Clone Repo", "status": "ok",
                              "detail": str(repo_dest)})

        # ── 3. Spec Processor ──────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [3/7] Spec Processor ...")
        spec_reqs = spec_run(ctx)
        print(f"  extracted {len(spec_reqs)} spec requirements")
        pipeline_log.append({"stage": "3/7", "name": "Spec Processor", "status": "ok",
                              "detail": f"{len(spec_reqs)} requirements extracted"})

        # ── 4. Gap Finder ──────────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [4/7] Gap Finder ...")
        ledger, findings = gap_run(ctx, spec_reqs, repo_dir)
        verdicts = ledger.to_verdicts()
        print(f"  verdicts={len(verdicts)} findings={len(findings)}")

        # Print per-assumption status table so the terminal always shows each verdict.
        _assumption_status_lines = []
        for _rec in ledger.all():
            _ev = ("; ".join((_rec.evidence.contradicting_evidence
                              or _rec.evidence.supporting_evidence
                              or _rec.evidence.source_refs)[:1]) or "—")[:100]
            _assumption_status_lines.append(
                f"    {_rec.assumption_id} [{_rec.necessity}] {_rec.status.value} — {_ev}"
            )
        print(f"  Assumption analysis ({len(ledger.all())} total):")
        for _line in _assumption_status_lines:
            print(_line)

        # When required assumptions are refuted the pipeline does NOT stop.
        # The Exploit Planner (stage 5) will enumerate bypass/pivot candidates
        # specifically aimed at circumventing the patch.  The verifier (stage 7)
        # then provides empirical confirmation of whether any bypass works.
        # Only if the builder/verifier cannot run does the run end early.
        _assumptions_refuted_flag = ledger.any_critical_refuted()
        if _assumptions_refuted_flag:
            _refuted_ids = [r.assumption_id for r in ledger.critical_refuted()]
            print(f"[hypogenie:{_id}] Required assumption(s) refuted: {_refuted_ids} — "
                  f"continuing to Exploit Planner for patch-bypass pivot enumeration")
            pipeline_log.append({"stage": "4/7", "name": "Gap Finder", "status": "warn",
                                  "detail": (f"assumptions refuted: {_refuted_ids}; "
                                             f"proceeding to pivot enumeration")})
        else:
            pipeline_log.append({"stage": "4/7", "name": "Gap Finder", "status": "ok",
                                  "detail": ""})

        n_confirmed = sum(1 for v in verdicts if v.status == "confirmed")
        # Append detail line only when no warn entry was already added above.
        if not _assumptions_refuted_flag:
            pipeline_log.append({"stage": "4/7", "name": "Gap Finder", "status": "ok",
                                  "detail": f"{len(findings)} finding(s), {n_confirmed}/{len(verdicts)} assumptions confirmed"})

        # ── 4b. Lifecycle applicability assessment ─────────────────────────────
        # Runs after Gap Finder (findings are inputs) and before Exploit Planner
        # (plan is not yet available; score may be supplemented in 7b).
        lc_mode_str = (
            ctx.validation.get("resource_lifecycle", {}).get("mode", "auto")
        )
        lc_mode = LifecycleMode(lc_mode_str)
        lc_plan = None
        if lc_mode is not LifecycleMode.DISABLED:
            lc_applicability = _lc_assess(ctx, findings=findings, plan=None)
            print(
                f"  [lifecycle] applicability={lc_applicability.decision} "
                f"score={lc_applicability.score:.1f}"
            )
            if (
                lc_mode is LifecycleMode.ENABLED
                or lc_applicability.decision in ("applicable", "uncertain")
            ):
                lc_plan = _lc_build_plan(ctx, lc_applicability)

        # ── 5. Exploit Planner ─────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [5/7] Exploit Planner ...")
        plan = plan_run(ctx, verdicts, findings, ledger=ledger)
        print(f"  severity={plan.severity} steps={len(plan.attack_sequence)}")
        pipeline_log.append({"stage": "5/7", "name": "Exploit Planner", "status": "ok",
                              "detail": f"severity={plan.severity}, {len(plan.attack_sequence)} steps"})

        # Re-score lifecycle applicability with plan signals now available
        if lc_mode is not LifecycleMode.DISABLED and lc_plan is None:
            lc_applicability2 = _lc_assess(ctx, findings=findings, plan=plan)
            print(
                f"  [lifecycle] re-score with plan: "
                f"applicability={lc_applicability2.decision} "
                f"score={lc_applicability2.score:.1f}"
            )
            if (
                lc_mode is LifecycleMode.ENABLED
                or lc_applicability2.decision in ("applicable", "uncertain")
            ):
                lc_plan = _lc_build_plan(ctx, lc_applicability2)

        # ── 6. Builder ─────────────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [6/7] Builder ...")
        _release_stale_containers()
        product = _product_from_repo(ctx.repo_url)
        container_info = build(
            product, ctx.version, ctx.entry_point,
            docker_image=ctx.docker_image,
            protocol=ctx.protocol,
            repo_url=ctx.repo_url,
            server_config_hint=getattr(ctx, "server_config", ""),
        )
        container_id   = container_info["container_id"]
        port           = _port_from_entry_point(ctx.entry_point)
        host           = "localhost"
        print(f"  container={container_id[:12]} port={port}")
        pipeline_log.append({"stage": "6/7", "name": "Builder", "status": "ok",
                              "detail": f"container={container_id[:12]}, port={port}"})

        # wait for server to come up
        time.sleep(4)

        # ── 7. DoS Verifier (wraps Exploiter) ──────────────────────────────────
        print(f"[hypogenie:{_id}] [7/7] DoS Verifier ...")

        def _exploit_fn(p, cid, h, prt, dur):
            return exploit_run(p, container_id=cid, host=h, port=prt, attack_duration_s=dur,
                               protocol=ctx.protocol, dos_class=ctx.dos_class,
                               entry_point=ctx.entry_point)

        _control_fn = _make_control_fn(ctx.protocol, ctx.dos_class)
        _benign_fn  = _make_benign_fn(ctx.protocol, ctx.dos_class)
        _persist_fn = _make_persist_fn(ctx.protocol, ctx.dos_class)

        conf_file   = str(_WORKSPACE / _id / "server.conf")
        verify_result = verify_run(
            plan, container_id, host, port,
            exploit_fn=_exploit_fn,
            image=container_info.get("image", ""),
            container_name=f"hypogenie-{_id}",
            ports=container_info.get("ports", ""),
            certs_dir=str(_CERTS_DIR),
            conf_file=conf_file,
            config_path=container_info.get("config_path", ""),
            env_vars=container_info.get("env_vars", {}),
            control_exploit_fn=_control_fn,
            benign_exploit_fn=_benign_fn,
            persist_exploit_fn=_persist_fn,
            has_code_findings=len(findings) > 0,
            protocol=ctx.protocol,
        )

        verdict = verify_result["verdict"]

        # ── 7a. Pivot retry: if base exploit returned INVALID_TEST (attack not representable),
        #    try each pivot candidate as an alternative attack plan.
        #    Pivots represent structural variants (e.g. "bypass rate-limiter") — the base
        #    plan failing to send frames is exactly when alternative angles are most useful.
        _pivot_tried = False
        if verdict == Verdict.INVALID_TEST and plan and plan.pivot_candidates:
            viable_pivots = [
                pv for pv in plan.pivot_candidates
                if pv.get("attack_sequence") and pv.get("status") != "DUPLICATE_OF_ORIGINAL"
            ]
            print(f"[hypogenie:{_id}] Base exploit INVALID_TEST — trying {len(viable_pivots)} pivot(s)...")
            for pv in viable_pivots:
                label = pv.get("label", "pivot")
                print(f"[hypogenie:{_id}] Pivot attempt: {label}")
                try:
                    pivot_plan = _plan_from_pivot(pv, plan)
                    pivot_result = verify_run(
                        pivot_plan, container_id, host, port,
                        exploit_fn=_exploit_fn,
                        image=container_info.get("image", ""),
                        container_name=f"hypogenie-{_id}",
                        ports=container_info.get("ports", ""),
                        certs_dir=str(_CERTS_DIR),
                        conf_file=conf_file,
                        config_path=container_info.get("config_path", ""),
                        env_vars=container_info.get("env_vars", {}),
                        control_exploit_fn=_control_fn,
                        benign_exploit_fn=_benign_fn,
                        persist_exploit_fn=_persist_fn,
                        has_code_findings=len(findings) > 0,
                        protocol=ctx.protocol,
                    )
                    pivot_verdict = pivot_result.get("verdict")
                    frames = pivot_result.get("attack", {}).get("exploit_frames_sent", 0) or 0
                    print(f"[hypogenie:{_id}] Pivot '{label}': verdict={pivot_verdict} frames={frames}")
                    _pivot_tried = True
                    if pivot_verdict not in (Verdict.INVALID_TEST, Verdict.ENVIRONMENT_ERROR):
                        verify_result = pivot_result
                        plan = pivot_plan
                        verdict = pivot_verdict
                        print(f"[hypogenie:{_id}] Pivot '{label}' succeeded — using pivot result")
                        break
                except Exception as e:
                    print(f"[hypogenie:{_id}] Pivot '{label}' error: {e}")
            if _pivot_tried and verdict == Verdict.INVALID_TEST:
                print(f"[hypogenie:{_id}] All pivots returned INVALID_TEST — base verdict stands")

        hypothesis_verdict = _compute_hypothesis_verdict(
            verify_result, verdicts, plan, ctx, ledger=ledger if 'ledger' in dir() else None
        )
        verify_result["hypothesis_verdict"] = hypothesis_verdict

        # Annotate when assumptions were statically refuted but we ran anyway.
        _ledger_ref = ledger if 'ledger' in dir() else None
        if _assumptions_refuted_flag:
            _refuted_ids = [r.assumption_id for r in _ledger_ref.critical_refuted()] if _ledger_ref else []
            if verdict == Verdict.CONFIRMED_DOS:
                verify_result["patch_bypass"] = True
                verify_result["notes"] = (
                    f"PATCH BYPASS CONFIRMED — required assumption(s) {_refuted_ids} were "
                    f"refuted by source analysis but exploit SUCCEEDED. "
                    + (verify_result.get("notes") or "")
                )
            else:
                verify_result["patch_bypass"] = False
                verify_result["notes"] = (
                    f"PATCH CONFIRMED — required assumption(s) {_refuted_ids} refuted by "
                    f"source analysis AND exploit attempt found no effect. "
                    + (verify_result.get("notes") or "")
                )

        # Per-assumption status in result for every run.
        if _ledger_ref is not None:
            verify_result["assumption_analysis"] = [
                {
                    "id":        r.assumption_id,
                    "necessity": r.necessity,
                    "status":    r.status.value,
                    "evidence":  ("; ".join(
                        (r.evidence.contradicting_evidence
                         or r.evidence.supporting_evidence
                         or r.evidence.source_refs)[:2]) or "—")[:200],
                }
                for r in _ledger_ref.all()
            ]

        print(f"\n[hypogenie:{_id}] *** VERDICT: {verdict} | HYPOTHESIS: {hypothesis_verdict} ***\n")
        verifier_status = "ok" if verdict == Verdict.CONFIRMED_DOS else (
            "warn" if verdict == Verdict.INCONCLUSIVE else "failed"
        )
        pipeline_log.append({"stage": "7/7", "name": "DoS Verifier", "status": verifier_status,
                              "detail": f"{verdict} → {hypothesis_verdict}"})

        # ── 7b. Lifecycle Validation (runs after verifier, separate containers) ──
        if lc_plan is not None:
            print(f"[hypogenie:{_id}] [lifecycle] Running lifecycle validation ...")
            workspace_dir = str(_WORKSPACE / _id)
            runner = LifecycleRunner(
                ctx=ctx,
                plan=lc_plan,
                certs_dir=str(_CERTS_DIR),
                workspace=workspace_dir,
            )
            lifecycle_result = runner.run()

        _write_outputs(out_dir, ctx, plan, verify_result, verdicts, findings,
                       lifecycle_result=lifecycle_result, pipeline_log=pipeline_log,
                       ledger=ledger if 'ledger' in dir() else None)
        return verify_result

    except Exception as e:
        import traceback
        print(f"[hypogenie:{_id}] ERROR: {e}")
        traceback.print_exc()
        pipeline_log.append({"stage": "?", "name": "Error", "status": "failed",
                             "detail": str(e)[:120]})
        result = {"verdict": Verdict.ENVIRONMENT_ERROR, "baseline": {}, "attack": {},
                  "attack2": {}, "triggered": [], "phases": [], "thresholds_config": {},
                  "notes": str(e)}
        try:
            _write_outputs(out_dir, ctx if 'ctx' in dir() else None,
                           plan if 'plan' in dir() else None, result, verdicts, findings,
                           lifecycle_result=lifecycle_result, pipeline_log=pipeline_log,
                           ledger=ledger if 'ledger' in dir() else None)
        except Exception:
            pass
        return result

    finally:
        if container_info.get("container_id"):
            try:
                teardown(container_info["container_id"])
            except Exception:
                pass


# ── test suite ────────────────────────────────────────────────────────────────

def run_test_suite(suite_dir: str, expect: str) -> None:
    """
    Run all YAMLs in suite_dir through the full pipeline.
    expect: "CONFIRMED_DOS" or "NO_DOS_EFFECT"
    """
    yamls = sorted(Path(suite_dir).glob("*.yaml"))
    if not yamls:
        print(f"No YAMLs found in {suite_dir}")
        return

    results = []
    for yaml_path in yamls:
        # Each YAML runs in its own subprocess to get a fresh run_id
        cmd = [
            str(_VENV_PYTHON), str(__file__),
            "--input", str(yaml_path),
        ]
        env = {**os.environ,
               "PYTHONPATH": f"{_SRC}:{_AGENTLIB}"}
        result = subprocess.run(cmd, env=env, timeout=1800)
        # read verdict from output directory (last run)
        output_dirs = sorted((_OUTPUT_DIR).glob("*"), key=lambda p: p.stat().st_mtime)
        verdict = "UNKNOWN"
        if output_dirs:
            vf = output_dirs[-1] / "verdict.json"
            if vf.exists():
                verdict = json.loads(vf.read_text()).get("verdict", "UNKNOWN")

        passed = (verdict == expect) or (
            expect == "NO_DOS_EFFECT" and verdict in (
                Verdict.NO_DOS_EFFECT, Verdict.INCONCLUSIVE, Verdict.INFEASIBLE,
                Verdict.DEFECT, Verdict.REJECTED, Verdict.INVALID_TEST)
        )
        results.append((yaml_path.name, verdict, passed))
        status = "✓" if passed else "✗"
        print(f"  {status} {yaml_path.name}: {verdict}")

    n_pass = sum(1 for _, _, p in results if p)
    n_total = len(results)
    print(f"\nTest suite: {n_pass}/{n_total} passed (expect={expect})")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HypoGenie DoS discovery pipeline")
    parser.add_argument("--input", help="Path to hypothesis YAML")
    parser.add_argument("--test-suite", help="Directory of YAML files to run")
    parser.add_argument("--expect", default="CONFIRMED_DOS",
                        choices=["CONFIRMED_DOS", "NO_DOS_EFFECT"],
                        help="Expected verdict for test-suite mode")
    args = parser.parse_args()

    if args.test_suite:
        run_test_suite(args.test_suite, args.expect)
    elif args.input:
        run_single(args.input)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
