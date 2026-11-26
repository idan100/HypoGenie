"""
suggest_next — reads a verdict.json and auto-generates new hypothesis YAMLs
from viable pivot candidates.

Entry point: run(verdict_path) -> list[SuggestedHypothesis]
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_client as _llm
from run_context import run_id as _run_id

from .prompts import SYSTEM, USER_TEMPLATE

# Pivot statuses worth generating a new hypothesis for.
_VIABLE_STATUSES = {"SUPPORTED_BY_EVIDENCE", "INCONCLUSIVE"}


@dataclass
class SuggestedHypothesis:
    pivot_id: str
    pivot_label: str
    yaml_text: str
    source_run_id: str
    source_verdict: str
    warnings: list[str] = field(default_factory=list)


def _load_verdict(verdict_path: str) -> dict:
    p = Path(verdict_path)
    if p.is_dir():
        p = p / "verdict.json"
    if not p.exists():
        raise FileNotFoundError(f"verdict.json not found at {verdict_path}")
    with open(p) as f:
        return json.load(f)


def _pivot_attack_steps_text(steps: list) -> str:
    if not steps:
        return "(none recorded)"
    lines = []
    for s in steps:
        n = s.get("n", s.get("step", "?"))
        action = s.get("action", "")
        frame = s.get("quic_frame", s.get("frame", ""))
        exp = s.get("expected_server_response", "")
        line = f"  Step {n}: {action}"
        if frame:
            line += f"  [frame: {frame}]"
        if exp:
            line += f"  → expected: {exp}"
        lines.append(line)
    return "\n".join(lines)


def _assumption_analysis_text(ledger: list) -> str:
    lines = []
    for a in ledger:
        aid = a.get("assumption_id", "?")
        nec = a.get("necessity", "?")
        st = a.get("status", "?")
        con = a.get("contradicting_evidence") or []
        sup = a.get("supporting_evidence") or []
        ev = (con or sup or [])
        ev_str = ev[0][:120] if ev else "—"
        lines.append(f"  {aid} [{nec}] {st}: {ev_str}")
    return "\n".join(lines) if lines else "(none)"


def _extract_phase2_notes(lab_tests: list) -> tuple[str, str, str]:
    """Return (phase2_notes, control_ratio, ambiguity_note)."""
    for ph in lab_tests:
        if ph.get("phase") == "attack":
            trig = ph.get("triggered", [])
            attr = ph.get("attributed")
            notes = f"triggered={trig} attributed={attr}"
            diff = ph.get("differential", {})
            ratio = diff.get("cpu_ratio", "—") if diff else "—"
            p2c_alt = ph.get("benign_alt") or ph.get("persist_alt") or {}
            ambig = ""
            if isinstance(ratio, float) and 0.50 <= ratio < 0.80:
                ambig = (f"CPU ratio={ratio:.2f} in ambiguous zone 0.50–0.80 — "
                         f"cannot distinguish application vs transport overhead")
            elif p2c_alt:
                ambig = (f"Phase 2d-alt: cpu_delta={p2c_alt.get('cpu_delta_pp', '?')}pp "
                         f"(threshold={p2c_alt.get('threshold_pp', '?')}pp)")
            return notes, str(ratio), ambig
    return "—", "—", "—"


def _rank_pivots(candidates: list) -> list:
    """Return pivots sorted best-first: SUPPORTED > INCONCLUSIVE, skip others."""
    order = {"SUPPORTED_BY_EVIDENCE": 0, "INCONCLUSIVE": 1}
    viable = [p for p in candidates if p.get("status") in _VIABLE_STATUSES]
    return sorted(viable, key=lambda p: order.get(p.get("status", ""), 99))


def _generate_yaml(verdict: dict, pivot: dict) -> tuple[str, list[str]]:
    """Call LLM to generate a hypothesis YAML for a given pivot. Returns (yaml_text, warnings)."""
    warnings = []

    # --- target info ---
    target_str = verdict.get("target", "")
    repo, _, version = target_str.partition("@")
    protocol = verdict.get("protocol", "HTTP/2")
    dos_class = verdict.get("dos_class", "resource_exhaustion")

    # Reconstruct entry_point and docker_image from exploit_plan if possible
    ep_obj = verdict.get("exploit_plan") or {}
    entry_point = ep_obj.get("entry_point", "")
    docker_image = ep_obj.get("docker_image", "~")

    # --- original description from verdict notes ---
    notes = verdict.get("notes", "")
    original_desc = notes[:600] if notes else "(see original hypothesis)"

    # --- assumption analysis ---
    ledger = verdict.get("assumption_ledger") or []
    assumption_text = _assumption_analysis_text(ledger)

    # --- pivot fields ---
    pivot_id = pivot.get("pivot_id", "P?")
    pivot_label = pivot.get("label", "unknown pivot")
    pivot_dos_mechanism = pivot.get("dos_mechanism", "")
    pivot_rationale = pivot.get("rationale", "")
    pivot_target_finding = pivot.get("target_finding", "")
    pivot_critic_reason = pivot.get("critic_reason", "")
    pivot_steps_text = _pivot_attack_steps_text(pivot.get("attack_sequence", []))

    # --- empirical results ---
    lab_tests = verdict.get("lab_tests") or []
    phase2_notes, control_ratio, ambiguity_note = _extract_phase2_notes(lab_tests)
    final_verdict = verdict.get("verdict", "INCONCLUSIVE")
    triggered = verdict.get("triggered", [])

    user = USER_TEMPLATE.format(
        repo=repo.strip(),
        version=version.strip(),
        protocol=protocol,
        dos_class=dos_class,
        entry_point=entry_point or "see original",
        docker_image=docker_image or "~",
        original_description=original_desc,
        assumption_analysis=assumption_text,
        pivot_id=pivot_id,
        pivot_label=pivot_label,
        pivot_dos_mechanism=pivot_dos_mechanism,
        pivot_rationale=pivot_rationale,
        pivot_target_finding=pivot_target_finding,
        pivot_critic_reason=pivot_critic_reason,
        pivot_attack_steps=pivot_steps_text,
        verdict=final_verdict,
        triggered=triggered,
        phase2_notes=phase2_notes,
        control_ratio=control_ratio,
        ambiguity_note=ambiguity_note,
    )

    raw = _llm.call_llm(SYSTEM, user, role_env="EXPLOIT_PLANNER_MODEL",
                        max_tokens=2048, json_mode=False)

    # Strip any accidental markdown fences
    yaml_text = raw.strip()
    yaml_text = re.sub(r"^```[a-zA-Z]*\n?", "", yaml_text)
    yaml_text = re.sub(r"\n?```$", "", yaml_text.strip())

    # Basic sanity checks
    if "hypothesis:" not in yaml_text:
        warnings.append("LLM output missing 'hypothesis:' key — may be malformed YAML")
    if "assumptions:" not in yaml_text:
        warnings.append("LLM output missing 'assumptions:' section")
    if "suspected_mechanism:" not in yaml_text:
        warnings.append("LLM output missing 'suspected_mechanism:' section")

    return yaml_text, warnings


def run(verdict_path: str, out_dir: str | None = None, max_suggestions: int = 3) -> list[SuggestedHypothesis]:
    """
    Generate new hypothesis YAMLs from pivot candidates in a verdict.json.

    Args:
        verdict_path:    path to verdict.json or its parent output directory
        out_dir:         where to write suggested_<pivot_id>.yaml files
                         (defaults to suggested/ sibling of verdict.json)
        max_suggestions: max number of suggestions to generate (default: 3)

    Returns:
        list of SuggestedHypothesis dataclasses
    """
    verdict = _load_verdict(verdict_path)
    source_run_id = verdict.get("run_id", "unknown")
    source_verdict = verdict.get("verdict", "UNKNOWN")

    # Determine output directory
    verdict_file = Path(verdict_path)
    if verdict_file.is_dir():
        verdict_file = verdict_file / "verdict.json"
    if out_dir is None:
        out_dir = str(verdict_file.parent / "suggested")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # Get viable pivots
    ep = verdict.get("exploit_plan") or {}
    candidates = ep.get("pivot_candidates") or []

    if not candidates:
        print(f"[suggest_next:{_run_id}] No pivot candidates found in verdict.json")
        print(f"  verdict={source_verdict} — only runs that reached stage 5 have pivots")
        return []

    ranked = _rank_pivots(candidates)
    if not ranked:
        all_statuses = [p.get("status") for p in candidates]
        print(f"[suggest_next:{_run_id}] No viable pivots "
              f"(all statuses: {all_statuses}) — nothing to suggest")
        return []

    to_process = ranked[:max_suggestions]
    print(f"[suggest_next:{_run_id}] {len(ranked)} viable pivot(s) → generating "
          f"{len(to_process)} suggestion(s) ...")

    results = []
    for pivot in to_process:
        pivot_id = pivot.get("pivot_id", "P?")
        pivot_label = pivot.get("label", "unknown")
        print(f"  Generating YAML for {pivot_id}: {pivot_label} ...")

        yaml_text, warnings = _generate_yaml(verdict, pivot)

        fname = f"suggested_{pivot_id.lower().replace(' ', '_')}.yaml"
        fpath = Path(out_dir) / fname
        with open(fpath, "w") as f:
            f.write(yaml_text + "\n")

        for w in warnings:
            print(f"  [suggest_next] WARNING: {w}")

        print(f"  Written: {fpath}")

        results.append(SuggestedHypothesis(
            pivot_id=pivot_id,
            pivot_label=pivot_label,
            yaml_text=yaml_text,
            source_run_id=source_run_id,
            source_verdict=source_verdict,
            warnings=warnings,
        ))

    return results
