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
from datetime import datetime
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
from builder.builder import build, teardown
from exploiter.exploiter import run as exploit_run
from verifier.verifier import run as verify_run, Verdict
import llm_client as _llm

_PROJECT_ROOT = Path(__file__).parent
_OUTPUT_DIR   = _PROJECT_ROOT / "output"
_CERTS_DIR    = _PROJECT_ROOT / "infra" / "certs"
_WORKSPACE    = _PROJECT_ROOT / "workspace" / "runs"
_VENV_PYTHON  = _PROJECT_ROOT / ".venv" / "bin" / "python"


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


def _product_from_repo(repo_url: str) -> str:
    """Extract product name from GitHub URL."""
    return repo_url.rstrip("/").split("/")[-1]


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
**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}

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

- Discovered: {datetime.utcnow().strftime('%Y-%m-%d')}
- Draft: {datetime.utcnow().strftime('%Y-%m-%d')}
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
    return base


def _write_outputs(out_dir: Path, ctx, plan, verify_result: dict,
                   verdicts: list, findings: list) -> None:
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

    verdict_data = {
        "run_id":    run_id,
        "verdict":   verify_result["verdict"],
        "triggered": triggered,
        "notes":     notes,

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
            "verdict":   verify_result["verdict"],
            "reasoning": conclusion_text,
            "phases_run": [ph.get("phase") for ph in phases],
        },

        # lab tests
        "lab_tests": phases,
        "thresholds_config": verify_result.get("thresholds_config", {}),

        # static analysis
        "assumption_verdicts": assumption_verdicts,
        "gap_finder_findings": finding_list,

        # exploit plan
        "exploit_plan": {
            "finding_type":         plan.finding_type if plan else None,
            "finding_ref":          plan.finding_ref if plan else None,
            "severity":             plan.severity if plan else None,
            "expected_effect":      plan.expected_effect if plan else None,
            "assumptions_relied_on": plan.assumptions_relied_on if plan else [],
            "pivot_note":           plan.pivot_note if plan else None,
            "attack_steps":         plan_steps,
        } if plan else None,
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

    try:
        # ── 1. YAML Parser ─────────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [1/7] YAML Parser ...")
        ctx = parse(yaml_path)
        print(f"  target={ctx.repo_url}@{ctx.version}, protocol={ctx.protocol}")

        # ── 2. Clone repo (for Gap Finder) ─────────────────────────────────────
        print(f"[hypogenie:{_id}] [2/7] Clone target repo ...")
        repo_dest = _WORKSPACE / _id / "target"
        repo_dir = _clone_repo(ctx.repo_url, ctx.version, repo_dest)

        # ── 3. Spec Processor ──────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [3/7] Spec Processor ...")
        spec_reqs = spec_run(ctx)
        print(f"  extracted {len(spec_reqs)} spec requirements")

        # ── 4. Gap Finder ──────────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [4/7] Gap Finder ...")
        verdicts, findings = gap_run(ctx, spec_reqs, repo_dir)
        print(f"  verdicts={len(verdicts)} findings={len(findings)}")

        # Assumption gate: if ALL required assumptions are refuted → INFEASIBLE.
        # Findings are ignored here: if every precondition for the attack is proven
        # false, the attack mechanism cannot work regardless of incidental findings
        # the gap finder may have produced (which often contradict the refutation).
        all_required = [a.id for a in ctx.assumptions if a.necessity == "required"]
        required_refuted = [
            a.id for a in ctx.assumptions
            if a.necessity == "required"
            and any(v.assumption_id == a.id and v.status == "refuted" for v in verdicts)
        ]
        all_required_refuted = bool(all_required) and set(required_refuted) == set(all_required)
        if all_required_refuted:
            print(f"[hypogenie:{_id}] All required assumptions refuted → INFEASIBLE")
            result = {"verdict": Verdict.INFEASIBLE, "baseline": {}, "attack": {},
                      "attack2": {}, "triggered": [], "phases": [], "thresholds_config": {},
                      "notes": f"Refuted: {required_refuted}"}
            _write_outputs(out_dir, ctx, None, result, verdicts, findings)
            return result

        # ── 5. Exploit Planner ─────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [5/7] Exploit Planner ...")
        plan = plan_run(ctx, verdicts, findings)
        print(f"  severity={plan.severity} steps={len(plan.attack_sequence)}")

        # ── 6. Builder ─────────────────────────────────────────────────────────
        print(f"[hypogenie:{_id}] [6/7] Builder ...")
        _release_stale_containers()
        product = _product_from_repo(ctx.repo_url)
        container_info = build(
            product, ctx.version, ctx.entry_point,
            docker_image=ctx.docker_image,
            protocol=ctx.protocol,
            repo_url=ctx.repo_url,
        )
        container_id   = container_info["container_id"]
        port           = _port_from_entry_point(ctx.entry_point)
        host           = "localhost"
        print(f"  container={container_id[:12]} port={port}")

        # wait for server to come up
        time.sleep(4)

        # ── 7. DoS Verifier (wraps Exploiter) ──────────────────────────────────
        print(f"[hypogenie:{_id}] [7/7] DoS Verifier ...")

        def _exploit_fn(p, cid, h, prt, dur):
            return exploit_run(p, container_id=cid, host=h, port=prt, attack_duration_s=dur,
                               protocol=ctx.protocol, dos_class=ctx.dos_class)

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
        )

        verdict = verify_result["verdict"]
        print(f"\n[hypogenie:{_id}] *** VERDICT: {verdict} ***\n")

        _write_outputs(out_dir, ctx, plan, verify_result, verdicts, findings)
        return verify_result

    except Exception as e:
        import traceback
        print(f"[hypogenie:{_id}] ERROR: {e}")
        traceback.print_exc()
        result = {"verdict": Verdict.ENVIRONMENT_ERROR, "baseline": {}, "attack": {},
                  "attack2": {}, "triggered": [], "phases": [], "thresholds_config": {},
                  "notes": str(e)}
        try:
            _write_outputs(out_dir, ctx if 'ctx' in dir() else None,
                           plan if 'plan' in dir() else None, result, verdicts, findings)
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
                Verdict.NO_DOS_EFFECT, Verdict.INCONCLUSIVE, Verdict.INFEASIBLE)
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
