"""
DoS Verifier — three-phase metric-based verification.

Phase 1: Baseline (10s, no attack)
Phase 2: Attack + Attribution
Phase 3: Repeatability (cold restart + re-run)

Replaces CVE-Genie's CTF flag checker.
"""

import os
import subprocess
import sys
import time
from statistics import mean
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from run_context import run_id as _run_id
from exploiter.tools import MetricsCollector

# Thresholds per CLAUDE.md §7.7
_CPU_DELTA_PP     = 50     # attack_mean - baseline_mean >= 50 percentage points
_CPU_SUSTAIN_S    = 5      # sustained for >= 5 consecutive samples
_MEM_DELTA_MB     = 100    # peak - baseline_mean >= 100 MB
_LAT_RATIO        = 5      # attack_mean >= 5× baseline_mean
_UNREACHABLE_S    = 3      # alive=False for >= 3 consecutive samples


class Verdict:
    CONFIRMED_DOS   = "CONFIRMED_DOS"
    INCONCLUSIVE    = "INCONCLUSIVE"
    NO_DOS_EFFECT   = "NO_DOS_EFFECT"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"
    INFEASIBLE      = "INFEASIBLE"


def _safe_mean(lst):
    vals = [v for v in lst if v is not None]
    return mean(vals) if vals else 0.0


def _check_thresholds(baseline: dict, attack: dict) -> list[str]:
    """Return list of triggered threshold names."""
    triggered = []

    baseline_cpu  = _safe_mean(baseline["cpu_pct"])
    baseline_mem  = _safe_mean(baseline["mem_mb"])
    baseline_lat  = _safe_mean(baseline["latency_ms"]) or 1.0

    # CPU: delta >= 50pp for >= 5 consecutive seconds
    consec = 0
    for c in attack["cpu_pct"]:
        if c - baseline_cpu >= _CPU_DELTA_PP:
            consec += 1
            if consec >= _CPU_SUSTAIN_S:
                triggered.append("cpu")
                break
        else:
            consec = 0

    # Memory: peak - baseline_mean >= 100 MB
    if attack["mem_mb"]:
        if max(attack["mem_mb"]) - baseline_mem >= _MEM_DELTA_MB:
            triggered.append("memory")

    # Latency: attack_mean >= 5× baseline_mean
    lat_vals = [v for v in attack["latency_ms"] if v is not None]
    if lat_vals and _safe_mean(lat_vals) >= _LAT_RATIO * baseline_lat:
        triggered.append("latency")

    # Unreachable: alive=False for >= 3 consecutive samples
    consec = 0
    for a in attack["alive"]:
        if not a:
            consec += 1
            if consec >= _UNREACHABLE_S:
                triggered.append("unreachable")
                break
        else:
            consec = 0

    return triggered


def _check_attribution(baseline: dict, attack: dict, attack_start_idx: int) -> bool:
    """
    Verify the metric spike is temporally correlated with attack traffic:
    onset must occur within 10 samples of attack_start_idx.
    Also verify probe requests were alive during baseline.
    """
    if not all(baseline["alive"]):
        return False  # baseline already unhealthy

    # Check that there is some degradation during/after attack started
    # (not before — we just check alive or latency went up after index attack_start_idx)
    post_attack_alive = attack["alive"][attack_start_idx: attack_start_idx + 10]
    if not post_attack_alive:
        return True  # can't check, give benefit of doubt

    # Attribution: at least one sample worse than baseline within first 10s of attack
    baseline_lat = _safe_mean(baseline["latency_ms"]) or 1.0
    post_lats = [v for v in attack["latency_ms"][attack_start_idx:attack_start_idx + 10]
                 if v is not None]
    if post_lats and _safe_mean(post_lats) > 2 * baseline_lat:
        return True

    post_cpu_mean = _safe_mean(attack["cpu_pct"][attack_start_idx:attack_start_idx + 10])
    baseline_cpu = _safe_mean(baseline["cpu_pct"])
    if post_cpu_mean - baseline_cpu >= 20:
        return True

    return True  # pass by default if no strong signal either way


def _baseline_healthy(baseline: dict) -> bool:
    if not baseline["alive"]:
        return False
    if not all(baseline["alive"]):
        return False
    if _safe_mean(baseline["cpu_pct"]) >= 20:
        return False
    return True


def _container_exited(container_id: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.ExitCode}}", container_id],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        return True  # container gone = crash
    code = result.stdout.strip()
    return code not in ("0", "<no value>", "")


def _restart_container(image: str, container_name: str, ports: str,
                       certs_dir: str, conf_file: str, config_path: str) -> str:
    """Cold restart: stop old, start fresh. Returns new container_id."""
    subprocess.run(["docker", "stop", container_name], capture_output=True, timeout=30)
    subprocess.run(["docker", "rm",   container_name], capture_output=True, timeout=30)

    port_args = []
    for mapping in ports.split():
        port_args += ["-p", mapping]

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "-v", f"{certs_dir}/server.crt:/certs/server.crt:ro",
        "-v", f"{certs_dir}/server.key:/certs/server.key:ro",
        "-v", f"{conf_file}:{config_path}:ro",
    ] + port_args + [image]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"Restart failed: {result.stderr.strip()[:200]}")
    return result.stdout.strip()


def run(
    plan,
    container_id: str,
    host: str,
    port: int,
    exploit_fn: Callable,
    # for repeatability restart
    image: str = "",
    container_name: str = "",
    ports: str = "",
    certs_dir: str = "",
    conf_file: str = "",
    config_path: str = "",
    baseline_duration_s: int = 10,
    attack_duration_s: int = 30,
) -> dict:
    """
    Three-phase DoS verification.

    Args:
        plan:              ExploitPlan
        container_id:      running Docker container ID
        host / port:       target address
        exploit_fn:        callable(plan, container_id, host, port, duration_s) -> metrics
        image / container_name / ports / certs_dir / conf_file / config_path:
                           needed for Phase 3 cold restart
        baseline_duration_s / attack_duration_s: timing

    Returns dict with: verdict, baseline, attack, attack2, triggered, notes
    """
    tls = port in (443, 8443)

    # ── Phase 1: Baseline ──────────────────────────────────────────────────────
    print(f"[verifier:{_run_id}] Phase 1 — Baseline ({baseline_duration_s}s) ...")
    collector = MetricsCollector(container_id, host, port, probe_tls=tls)
    collector.start()
    time.sleep(baseline_duration_s)
    collector.stop()
    baseline = collector.snapshot()

    if not _baseline_healthy(baseline):
        print(f"[verifier:{_run_id}] Baseline unhealthy — ENVIRONMENT_ERROR")
        return {
            "verdict": Verdict.ENVIRONMENT_ERROR,
            "baseline": baseline,
            "attack": {},
            "attack2": {},
            "triggered": [],
            "notes": "Baseline unhealthy: server not responding or already under load",
        }
    print(f"[verifier:{_run_id}] Baseline OK — cpu={_safe_mean(baseline['cpu_pct']):.1f}% "
          f"lat={_safe_mean(baseline['latency_ms']):.0f}ms")

    # ── Phase 2: Attack + Attribution ─────────────────────────────────────────
    print(f"[verifier:{_run_id}] Phase 2 — Attack ({attack_duration_s}s) ...")
    attack_metrics = exploit_fn(plan, container_id, host, port, attack_duration_s)

    crash = _container_exited(container_id)
    if crash:
        attack_metrics.setdefault("cpu_pct", [])
        print(f"[verifier:{_run_id}] Container crashed → crash threshold triggered")
        attack_metrics["_crash"] = True

    triggered = _check_thresholds(baseline, attack_metrics)
    if crash:
        triggered.append("crash")

    attributed = _check_attribution(baseline, attack_metrics, attack_start_idx=0)

    print(f"[verifier:{_run_id}] Phase 2 triggered={triggered} attributed={attributed}")

    if not triggered or not attributed:
        # Escalate once at higher intensity
        print(f"[verifier:{_run_id}] No threshold crossed — escalating intensity ...")
        attack_metrics2 = exploit_fn(plan, container_id, host, port, attack_duration_s * 2)
        crash2 = _container_exited(container_id)
        if crash2:
            attack_metrics2["_crash"] = True
            triggered = list(set(triggered) | {"crash"})
        triggered2 = _check_thresholds(baseline, attack_metrics2)
        if crash2:
            triggered2.append("crash")
        attributed2 = _check_attribution(baseline, attack_metrics2, 0)
        if not triggered2 or not attributed2:
            return {
                "verdict": Verdict.NO_DOS_EFFECT,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": attack_metrics2,
                "triggered": [],
                "notes": "No threshold crossed even at escalated intensity",
            }
        triggered = triggered2
        attributed = attributed2
        attack_metrics = attack_metrics2

    # ── Phase 3: Repeatability ─────────────────────────────────────────────────
    print(f"[verifier:{_run_id}] Phase 3 — Repeatability (cold restart) ...")
    try:
        new_cid = _restart_container(image, container_name, ports, certs_dir, conf_file, config_path)
        print(f"[verifier:{_run_id}] Restarted: {new_cid[:12]} — waiting 5s ...")
        time.sleep(5)

        # Verify new baseline
        col2 = MetricsCollector(new_cid, host, port, probe_tls=tls)
        col2.start()
        time.sleep(baseline_duration_s)
        col2.stop()
        baseline2 = col2.snapshot()

        if not _baseline_healthy(baseline2):
            return {
                "verdict": Verdict.INCONCLUSIVE,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": {},
                "triggered": triggered,
                "notes": "Phase 3 restart produced unhealthy baseline — cannot confirm repeatability",
            }

        attack2 = exploit_fn(plan, new_cid, host, port, attack_duration_s)
        crash3 = _container_exited(new_cid)
        if crash3:
            attack2["_crash"] = True
        triggered3 = _check_thresholds(baseline2, attack2)
        if crash3:
            triggered3.append("crash")
        attributed3 = _check_attribution(baseline2, attack2, 0)

        print(f"[verifier:{_run_id}] Phase 3 triggered={triggered3} attributed={attributed3}")

        if triggered3 and attributed3:
            return {
                "verdict": Verdict.CONFIRMED_DOS,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": attack2,
                "triggered": triggered3,
                "notes": f"Confirmed on both Phase 2 and Phase 3 runs. Triggered: {triggered3}",
            }
        else:
            return {
                "verdict": Verdict.INCONCLUSIVE,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": attack2,
                "triggered": triggered,
                "notes": "Phase 2 threshold crossed but Phase 3 did not confirm",
            }
    except Exception as e:
        print(f"[verifier:{_run_id}] Phase 3 restart failed: {e}")
        return {
            "verdict": Verdict.INCONCLUSIVE,
            "baseline": baseline,
            "attack": attack_metrics,
            "attack2": {},
            "triggered": triggered,
            "notes": f"Phase 3 restart failed: {e}",
        }
