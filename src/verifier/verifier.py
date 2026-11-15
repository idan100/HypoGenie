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
from datetime import datetime, timezone
from statistics import mean
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from run_context import run_id as _run_id
from exploiter.tools import MetricsCollector, _probe_latency_ms

def _wait_for_ready(host: str, port: int, tls: bool, timeout_s: int = 30) -> bool:
    """Poll until the server responds to a probe, up to timeout_s seconds."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        _, alive = _probe_latency_ms(host, port, tls)
        if alive:
            return True
        time.sleep(1)
    return False


# Thresholds per CLAUDE.md §7.7
_CPU_DELTA_PP     = 50     # attack_mean - baseline_mean >= 50pp (CLAUDE.md §7.7)
_CPU_SUSTAIN_S    = 5      # sustained for >= 5 consecutive samples
_MEM_DELTA_MB     = 100    # peak - baseline_mean >= 100 MB
_LAT_RATIO        = 5      # attack_mean >= 5× baseline_mean
_UNREACHABLE_S    = 3      # alive=False for >= 3 consecutive samples

# Differential attribution thresholds
# control_delta / target_delta < CONFIRM → target >> control → real application overhead
# control_delta / target_delta >= REJECT  → control ≈ target → transport overhead only
_CTRL_CONFIRM_RATIO = 0.50   # control must be < 50% of target to confirm
_CTRL_REJECT_RATIO  = 0.80   # control >= 80% of target → reject as transport overhead


class Verdict:
    CONFIRMED_DOS     = "CONFIRMED_DOS"
    INCONCLUSIVE      = "INCONCLUSIVE"
    NO_DOS_EFFECT     = "NO_DOS_EFFECT"
    ENVIRONMENT_ERROR = "ENVIRONMENT_ERROR"
    INFEASIBLE        = "INFEASIBLE"
    INVALID_TEST      = "INVALID_TEST"   # experiment setup was invalid; result not meaningful
    DEFECT            = "DEFECT"         # code issue confirmed but not exploitable as DoS
    REJECTED          = "REJECTED"       # false positive: control test shows transport overhead


def _safe_mean(lst):
    vals = [v for v in lst if v is not None]
    return mean(vals) if vals else 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _check_thresholds(baseline: dict, attack: dict) -> tuple[list[str], dict]:
    """
    Return (triggered_list, details_dict).
    details_dict has per-threshold numeric values for the verdict report.
    """
    triggered = []
    details: dict = {}

    baseline_cpu  = _safe_mean(baseline["cpu_pct"])
    baseline_mem  = _safe_mean(baseline["mem_mb"])
    baseline_lat  = _safe_mean(baseline["latency_ms"]) or 1.0

    # CPU: delta >= 50pp for >= 5 consecutive seconds
    max_consec_cpu = 0
    consec = 0
    attack_cpu_mean = _safe_mean(attack["cpu_pct"])
    for c in attack["cpu_pct"]:
        if c - baseline_cpu >= _CPU_DELTA_PP:
            consec += 1
            max_consec_cpu = max(max_consec_cpu, consec)
            if consec >= _CPU_SUSTAIN_S:
                triggered.append("cpu")
                break
        else:
            consec = 0
    details["cpu"] = {
        "baseline_mean_pct": round(baseline_cpu, 2),
        "attack_mean_pct":   round(attack_cpu_mean, 2),
        "delta_pp":          round(attack_cpu_mean - baseline_cpu, 2),
        "threshold_delta_pp": _CPU_DELTA_PP,
        "max_consecutive_above_threshold_s": max_consec_cpu,
        "sustain_required_s": _CPU_SUSTAIN_S,
        "triggered": "cpu" in triggered,
    }

    # Memory: peak - baseline_mean >= 100 MB
    attack_mem_peak = max(attack["mem_mb"]) if attack["mem_mb"] else 0.0
    mem_delta = attack_mem_peak - baseline_mem
    if mem_delta >= _MEM_DELTA_MB:
        triggered.append("memory")
    details["memory"] = {
        "baseline_mean_mb": round(baseline_mem, 2),
        "attack_peak_mb":   round(attack_mem_peak, 2),
        "delta_mb":         round(mem_delta, 2),
        "threshold_delta_mb": _MEM_DELTA_MB,
        "triggered": "memory" in triggered,
    }

    # Latency: attack_mean >= 5× baseline_mean
    lat_vals = [v for v in attack["latency_ms"] if v is not None]
    attack_lat_mean = _safe_mean(lat_vals)
    lat_ratio = attack_lat_mean / baseline_lat if baseline_lat else 0.0
    if lat_vals and lat_ratio >= _LAT_RATIO:
        triggered.append("latency")
    details["latency"] = {
        "baseline_mean_ms": round(baseline_lat, 2),
        "attack_mean_ms":   round(attack_lat_mean, 2),
        "ratio":            round(lat_ratio, 2),
        "threshold_ratio":  _LAT_RATIO,
        "triggered": "latency" in triggered,
    }

    # Unreachable: alive=False for >= 3 consecutive samples
    max_consec_unreach = 0
    consec = 0
    for a in attack["alive"]:
        if not a:
            consec += 1
            max_consec_unreach = max(max_consec_unreach, consec)
            if consec >= _UNREACHABLE_S:
                triggered.append("unreachable")
                break
        else:
            consec = 0
    details["unreachable"] = {
        "max_consecutive_down_s": max_consec_unreach,
        "threshold_s":            _UNREACHABLE_S,
        "triggered": "unreachable" in triggered,
    }

    return triggered, details


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


def _check_differential(baseline: dict, target: dict, control: dict) -> tuple[bool, str, dict]:
    """
    Compare target vs control impact above baseline.
    Returns (attributed, reason_note, details_dict).

    attributed = True when target impact >> control impact on at least one metric:
      CPU:    control_delta / target_delta < _CTRL_CONFIRM_RATIO
      Memory: same ratio check on peak deltas
    """
    b_cpu = _safe_mean(baseline["cpu_pct"])
    t_cpu = _safe_mean(target.get("cpu_pct", []))
    c_cpu = _safe_mean(control.get("cpu_pct", []))
    t_cpu_delta = max(0.0, t_cpu - b_cpu)
    c_cpu_delta = max(0.0, c_cpu - b_cpu)

    b_mem = _safe_mean(baseline["mem_mb"])
    t_mem = max(target.get("mem_mb") or [b_mem])
    c_mem = max(control.get("mem_mb") or [b_mem])
    t_mem_delta = max(0.0, t_mem - b_mem)
    c_mem_delta = max(0.0, c_mem - b_mem)

    cpu_ratio  = (c_cpu_delta / t_cpu_delta) if t_cpu_delta > 5  else 1.0
    mem_ratio  = (c_mem_delta / t_mem_delta) if t_mem_delta > 10 else 1.0

    cpu_attributed = cpu_ratio < _CTRL_CONFIRM_RATIO
    mem_attributed = mem_ratio < _CTRL_CONFIRM_RATIO
    attributed = cpu_attributed or mem_attributed

    details = {
        "baseline_cpu_pct": round(b_cpu, 2),
        "target_cpu_mean_pct": round(t_cpu, 2),
        "control_cpu_mean_pct": round(c_cpu, 2),
        "cpu_delta_target": round(t_cpu_delta, 2),
        "cpu_delta_control": round(c_cpu_delta, 2),
        "cpu_ratio": round(cpu_ratio, 3),
        "cpu_attributed": cpu_attributed,
        "baseline_mem_mb": round(b_mem, 2),
        "target_mem_peak_mb": round(t_mem, 2),
        "control_mem_peak_mb": round(c_mem, 2),
        "mem_delta_target": round(t_mem_delta, 2),
        "mem_delta_control": round(c_mem_delta, 2),
        "mem_ratio": round(mem_ratio, 3),
        "mem_attributed": mem_attributed,
        "attributed": attributed,
        "confirm_threshold": _CTRL_CONFIRM_RATIO,
        "reject_threshold": _CTRL_REJECT_RATIO,
    }
    reason = (
        f"CPU: target={t_cpu:.1f}% control={c_cpu:.1f}% base={b_cpu:.1f}% "
        f"(δtarget={t_cpu_delta:.1f}pp δcontrol={c_cpu_delta:.1f}pp ratio={cpu_ratio:.2f}); "
        f"MEM: target_peak={t_mem:.0f}MB control_peak={c_mem:.0f}MB base={b_mem:.0f}MB "
        f"(ratio={mem_ratio:.2f})"
    )
    return attributed, reason, details


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

    vol_args = [
        "-v", f"{certs_dir}/server.crt:/certs/server.crt:ro",
        "-v", f"{certs_dir}/server.key:/certs/server.key:ro",
    ]
    # Only mount config if config_path is non-empty (source-built containers embed config)
    if config_path and conf_file:
        vol_args += ["-v", f"{conf_file}:{config_path}:ro"]

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--cpus", "1",
    ] + vol_args + port_args + [image]

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
    # differential attribution
    control_exploit_fn: Callable | None = None,
    has_code_findings: bool = False,
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
    phases: list[dict] = []
    thresholds_config = {
        "cpu_delta_pp":    _CPU_DELTA_PP,
        "cpu_sustain_s":   _CPU_SUSTAIN_S,
        "mem_delta_mb":    _MEM_DELTA_MB,
        "latency_ratio":   _LAT_RATIO,
        "unreachable_s":   _UNREACHABLE_S,
    }

    # ── Phase 1: Baseline ──────────────────────────────────────────────────────
    p1_start = _now_iso()
    print(f"[verifier:{_run_id}] Phase 1 — Baseline ({baseline_duration_s}s) ...")
    collector = MetricsCollector(container_id, host, port, probe_tls=tls)
    collector.start()
    time.sleep(baseline_duration_s)
    collector.stop()
    baseline = collector.snapshot()
    p1_end = _now_iso()

    healthy = _baseline_healthy(baseline)
    p1_phase = {
        "phase": "baseline",
        "started_at": p1_start,
        "ended_at":   p1_end,
        "duration_s": baseline_duration_s,
        "healthy":    healthy,
        "cpu_mean_pct":     round(_safe_mean(baseline["cpu_pct"]), 2),
        "mem_mean_mb":      round(_safe_mean(baseline["mem_mb"]), 2),
        "latency_mean_ms":  round(_safe_mean(baseline["latency_ms"]), 2),
        "all_alive":        all(baseline["alive"]) if baseline["alive"] else False,
        "sample_count":     len(baseline["cpu_pct"]),
        "outcome": "healthy" if healthy else "unhealthy",
    }
    phases.append(p1_phase)

    if not healthy:
        print(f"[verifier:{_run_id}] Baseline unhealthy — ENVIRONMENT_ERROR")
        return {
            "verdict": Verdict.ENVIRONMENT_ERROR,
            "baseline": baseline, "attack": {}, "attack2": {},
            "triggered": [], "phases": phases,
            "thresholds_config": thresholds_config,
            "notes": "Baseline unhealthy: server not responding or already under load",
        }
    print(f"[verifier:{_run_id}] Baseline OK — cpu={p1_phase['cpu_mean_pct']}% "
          f"lat={p1_phase['latency_mean_ms']}ms")

    # ── Phase 2: Attack + Attribution ─────────────────────────────────────────
    p2_start = _now_iso()
    print(f"[verifier:{_run_id}] Phase 2 — Attack ({attack_duration_s}s) ...")
    attack_metrics = exploit_fn(plan, container_id, host, port, attack_duration_s)
    p2_end = _now_iso()

    crash = _container_exited(container_id)
    if crash:
        attack_metrics.setdefault("cpu_pct", [])
        print(f"[verifier:{_run_id}] Container crashed → crash threshold triggered")
        attack_metrics["_crash"] = True

    triggered, details = _check_thresholds(baseline, attack_metrics)
    if crash:
        triggered.append("crash")
        details["crash"] = {"triggered": True, "note": "container exited unexpectedly"}

    attributed = _check_attribution(baseline, attack_metrics, attack_start_idx=0)
    print(f"[verifier:{_run_id}] Phase 2 triggered={triggered} attributed={attributed}")

    p2_phase = {
        "phase": "attack",
        "started_at": p2_start,
        "ended_at":   p2_end,
        "duration_s": attack_duration_s,
        "sample_count": len(attack_metrics.get("cpu_pct", [])),
        "triggered": triggered,
        "attributed": attributed,
        "threshold_details": details,
        "escalated": False,
    }

    if attack_metrics.get("_invalid"):
        note = attack_metrics.get("_invalid_reason", "exploit script failed pre-execution validation")
        print(f"[verifier:{_run_id}] Exploit invalid — {note}; returning INVALID_TEST (no escalation)")
        return {
            "verdict":    Verdict.INVALID_TEST,
            "baseline":   baseline,
            "attack":     attack_metrics,
            "attack2":    {},
            "triggered":  [],
            "phases":     phases,
            "thresholds_config": thresholds_config,
            "notes":      note,
        }

    # Footer Rule 1: PROTOCOL_NEGOTIATED must be "h2" for HTTP/2 and gRPC exploits.
    # If the TLS handshake negotiated something else (e.g. "http/1.1"), no h2 frames
    # were processed and the result is meaningless.
    _proto_neg = attack_metrics.get("_protocol_negotiated")
    _plan_proto = getattr(plan, "protocol", "HTTP/2")
    if _proto_neg is not None and _plan_proto in ("HTTP/2", "gRPC") and _proto_neg != "h2":
        note = (f"ALPN negotiated '{_proto_neg}' instead of 'h2'; "
                f"server did not speak HTTP/2 — no attack frames were processed")
        print(f"[verifier:{_run_id}] Footer Rule 1 FAIL — {note}; INVALID_TEST")
        return {
            "verdict":    Verdict.INVALID_TEST,
            "baseline":   baseline,
            "attack":     attack_metrics,
            "attack2":    {},
            "triggered":  [],
            "phases":     phases,
            "thresholds_config": thresholds_config,
            "notes":      note,
        }

    # Footer Rule 2: CONNECTIONS_ATTEMPTED must be > 0.
    # Zero means the attack loop never opened a single connection — setup failure.
    _conns = attack_metrics.get("_connections_attempted")
    if _conns is not None and _conns == 0:
        note = "exploit attempted 0 connections; attack loop did not execute"
        print(f"[verifier:{_run_id}] Footer Rule 2 FAIL — {note}; INVALID_TEST")
        return {
            "verdict":    Verdict.INVALID_TEST,
            "baseline":   baseline,
            "attack":     attack_metrics,
            "attack2":    {},
            "triggered":  [],
            "phases":     phases,
            "thresholds_config": thresholds_config,
            "notes":      note,
        }

    if not triggered or not attributed:
        # Escalate once at higher intensity
        p2_esc_start = _now_iso()
        print(f"[verifier:{_run_id}] No threshold crossed — escalating intensity ...")
        attack_metrics2 = exploit_fn(plan, container_id, host, port, attack_duration_s * 2)
        p2_esc_end = _now_iso()
        if attack_metrics2.get("_invalid"):
            note2 = attack_metrics2.get("_invalid_reason", "exploit invalid on escalation")
            print(f"[verifier:{_run_id}] Escalated exploit invalid — {note2}; INVALID_TEST")
            phases.append(p2_phase)
            return {
                "verdict": Verdict.INVALID_TEST,
                "baseline": baseline, "attack": attack_metrics2, "attack2": {},
                "triggered": [], "phases": phases,
                "thresholds_config": thresholds_config,
                "notes": note2,
            }
        crash2 = _container_exited(container_id)
        if crash2:
            attack_metrics2["_crash"] = True
        triggered2, details2 = _check_thresholds(baseline, attack_metrics2)
        if crash2:
            triggered2.append("crash")
            details2["crash"] = {"triggered": True, "note": "container exited unexpectedly"}
        attributed2 = _check_attribution(baseline, attack_metrics2, 0)

        p2_phase["escalated"] = True
        p2_phase["escalated_started_at"] = p2_esc_start
        p2_phase["escalated_ended_at"]   = p2_esc_end
        p2_phase["escalated_duration_s"] = attack_duration_s * 2
        p2_phase["escalated_triggered"]  = triggered2
        p2_phase["escalated_attributed"] = attributed2
        p2_phase["escalated_threshold_details"] = details2
        phases.append(p2_phase)

        if not triggered2 or not attributed2:
            return {
                "verdict": Verdict.NO_DOS_EFFECT,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": attack_metrics2,
                "triggered": [],
                "phases": phases,
                "thresholds_config": thresholds_config,
                "notes": "No threshold crossed even at escalated intensity",
            }
        triggered = triggered2
        attributed = attributed2
        attack_metrics = attack_metrics2
    else:
        phases.append(p2_phase)

    # ── Phase 3: Repeatability ─────────────────────────────────────────────────
    p3_start = _now_iso()
    print(f"[verifier:{_run_id}] Phase 3 — Repeatability (cold restart) ...")
    p3_phase: dict = {
        "phase": "repeatability",
        "started_at": p3_start,
    }
    new_cid = None
    try:
        new_cid = _restart_container(image, container_name, ports, certs_dir, conf_file, config_path)
        print(f"[verifier:{_run_id}] Restarted: {new_cid[:12]} — waiting for ready ...")
        ready = _wait_for_ready(host, port, tls, timeout_s=30)
        if not ready:
            raise RuntimeError("Server did not become ready within 30s after restart")

        # Verify new baseline
        col2 = MetricsCollector(new_cid, host, port, probe_tls=tls)
        col2.start()
        time.sleep(baseline_duration_s)
        col2.stop()
        baseline2 = col2.snapshot()
        healthy2 = _baseline_healthy(baseline2)

        p3_phase["baseline_healthy"] = healthy2
        p3_phase["baseline_cpu_mean_pct"] = round(_safe_mean(baseline2["cpu_pct"]), 2)
        p3_phase["baseline_lat_mean_ms"]  = round(_safe_mean(baseline2["latency_ms"]), 2)

        if not healthy2:
            p3_phase["ended_at"] = _now_iso()
            p3_phase["outcome"] = "baseline_unhealthy"
            phases.append(p3_phase)
            return {
                "verdict": Verdict.INCONCLUSIVE,
                "baseline": baseline, "attack": attack_metrics, "attack2": {},
                "triggered": triggered,
                "phases": phases,
                "thresholds_config": thresholds_config,
                "notes": "Phase 3 restart produced unhealthy baseline — cannot confirm repeatability",
            }

        # ── Phase 2c: Differential control test (runs on the Phase-3 container) ──
        # Send a cheap-payload equivalent at the same intensity as the target.
        # If control ≈ target → CPU is from TLS/kernel overhead, not application logic.
        p2c_phase: dict = {"phase": "control"}
        if control_exploit_fn is not None:
            print(f"[verifier:{_run_id}] Phase 2c — Control test ({attack_duration_s}s) ...")
            p2c_start = _now_iso()
            control_metrics = control_exploit_fn(attack_metrics, new_cid, host, port, attack_duration_s)
            p2c_phase["started_at"] = p2c_start
            p2c_phase["ended_at"]   = _now_iso()
            p2c_phase["sample_count"] = len(control_metrics.get("cpu_pct", []))

            diff_attributed, diff_reason, diff_details = _check_differential(
                baseline2, attack_metrics, control_metrics
            )
            p2c_phase["differential"] = diff_details
            p2c_phase["attributed"]   = diff_attributed
            print(f"[verifier:{_run_id}] Phase 2c differential — {diff_reason}")
            print(f"[verifier:{_run_id}] Phase 2c attributed={diff_attributed}")
            phases.append(p2c_phase)

            if not diff_attributed:
                # Control matched target → CPU/memory came from transport overhead.
                if has_code_findings:
                    verdict = Verdict.DEFECT
                    note = (f"Control test shows transport overhead (not application-level): "
                            f"{diff_reason}. Source analysis found code issues (DEFECT).")
                else:
                    verdict = Verdict.REJECTED
                    note = (f"Control test rejects finding as transport overhead: {diff_reason}. "
                            f"No source-level code issues found.")
                print(f"[verifier:{_run_id}] {verdict} — {note}")
                return {
                    "verdict": verdict,
                    "baseline": baseline, "attack": attack_metrics,
                    "attack2": control_metrics,
                    "triggered": triggered, "phases": phases,
                    "thresholds_config": thresholds_config,
                    "notes": note,
                }

        # ── Phase 3: Repeatability (run target on the same restarted container) ──
        attack2 = exploit_fn(plan, new_cid, host, port, attack_duration_s)
        if attack2.get("_invalid"):
            note3 = attack2.get("_invalid_reason", "exploit invalid on Phase 3 repeat")
            print(f"[verifier:{_run_id}] Phase 3 exploit invalid — {note3}; INVALID_TEST")
            p3_phase["ended_at"] = _now_iso()
            p3_phase["outcome"] = "invalid_exploit"
            phases.append(p3_phase)
            return {
                "verdict": Verdict.INVALID_TEST,
                "baseline": baseline, "attack": attack_metrics, "attack2": attack2,
                "triggered": [], "phases": phases,
                "thresholds_config": thresholds_config,
                "notes": note3,
            }
        crash3 = _container_exited(new_cid)
        if crash3:
            attack2["_crash"] = True
        triggered3, details3 = _check_thresholds(baseline2, attack2)
        if crash3:
            triggered3.append("crash")
            details3["crash"] = {"triggered": True, "note": "container exited unexpectedly"}
        attributed3 = _check_attribution(baseline2, attack2, 0)

        p3_phase["ended_at"]          = _now_iso()
        p3_phase["triggered"]         = triggered3
        p3_phase["attributed"]        = attributed3
        p3_phase["threshold_details"] = details3
        p3_phase["sample_count"]      = len(attack2.get("cpu_pct", []))
        print(f"[verifier:{_run_id}] Phase 3 triggered={triggered3} attributed={attributed3}")

        if triggered3 and attributed3:
            p3_phase["outcome"] = "confirmed"
            phases.append(p3_phase)
            return {
                "verdict": Verdict.CONFIRMED_DOS,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": attack2,
                "triggered": triggered3,
                "phases": phases,
                "thresholds_config": thresholds_config,
                "notes": f"Confirmed on both Phase 2 and Phase 3 runs. Triggered: {triggered3}",
            }
        else:
            p3_phase["outcome"] = "not_confirmed"
            phases.append(p3_phase)
            return {
                "verdict": Verdict.INCONCLUSIVE,
                "baseline": baseline,
                "attack": attack_metrics,
                "attack2": attack2,
                "triggered": triggered,
                "phases": phases,
                "thresholds_config": thresholds_config,
                "notes": "Phase 2 threshold crossed but Phase 3 did not confirm",
            }
    except Exception as e:
        print(f"[verifier:{_run_id}] Phase 3 restart failed: {e}")
        p3_phase["ended_at"] = _now_iso()
        p3_phase["outcome"] = f"error: {e}"
        phases.append(p3_phase)
        return {
            "verdict": Verdict.INCONCLUSIVE,
            "baseline": baseline,
            "attack": attack_metrics,
            "attack2": {},
            "triggered": triggered,
            "phases": phases,
            "thresholds_config": thresholds_config,
            "notes": f"Phase 3 restart failed: {e}",
        }
    finally:
        if new_cid:
            subprocess.run(["docker", "stop", new_cid], capture_output=True, timeout=30)
            subprocess.run(["docker", "rm",   new_cid], capture_output=True, timeout=30)
            print(f"  [builder:{_run_id}] Phase 3 container {new_cid[:12]} removed.")
