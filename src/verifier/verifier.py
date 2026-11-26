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
import tempfile
import time
import threading
from datetime import datetime, timezone
from statistics import mean
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from run_context import run_id as _run_id
from exploiter.tools import MetricsCollector, _probe_latency_ms
from exploiter.prompts import QUIC_CONTROL_SKELETON_TEMPLATE
from verifier.dynamic_baseline import AttributionEngine as _AttributionEngine, ATTRIBUTED as _ATTR_YES

def _wait_for_ready(host: str, port: int, tls: bool, timeout_s: int = 30,
                    container_id: str = "") -> bool:
    """Poll until the server responds to a probe, up to timeout_s seconds."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        _, alive = _probe_latency_ms(host, port, tls, container_id=container_id)
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
_DISK_DELTA_MB    = 500    # disk used: peak - baseline_mean >= 500 MB (disk_exhaustion class)

# Differential attribution thresholds
# control_delta / target_delta < CONFIRM → target >> control → real application overhead
# control_delta / target_delta >= REJECT  → control ≈ target → transport overhead only
_CTRL_CONFIRM_RATIO = 0.50   # control must be < 50% of target to confirm
_CTRL_REJECT_RATIO  = 0.80   # control >= 80% of target → reject as transport overhead

# In-process CPU profiling via Go pprof admin API
_PPROF_PROFILE_S    = 15     # CPU profile capture duration in seconds
_PPROF_APP_ATTR_PCT = 25.0   # min % of CPU in application code to attribute via pprof
_PPROF_ADMIN_PORTS  = (2019, 6060)  # common Go pprof admin ports to probe

# Benign-equivalent thresholds (Phase 2c-alt / Phase 2d)
# benign_ratio = benign_cpu_delta / attack_cpu_delta
_BENIGN_CONFIRM_RATIO   = 0.50   # below this: attack ≥2× more expensive than normal work
_BENIGN_DOWNGRADE_RATIO = 0.80   # above this: attack ≈ normal work → not disproportionate

# Work-unit type pairs that are considered comparable for rate normalization.
# Same type is always compatible; this table covers cross-type compatible pairs.
_COMPATIBLE_UNIT_PAIRS: frozenset = frozenset({
    frozenset({"h2_stream", "h2_request"}),
})


def _work_units_compatible(type_a: str, type_b: str) -> bool:
    """Return True when attack and benign work unit types are comparable."""
    if not type_a or not type_b:
        return False
    if type_a == type_b:
        return True
    return frozenset({type_a, type_b}) in _COMPATIBLE_UNIT_PAIRS

# TLS calibration: measures per-connection TLS CPU cost during Phase 1b
_TLS_CAL_RATE     = 100   # TCP/TLS handshakes/s during calibration
_TLS_CAL_DURATION = 15    # seconds

# QUIC calibration: QUIC handshakes are more expensive than TCP/TLS,
# so a lower rate avoids saturating the server during the calibration step.
_QUIC_CAL_RATE     = 20   # QUIC handshakes/s during calibration
_QUIC_CAL_DURATION = 15   # seconds

# Matched-calibration: re-run TLS calibration at the attack's actual connection rate
# when the attack rate differs from the fixed Phase 1b rate by more than this factor.
# This gives an empirical, rate-matched per-connection TLS overhead estimate.
_TLS_RECAL_FACTOR  = 2.0  # re-calibrate when |attack_rate / cal_rate| > 2×
_TLS_RECAL_DURATION = 10  # seconds (shorter than Phase 1b to save time)


class Verdict:
    CONFIRMED_DOS          = "CONFIRMED_DOS"
    INCONCLUSIVE           = "INCONCLUSIVE"
    NO_DOS_EFFECT          = "NO_DOS_EFFECT"
    ENVIRONMENT_ERROR      = "ENVIRONMENT_ERROR"
    INFEASIBLE             = "INFEASIBLE"
    INVALID_TEST           = "INVALID_TEST"            # experiment setup was invalid; result not meaningful
    ATTACK_UNREPRESENTABLE = "ATTACK_UNREPRESENTABLE"  # client-side limitation prevents expressing the attack
    ATTACK_BLOCKED         = "ATTACK_BLOCKED"          # server-side mitigation blocked the attack
    DEFECT                 = "DEFECT"                  # code issue confirmed but not exploitable as DoS
    REJECTED               = "REJECTED"                # false positive: control test shows transport overhead

    # Hypothesis-level verdicts (computed after the verifier from measurement + assumption evidence)
    DOS_CONFIRMED                  = "DOS_CONFIRMED"               # reproducible, causally attributed DoS
    HYPOTHESIS_DISPROVEN           = "HYPOTHESIS_DISPROVEN"        # necessary assumptions falsified
    HYPOTHESIS_PARTIALLY_DISPROVEN = "HYPOTHESIS_PARTIALLY_DISPROVEN"  # one path disproven; others untested
    HYPOTHESIS_INCONCLUSIVE        = "HYPOTHESIS_INCONCLUSIVE"     # insufficient evidence either way


def _classify_invalid_reason(reason: str) -> str:
    """
    Map an exploit-invalid reason string to the appropriate semantic verdict.

    Three distinct outcomes — only the last two are evidence-bearing:
      ATTACK_UNREPRESENTABLE — the client library or tooling cannot express
          this attack.  This is a test-infrastructure limitation, NOT evidence
          that the target is patched or resistant.
      ATTACK_BLOCKED — the server explicitly rejected or rate-limited the attack
          at the protocol layer.  This IS evidence of server-side mitigation.
      INVALID_TEST — misconfigured test: wrong port, no connection, bad certs,
          malformed script.  Result is meaningless; fix the setup and retry.

    Never conflate ATTACK_UNREPRESENTABLE with patch effectiveness.
    """
    r = reason.lower()

    # Server-side block / rate-limit signals — checked first because they are
    # more specific; e.g. "refused stream" (server H2 enforcement) must not be
    # masked by "connection refused" (OS-level client failure).
    _blocked_tokens = (
        "blocked", "rate limit", "rate-limit", "rejected by server",
        "max concurrent", "stream limit", "refused by", "policy",
        "server reset", "goaway", "go_away", "stream closed by server",
        "enhance your calm", "refused stream",
    )
    if any(tok in r for tok in _blocked_tokens):
        return Verdict.ATTACK_BLOCKED

    # Client-side library limitations or malformed-test signals.
    # These are NOT evidence of patch effectiveness.
    _unrepresentable_tokens = (
        "alpn", "h2 library", "protocol not supported", "ssl", "library",
        "import", "module", "no module named", "syntax error", "typeerror",
        "attributeerror", "h2.exceptions", "hyperframe", "encoding",
        "script crashed", "failed to connect", "connection refused",
        "timed out", "timeout",
    )
    if any(tok in r for tok in _unrepresentable_tokens):
        return Verdict.ATTACK_UNREPRESENTABLE

    return Verdict.INVALID_TEST


def _safe_mean(lst):
    vals = [v for v in lst if v is not None]
    return mean(vals) if vals else 0.0


def _run_tls_calibration(container_id: str, host: str, port: int,
                          rate: int = _TLS_CAL_RATE,
                          duration: int = _TLS_CAL_DURATION) -> float:
    """
    Measure per-connection TLS handshake CPU cost on the server.

    Opens TLS connections at `rate`/s for `duration` seconds without sending
    any application-layer frames.  MetricsCollector runs in parallel to record
    container CPU.  Returns the mean CPU % observed during calibration.

    Returns 0.0 on any failure so the caller can safely fall back to ratio-only
    differential attribution.
    """
    script = f"""\
import ssl, socket, time, threading

HOST = {repr(host)}
PORT = {port}
RATE = {rate}
DURATION = {duration}

def _connect():
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((HOST, PORT), timeout=2)
        tls = ctx.wrap_socket(s, server_hostname=HOST)
        tls.close()
    except Exception:
        pass

start = time.time()
interval = 1.0 / RATE
while time.time() - start < DURATION:
    threading.Thread(target=_connect, daemon=True).start()
    time.sleep(interval)
time.sleep(1)
"""
    collector = MetricsCollector(container_id, host, port, probe_tls=(port in (443, 8443)))
    collector.start()
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script)
            script_path = f.name
        subprocess.run(
            [sys.executable, script_path],
            capture_output=True, timeout=duration + 10,
        )
    except Exception:
        pass
    finally:
        collector.stop()
        try:
            os.unlink(script_path)
        except Exception:
            pass

    return _safe_mean(collector.snapshot().get("cpu_pct", []))


def _run_quic_calibration(container_id: str, host: str, port: int,
                           rate: int = _QUIC_CAL_RATE,
                           duration: int = _QUIC_CAL_DURATION) -> float:
    """
    Measure per-connection QUIC handshake CPU cost on the server.

    Runs the QUIC control skeleton (handshake-only, zero streams) at `rate`
    connections/s for `duration` seconds. MetricsCollector runs in parallel.
    Returns mean CPU % during calibration, 0.0 on any failure.

    With THREADS=10 in the skeleton, conn_sleep = 10/rate gives the per-thread
    delay needed to achieve the target aggregate rate.
    """
    # THREADS=10 baked into QUIC_CONTROL_SKELETON_TEMPLATE.
    conn_sleep = max(10.0 / rate, 0.001)
    script = (QUIC_CONTROL_SKELETON_TEMPLATE
              .replace("DURATION = 30", f"DURATION = {duration}")
              .replace("__CONN_SLEEP__", f"{conn_sleep:.6f}"))

    collector = MetricsCollector(container_id, host, port, probe_tls=False)
    collector.start()
    script_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script)
            script_path = f.name
        subprocess.run(
            [sys.executable, script_path],
            capture_output=True, timeout=duration + 10,
        )
    except Exception:
        pass
    finally:
        collector.stop()
        if script_path:
            try:
                os.unlink(script_path)
            except Exception:
                pass

    return _safe_mean(collector.snapshot().get("cpu_pct", []))


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

    # Disk: peak used - baseline_mean >= 500 MB (disk_exhaustion dos_class)
    # Skipped when disk_mb was not collected (all zeros → returns 0.0 mean).
    baseline_disk = _safe_mean(baseline.get("disk_mb", []))
    attack_disk_vals = attack.get("disk_mb", [])
    attack_disk_peak = max(attack_disk_vals) if attack_disk_vals else 0.0
    disk_delta = attack_disk_peak - baseline_disk
    if baseline_disk > 0 and disk_delta >= _DISK_DELTA_MB:
        triggered.append("disk")
    details["disk"] = {
        "baseline_mean_mb": round(baseline_disk, 1),
        "attack_peak_mb":   round(attack_disk_peak, 1),
        "delta_mb":         round(disk_delta, 1),
        "threshold_delta_mb": _DISK_DELTA_MB,
        "triggered": "disk" in triggered,
    }

    return triggered, details


_ATTRIBUTION_SUSTAIN_S = 3   # consecutive samples required for correlation evidence
_ATTRIBUTION_CPU_PP    = 20  # CPU delta above baseline to count as elevated (correlation bar,
                             # lower than _CPU_DELTA_PP which is the confirmation bar)


def _check_attribution(baseline: dict, attack: dict, attack_start_idx: int) -> bool:
    """
    Check that attack-period metrics show sustained (not transient) degradation above
    baseline.  Three independent paths — any one suffices:

    1. Latency: mean latency in first 10s > 2× baseline mean (fast onset).
    2. CPU fast onset: mean CPU in first 10s ≥ baseline_cpu + _ATTRIBUTION_CPU_PP.
    3. CPU sustained: ≥ _ATTRIBUTION_SUSTAIN_S consecutive samples anywhere in the
       attack window that each exceed baseline_cpu + _ATTRIBUTION_CPU_PP.
       This catches gradual attacks without accepting single-sample noise.

    Returns False (not attributed) rather than passing by default when none of the
    above conditions hold — single isolated CPU spikes do not satisfy path 3.
    """
    if not all(baseline["alive"]):
        return False  # baseline already unhealthy

    post_attack_alive = attack["alive"][attack_start_idx: attack_start_idx + 10]
    if not post_attack_alive:
        return True  # can't check, give benefit of doubt

    baseline_lat = _safe_mean(baseline["latency_ms"]) or 1.0
    post_lats = [v for v in attack["latency_ms"][attack_start_idx:attack_start_idx + 10]
                 if v is not None]
    if post_lats and _safe_mean(post_lats) > 2 * baseline_lat:
        return True  # path 1: latency onset

    baseline_cpu = _safe_mean(baseline["cpu_pct"])
    elevated = baseline_cpu + _ATTRIBUTION_CPU_PP

    # Path 2: fast-onset CPU mean in first 10 samples
    post_cpu_mean = _safe_mean(attack["cpu_pct"][attack_start_idx:attack_start_idx + 10])
    if post_cpu_mean >= elevated:
        return True

    # Path 3: sustained elevation anywhere in the attack window.
    # Requires _ATTRIBUTION_SUSTAIN_S consecutive samples; a single spike is not enough.
    consec = 0
    for v in attack["cpu_pct"][attack_start_idx:]:
        if v is not None and v >= elevated:
            consec += 1
            if consec >= _ATTRIBUTION_SUSTAIN_S:
                return True
        else:
            consec = 0

    return False  # no sustained metric correlation with attack period


def _baseline_healthy(baseline: dict) -> bool:
    if not baseline["alive"]:
        return False
    if not all(baseline["alive"]):
        return False
    if _safe_mean(baseline["cpu_pct"]) >= 20:
        return False
    return True


def _check_differential(target_baseline: dict, target: dict,
                        control_baseline: dict, control: dict,
                        tls_cpu_per_conn_s: float = 0.0,
                        attack_conn_rate: float = 0.0) -> tuple[bool, str, dict, bool]:
    """
    Compare target vs control impact, each measured against its own container baseline.

    target_baseline:  idle metrics from the same container that ran the attack (Phase 1).
    control_baseline: idle metrics from the same container that ran the control (Phase 3).
    Using separate baselines eliminates cross-container measurement error.

    Returns (attributed, reason_note, details_dict, transport_overhead_confirmed).

    Two independent attribution paths — either one is sufficient:
      1. Ratio path: control_delta / target_delta < _CTRL_CONFIRM_RATIO
      2. Net-app path: (target_delta - predicted_tls_cpu) >= _CPU_DELTA_PP

    transport_overhead_confirmed=True means cpu_ratio >= _CTRL_REJECT_RATIO.
    When attributed=False and transport_overhead_confirmed=False (0.50 ≤ ratio < 0.80),
    the caller should return INCONCLUSIVE rather than REJECTED/DEFECT.

    tls_cpu_per_conn_s: per-connection TLS CPU cost from Phase 1b calibration
    attack_conn_rate:   connections/s during the target attack (from footer)
    """
    tb_cpu = _safe_mean(target_baseline["cpu_pct"])
    cb_cpu = _safe_mean(control_baseline["cpu_pct"])
    t_cpu = _safe_mean(target.get("cpu_pct", []))
    c_cpu = _safe_mean(control.get("cpu_pct", []))
    t_cpu_delta = max(0.0, t_cpu - tb_cpu)
    c_cpu_delta = max(0.0, c_cpu - cb_cpu)

    tb_mem = _safe_mean(target_baseline["mem_mb"])
    cb_mem = _safe_mean(control_baseline["mem_mb"])
    t_mem = max(target.get("mem_mb") or [tb_mem])
    c_mem = max(control.get("mem_mb") or [cb_mem])
    t_mem_delta = max(0.0, t_mem - tb_mem)
    c_mem_delta = max(0.0, c_mem - cb_mem)

    cpu_ratio = (c_cpu_delta / t_cpu_delta) if t_cpu_delta > 5 else 1.0

    # Memory ratio is only meaningful when the target's delta reaches the DoS memory
    # threshold (_MEM_DELTA_MB = 100 MB).  Below that, fluctuations (GC, page-cache
    # variation) produce a noisy ratio that is not evidence of DoS amplification.
    # A sentinel value of 1.0 means "not enough memory signal to attribute."
    mem_ratio = (c_mem_delta / t_mem_delta) if t_mem_delta >= _MEM_DELTA_MB else 1.0
    mem_significant = t_mem_delta >= _MEM_DELTA_MB

    # Net application CPU: subtract the predicted TLS handshake contribution.
    # If the calibration was not run (tls_cpu_per_conn_s == 0), this collapses
    # to t_cpu_delta and the net-app path is irrelevant (ratio path still works).
    expected_tls_cpu  = tls_cpu_per_conn_s * attack_conn_rate
    net_app_cpu_delta = max(0.0, t_cpu_delta - expected_tls_cpu)

    # CPU attribution — evaluated independently of memory.
    cpu_ratio_attributed  = cpu_ratio < _CTRL_CONFIRM_RATIO
    cpu_netapp_attributed = (tls_cpu_per_conn_s > 0 and attack_conn_rate > 0
                             and net_app_cpu_delta >= _CPU_DELTA_PP)
    cpu_attributed = cpu_ratio_attributed or cpu_netapp_attributed

    # Memory attribution — only counted when the delta is DoS-significant.
    # A sub-threshold memory delta (even with ratio=0.00 due to GC variation on the
    # control side) must not drive attributed=True when CPU is ambiguous.
    mem_attributed = mem_significant and mem_ratio < _CTRL_CONFIRM_RATIO

    attributed = cpu_attributed or mem_attributed

    # transport_overhead_confirmed: ratio >= _CTRL_REJECT_RATIO means control ≈ target.
    # Memory transport overhead requires a significant delta for the same reason.
    cpu_transport_overhead = not cpu_netapp_attributed and cpu_ratio >= _CTRL_REJECT_RATIO
    mem_transport_overhead = mem_significant and mem_ratio >= _CTRL_REJECT_RATIO
    transport_overhead_confirmed = (not attributed) and (cpu_transport_overhead or mem_transport_overhead)

    details = {
        # Separate baselines — each delta uses its own container's idle measurement
        "target_baseline_cpu_pct":   round(tb_cpu, 2),
        "control_baseline_cpu_pct":  round(cb_cpu, 2),
        "target_cpu_mean_pct":       round(t_cpu, 2),
        "control_cpu_mean_pct":      round(c_cpu, 2),
        "cpu_delta_target":          round(t_cpu_delta, 2),
        "cpu_delta_control":         round(c_cpu_delta, 2),
        "cpu_ratio":                 round(cpu_ratio, 3),
        "cpu_ratio_attributed":      cpu_ratio_attributed,
        # TLS-calibrated net-app path
        "tls_cpu_per_conn_s":        round(tls_cpu_per_conn_s, 5),
        "attack_conn_rate":          round(attack_conn_rate, 1),
        "expected_tls_cpu_pp":       round(expected_tls_cpu, 2),
        "net_app_cpu_delta_pp":      round(net_app_cpu_delta, 2),
        "cpu_netapp_attributed":     cpu_netapp_attributed,
        "cpu_attributed":            cpu_attributed,
        # Memory
        "target_baseline_mem_mb":    round(tb_mem, 2),
        "control_baseline_mem_mb":   round(cb_mem, 2),
        "target_mem_peak_mb":        round(t_mem, 2),
        "control_mem_peak_mb":       round(c_mem, 2),
        "mem_delta_target":          round(t_mem_delta, 2),
        "mem_delta_control":         round(c_mem_delta, 2),
        "mem_significant":           mem_significant,
        "mem_ratio":                 round(mem_ratio, 3),
        "mem_attributed":            mem_attributed,
        "attributed":                        attributed,
        "transport_overhead_confirmed":      transport_overhead_confirmed,
        "confirm_threshold":                 _CTRL_CONFIRM_RATIO,
        "reject_threshold":                  _CTRL_REJECT_RATIO,
    }

    net_app_note = (
        f" net_app={net_app_cpu_delta:.1f}pp (tls_pred={expected_tls_cpu:.1f}pp)"
        if tls_cpu_per_conn_s > 0 else ""
    )
    reason = (
        f"CPU: target={t_cpu:.1f}%(base={tb_cpu:.1f}%) control={c_cpu:.1f}%(base={cb_cpu:.1f}%) "
        f"(δtarget={t_cpu_delta:.1f}pp δcontrol={c_cpu_delta:.1f}pp ratio={cpu_ratio:.2f})"
        f"{net_app_note}; "
        f"MEM: target_peak={t_mem:.0f}MB(base={tb_mem:.0f}MB) "
        f"control_peak={c_mem:.0f}MB(base={cb_mem:.0f}MB) "
        f"(ratio={mem_ratio:.2f})"
    )
    return attributed, reason, details, transport_overhead_confirmed


# ── pprof — in-process CPU attribution for Go servers ────────────────────────
# Token sets for classifying pprof function names by layer (substring match).
_PPROF_TRANSPORT_TOKENS = (
    "quic-go/", "crypto/tls.", "runtime.gc", "runtime.mallo",
    "syscall.", "net.(*netFD", "net.(*conn.Read",
    "golang.org/x/net/", "net/http.(*Transport",
    "runtime/pprof",
)
_PPROF_APP_TOKENS = (
    # Caddy
    "caddyhttp/", "reverseproxy/", "caddytls/",
    # net/http server-side handlers — any Go HTTP server
    "net/http.(*Server).Serve", "net/http.(*serverConn",
    "net/http.(*response).", "net/http.(*conn).serve",
    "net/http.(*ServeMux", "net/http.HandlerFunc",
    "net/http.(*ServeMux).ServeHTTP", "bufio.",
    # CoreDNS
    "github.com/coredns/", "coredns/",
    # quic-go HTTP/3 application layer (excludes transport internals)
    "github.com/quic-go/quic-go/http3",
    # gRPC-Go application layer
    "google.golang.org/grpc/",
    # Generic Go HTTP handler patterns
    "ServeHTTP", ".HandleFunc(",
    # RabbitMQ / AMQP Go client
    "github.com/rabbitmq/",
    # NATS
    "github.com/nats-io/",
    # Envoy / MOSN / generic proxy Go
    "github.com/envoyproxy/", "mosn.io/",
)


def _pprof_find_port(container_id: str) -> int | None:
    """Probe common pprof admin ports inside the container. Returns port or None."""
    for port in _PPROF_ADMIN_PORTS:
        r = subprocess.run(
            ["docker", "exec", container_id, "sh", "-c",
             f"curl -sf http://localhost:{port}/debug/pprof/ > /dev/null 2>&1"],
            capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            return port
    return None


def _pprof_capture(container_id: str, admin_port: int, duration_s: int) -> dict | None:
    """
    Capture a CPU profile from the container's Go pprof endpoint.
    Returns classification dict or None on any failure.
    """
    print(f"  [pprof] Capturing {duration_s}s CPU profile "
          f"(container {container_id[:12]}, port {admin_port}) ...")
    inner_path = "/tmp/_hypogenie_pprof.pb.gz"
    capture_cmd = (
        f"curl -sf 'http://localhost:{admin_port}/debug/pprof/profile?seconds={duration_s}'"
        f" -o {inner_path}"
    )
    r = subprocess.run(
        ["docker", "exec", container_id, "sh", "-c", capture_cmd],
        capture_output=True, timeout=duration_s + 15,
    )
    if r.returncode != 0:
        print(f"  [pprof] Profile capture failed (exit {r.returncode})")
        return None

    local_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pb.gz", delete=False) as tmp:
            local_path = tmp.name
        cp = subprocess.run(
            ["docker", "cp", f"{container_id}:{inner_path}", local_path],
            capture_output=True, timeout=15,
        )
        if cp.returncode != 0:
            return None
        return _pprof_analyze(local_path)
    finally:
        if local_path:
            try:
                os.unlink(local_path)
            except OSError:
                pass


def _pprof_analyze(profile_path: str) -> dict | None:
    """Run `go tool pprof -text` and classify CPU usage by layer."""
    r = subprocess.run(
        ["go", "tool", "pprof", "-text", "-nodecount=200", profile_path],
        capture_output=True, text=True, timeout=20,
    )
    if r.returncode != 0:
        print(f"  [pprof] go tool pprof not available — skipping in-process profiling")
        return None
    return _pprof_classify(r.stdout)


def _pprof_classify(pprof_text: str) -> dict | None:
    """
    Parse `go tool pprof -text` output and classify CPU by layer.

    Format per line: flat  flat%  sum%  cum  cum%  <function name>
    Returns {app_pct, transport_pct, unknown_pct, total_s, top_functions} or None.
    """
    app_s = transport_s = unknown_s = 0.0
    top: list[tuple[float, str]] = []

    for line in pprof_text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            flat_str = parts[0]
            if not flat_str.endswith("s"):
                continue
            flat_s = float(flat_str[:-1])
            if flat_s <= 0:
                continue
        except ValueError:
            continue

        fn_name = " ".join(parts[5:])
        if any(tok in fn_name for tok in _PPROF_APP_TOKENS):
            app_s += flat_s
        elif any(tok in fn_name for tok in _PPROF_TRANSPORT_TOKENS):
            transport_s += flat_s
        else:
            unknown_s += flat_s

        top.append((flat_s, fn_name))

    top.sort(reverse=True)
    total = app_s + transport_s + unknown_s
    if total <= 0:
        return None

    return {
        "app_pct":       round(100 * app_s / total, 1),
        "transport_pct": round(100 * transport_s / total, 1),
        "unknown_pct":   round(100 * unknown_s / total, 1),
        "total_s":       round(total, 2),
        "top_functions": [(fn, round(s, 3)) for s, fn in top[:10]],
    }


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
                       certs_dir: str, conf_file: str, config_path: str,
                       env_vars: dict | None = None) -> str:
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

    env_args = []
    for k, v in (env_vars or {}).items():
        env_args += ["-e", f"{k}={v}"]

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--cpus", "1",
    ] + vol_args + env_args + port_args + [image]

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
    env_vars: dict | None = None,
    baseline_duration_s: int = 10,
    attack_duration_s: int = 30,
    # differential attribution
    control_exploit_fn: Callable | None = None,
    benign_exploit_fn: Callable | None = None,
    has_code_findings: bool = False,
    protocol: str = "",
    lifecycle_validation_plan=None,  # LifecycleValidationPlan | None — reserved for future use
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
    tls = port in (443, 8443, 853)  # 853 = DNS-over-TLS
    phases: list[dict] = []
    thresholds_config = {
        "cpu_delta_pp":    _CPU_DELTA_PP,
        "cpu_sustain_s":   _CPU_SUSTAIN_S,
        "mem_delta_mb":    _MEM_DELTA_MB,
        "latency_ratio":   _LAT_RATIO,
        "unreachable_s":   _UNREACHABLE_S,
        "disk_delta_mb":   _DISK_DELTA_MB,
    }

    # ── Phase 1: Baseline ──────────────────────────────────────────────────────
    # Wait for the server to accept connections before measuring baseline.
    # Slow-starting runtimes (Erlang/OTP, JVM, etc.) can spike CPU during
    # init; measuring before they settle produces false ENVIRONMENT_ERROR.
    print(f"[verifier:{_run_id}] Waiting for server ready (up to 60s) ...")
    if not _wait_for_ready(host, port, tls, timeout_s=60, container_id=container_id):
        return {
            "verdict": "ENVIRONMENT_ERROR",
            "triggered": [],
            "notes": "Server did not become reachable within 60s of startup",
            "lab_tests": [],
            "thresholds_config": thresholds_config,
        }
    # Poll until container CPU settles below the baseline threshold.
    # Erlang/OTP, JVM, and similar runtimes accept connections while still
    # doing expensive init work; a fixed sleep is not sufficient.
    _settle_deadline = time.time() + 90
    _settle_target   = 15  # pp; just under _baseline_healthy's 20pp limit
    print(f"[verifier:{_run_id}] Waiting for CPU to settle below {_settle_target}% ...")
    while time.time() < _settle_deadline:
        try:
            r = subprocess.run(
                ["docker", "stats", container_id, "--no-stream", "--no-trunc",
                 "--format", "{{.CPUPerc}}"],
                capture_output=True, text=True, timeout=5,
            )
            cpu_s = r.stdout.strip().rstrip("%")
            if cpu_s and float(cpu_s) < _settle_target:
                break
        except Exception:
            pass
        time.sleep(2)
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

    # ── Phase 1b: connection-cost calibration ─────────────────────────────────
    # Measures per-connection CPU overhead so _check_differential can subtract
    # it mathematically (net_app path) even when the control test fails.
    # TCP/TLS: TCP+TLS handshakes at 100/s.  QUIC: QUIC handshakes at 20/s.
    # Skipped for plain TCP (no TLS) and for QUIC without protocol tag.
    tls_cpu_per_conn_s = 0.0
    is_quic = protocol.upper().startswith("QUIC")
    if tls:
        if is_quic:
            print(f"[verifier:{_run_id}] Phase 1b — QUIC calibration "
                  f"({_QUIC_CAL_DURATION}s at {_QUIC_CAL_RATE}/s) ...")
            cal_cpu  = _run_quic_calibration(container_id, host, port)
            cal_rate = _QUIC_CAL_RATE
        else:
            print(f"[verifier:{_run_id}] Phase 1b — TLS calibration "
                  f"({_TLS_CAL_DURATION}s at {_TLS_CAL_RATE}/s) ...")
            cal_cpu  = _run_tls_calibration(container_id, host, port)
            cal_rate = _TLS_CAL_RATE
        idle_cpu = _safe_mean(baseline["cpu_pct"])
        # Net handshake cost above idle, normalised to per-connection CPU-seconds.
        tls_cpu_per_conn_s = max(0.0, cal_cpu - idle_cpu) / cal_rate
        baseline["tls_cpu_per_conn_s"] = round(tls_cpu_per_conn_s, 5)
        p1_phase["tls_cal_cpu_pct"]    = round(cal_cpu, 2)
        p1_phase["tls_cpu_per_conn_s"] = round(tls_cpu_per_conn_s, 5)
        label = "QUIC cal" if is_quic else "TLS cal"
        print(f"[verifier:{_run_id}] {label}: cpu={cal_cpu:.1f}% "
              f"idle={idle_cpu:.1f}% per_conn_s={tls_cpu_per_conn_s:.4f}%")

    # Probe for Go pprof admin API — available on most Go servers at :2019 or :6060.
    # Used in Phase 2c to break differential ambiguity via in-process CPU classification.
    pprof_port: int | None = _pprof_find_port(container_id) if tls else None
    pprof_data: dict | None = None
    if pprof_port:
        print(f"[verifier:{_run_id}] pprof admin API found on port {pprof_port}")

    # ── Phase 2: Attack + Attribution ─────────────────────────────────────────
    # Start pprof CPU capture concurrently so a profile is ready for Phase 2c.
    _pprof_box: list = [None]
    def _pprof_bg() -> None:
        _pprof_box[0] = _pprof_capture(container_id, pprof_port, _PPROF_PROFILE_S)
    _pprof_t: threading.Thread | None = None
    if pprof_port:
        _pprof_t = threading.Thread(target=_pprof_bg, daemon=True)
        _pprof_t.start()

    p2_start = _now_iso()
    print(f"[verifier:{_run_id}] Phase 2 — Attack ({attack_duration_s}s) ...")
    attack_metrics = exploit_fn(plan, container_id, host, port, attack_duration_s)
    p2_end = _now_iso()

    if _pprof_t is not None:
        _pprof_t.join(timeout=_PPROF_PROFILE_S + 10)
    pprof_data = _pprof_box[0]

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
        _invalid_verdict = _classify_invalid_reason(note)
        print(f"[verifier:{_run_id}] Exploit invalid — {note}; returning {_invalid_verdict} (no escalation)")
        return {
            "verdict":    _invalid_verdict,
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
    # were processed and the result is meaningless.  This is a client-side TLS/ALPN
    # limitation — it is NOT evidence that the target is patched.
    _proto_neg = attack_metrics.get("_protocol_negotiated")
    _plan_proto = getattr(plan, "protocol", "HTTP/2")
    if _proto_neg is not None and _plan_proto in ("HTTP/2", "gRPC") and _proto_neg != "h2":
        note = (f"ALPN negotiated '{_proto_neg}' instead of 'h2'; "
                f"server did not speak HTTP/2 — no attack frames were processed")
        print(f"[verifier:{_run_id}] Footer Rule 1 FAIL — {note}; ATTACK_UNREPRESENTABLE")
        return {
            "verdict":    Verdict.ATTACK_UNREPRESENTABLE,
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
        # Escalate once at higher intensity — also capture a fresh pprof profile.
        p2_esc_start = _now_iso()
        print(f"[verifier:{_run_id}] No threshold crossed — escalating intensity ...")
        _pprof_box_e: list = [None]
        def _pprof_bg_e() -> None:
            _pprof_box_e[0] = _pprof_capture(container_id, pprof_port, _PPROF_PROFILE_S)
        _pprof_t_e: threading.Thread | None = None
        if pprof_port:
            _pprof_t_e = threading.Thread(target=_pprof_bg_e, daemon=True)
            _pprof_t_e.start()
        attack_metrics2 = exploit_fn(plan, container_id, host, port, attack_duration_s * 2)
        p2_esc_end = _now_iso()
        if _pprof_t_e is not None:
            _pprof_t_e.join(timeout=_PPROF_PROFILE_S + 10)
        if _pprof_box_e[0] is not None:
            pprof_data = _pprof_box_e[0]
        if attack_metrics2.get("_invalid"):
            note2 = attack_metrics2.get("_invalid_reason", "exploit invalid on escalation")
            _esc_verdict = _classify_invalid_reason(note2)
            print(f"[verifier:{_run_id}] Escalated exploit invalid — {note2}; {_esc_verdict}")
            phases.append(p2_phase)
            return {
                "verdict": _esc_verdict,
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

    # ── Phase 1c: Matched TLS calibration (optional, runs after Phase 2) ─────────
    # Phase 1b calibrates at _TLS_CAL_RATE (100/s).  If the attack used a
    # substantially different connection rate (more than _TLS_RECAL_FACTOR×), the
    # per-connection TLS estimate may be inaccurate due to rate-dependent parallelism
    # effects.  Running a matched calibration at the attack's actual rate gives an
    # empirical baseline that is used by _check_differential's net-app attribution path.
    # Skipped when: no TLS, no footer data, rate is similar to Phase 1b, or QUIC.
    if tls and not is_quic:
        _atk_conns_1c = attack_metrics.get("_connections_attempted", 0) or 0
        _atk_life_1c  = attack_metrics.get("_avg_lifetime_s", 30.0) or 30.0
        _short_lived_1c = _atk_life_1c < 2.0
        if _short_lived_1c and _atk_conns_1c > 0:
            _actual_rate_1c = _atk_conns_1c / attack_duration_s
            _cal_rate_1c    = _TLS_CAL_RATE
            _rate_ratio_1c  = max(_actual_rate_1c, 1.0) / max(_cal_rate_1c, 1.0)
            if _rate_ratio_1c > _TLS_RECAL_FACTOR or _rate_ratio_1c < 1.0 / _TLS_RECAL_FACTOR:
                _recal_rate = max(5, min(int(_actual_rate_1c), 300))
                print(f"[verifier:{_run_id}] Phase 1c — matched TLS calibration "
                      f"({_TLS_RECAL_DURATION}s at {_recal_rate}/s, "
                      f"attack was {_actual_rate_1c:.0f}/s vs Phase 1b {_cal_rate_1c}/s) ...")
                _recal_cpu  = _run_tls_calibration(container_id, host, port,
                                                   rate=_recal_rate,
                                                   duration=_TLS_RECAL_DURATION)
                _idle_cpu_1c = _safe_mean(baseline["cpu_pct"])
                _new_per_conn = max(0.0, _recal_cpu - _idle_cpu_1c) / _recal_rate
                print(f"[verifier:{_run_id}] Phase 1c matched cal: cpu={_recal_cpu:.1f}% "
                      f"idle={_idle_cpu_1c:.1f}% per_conn={_new_per_conn:.5f}% "
                      f"(was {tls_cpu_per_conn_s:.5f}%)")
                tls_cpu_per_conn_s = _new_per_conn
                baseline["tls_cpu_per_conn_s"] = round(tls_cpu_per_conn_s, 5)

    # ── Phase 3: Repeatability ─────────────────────────────────────────────────
    p3_start = _now_iso()
    print(f"[verifier:{_run_id}] Phase 3 — Repeatability (cold restart) ...")
    p3_phase: dict = {
        "phase": "repeatability",
        "started_at": p3_start,
    }
    new_cid = None
    try:
        new_cid = _restart_container(image, container_name, ports, certs_dir, conf_file, config_path, env_vars)
        print(f"[verifier:{_run_id}] Restarted: {new_cid[:12]} — waiting for ready ...")
        ready = _wait_for_ready(host, port, tls, timeout_s=60, container_id=new_cid)
        if not ready:
            raise RuntimeError("Server did not become ready within 60s after restart")
        # After a heavy attack phase the host CPU needs time to cool down before
        # we can take a valid Phase 3 baseline.
        _p3_settle_deadline = time.time() + 120
        _p3_settle_target   = 15
        print(f"[verifier:{_run_id}] Waiting for Phase 3 CPU to settle below {_p3_settle_target}% ...")
        while time.time() < _p3_settle_deadline:
            try:
                r = subprocess.run(
                    ["docker", "stats", new_cid, "--no-stream", "--no-trunc",
                     "--format", "{{.CPUPerc}}"],
                    capture_output=True, text=True, timeout=5,
                )
                cpu_s = r.stdout.strip().rstrip("%")
                if cpu_s and float(cpu_s) < _p3_settle_target:
                    break
            except Exception:
                pass
            time.sleep(2)

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
        benign_already_run: bool = False
        # Attribution tracking: did Phase 2c run, and was differential attribution confirmed?
        # Used by AttributionEngine.check_control_requirement() before CONFIRMED_DOS.
        _p2c_ran: bool = False
        _p2c_diff_attributed: bool = False
        p2c_phase: dict = {"phase": "control"}
        if control_exploit_fn is not None:
            print(f"[verifier:{_run_id}] Phase 2c — Control test ({attack_duration_s}s) ...")
            p2c_start = _now_iso()
            control_metrics = control_exploit_fn(attack_metrics, new_cid, host, port, attack_duration_s)
            p2c_phase["started_at"] = p2c_start
            p2c_phase["ended_at"]   = _now_iso()
            p2c_phase["sample_count"] = len(control_metrics.get("cpu_pct", []))

            # Derive connection rate from attack metrics for TLS-calibrated attribution.
            _atk_conns = attack_metrics.get("_connections_attempted", 0)
            _atk_dur   = attack_metrics.get("_duration_s", attack_duration_s) or attack_duration_s
            attack_conn_rate = _atk_conns / _atk_dur if _atk_conns else 0.0

            diff_attributed, diff_reason, diff_details, transport_confirmed = _check_differential(
                target_baseline=baseline,     # Phase 1: same container as attack
                target=attack_metrics,
                control_baseline=baseline2,   # Phase 3: same container as control
                control=control_metrics,
                tls_cpu_per_conn_s=tls_cpu_per_conn_s,
                attack_conn_rate=attack_conn_rate,
            )
            p2c_phase["differential"] = diff_details
            p2c_phase["attributed"]   = diff_attributed
            print(f"[verifier:{_run_id}] Phase 2c differential — {diff_reason}")
            print(f"[verifier:{_run_id}] Phase 2c attributed={diff_attributed} transport_confirmed={transport_confirmed}")
            phases.append(p2c_phase)
            # Record that Phase 2c ran; diff_attributed will be updated after the
            # fall-through logic below if secondary evidence changes the decision.
            _p2c_ran = True
            _p2c_diff_attributed = diff_attributed

            if not diff_attributed:
                if not transport_confirmed:
                    # Ambiguous zone: 0.50 ≤ ratio < 0.80.
                    # Two secondary signals can break the tie before returning INCONCLUSIVE:
                    #  1. Complete-request baseline (Phase 2c-alt): run benign_exploit_fn.
                    #     benign_ratio = FIN-stream CPU delta / RESET-stream CPU delta.
                    #     < _BENIGN_CONFIRM_RATIO   → cancellation ≥2× costlier than normal work
                    #     ≥ _BENIGN_DOWNGRADE_RATIO → RESET ≈ FIN cost → not disproportionate
                    #  2. pprof: in-process CPU fraction in application-layer code.
                    _p2c_alt_ratio: float | None = None
                    if benign_exploit_fn is not None:
                        print(f"[verifier:{_run_id}] Phase 2c-alt — Complete-request baseline "
                              f"({attack_duration_s}s) ...")
                        _p2c_alt_m = benign_exploit_fn(
                            attack_metrics, new_cid, host, port, attack_duration_s
                        )
                        _alt_base   = _safe_mean(baseline.get("cpu_pct", []))
                        _alt_idle   = _safe_mean(baseline2.get("cpu_pct", []))
                        _alt_atk    = _safe_mean(attack_metrics.get("cpu_pct", []))
                        _alt_ben    = _safe_mean(_p2c_alt_m.get("cpu_pct", []))
                        _alt_adelta = max(_alt_atk - _alt_base, 0.1)
                        _alt_bdelta = max(_alt_ben - _alt_idle, 0.0)
                        _p2c_alt_ratio = round(_alt_bdelta / _alt_adelta, 3)
                        p2c_phase["benign_alt"] = {
                            "benign_cpu_pct":  round(_alt_ben, 2),
                            "idle_cpu_pct":    round(_alt_idle, 2),
                            "attack_delta_pp": round(_alt_adelta, 2),
                            "benign_delta_pp": round(_alt_bdelta, 2),
                            "benign_ratio":    _p2c_alt_ratio,
                        }
                        benign_already_run = True
                        print(f"[verifier:{_run_id}] Phase 2c-alt benign_ratio={_p2c_alt_ratio:.3f} "
                              f"(attack+{_alt_adelta:.1f}pp  benign+{_alt_bdelta:.1f}pp  "
                              f"idle={_alt_idle:.1f}%)")

                    _pprof_app     = pprof_data.get("app_pct", 0.0) if pprof_data else 0.0
                    _benign_attrs  = (_p2c_alt_ratio is not None
                                      and _p2c_alt_ratio < _BENIGN_CONFIRM_RATIO)
                    _benign_downgr = (_p2c_alt_ratio is not None
                                      and _p2c_alt_ratio >= _BENIGN_DOWNGRADE_RATIO)
                    _pprof_breaks  = pprof_data is not None and _pprof_app >= _PPROF_APP_ATTR_PCT

                    if _benign_downgr:
                        note = (f"Phase 2c ambiguous (ratio={diff_details['cpu_ratio']:.3f}). "
                                f"Complete-request baseline: benign_ratio={_p2c_alt_ratio:.3f} "
                                f"(≥{_BENIGN_DOWNGRADE_RATIO:.0%}): RESET_STREAM adds no "
                                f"disproportionate overhead beyond normal stream completion.")
                        print(f"[verifier:{_run_id}] DEFECT — {note}")
                        phases.append(p2c_phase)
                        return {
                            "verdict": Verdict.DEFECT,
                            "baseline": baseline, "attack": attack_metrics,
                            "attack2": control_metrics,
                            "triggered": triggered, "phases": phases,
                            "thresholds_config": thresholds_config,
                            "notes": note,
                        }

                    if _benign_attrs or _pprof_breaks:
                        if _benign_attrs:
                            diff_reason += (
                                f"; complete-request baseline: benign_ratio={_p2c_alt_ratio:.3f} "
                                f"(<{_BENIGN_CONFIRM_RATIO})"
                            )
                        if _pprof_breaks:
                            diff_reason += (
                                f"; pprof CPU profile: {_pprof_app:.1f}% application-layer "
                                f"({pprof_data['transport_pct']:.1f}% transport)"
                            )
                            p2c_phase["pprof"] = pprof_data
                        print(f"[verifier:{_run_id}] Secondary attribution confirmed "
                              f"(benign_attrs={_benign_attrs}, pprof={_pprof_breaks}) "
                              f"— proceeding to Phase 3")
                        # fall through to Phase 3
                    else:
                        note = (f"Control test inconclusive (ratio in ambiguous zone 0.50–0.80): "
                                f"{diff_reason}. Cannot attribute overhead to application logic.")
                        if _p2c_alt_ratio is not None:
                            note += (f" Complete-request baseline: benign_ratio={_p2c_alt_ratio:.3f} "
                                    f"(≥{_BENIGN_CONFIRM_RATIO:.0%} — not disproportionate).")
                        if pprof_data:
                            note += (f" pprof: {_pprof_app:.1f}% application-layer, "
                                    f"{pprof_data['transport_pct']:.1f}% transport "
                                    f"(< {_PPROF_APP_ATTR_PCT:.0f}% app threshold).")
                        print(f"[verifier:{_run_id}] INCONCLUSIVE — {note}")
                        return {
                            "verdict": Verdict.INCONCLUSIVE,
                            "baseline": baseline, "attack": attack_metrics,
                            "attack2": control_metrics,
                            "triggered": triggered, "phases": phases,
                            "thresholds_config": thresholds_config,
                            "notes": note,
                            "pprof": pprof_data,
                        }
                else:
                    # Transport overhead confirmed (ratio >= 0.80): DEFECT or REJECTED.
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

        # ── Phase 2d: Benign equivalent test ─────────────────────────────────────
        # Answers the reviewer's key question: is the attack's CPU overhead
        # disproportionate compared to ordinary protocol work at the same intensity?
        #
        # Rate normalization: when the attack achieves a higher throughput than the
        # benign (e.g. RESET_STREAM cancels faster than FIN+response), a raw CPU
        # comparison is unfair — the benign runs at half the rate, so its absolute
        # CPU is halved even if each unit of work is more expensive.  We scale the
        # benign delta up to what it would cost at the attack's throughput rate.
        #
        # Accumulation attacks are excluded from normalization: if attack CPU is
        # still rising at the end of the measurement window, the CPU overhead comes
        # from accumulated server state (goroutines, buffers), not from the current
        # sending rate.  Scaling by rate would over-correct and mask real DoS.
        #
        # benign_ratio (rate-normalized when applicable):
        #   < _BENIGN_CONFIRM_RATIO   → attack ≥2× more expensive per unit → confirmed
        #   ≥ _BENIGN_DOWNGRADE_RATIO → attack ≈ normal work → not exploitable
        # Skipped if already executed in Phase 2c-alt (ambiguous zone path).
        p2d_phase: dict = {"phase": "benign"}
        benign_ratio: float | None = None
        if benign_exploit_fn is not None and not benign_already_run:
            print(f"[verifier:{_run_id}] Phase 2d — Benign equivalent test ({attack_duration_s}s) ...")
            p2d_start = _now_iso()
            benign_metrics = benign_exploit_fn(attack_metrics, new_cid, host, port, attack_duration_s)
            p2d_phase["started_at"] = p2d_start
            p2d_phase["ended_at"]   = _now_iso()
            p2d_phase["sample_count"] = len(benign_metrics.get("cpu_pct", []))

            idle_cpu    = _safe_mean(baseline2.get("cpu_pct", []))
            attack_cpu  = _safe_mean(attack_metrics.get("cpu_pct", []))
            benign_cpu  = _safe_mean(benign_metrics.get("cpu_pct", []))
            attack_delta = max(attack_cpu - idle_cpu, 0.1)   # avoid div/0
            benign_delta = max(benign_cpu - idle_cpu, 0.0)

            # Accumulation detection — CPU slope and memory slope independently.
            # If either resource is still growing, overhead comes from accumulated
            # state (goroutines, buffers) rather than current send rate, so rate
            # normalization would over-correct and mask real DoS signals.
            attack_cpu_series = attack_metrics.get("cpu_pct", [])
            attack_mem_series = attack_metrics.get("mem_mb", [])

            cpu_accumulating = False
            if len(attack_cpu_series) >= 20:
                _early_cpu = _safe_mean(attack_cpu_series[:10])
                _late_cpu  = _safe_mean(attack_cpu_series[-10:])
                cpu_accumulating = (_late_cpu - _early_cpu) > 15.0

            mem_accumulating = False
            if len(attack_mem_series) >= 20:
                _early_mem = _safe_mean(attack_mem_series[:10])
                _late_mem  = _safe_mean(attack_mem_series[-10:])
                mem_accumulating = (_late_mem - _early_mem) > max(5.0, 0.1 * _early_mem)

            is_accumulating = cpu_accumulating or mem_accumulating

            # Symmetric rate normalization: scale benign delta by the ratio of
            # attack throughput to benign throughput so the comparison is per unit
            # of work, not per unit of time.  Skipped when accumulation is detected
            # or when work unit types are incompatible (apples-to-oranges).
            attack_rate      = attack_metrics.get("work_rate", 0) or 0
            benign_rate      = benign_metrics.get("work_rate", 0) or 0
            attack_unit_type = attack_metrics.get("work_unit_type", "")
            benign_unit_type = benign_metrics.get("work_unit_type", "")
            units_compatible = _work_units_compatible(attack_unit_type, benign_unit_type)

            rate_ratio       = 1.0
            rate_note        = ""
            skip_norm_reason = ""
            if is_accumulating:
                skip_norm_reason = "accumulating"
            elif not units_compatible:
                skip_norm_reason = "incompatible_units"
            elif attack_rate <= 0 or benign_rate <= 0:
                skip_norm_reason = "missing_rate"
            else:
                rate_ratio = attack_rate / benign_rate

            benign_ratio_raw = round(benign_delta / attack_delta, 3)
            benign_delta_norm = benign_delta * rate_ratio
            benign_ratio_normalized = round(benign_delta_norm / attack_delta, 3)
            throughput_impact = round(rate_ratio, 3)

            if rate_ratio != 1.0:
                rate_note = (f" [rate-normalized: attack={attack_rate}/s "
                             f"benign={benign_rate}/s x{rate_ratio:.2f}]")
            elif skip_norm_reason:
                rate_note = f" [normalization skipped: {skip_norm_reason}]"

            benign_ratio = benign_ratio_normalized  # decision uses normalized value

            p2d_phase["idle_cpu_pct"]            = round(idle_cpu, 2)
            p2d_phase["attack_cpu_pct"]          = round(attack_cpu, 2)
            p2d_phase["benign_cpu_pct"]          = round(benign_cpu, 2)
            p2d_phase["attack_delta_pp"]         = round(attack_delta, 2)
            p2d_phase["benign_delta_pp"]         = round(benign_delta, 2)
            p2d_phase["benign_delta_norm"]       = round(benign_delta_norm, 2)
            p2d_phase["attack_rate"]             = attack_rate
            p2d_phase["benign_rate"]             = benign_rate
            p2d_phase["rate_ratio"]              = round(rate_ratio, 3)
            p2d_phase["attack_unit_type"]        = attack_unit_type
            p2d_phase["benign_unit_type"]        = benign_unit_type
            p2d_phase["units_compatible"]        = units_compatible
            p2d_phase["cpu_accumulating"]        = cpu_accumulating
            p2d_phase["mem_accumulating"]        = mem_accumulating
            p2d_phase["is_accumulating"]         = is_accumulating
            p2d_phase["benign_ratio_raw"]        = benign_ratio_raw
            p2d_phase["benign_ratio_normalized"] = benign_ratio_normalized
            p2d_phase["throughput_impact"]       = throughput_impact
            p2d_phase["benign_ratio"]            = benign_ratio
            print(f"[verifier:{_run_id}] Phase 2d benign_ratio={benign_ratio:.3f} "
                  f"(raw={benign_ratio_raw:.3f} attack+{attack_delta:.1f}pp "
                  f"benign+{benign_delta:.1f}pp idle={idle_cpu:.1f}%{rate_note})")

            if benign_ratio >= _BENIGN_DOWNGRADE_RATIO:
                # Attack overhead is not distinguishable from normal protocol work.
                p2d_phase["outcome"] = "proportionate_to_benign"
                phases.append(p2d_phase)
                note = (f"Phase 2d: benign equivalent costs {benign_ratio:.0%} of attack CPU "
                        f"(≥{_BENIGN_DOWNGRADE_RATIO:.0%} threshold). "
                        f"Attack overhead is not disproportionate to ordinary protocol work."
                        + rate_note)
                print(f"[verifier:{_run_id}] DEFECT — {note}")
                return {
                    "verdict": Verdict.DEFECT,
                    "baseline": baseline, "attack": attack_metrics, "attack2": benign_metrics,
                    "triggered": triggered,
                    "phases": phases,
                    "thresholds_config": thresholds_config,
                    "notes": note,
                }
            elif benign_ratio >= _BENIGN_CONFIRM_RATIO:
                # Moderate: attack is somewhat more expensive but not dramatically so.
                p2d_phase["outcome"] = "moderate_disproportionality"
            else:
                # Attack is ≥2× more expensive than benign work: confirmed disproportionate.
                p2d_phase["outcome"] = "disproportionate"
            phases.append(p2d_phase)

        # ── Phase 3: Repeatability (run target on the same restarted container) ──
        attack2 = exploit_fn(plan, new_cid, host, port, attack_duration_s)
        if attack2.get("_invalid"):
            note3 = attack2.get("_invalid_reason", "exploit invalid on Phase 3 repeat")
            _p3_verdict = _classify_invalid_reason(note3)
            print(f"[verifier:{_run_id}] Phase 3 exploit invalid — {note3}; {_p3_verdict}")
            p3_phase["ended_at"] = _now_iso()
            p3_phase["outcome"] = "invalid_exploit"
            phases.append(p3_phase)
            return {
                "verdict": _p3_verdict,
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
            # Require causal attribution evidence before issuing CONFIRMED_DOS.
            # High CPU/memory alone is insufficient — we need a matched control
            # showing the hypothesized behavior causes disproportionate overhead.
            _attr_engine = _AttributionEngine()
            _attr_check = _attr_engine.check_control_requirement(
                protocol=protocol,
                control_exploit_fn_provided=control_exploit_fn is not None,
                p2c_attribution_ran=_p2c_ran,
                p2c_diff_attributed=_p2c_diff_attributed,
            )
            if _attr_check.status != _ATTR_YES:
                p3_phase["outcome"] = "attribution_inconclusive"
                phases.append(p3_phase)
                print(f"[verifier:{_run_id}] INCONCLUSIVE — Phase 3 triggered but "
                      f"attribution evidence insufficient: {_attr_check.reason[:120]}")
                return {
                    "verdict": Verdict.INCONCLUSIVE,
                    "baseline": baseline,
                    "attack": attack_metrics,
                    "attack2": attack2,
                    "triggered": triggered3,
                    "phases": phases,
                    "thresholds_config": thresholds_config,
                    "notes": (
                        f"Phase 3 thresholds triggered ({triggered3}) but causal attribution "
                        f"could not be established: {_attr_check.reason}"
                    ),
                    "attribution": _attr_check.details,
                }
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
