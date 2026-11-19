"""
Lifecycle accumulation analysis.

Determines LifecycleOutcome from collected RetentionSamples,
proxy goroutine trends, and the post-attack recovery time-series.

Decision hierarchy:
  1. outstanding_cleanups recovery (primary):
       - reached 0 within recovery_wait_s → BOUNDED_RETENTION (cleanup completes)
       - never reached 0 → RESOURCE_ACCUMULATION
  2. Proxy goroutine trend (secondary, when pprof observable):
       - monotonic rise with no recovery → RESOURCE_ACCUMULATION
       - rise with recovery → BOUNDED_RETENTION
  3. Backend cleanup_pending cross-batch delta (tertiary):
       - growing deltas → RESOURCE_ACCUMULATION
       - non-zero but stable → BOUNDED_RETENTION
  4. All metrics at baseline → NO_RESOURCE_RETENTION
"""

from lifecycle.model import (
    LifecycleOutcome,
    LifecycleValidationPlan,
    RecoverySample,
    RetentionSample,
)

# Goroutine growth per batch considered noise
_GOROUTINE_NOISE_THRESHOLD = 5

# A cleanup_pending delta N% above average is "growing"
_DELTA_GROWTH_FACTOR = 1.25


def analyze(
    batches: list[RetentionSample],
    control_batches: list[RetentionSample],
    proxy_goroutine_trend: list[int],
    recovery_samples: list[RecoverySample],
    plan: LifecycleValidationPlan,
) -> tuple[LifecycleOutcome, str]:
    """
    Determine accumulation outcome from collected samples.

    batches               — RetentionSamples for cancel scenarios (C + D attack arm)
    control_batches       — RetentionSamples for matched control arm
    proxy_goroutine_trend — goroutine count before each attack batch (-1 if unobservable)
    recovery_samples      — time-series from post-attack recovery window
    plan                  — LifecycleValidationPlan (for recovery_wait_s)
    """
    if not batches:
        return LifecycleOutcome.NO_RESOURCE_RETENTION, "No attack batches collected."

    # ── 1. outstanding_cleanups recovery (primary signal) ────────────────────
    # outstanding_cleanups is a gauge: incremented on op start, decremented on
    # resource_released.  If it drains to 0 during recovery_wait_s, cleanup
    # completed.  If it stays positive, ops are permanently stuck.
    if recovery_samples:
        drained = any(s.outstanding_cleanups == 0 for s in recovery_samples)
        final = recovery_samples[-1].outstanding_cleanups
        peak = max(
            (s.outstanding_cleanups for s in batches), default=0
        )
        drain_time = next(
            (s.elapsed_s for s in recovery_samples if s.outstanding_cleanups == 0),
            None,
        )

        if peak > 0:
            if drained:
                notes = (
                    f"outstanding_cleanups drained to 0 within "
                    f"{drain_time:.1f}s (recovery_wait_s={plan.recovery_wait_s}s). "
                    f"Peak concurrent live ops during attack: {peak}. "
                    f"Caddy propagates cancellations to the backend; each cancelled op "
                    f"runs through all three phases (context_cancelled → op_terminated → "
                    f"resource_released) and cleanup completes normally."
                )
                return LifecycleOutcome.BOUNDED_RETENTION, notes
            else:
                notes = (
                    f"outstanding_cleanups did not reach 0 after "
                    f"{plan.recovery_wait_s}s recovery window "
                    f"(final={final}, peak={peak}). "
                    f"Ops are retained beyond the recovery period — "
                    f"resources accumulate without bound."
                )
                return LifecycleOutcome.RESOURCE_ACCUMULATION, notes

    # ── 2. Proxy goroutine trend (when pprof observable) ────────────────────
    proxy_obs = [g for g in proxy_goroutine_trend if g >= 0]
    if len(proxy_obs) >= 3:
        deltas = [proxy_obs[i] - proxy_obs[i - 1] for i in range(1, len(proxy_obs))]
        rising = sum(1 for d in deltas if d > _GOROUTINE_NOISE_THRESHOLD)

        # Derive proxy recovery from the last recovery sample's goroutine count.
        recovery_goroutines = (
            recovery_samples[-1].proxy_goroutines
            if recovery_samples else -1
        )
        if recovery_goroutines < 0:
            recovery_ok = False
        else:
            initial = proxy_obs[0]
            recovery_ok = abs(recovery_goroutines - initial) <= max(
                _GOROUTINE_NOISE_THRESHOLD * 2, int(initial * 0.2)
            )

        if rising >= 3 and not recovery_ok:
            notes = (
                f"Proxy goroutine count rose in {rising}/{len(deltas)} consecutive "
                f"batches (trend={proxy_obs}) and did not return to baseline within "
                f"{plan.recovery_wait_s}s. Goroutines accumulated without cleanup."
            )
            return LifecycleOutcome.RESOURCE_ACCUMULATION, notes

        if rising >= 2 and recovery_ok:
            notes = (
                f"Proxy goroutine count rose in {rising}/{len(deltas)} batches "
                f"(trend={proxy_obs}) but recovered within {plan.recovery_wait_s}s."
            )
            return LifecycleOutcome.BOUNDED_RETENTION, notes

    # ── 3. Backend cleanup_pending cross-batch delta ─────────────────────────
    cp_values = [s.cleanup_pending for s in batches]
    control_cp = [s.cleanup_pending for s in control_batches]
    max_attack_cp = max(cp_values, default=0)
    max_control_cp = max(control_cp, default=0)

    if max_attack_cp == 0:
        return (
            LifecycleOutcome.NO_RESOURCE_RETENTION,
            "Backend cleanup_pending=0 for all attack scenarios. "
            "Either Caddy cancels requests before backend dispatch, "
            "or cancellation is not propagated to the backend.",
        )

    if len(cp_values) >= 3:
        deltas = [cp_values[i] - cp_values[i - 1] for i in range(1, len(cp_values))]
        avg_delta = sum(deltas) / len(deltas) if deltas else 0
        growing = sum(1 for d in deltas if d > avg_delta * _DELTA_GROWTH_FACTOR)
        if growing >= len(deltas) // 2 and avg_delta > 0:
            notes = (
                f"Backend cleanup_pending growing across batches: values={cp_values}, "
                f"deltas={deltas}. Proxy may be delaying cancellation propagation "
                f"as internal state accumulates."
            )
            return LifecycleOutcome.RESOURCE_ACCUMULATION, notes

    if max_attack_cp > max_control_cp:
        notes = (
            f"cleanup_pending={max_attack_cp} for cancel scenarios vs "
            f"{max_control_cp} for matched control. "
            f"Caddy propagates {max_attack_cp} backend cancellations per test run; "
            f"each cancellation represents wasted backend work. "
            f"No monotonic accumulation detected across {len(batches)} batch(es)."
        )
        return LifecycleOutcome.BOUNDED_RETENTION, notes

    return (
        LifecycleOutcome.NO_RESOURCE_RETENTION,
        f"cleanup_pending similar for attack ({max_attack_cp}) and "
        f"control ({max_control_cp}). No resource retention detected.",
    )
