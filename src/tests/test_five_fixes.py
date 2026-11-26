"""
Regression tests for the five fixes applied in Nov 2026.

Fix 1: INFEASIBLE gate — any_critical_refuted() (dependency-aware)
Fix 2: TLS reconnect calibration — matched-rate Phase 1c constants
Fix 3: Semantic test outcomes — ATTACK_UNREPRESENTABLE, ATTACK_BLOCKED
Fix 4: Datetime deprecation — no utcnow() in production modules
Fix 5: Lifecycle sidecar — robust port allocation
"""

import ast
import os
import socket
import sys
import textwrap
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from assumption_ledger.models import (
    AssumptionLedger,
    AssumptionRecord,
    AssumptionStatus,
)
from verifier.verifier import (
    Verdict,
    _classify_invalid_reason,
    _TLS_RECAL_FACTOR,
    _TLS_RECAL_DURATION,
)
from lifecycle.applicability import _find_free_port


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_assumption(aid, necessity="required"):
    a = types.SimpleNamespace()
    a.id = aid
    a.description = f"Assumption {aid}"
    a.necessity = necessity
    return a


def _make_ctx(assumptions):
    ctx = types.SimpleNamespace()
    ctx.assumptions = assumptions
    ctx.description = "Test hypothesis"
    ctx.dos_class = "StreamStateExhaustion"
    ctx.protocol = "HTTP/2"
    ctx.repo_url = "https://github.com/test/repo"
    ctx.version = "v1.0.0"
    return ctx


def _make_ledger(assumption_specs):
    """Build a ledger from list of (id, necessity) tuples."""
    ctx = _make_ctx([_make_assumption(aid, nec) for aid, nec in assumption_specs])
    return AssumptionLedger.from_context(ctx)


# ── Fix 1: INFEASIBLE gate ────────────────────────────────────────────────────

class TestAnyBriticalRefuted(unittest.TestCase):

    def test_any_critical_refuted_true_when_one_refuted(self):
        ledger = _make_ledger([("A1", "required"), ("A2", "required")])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        self.assertTrue(ledger.any_critical_refuted(),
                        "One REFUTED required assumption should trigger any_critical_refuted")

    def test_any_critical_refuted_true_when_all_refuted(self):
        ledger = _make_ledger([("A1", "required"), ("A2", "required")])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.REFUTED)
        self.assertTrue(ledger.any_critical_refuted())

    def test_any_critical_refuted_false_when_none_refuted(self):
        ledger = _make_ledger([("A1", "required"), ("A2", "required")])
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A2", AssumptionStatus.UNVERIFIED)
        self.assertFalse(ledger.any_critical_refuted())

    def test_any_critical_refuted_false_when_no_required(self):
        ledger = _make_ledger([("A1", "favorable")])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        self.assertFalse(ledger.any_critical_refuted(),
                         "Only required assumptions count for any_critical_refuted")

    def test_unverified_does_not_trigger(self):
        """UNVERIFIED (unknown) != REFUTED — gate must not fire."""
        ledger = _make_ledger([("A1", "required"), ("A2", "required")])
        ledger.update_status("A1", AssumptionStatus.UNVERIFIED)
        ledger.update_status("A2", AssumptionStatus.NOT_STATED)
        self.assertFalse(ledger.any_critical_refuted())

    def test_indeterminate_does_not_trigger(self):
        ledger = _make_ledger([("A1", "required")])
        ledger.update_status("A1", AssumptionStatus.INDETERMINATE)
        self.assertFalse(ledger.any_critical_refuted())

    def test_all_critical_refuted_still_works(self):
        """Backward compat: all_critical_refuted() unchanged."""
        ledger = _make_ledger([("A1", "required"), ("A2", "required")])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        # only ONE refuted → all_critical_refuted must remain False
        self.assertFalse(ledger.all_critical_refuted())
        # mark A2 refuted as well → all_critical_refuted must become True
        ledger.update_status("A2", AssumptionStatus.REFUTED)
        self.assertTrue(ledger.all_critical_refuted())

    def test_any_vs_all_diverge_when_some_supported(self):
        """The key behavioural difference between any and all."""
        ledger = _make_ledger([("A1", "required"), ("A2", "required")])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        self.assertTrue(ledger.any_critical_refuted())
        self.assertFalse(ledger.all_critical_refuted())

    def test_favorable_refuted_does_not_trigger_any(self):
        ledger = _make_ledger([("A1", "required"), ("A4", "favorable")])
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A4", AssumptionStatus.REFUTED)
        self.assertFalse(ledger.any_critical_refuted())


# ── Fix 2: TLS calibration constants ─────────────────────────────────────────

class TestTLSCalibrationConstants(unittest.TestCase):

    def test_recal_factor_gt_one(self):
        """Factor must be > 1 so calibration only fires on significant rate divergence."""
        self.assertGreater(_TLS_RECAL_FACTOR, 1.0)

    def test_recal_duration_positive(self):
        self.assertGreater(_TLS_RECAL_DURATION, 0)

    def test_recal_duration_less_than_tls_cal_duration(self):
        from verifier.verifier import _TLS_CAL_DURATION
        self.assertLessEqual(_TLS_RECAL_DURATION, _TLS_CAL_DURATION,
                             "Matched calibration should be no longer than the initial one")

    def test_recal_factor_in_reasonable_range(self):
        """Factor of 2–5 is reasonable; outside that is a suspicious change."""
        self.assertGreaterEqual(_TLS_RECAL_FACTOR, 1.5)
        self.assertLessEqual(_TLS_RECAL_FACTOR, 10.0)


# ── Fix 3: Semantic test outcomes ─────────────────────────────────────────────

class TestClassifyInvalidReason(unittest.TestCase):

    # ATTACK_UNREPRESENTABLE: client-side library/TLS/protocol limitations

    def test_alpn_mismatch_is_unrepresentable(self):
        r = _classify_invalid_reason(
            "ALPN negotiated 'http/1.1' instead of 'h2'; server did not speak HTTP/2"
        )
        self.assertEqual(r, Verdict.ATTACK_UNREPRESENTABLE)

    def test_ssl_error_is_unrepresentable(self):
        r = _classify_invalid_reason("ssl.SSLError: certificate verify failed")
        self.assertEqual(r, Verdict.ATTACK_UNREPRESENTABLE)

    def test_script_crashed_is_unrepresentable(self):
        r = _classify_invalid_reason("exploit produced no output — script crashed or failed to connect")
        self.assertEqual(r, Verdict.ATTACK_UNREPRESENTABLE)

    def test_connection_refused_is_unrepresentable(self):
        r = _classify_invalid_reason("connection refused on port 443")
        self.assertEqual(r, Verdict.ATTACK_UNREPRESENTABLE)

    def test_import_error_is_unrepresentable(self):
        r = _classify_invalid_reason("No module named 'h2.connection'")
        self.assertEqual(r, Verdict.ATTACK_UNREPRESENTABLE)

    def test_timeout_is_unrepresentable(self):
        r = _classify_invalid_reason("exploit timed out waiting for server response")
        self.assertEqual(r, Verdict.ATTACK_UNREPRESENTABLE)

    # ATTACK_BLOCKED: server-side mitigation

    def test_max_concurrent_streams_is_blocked(self):
        r = _classify_invalid_reason(
            "server enforced MAX_CONCURRENT_STREAMS=100; connection refused stream"
        )
        self.assertEqual(r, Verdict.ATTACK_BLOCKED)

    def test_rate_limit_is_blocked(self):
        r = _classify_invalid_reason("server replied ENHANCE_YOUR_CALM (rate-limit reached)")
        self.assertEqual(r, Verdict.ATTACK_BLOCKED)

    def test_goaway_is_blocked(self):
        r = _classify_invalid_reason("server sent GOAWAY frame; refused further streams")
        self.assertEqual(r, Verdict.ATTACK_BLOCKED)

    # INVALID_TEST: misconfigured test

    def test_zero_connections_is_invalid(self):
        r = _classify_invalid_reason(
            "exploit attempted 0 connections; attack loop did not execute"
        )
        self.assertEqual(r, Verdict.INVALID_TEST)

    def test_empty_reason_is_invalid(self):
        r = _classify_invalid_reason("")
        self.assertEqual(r, Verdict.INVALID_TEST)

    def test_generic_validation_failure_is_invalid(self):
        r = _classify_invalid_reason("exploit script failed pre-execution validation")
        self.assertEqual(r, Verdict.INVALID_TEST)

    # Negative: ATTACK_UNREPRESENTABLE must NOT be interpreted as evidence of patch

    def test_unrepresentable_is_not_attack_blocked(self):
        r = _classify_invalid_reason("ALPN negotiated 'http/1.1' instead of 'h2'")
        self.assertNotEqual(r, Verdict.ATTACK_BLOCKED,
                            "ALPN failure is a client-side limitation, not server mitigation")

    def test_unrepresentable_is_not_no_dos_effect(self):
        r = _classify_invalid_reason("No module named 'h2.connection'")
        self.assertNotEqual(r, Verdict.NO_DOS_EFFECT,
                            "Import failure is not evidence of absence of DoS")

    # New verdicts exist on Verdict class

    def test_attack_unrepresentable_in_verdict_class(self):
        self.assertTrue(hasattr(Verdict, "ATTACK_UNREPRESENTABLE"))
        self.assertEqual(Verdict.ATTACK_UNREPRESENTABLE, "ATTACK_UNREPRESENTABLE")

    def test_attack_blocked_in_verdict_class(self):
        self.assertTrue(hasattr(Verdict, "ATTACK_BLOCKED"))
        self.assertEqual(Verdict.ATTACK_BLOCKED, "ATTACK_BLOCKED")


# ── Fix 4: Datetime deprecation ───────────────────────────────────────────────

class TestDatetimeDeprecation(unittest.TestCase):

    def _get_source(self, rel_path: str) -> str:
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        full = os.path.join(base, rel_path)
        with open(full) as f:
            return f.read()

    def test_hypogenie_no_utcnow(self):
        src = self._get_source("hypogenie.py")
        self.assertNotIn("datetime.utcnow()", src,
                         "hypogenie.py must not use deprecated datetime.utcnow()")

    def test_hypogenie_uses_timezone(self):
        src = self._get_source("hypogenie.py")
        self.assertIn("timezone", src,
                      "hypogenie.py must import and use timezone for UTC timestamps")

    def test_verifier_no_utcnow(self):
        src = self._get_source("src/verifier/verifier.py")
        self.assertNotIn("datetime.utcnow()", src,
                         "verifier.py must not use deprecated datetime.utcnow()")

    def test_timezone_aware_timestamp_format(self):
        """datetime.now(timezone.utc) must produce a consistent timestamp."""
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc)
        self.assertIsNotNone(ts.tzinfo, "Timestamp must be timezone-aware")
        formatted = ts.strftime("%Y-%m-%d %H:%M UTC")
        self.assertRegex(formatted, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$")


# ── Fix 5: Lifecycle sidecar port allocation ──────────────────────────────────

class TestFindFreePort(unittest.TestCase):

    def test_returns_int_in_valid_range(self):
        port = _find_free_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 1024)
        self.assertLessEqual(port, 65535)

    def test_returned_port_is_bindable(self):
        """The port returned must be immediately bindable (before TOCTOU window)."""
        port = _find_free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Should succeed — port was just verified free.
            s.bind(("127.0.0.1", port))

    def test_multiple_calls_return_different_ports(self):
        """Random base means successive calls almost certainly differ."""
        ports = {_find_free_port() for _ in range(10)}
        self.assertGreater(len(ports), 1,
                           "Successive _find_free_port() calls should not all return the same port")

    def test_fallback_on_busy_range(self):
        """When a held socket occupies the range, _find_free_port still returns a port."""
        held = []
        try:
            # Hold 20 sockets to stress the random picker; it should still find a free one.
            for _ in range(20):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", 0))
                held.append(s)
            port = _find_free_port()
            self.assertIsInstance(port, int)
        finally:
            for s in held:
                s.close()

    def test_find_free_port_uses_random_range(self):
        """Port must NOT always return the same low-numbered port (old behaviour)."""
        # With the old `s.bind(("", 0))` approach the OS always returned from the
        # ephemeral range starting at ~32768.  The new implementation uses a random
        # range; check that the value is spread across the configured band.
        ports = [_find_free_port() for _ in range(30)]
        unique = set(ports)
        self.assertGreater(len(unique), 5,
                           "Port picker must return varied values, not always the same port")


if __name__ == "__main__":
    unittest.main()
