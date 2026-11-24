"""
Unit and integration tests for the Evidence-Driven Assumption Reasoning system.

Covers:
 - AssumptionLedger CRUD and status semantics
 - Status mapping (new 8-status ↔ legacy 3-status)
 - _parse_developer_output for all key cases
 - INFEASIBLE gate via AssumptionLedger.all_critical_refuted()
 - Critic response parsing
 - Implicit assumption extractor response parsing (mocked)
"""

import json
import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from assumption_ledger.models import (
    AssumptionStatus,
    AssumptionEvidence,
    AssumptionRecord,
    AssumptionLedger,
    LEGACY_TO_STATUS,
    _STATUS_TO_LEGACY,
)
from gap_finder.models import AssumptionVerdict


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(assumptions):
    """Build a minimal HypothesisContext-like object for testing."""
    ctx = types.SimpleNamespace()
    ctx.assumptions = assumptions
    ctx.description = "Test hypothesis"
    ctx.dos_class = "StreamStateExhaustion"
    ctx.protocol = "HTTP/2"
    ctx.repo_url = "https://github.com/test/repo"
    ctx.version = "v1.0.0"
    return ctx


def _make_assumption(aid, necessity="required"):
    a = types.SimpleNamespace()
    a.id = aid
    a.description = f"Assumption {aid}"
    a.necessity = necessity
    return a


def _make_ledger(assumption_ids, necessity="required"):
    """Build an AssumptionLedger from a list of assumption ids."""
    ctx = _make_ctx([_make_assumption(aid, necessity) for aid in assumption_ids])
    return AssumptionLedger.from_context(ctx)


# ── AssumptionLedger unit tests ───────────────────────────────────────────────

class TestAssumptionLedgerCRUD(unittest.TestCase):

    def test_from_context_populates_records(self):
        ledger = _make_ledger(["A1", "A2", "A3"])
        self.assertEqual(len(ledger), 3)
        for aid in ("A1", "A2", "A3"):
            r = ledger.get(aid)
            self.assertIsNotNone(r)
            self.assertEqual(r.status, AssumptionStatus.NOT_STATED)
            self.assertTrue(r.is_critical)

    def test_add_new_record(self):
        ledger = _make_ledger([])
        ledger.add(AssumptionRecord(
            assumption_id="X1",
            description="New implicit",
            necessity="favorable",
            status=AssumptionStatus.NOT_STATED,
        ))
        self.assertIsNotNone(ledger.get("X1"))
        self.assertEqual(len(ledger), 1)

    def test_add_duplicate_raises(self):
        ledger = _make_ledger(["A1"])
        with self.assertRaises(ValueError):
            ledger.add(AssumptionRecord(
                assumption_id="A1",
                description="dup",
                necessity="required",
            ))

    def test_add_or_replace_silently_upserts(self):
        ledger = _make_ledger(["A1"])
        ledger.add_or_replace(AssumptionRecord(
            assumption_id="A1",
            description="replaced",
            necessity="required",
            status=AssumptionStatus.SUPPORTED,
        ))
        self.assertEqual(ledger.get("A1").status, AssumptionStatus.SUPPORTED)

    def test_update_status_changes_record(self):
        ledger = _make_ledger(["A1"])
        ev = AssumptionEvidence(
            supporting_evidence=["file.go:10: code here"],
            reasoning="clear",
        )
        ledger.update_status("A1", AssumptionStatus.SUPPORTED, ev)
        r = ledger.get("A1")
        self.assertEqual(r.status, AssumptionStatus.SUPPORTED)
        self.assertEqual(r.evidence.reasoning, "clear")

    def test_update_status_unknown_key_raises(self):
        ledger = _make_ledger([])
        with self.assertRaises(KeyError):
            ledger.update_status("MISSING", AssumptionStatus.SUPPORTED)

    def test_all_returns_all_records(self):
        ledger = _make_ledger(["A1", "A2"])
        self.assertEqual(len(ledger.all()), 2)

    def test_by_status_filter(self):
        ledger = _make_ledger(["A1", "A2", "A3"])
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A2", AssumptionStatus.REFUTED)
        supported = ledger.by_status(AssumptionStatus.SUPPORTED)
        self.assertEqual(len(supported), 1)
        self.assertEqual(supported[0].assumption_id, "A1")


class TestAssumptionLedgerInfeasibleGate(unittest.TestCase):

    def test_all_critical_refuted_true_when_all_refuted(self):
        ledger = _make_ledger(["A1", "A2"])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.REFUTED)
        self.assertTrue(ledger.all_critical_refuted())

    def test_all_critical_refuted_false_when_one_supported(self):
        ledger = _make_ledger(["A1", "A2"])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        self.assertFalse(ledger.all_critical_refuted())

    def test_all_critical_refuted_false_when_no_required(self):
        ledger = _make_ledger(["A1"], necessity="favorable")
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        # No required assumptions → gate does not trigger
        self.assertFalse(ledger.all_critical_refuted())

    def test_critical_refuted_returns_subset(self):
        ledger = _make_ledger(["A1", "A2", "A3"])
        ledger.update_status("A1", AssumptionStatus.REFUTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        ledger.update_status("A3", AssumptionStatus.REFUTED)
        refuted = ledger.critical_refuted()
        self.assertEqual({r.assumption_id for r in refuted}, {"A1", "A3"})

    def test_critical_unresolved_excludes_supported_and_na(self):
        ledger = _make_ledger(["A1", "A2", "A3"])
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A2", AssumptionStatus.NOT_APPLICABLE)
        # A3 stays NOT_STATED → unresolved
        unresolved = ledger.critical_unresolved()
        self.assertEqual([r.assumption_id for r in unresolved], ["A3"])


# ── Status mapping tests ──────────────────────────────────────────────────────

class TestStatusMapping(unittest.TestCase):

    def test_legacy_to_status_all_keys(self):
        self.assertEqual(LEGACY_TO_STATUS["confirmed"], AssumptionStatus.SUPPORTED)
        self.assertEqual(LEGACY_TO_STATUS["refuted"],   AssumptionStatus.REFUTED)
        self.assertEqual(LEGACY_TO_STATUS["unclear"],   AssumptionStatus.UNVERIFIED)

    def test_status_to_legacy_supported(self):
        self.assertEqual(_STATUS_TO_LEGACY[AssumptionStatus.SUPPORTED], "confirmed")

    def test_status_to_legacy_refuted(self):
        self.assertEqual(_STATUS_TO_LEGACY[AssumptionStatus.REFUTED], "refuted")

    def test_status_to_legacy_unclear_variants(self):
        for status in (
            AssumptionStatus.NOT_STATED,
            AssumptionStatus.AMBIGUOUS,
            AssumptionStatus.UNVERIFIED,
            AssumptionStatus.CONFLICTING_EVIDENCE,
            AssumptionStatus.INDETERMINATE,
            AssumptionStatus.NOT_APPLICABLE,
        ):
            self.assertEqual(_STATUS_TO_LEGACY[status], "unclear",
                             f"{status} should map to 'unclear'")

    def test_to_legacy_verdict_supported(self):
        record = AssumptionRecord(
            assumption_id="A1",
            description="test",
            necessity="required",
            status=AssumptionStatus.SUPPORTED,
            evidence=AssumptionEvidence(
                supporting_evidence=["file.go:10: snippet"],
                reasoning="clear reasoning",
            ),
        )
        v = record.to_legacy_verdict()
        self.assertIsInstance(v, AssumptionVerdict)
        self.assertEqual(v.assumption_id, "A1")
        self.assertEqual(v.status, "confirmed")
        self.assertIn("file.go:10", v.code_evidence)

    def test_to_legacy_verdict_refuted(self):
        record = AssumptionRecord(
            assumption_id="A2",
            description="test",
            necessity="required",
            status=AssumptionStatus.REFUTED,
            evidence=AssumptionEvidence(
                contradicting_evidence=["file.go:20: limit found"],
            ),
        )
        v = record.to_legacy_verdict()
        self.assertEqual(v.status, "refuted")
        self.assertIn("file.go:20", v.code_evidence)

    def test_to_verdicts_full_round_trip(self):
        ledger = _make_ledger(["A1", "A2"])
        ledger.update_status("A1", AssumptionStatus.SUPPORTED,
                             AssumptionEvidence(supporting_evidence=["f.go:1"]))
        ledger.update_status("A2", AssumptionStatus.REFUTED,
                             AssumptionEvidence(contradicting_evidence=["f.go:2"]))
        verdicts = ledger.to_verdicts()
        self.assertEqual(len(verdicts), 2)
        status_map = {v.assumption_id: v.status for v in verdicts}
        self.assertEqual(status_map["A1"], "confirmed")
        self.assertEqual(status_map["A2"], "refuted")


# ── _parse_developer_output tests ─────────────────────────────────────────────

class TestParseDeveloperOutput(unittest.TestCase):

    def _run_parse(self, dev_json: dict, assumption_ids=("A1", "A2"),
                   necessity="required"):
        from gap_finder.gap_finder import _parse_developer_output
        from tests.fixtures import quic_spec_reqs
        ctx = _make_ctx([_make_assumption(aid, necessity) for aid in assumption_ids])
        ledger = AssumptionLedger.from_context(ctx)
        raw = json.dumps(dev_json)
        return _parse_developer_output(raw, ctx, quic_spec_reqs, ledger)

    def test_supported_assumption_updates_ledger(self):
        dev = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "SUPPORTED",
                "supporting_evidence": ["server.go:100: code snippet"],
                "contradicting_evidence": [],
                "reasoning": "code confirms unbounded allocation",
                "limitations": [],
                "alternative_explanations": ["could be bounded elsewhere — checked, not found"],
                "suggested_validation": "",
                "source_refs": ["server.go:100"],
                "searches_attempted": [],
            }],
            "findings": [],
        }
        ledger, findings = self._run_parse(dev)
        r = ledger.get("A1")
        self.assertEqual(r.status, AssumptionStatus.SUPPORTED)
        self.assertIn("server.go:100", r.evidence.supporting_evidence[0])
        self.assertFalse(findings)

    def test_refuted_assumption_updates_ledger(self):
        dev = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "REFUTED",
                "supporting_evidence": [],
                "contradicting_evidence": ["server.go:200: maxStreams = 100"],
                "reasoning": "cap exists",
                "limitations": [],
                "alternative_explanations": [],
                "suggested_validation": "",
                "source_refs": ["server.go:200"],
                "searches_attempted": ["search maxStreams"],
            }],
            "findings": [],
        }
        ledger, findings = self._run_parse(dev)
        r = ledger.get("A1")
        self.assertEqual(r.status, AssumptionStatus.REFUTED)
        self.assertIn("server.go:200", r.evidence.contradicting_evidence[0])

    def test_indeterminate_assumption(self):
        dev = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "INDETERMINATE",
                "supporting_evidence": [],
                "contradicting_evidence": [],
                "reasoning": "code is generated at runtime",
                "limitations": ["only source analysis possible"],
                "alternative_explanations": [],
                "suggested_validation": "run dynamic profiling under load",
                "source_refs": [],
                "searches_attempted": ["search bufferPool", "search alloc"],
            }],
            "findings": [],
        }
        ledger, findings = self._run_parse(dev)
        r = ledger.get("A1")
        self.assertEqual(r.status, AssumptionStatus.INDETERMINATE)
        self.assertEqual(r.evidence.suggested_validation, "run dynamic profiling under load")

    def test_initially_unclear_becomes_supported_on_retry(self):
        """Simulate a two-pass scenario: first UNVERIFIED, then SUPPORTED."""
        dev_pass1 = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "UNVERIFIED",
                "supporting_evidence": [],
                "contradicting_evidence": [],
                "reasoning": "no results",
                "limitations": [],
                "alternative_explanations": [],
                "suggested_validation": "",
                "source_refs": [],
                "searches_attempted": ["search rateLimiter", "search maxReset"],
            }],
            "findings": [],
        }
        dev_pass2 = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "SUPPORTED",
                "supporting_evidence": ["http2/server.go:1708: recvBuf = make([]byte, 65535)"],
                "contradicting_evidence": [],
                "reasoning": "unbounded buffer found",
                "limitations": [],
                "alternative_explanations": ["might be pooled — checked, not pooled"],
                "suggested_validation": "",
                "source_refs": ["http2/server.go:1708"],
                "searches_attempted": [],
            }],
            "findings": [],
        }
        from gap_finder.gap_finder import _parse_developer_output
        from tests.fixtures import quic_spec_reqs
        ctx = _make_ctx([_make_assumption("A1")])

        ledger1 = AssumptionLedger.from_context(ctx)
        ledger1, _ = _parse_developer_output(json.dumps(dev_pass1), ctx, quic_spec_reqs, ledger1)
        self.assertEqual(ledger1.get("A1").status, AssumptionStatus.UNVERIFIED)

        ledger2 = AssumptionLedger.from_context(ctx)
        ledger2, _ = _parse_developer_output(json.dumps(dev_pass2), ctx, quic_spec_reqs, ledger2)
        self.assertEqual(ledger2.get("A1").status, AssumptionStatus.SUPPORTED)

    def test_unevaluated_assumption_stays_not_stated(self):
        """Assumption not in developer output keeps NOT_STATED."""
        dev = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "SUPPORTED",
                "supporting_evidence": ["f.go:1"],
                "contradicting_evidence": [],
                "reasoning": "ok",
                "limitations": [],
                "alternative_explanations": ["none apply"],
                "suggested_validation": "",
                "source_refs": [],
                "searches_attempted": [],
            }],
            "findings": [],
        }
        ledger, _ = self._run_parse(dev)
        # A2 was never evaluated
        r2 = ledger.get("A2")
        self.assertEqual(r2.status, AssumptionStatus.NOT_STATED)

    def test_legacy_format_confirmed_ingested(self):
        """Old-format 'confirmed'/'refuted'/'unclear' values are accepted."""
        dev = {
            "assumption_verdicts": [{
                "assumption_id": "A1",
                "status": "confirmed",          # old format
                "code_evidence": "f.go:5: cap found",  # old field
                "reasoning": "legacy reasoning",
            }],
            "findings": [],
        }
        ledger, _ = self._run_parse(dev)
        self.assertEqual(ledger.get("A1").status, AssumptionStatus.SUPPORTED)

    def test_bad_json_returns_empty(self):
        from gap_finder.gap_finder import _parse_developer_output
        from tests.fixtures import quic_spec_reqs
        ctx = _make_ctx([_make_assumption("A1")])
        ledger = AssumptionLedger.from_context(ctx)
        ledger2, findings = _parse_developer_output("not json at all", ctx, quic_spec_reqs, ledger)
        self.assertFalse(findings)


# ── Critic response parsing ───────────────────────────────────────────────────

class TestParseCriticOutput(unittest.TestCase):

    def _parse(self, raw):
        from gap_finder.gap_finder import _parse_critic_output
        return _parse_critic_output(raw)

    def test_pass(self):
        passed, reason, instruction = self._parse("PASS")
        self.assertTrue(passed)
        self.assertEqual(reason, "")

    def test_pass_with_trailing_text(self):
        passed, _, _ = self._parse("PASS\n\nExtra commentary")
        self.assertTrue(passed)

    def test_retry_with_reason_and_instruction(self):
        raw = (
            "RETRY\n"
            "reason: supporting_evidence is empty for SUPPORTED A1\n"
            "instruction: search for 'recvBuf' in http2/server.go lines 1700-1750"
        )
        passed, reason, instruction = self._parse(raw)
        self.assertFalse(passed)
        self.assertIn("supporting_evidence", reason)
        self.assertIn("recvBuf", instruction)

    def test_retry_reason_only(self):
        raw = "RETRY\nreason: missing alternative explanations"
        passed, reason, instruction = self._parse(raw)
        self.assertFalse(passed)
        self.assertIn("alternative", reason)
        self.assertEqual(instruction, "")


# ── Implicit extractor response parsing ──────────────────────────────────────

class TestExtractImplicit(unittest.TestCase):

    def _make_ctx_for_extractor(self):
        ctx = _make_ctx([_make_assumption("A1")])
        ctx.assumptions[0].description = "recv buffer is unbounded"
        return ctx

    def test_valid_response_returns_assumptions(self):
        response_json = json.dumps({
            "implicit_assumptions": [
                {"id": "IMPL_1", "description": "no global rate limit", "necessity": "required"},
                {"id": "IMPL_2", "description": "buffers are heap-allocated per request",
                 "necessity": "favorable"},
            ]
        })
        ctx = self._make_ctx_for_extractor()
        with patch("assumption_ledger.extractor._llm.call_llm", return_value=response_json):
            from assumption_ledger.extractor import extract_implicit
            result = extract_implicit(ctx)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].id, "IMPL_1")
        self.assertEqual(result[0].necessity, "required")
        self.assertEqual(result[1].id, "IMPL_2")

    def test_id_collision_gets_prefix(self):
        """If LLM returns an ID that matches an existing assumption, it gets prefixed."""
        response_json = json.dumps({
            "implicit_assumptions": [
                {"id": "A1", "description": "collision id", "necessity": "favorable"},
            ]
        })
        ctx = self._make_ctx_for_extractor()
        with patch("assumption_ledger.extractor._llm.call_llm", return_value=response_json):
            from assumption_ledger.extractor import extract_implicit
            result = extract_implicit(ctx)
        # ID "A1" collides → becomes "IMPL_A1"
        self.assertEqual(result[0].id, "IMPL_A1")

    def test_empty_list_on_llm_failure(self):
        ctx = self._make_ctx_for_extractor()
        with patch("assumption_ledger.extractor._llm.call_llm",
                   side_effect=RuntimeError("LLM unavailable")):
            from assumption_ledger.extractor import extract_implicit
            result = extract_implicit(ctx)
        self.assertEqual(result, [])

    def test_empty_list_on_bad_json(self):
        ctx = self._make_ctx_for_extractor()
        with patch("assumption_ledger.extractor._llm.call_llm", return_value="not json"):
            from assumption_ledger.extractor import extract_implicit
            result = extract_implicit(ctx)
        self.assertEqual(result, [])

    def test_missing_fields_skipped(self):
        response_json = json.dumps({
            "implicit_assumptions": [
                {"id": "", "description": "missing id — should be skipped"},
                {"id": "IMPL_3", "description": "valid one", "necessity": "required"},
            ]
        })
        ctx = self._make_ctx_for_extractor()
        with patch("assumption_ledger.extractor._llm.call_llm", return_value=response_json):
            from assumption_ledger.extractor import extract_implicit
            result = extract_implicit(ctx)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "IMPL_3")

    def test_invalid_necessity_normalized(self):
        response_json = json.dumps({
            "implicit_assumptions": [
                {"id": "IMPL_4", "description": "valid", "necessity": "optional"},
            ]
        })
        ctx = self._make_ctx_for_extractor()
        with patch("assumption_ledger.extractor._llm.call_llm", return_value=response_json):
            from assumption_ledger.extractor import extract_implicit
            result = extract_implicit(ctx)
        self.assertEqual(result[0].necessity, "favorable")


# ── AssumptionLedger serialization ────────────────────────────────────────────

class TestAssumptionLedgerSerialization(unittest.TestCase):

    def test_to_dict_list_all_fields_present(self):
        ledger = _make_ledger(["A1"])
        ledger.update_status(
            "A1",
            AssumptionStatus.SUPPORTED,
            AssumptionEvidence(
                supporting_evidence=["f.go:10: code"],
                reasoning="sound",
                alternative_explanations=["none apply"],
            ),
        )
        d = ledger.to_dict_list()
        self.assertEqual(len(d), 1)
        entry = d[0]
        self.assertEqual(entry["assumption_id"], "A1")
        self.assertEqual(entry["status"], "SUPPORTED")
        self.assertTrue(entry["is_critical"])
        self.assertFalse(entry["is_implicit"])
        ev = entry["evidence"]
        self.assertIn("f.go:10", ev["supporting_evidence"][0])
        self.assertEqual(ev["reasoning"], "sound")

    def test_is_resolved_and_is_unresolved_properties(self):
        for status in (AssumptionStatus.SUPPORTED, AssumptionStatus.REFUTED,
                       AssumptionStatus.NOT_APPLICABLE):
            r = AssumptionRecord("X", "d", "required", status=status)
            self.assertTrue(r.is_resolved, f"{status} should be resolved")
            self.assertFalse(r.is_unresolved, f"{status} should not be unresolved")

        for status in (AssumptionStatus.NOT_STATED, AssumptionStatus.AMBIGUOUS,
                       AssumptionStatus.UNVERIFIED, AssumptionStatus.INDETERMINATE,
                       AssumptionStatus.CONFLICTING_EVIDENCE):
            r = AssumptionRecord("Y", "d", "required", status=status)
            self.assertFalse(r.is_resolved, f"{status} should not be resolved")
            self.assertTrue(r.is_unresolved, f"{status} should be unresolved")


# ── Favorable assumption investigation priority tests ─────────────────────────

class TestFavorableAssumptionPriority(unittest.TestCase):
    """
    Verify that favorable/optional assumptions are treated with the same
    investigation priority as required ones.  These tests simulate the Gap
    Finder's ledger behavior — not the full LLM run.
    """

    def test_favorable_assumption_gets_full_record(self):
        """Favorable assumptions should have is_critical=False but still be in ledger."""
        ledger = _make_ledger(["A1", "A2"], necessity="required")
        ctx_fav = _make_ctx([
            _make_assumption("A1", "required"),
            _make_assumption("A4", "favorable"),
        ])
        ledger_mixed = AssumptionLedger.from_context(ctx_fav)
        self.assertIsNotNone(ledger_mixed.get("A4"))
        self.assertFalse(ledger_mixed.get("A4").is_critical)
        self.assertEqual(ledger_mixed.get("A4").status, AssumptionStatus.NOT_STATED)

    def test_favorable_unresolved_does_not_trigger_infeasible(self):
        """
        Required assumptions all SUPPORTED + favorable assumption UNVERIFIED
        must not trigger the INFEASIBLE gate.
        """
        ctx = _make_ctx([
            _make_assumption("A1", "required"),
            _make_assumption("A4", "favorable"),
        ])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A4", AssumptionStatus.UNVERIFIED)
        self.assertFalse(ledger.all_critical_refuted())

    def test_favorable_unresolved_base_attack_still_viable(self):
        """
        critical_unresolved should NOT include favorable assumptions —
        they are independent amplifiers, not blockers.
        """
        ctx = _make_ctx([
            _make_assumption("A1", "required"),
            _make_assumption("A2", "required"),
            _make_assumption("A4", "favorable"),
        ])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        ledger.update_status("A4", AssumptionStatus.UNVERIFIED)
        # critical_unresolved only looks at is_critical=True records
        unresolved = ledger.critical_unresolved()
        self.assertEqual(len(unresolved), 0,
                         "Unresolved favorable assumption should not appear in critical_unresolved")

    def test_favorable_refuted_does_not_affect_infeasible_gate(self):
        """Refuted favorable assumption + supported required → NOT INFEASIBLE."""
        ctx = _make_ctx([
            _make_assumption("A1", "required"),
            _make_assumption("A4", "favorable"),
        ])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A4", AssumptionStatus.REFUTED)
        self.assertFalse(ledger.all_critical_refuted())

    def test_favorable_supported_captured_in_ledger(self):
        """When a favorable assumption is confirmed, it should be SUPPORTED in the ledger."""
        ctx = _make_ctx([
            _make_assumption("A1", "required"),
            _make_assumption("A4", "favorable"),
        ])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A4", AssumptionStatus.SUPPORTED,
                             AssumptionEvidence(
                                 supporting_evidence=["quic_stream.go:200: deleteStream sends MAX_STREAMS"],
                                 reasoning="Evidence shows predictable MAX_STREAMS timing",
                             ))
        a4 = ledger.get("A4")
        self.assertEqual(a4.status, AssumptionStatus.SUPPORTED)
        self.assertIn("deleteStream", a4.evidence.supporting_evidence[0])


class TestReinvestigateUnclear(unittest.TestCase):
    """
    Verify that _reinvestigate_unclear triggers and updates the ledger.
    """

    def test_reinvestigation_resolves_unverified_assumption(self):
        """Simulate a successful re-investigation resolving UNVERIFIED → SUPPORTED."""
        from gap_finder.gap_finder import _reinvestigate_unclear

        ctx = _make_ctx([_make_assumption("A4", "favorable")])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A4", AssumptionStatus.UNVERIFIED,
                             AssumptionEvidence(searches_attempted=["search maxStreams"]))

        reinvestigation_response = json.dumps({
            "assumption_verdicts": [{
                "assumption_id": "A4",
                "status": "SUPPORTED",
                "supporting_evidence": [
                    "quic_stream.go:200: deleteStream sends MAX_STREAMS after stream close"
                ],
                "contradicting_evidence": [],
                "reasoning": "deleteStream always sends a MAX_STREAMS frame — timing is deterministic",
                "limitations": [],
                "alternative_explanations": ["random backoff? checked — no backoff logic found"],
                "suggested_validation": "",
                "source_refs": ["quic_stream.go:200"],
                "searches_attempted": ["search deleteStream", "search queueMaxStreamID",
                                       "search queueControlFrame"],
            }],
            "findings": [],
        })

        with patch("gap_finder.gap_finder._llm_with_tools",
                   return_value=reinvestigation_response):
            _reinvestigate_unclear(ledger, "/fake/repo")

        self.assertEqual(ledger.get("A4").status, AssumptionStatus.SUPPORTED)
        self.assertIn("deleteStream", ledger.get("A4").evidence.supporting_evidence[0])

    def test_reinvestigation_skipped_when_no_unclear(self):
        """If no UNVERIFIED/AMBIGUOUS assumptions exist, re-investigation does nothing."""
        from gap_finder.gap_finder import _reinvestigate_unclear

        ctx = _make_ctx([_make_assumption("A1", "required")])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)

        # _llm_with_tools should NOT be called
        with patch("gap_finder.gap_finder._llm_with_tools") as mock_llm:
            _reinvestigate_unclear(ledger, "/fake/repo")
            mock_llm.assert_not_called()

    def test_reinvestigation_handles_bad_json_gracefully(self):
        """Bad JSON from LLM during re-investigation should leave ledger unchanged."""
        from gap_finder.gap_finder import _reinvestigate_unclear

        ctx = _make_ctx([_make_assumption("A4", "favorable")])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A4", AssumptionStatus.UNVERIFIED)

        with patch("gap_finder.gap_finder._llm_with_tools", return_value="not json"):
            _reinvestigate_unclear(ledger, "/fake/repo")

        self.assertEqual(ledger.get("A4").status, AssumptionStatus.UNVERIFIED)

    def test_reinvestigation_does_not_overwrite_resolved_assumptions(self):
        """Re-investigation only updates the UNVERIFIED/AMBIGUOUS assumptions, not others."""
        from gap_finder.gap_finder import _reinvestigate_unclear

        ctx = _make_ctx([
            _make_assumption("A1", "required"),
            _make_assumption("A4", "favorable"),
        ])
        ledger = AssumptionLedger.from_context(ctx)
        ledger.update_status("A1", AssumptionStatus.SUPPORTED,
                             AssumptionEvidence(supporting_evidence=["f.go:1"]))
        ledger.update_status("A4", AssumptionStatus.UNVERIFIED)

        # LLM tries to also change A1
        response = json.dumps({
            "assumption_verdicts": [
                {
                    "assumption_id": "A1",  # should be ignored — not unclear
                    "status": "REFUTED",
                    "supporting_evidence": [],
                    "contradicting_evidence": ["f.go:99: bogus"],
                    "reasoning": "attempt to overwrite",
                    "limitations": [], "alternative_explanations": [],
                    "suggested_validation": "", "source_refs": [], "searches_attempted": [],
                },
                {
                    "assumption_id": "A4",
                    "status": "INDETERMINATE",
                    "supporting_evidence": [],
                    "contradicting_evidence": [],
                    "reasoning": "cannot determine from static analysis",
                    "limitations": ["runtime-only"],
                    "alternative_explanations": [],
                    "suggested_validation": "dynamic tracing",
                    "source_refs": [], "searches_attempted": ["search maxStream"],
                },
            ],
            "findings": [],
        })

        with patch("gap_finder.gap_finder._llm_with_tools", return_value=response):
            _reinvestigate_unclear(ledger, "/fake/repo")

        # A1 must remain SUPPORTED
        self.assertEqual(ledger.get("A1").status, AssumptionStatus.SUPPORTED)
        # A4 updated to INDETERMINATE
        self.assertEqual(ledger.get("A4").status, AssumptionStatus.INDETERMINATE)


class TestQuicA4Regression(unittest.TestCase):
    """
    Regression tests for the QUIC max-streams hypothesis (quic_max_streams_v3.yaml).

    A4 (favorable) was initially unclear; the previous pipeline ended in DEFECT.
    These tests verify that:
      - A4 is included in the ledger despite being favorable
      - UNVERIFIED A4 triggers re-investigation
      - Unresolved A4 does not invalidate the A1+A2 base attack
      - Supported A4 is captured as an amplifier
    """

    def setUp(self):
        """Build context from quic_max_streams_v3.yaml assumptions."""
        # Replicate the YAML assumption set
        self.a1 = _make_assumption("A1", "required")
        self.a1.description = ("The implementation can be forced to grant MAX_STREAMS "
                               "credit on transport-level stream closure before application-level "
                               "request processing completes.")
        self.a2 = _make_assumption("A2", "required")
        self.a2.description = ("Per-stream HTTP/3 request processing incurs non-trivial CPU work "
                               "that is not cancelled promptly when the stream is closed.")
        self.a3 = _make_assumption("A3", "favorable")
        self.a3.description = ("The client can predict packet numbers for RESET_STREAM frames.")
        self.a4 = _make_assumption("A4", "favorable")
        self.a4.description = ("The client can predict MAX_STREAMS frames to open streams "
                               "using credit it expects to receive before it is granted.")
        self.a5 = _make_assumption("A5", "favorable")
        self.a5.description = "No application-layer stream-churn or reset-rate limit exists."
        self.ctx = _make_ctx([self.a1, self.a2, self.a3, self.a4, self.a5])

    def test_a4_included_in_ledger_despite_being_favorable(self):
        ledger = AssumptionLedger.from_context(self.ctx)
        self.assertIsNotNone(ledger.get("A4"), "A4 must be in the ledger")
        self.assertFalse(ledger.get("A4").is_critical, "A4 should not be critical (favorable)")
        self.assertEqual(ledger.get("A4").status, AssumptionStatus.NOT_STATED)

    def test_unverified_a4_triggers_reinvestigation(self):
        """When A4 comes back UNVERIFIED from the developer, re-investigation is triggered."""
        from gap_finder.gap_finder import _reinvestigate_unclear

        ledger = AssumptionLedger.from_context(self.ctx)
        # Simulate developer pass: A1,A2 supported; A4 UNVERIFIED
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        ledger.update_status("A4", AssumptionStatus.UNVERIFIED,
                             AssumptionEvidence(
                                 searches_attempted=["search MAX_STREAMS", "search predictPacket"]
                             ))

        unclear = ledger.by_status(AssumptionStatus.UNVERIFIED, AssumptionStatus.AMBIGUOUS)
        # A3, A4, A5 are NOT_STATED; A4 is UNVERIFIED
        self.assertIn("A4", [r.assumption_id for r in unclear])

        # Simulate re-investigation resolving A4 → SUPPORTED
        response = json.dumps({
            "assumption_verdicts": [{
                "assumption_id": "A4",
                "status": "SUPPORTED",
                "supporting_evidence": [
                    "stream.go:200: deleteStream always sends MAX_STREAMS immediately"
                ],
                "contradicting_evidence": [],
                "reasoning": "deleteStream + queueMaxStreamID + queueControlFrame chain is deterministic",
                "limitations": ["timing jitter may affect precision"],
                "alternative_explanations": ["non-deterministic scheduling? found no jitter"],
                "suggested_validation": "",
                "source_refs": ["stream.go:200", "stream.go:450"],
                "searches_attempted": [
                    "search deleteStream", "search queueMaxStreamID",
                    "search queueControlFrame", "search m.maxStream",
                ],
            }],
            "findings": [],
        })
        with patch("gap_finder.gap_finder._llm_with_tools", return_value=response):
            _reinvestigate_unclear(ledger, "/fake/repo")

        self.assertEqual(ledger.get("A4").status, AssumptionStatus.SUPPORTED)
        sup = ledger.get("A4").evidence.supporting_evidence[0]
        self.assertIn("deleteStream", sup)

    def test_unresolved_a4_does_not_block_base_attack(self):
        """
        If A4 remains INDETERMINATE after re-investigation, the A1+A2 base attack
        must still be viable (all_critical_refuted must be False, critical_unresolved empty).
        """
        ledger = AssumptionLedger.from_context(self.ctx)
        ledger.update_status("A1", AssumptionStatus.SUPPORTED)
        ledger.update_status("A2", AssumptionStatus.SUPPORTED)
        ledger.update_status("A4", AssumptionStatus.INDETERMINATE,
                             AssumptionEvidence(
                                 suggested_validation="dynamic tracing under load",
                             ))
        self.assertFalse(ledger.all_critical_refuted(),
                         "INFEASIBLE gate must not trigger with INDETERMINATE A4")
        self.assertEqual(len(ledger.critical_unresolved()), 0,
                         "INDETERMINATE favorable A4 must not appear in critical_unresolved")

    def test_a4_evidence_surfaces_in_ledger_serialization(self):
        """Full A4 evidence should appear in to_dict_list() output."""
        ledger = AssumptionLedger.from_context(self.ctx)
        ledger.update_status("A4", AssumptionStatus.SUPPORTED,
                             AssumptionEvidence(
                                 supporting_evidence=["stream.go:200: deleteStream sends MAX_STREAMS"],
                                 reasoning="deterministic chain",
                                 searches_attempted=["search deleteStream", "search queueMaxStreamID"],
                             ))
        d_list = ledger.to_dict_list()
        a4_dict = next((d for d in d_list if d["assumption_id"] == "A4"), None)
        self.assertIsNotNone(a4_dict)
        self.assertEqual(a4_dict["status"], "SUPPORTED")
        self.assertIn("deleteStream", a4_dict["evidence"]["supporting_evidence"][0])
        self.assertIn("deleteStream", a4_dict["evidence"]["searches_attempted"][0])


class TestExploitPlannerAblation(unittest.TestCase):
    """
    Verify that ExploitPlan correctly captures base and amplified attack paths.
    """

    def _make_steps(self, count=3):
        from exploit_planner.models import Step
        return [Step(n=i+1, action=f"action {i+1}", quic_frame="STREAM",
                     expected_server_response="server processes", rationale="reason")
                for i in range(count)]

    def test_exploit_plan_accepts_base_and_amplified_sequences(self):
        from exploit_planner.models import ExploitPlan, Step
        base = self._make_steps(3)
        amplified = self._make_steps(5)
        plan = ExploitPlan(
            finding_type="SecurityDesignGap",
            finding_ref="quic-max-streams",
            assumptions_relied_on=["A1", "A2"],
            attack_sequence=base,
            expected_effect="CPU exhaustion",
            severity="high",
            pivot_note=None,
            base_attack_sequence=base,
            amplified_attack_sequence=amplified,
            favorable_assumptions_used=["A4"],
        )
        self.assertEqual(len(plan.base_attack_sequence), 3)
        self.assertEqual(len(plan.amplified_attack_sequence), 5)
        self.assertEqual(plan.favorable_assumptions_used, ["A4"])

    def test_parse_plan_reads_ablation_fields(self):
        from exploit_planner.exploit_planner import _parse_plan
        plan_json = json.dumps({
            "finding_type": "SecurityDesignGap",
            "finding_ref": "quic-streams-churn",
            "assumptions_relied_on": ["A1", "A2"],
            "attack_sequence": [
                {"n": 1, "action": "open stream", "quic_frame": "STREAM",
                 "expected_server_response": "server accepts", "rationale": "base"}
            ],
            "base_attack_sequence": [
                {"n": 1, "action": "open stream", "quic_frame": "STREAM",
                 "expected_server_response": "server accepts", "rationale": "base"}
            ],
            "amplified_attack_sequence": [
                {"n": 1, "action": "open stream with predicted credit", "quic_frame": "STREAM",
                 "expected_server_response": "server accepts early", "rationale": "amplified"},
                {"n": 2, "action": "immediately close", "quic_frame": "STOP_SENDING",
                 "expected_server_response": "RESET_STREAM", "rationale": "amplified"}
            ],
            "favorable_assumptions_used": ["A4"],
            "expected_effect": "CPU and connection state exhaustion",
            "severity": "high",
            "pivot_note": None,
        })
        plan = _parse_plan(plan_json)
        self.assertIsNotNone(plan)
        self.assertIsNotNone(plan.base_attack_sequence)
        self.assertIsNotNone(plan.amplified_attack_sequence)
        self.assertEqual(len(plan.base_attack_sequence), 1)
        self.assertEqual(len(plan.amplified_attack_sequence), 2)
        self.assertEqual(plan.favorable_assumptions_used, ["A4"])

    def test_parse_plan_no_amplified_gives_none(self):
        from exploit_planner.exploit_planner import _parse_plan
        plan_json = json.dumps({
            "finding_type": "SecurityDesignGap",
            "finding_ref": "basic",
            "assumptions_relied_on": ["A1"],
            "attack_sequence": [
                {"n": 1, "action": "send", "quic_frame": "STREAM",
                 "expected_server_response": "ok", "rationale": "r"}
            ],
            "amplified_attack_sequence": None,
            "favorable_assumptions_used": [],
            "expected_effect": "exhaustion",
            "severity": "medium",
            "pivot_note": None,
        })
        plan = _parse_plan(plan_json)
        self.assertIsNone(plan.amplified_attack_sequence)
        self.assertEqual(plan.favorable_assumptions_used, [])


if __name__ == "__main__":
    unittest.main()
