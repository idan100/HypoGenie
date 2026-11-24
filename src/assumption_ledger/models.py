"""
Assumption Ledger — single source of truth for assumption resolution state.

Each AssumptionRecord accumulates evidence from Gap Finder and may be updated
by later pipeline agents (Exploit Planner, Critic) rather than independently
re-derived.  The ledger is threaded through the pipeline so each stage
contributes evidence without overwriting another stage's work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AssumptionStatus(str, Enum):
    """Resolution status for one assumption.

    Statuses are ordered by certainty:
      NOT_STATED → investigation has not started
      AMBIGUOUS  → claim is too vague to verify
      UNVERIFIED → investigation attempted; no conclusive evidence
      SUPPORTED  → direct evidence confirms the claim
      REFUTED    → direct evidence contradicts the claim
      CONFLICTING_EVIDENCE → both supporting and contradicting evidence found
      INDETERMINATE → irreducible uncertainty; no available investigation path
      NOT_APPLICABLE → assumption does not apply to this target/version
    """
    NOT_STATED           = "NOT_STATED"
    AMBIGUOUS            = "AMBIGUOUS"
    UNVERIFIED           = "UNVERIFIED"
    SUPPORTED            = "SUPPORTED"
    REFUTED              = "REFUTED"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    INDETERMINATE        = "INDETERMINATE"
    NOT_APPLICABLE       = "NOT_APPLICABLE"


# Map to the old 3-status model used by Gap Finder AssumptionVerdict.
_STATUS_TO_LEGACY: dict[AssumptionStatus, str] = {
    AssumptionStatus.SUPPORTED:            "confirmed",
    AssumptionStatus.REFUTED:              "refuted",
    AssumptionStatus.NOT_STATED:           "unclear",
    AssumptionStatus.AMBIGUOUS:            "unclear",
    AssumptionStatus.UNVERIFIED:           "unclear",
    AssumptionStatus.CONFLICTING_EVIDENCE: "unclear",
    AssumptionStatus.INDETERMINATE:        "unclear",
    AssumptionStatus.NOT_APPLICABLE:       "unclear",
}

# Legacy string → canonical new status (used when ingesting old-format output).
LEGACY_TO_STATUS: dict[str, AssumptionStatus] = {
    "confirmed": AssumptionStatus.SUPPORTED,
    "refuted":   AssumptionStatus.REFUTED,
    "unclear":   AssumptionStatus.UNVERIFIED,
}


@dataclass
class AssumptionEvidence:
    """
    Evidence bundle for one assumption.

    Every field defaults to empty.  Agents populate only what they actually
    found — fabricating evidence is prohibited.
    """
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    reasoning: str = ""
    limitations: list[str] = field(default_factory=list)
    alternative_explanations: list[str] = field(default_factory=list)
    suggested_validation: str = ""
    source_refs: list[str] = field(default_factory=list)
    searches_attempted: list[str] = field(default_factory=list)


@dataclass
class AssumptionRecord:
    """
    Single assumption + its full resolution state.

    Replaces (and is backward-compatible with) AssumptionVerdict.
    """
    assumption_id: str
    description: str
    necessity: str                  # "required" | "favorable" | "inferred"
    status: AssumptionStatus = AssumptionStatus.NOT_STATED
    evidence: AssumptionEvidence = field(default_factory=AssumptionEvidence)
    is_critical: bool = False       # True when necessity == "required"
    is_implicit: bool = False       # True when added by assumption extractor

    def to_legacy_verdict(self):
        """Return a backward-compatible AssumptionVerdict."""
        # Lazy import to avoid circular dependency.
        from gap_finder.models import AssumptionVerdict
        legacy_status = _STATUS_TO_LEGACY.get(self.status, "unclear")
        code_evidence = ""
        if self.evidence.supporting_evidence:
            code_evidence = "; ".join(self.evidence.supporting_evidence[:2])
        elif self.evidence.contradicting_evidence:
            code_evidence = "; ".join(self.evidence.contradicting_evidence[:2])
        elif self.evidence.source_refs:
            code_evidence = "; ".join(self.evidence.source_refs[:2])
        return AssumptionVerdict(
            assumption_id=self.assumption_id,
            status=legacy_status,
            code_evidence=code_evidence,
            reasoning=self.evidence.reasoning,
        )

    @property
    def is_unresolved(self) -> bool:
        return self.status in (
            AssumptionStatus.NOT_STATED,
            AssumptionStatus.AMBIGUOUS,
            AssumptionStatus.UNVERIFIED,
            AssumptionStatus.INDETERMINATE,
            AssumptionStatus.CONFLICTING_EVIDENCE,
        )

    @property
    def is_resolved(self) -> bool:
        return self.status in (
            AssumptionStatus.SUPPORTED,
            AssumptionStatus.REFUTED,
            AssumptionStatus.NOT_APPLICABLE,
        )


class AssumptionLedger:
    """
    Single source of truth for all assumptions in a hypothesis run.

    Agents must call update_status() to modify existing records rather than
    creating new ones, so the full evidence chain accumulates in one place.
    """

    def __init__(self, records: Optional[list[AssumptionRecord]] = None):
        self._records: dict[str, AssumptionRecord] = {}
        for r in (records or []):
            self._records[r.assumption_id] = r

    @classmethod
    def from_context(cls, ctx) -> "AssumptionLedger":
        """Initialise ledger from HypothesisContext.assumptions."""
        records = [
            AssumptionRecord(
                assumption_id=a.id,
                description=a.description,
                necessity=a.necessity,
                status=AssumptionStatus.NOT_STATED,
                is_critical=(a.necessity == "required"),
                is_implicit=False,
            )
            for a in ctx.assumptions
        ]
        return cls(records)

    # ── mutations ─────────────────────────────────────────────────────────────

    def add(self, record: AssumptionRecord) -> None:
        """Add a brand-new assumption record.  Raises if the id already exists."""
        if record.assumption_id in self._records:
            raise ValueError(
                f"Assumption {record.assumption_id!r} already in ledger; "
                f"use update_status() to change it."
            )
        self._records[record.assumption_id] = record

    def add_or_replace(self, record: AssumptionRecord) -> None:
        """Upsert — adds a new record or silently replaces an existing one."""
        self._records[record.assumption_id] = record

    def update_status(
        self,
        assumption_id: str,
        status: AssumptionStatus,
        evidence: Optional[AssumptionEvidence] = None,
    ) -> None:
        """
        Update the status (and optionally evidence) for an existing assumption.
        Raises KeyError if the id is not in the ledger.
        """
        record = self._records.get(assumption_id)
        if record is None:
            raise KeyError(
                f"No assumption {assumption_id!r} in ledger; call add() first."
            )
        record.status = status
        if evidence is not None:
            record.evidence = evidence

    # ── queries ───────────────────────────────────────────────────────────────

    def get(self, assumption_id: str) -> Optional[AssumptionRecord]:
        return self._records.get(assumption_id)

    def all(self) -> list[AssumptionRecord]:
        return list(self._records.values())

    def by_status(self, *statuses: AssumptionStatus) -> list[AssumptionRecord]:
        return [r for r in self._records.values() if r.status in statuses]

    def critical_unresolved(self) -> list[AssumptionRecord]:
        """Required assumptions that are not SUPPORTED or NOT_APPLICABLE."""
        return [
            r for r in self._records.values()
            if r.is_critical
            and r.status not in (
                AssumptionStatus.SUPPORTED,
                AssumptionStatus.NOT_APPLICABLE,
            )
        ]

    def critical_refuted(self) -> list[AssumptionRecord]:
        """Required assumptions that are REFUTED."""
        return [
            r for r in self._records.values()
            if r.is_critical and r.status == AssumptionStatus.REFUTED
        ]

    def all_critical_refuted(self) -> bool:
        """True when every required assumption is REFUTED (INFEASIBLE gate)."""
        required = [r for r in self._records.values() if r.is_critical]
        return bool(required) and all(
            r.status == AssumptionStatus.REFUTED for r in required
        )

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_verdicts(self) -> list:
        """Backward-compatible: return list[AssumptionVerdict]."""
        return [r.to_legacy_verdict() for r in self._records.values()]

    def to_dict_list(self) -> list[dict]:
        """Full serialisation for JSON output."""
        result = []
        for r in self._records.values():
            result.append({
                "assumption_id": r.assumption_id,
                "description": r.description,
                "necessity": r.necessity,
                "status": r.status.value,
                "is_critical": r.is_critical,
                "is_implicit": r.is_implicit,
                "evidence": {
                    "supporting_evidence": r.evidence.supporting_evidence,
                    "contradicting_evidence": r.evidence.contradicting_evidence,
                    "reasoning": r.evidence.reasoning,
                    "limitations": r.evidence.limitations,
                    "alternative_explanations": r.evidence.alternative_explanations,
                    "suggested_validation": r.evidence.suggested_validation,
                    "source_refs": r.evidence.source_refs,
                    "searches_attempted": r.evidence.searches_attempted,
                },
            })
        return result

    def __len__(self) -> int:
        return len(self._records)

    def __repr__(self) -> str:
        statuses = {r.assumption_id: r.status.value for r in self._records.values()}
        return f"AssumptionLedger({statuses})"
