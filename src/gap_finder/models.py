from dataclasses import dataclass
from typing import Literal, Union

from spec_processor.models import SpecRequirement


@dataclass
class AssumptionVerdict:
    assumption_id: str
    status: Literal["confirmed", "refuted", "unclear"]
    code_evidence: str    # verbatim snippet(s) + file:line
    reasoning: str


@dataclass
class ComplianceGap:
    """classification: must_violation | should_deviation"""
    requirement: SpecRequirement
    gap_description: str    # what spec requires vs what code does
    code_location: str      # file:line where enforcement is missing
    code_snippet: str       # surrounding code for context


@dataclass
class SecurityDesignGap:
    """classification: may_behavior | security_consideration"""
    requirement: SpecRequirement
    gap_description: str    # what defensive measure is absent
    code_location: str      # file:line of the unguarded code path
    code_snippet: str


@dataclass
class ImplementationInvariantViolation:
    """classification: implementation_invariant"""
    requirement: SpecRequirement
    invariant_description: str   # property that must hold for safe operation
    code_location: str           # file:line where invariant is absent
    code_snippet: str


Finding = Union[ComplianceGap, SecurityDesignGap, ImplementationInvariantViolation]
