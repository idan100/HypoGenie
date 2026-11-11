from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class SpecRequirement:
    rfc: str
    section: str
    requirement_text: str
    classification: Literal[
        "must_violation",
        "should_deviation",
        "may_behavior",
        "security_consideration",
        "implementation_invariant",
    ]
    dos_mechanism: str
    relevant_to_assumption: Optional[str]  # e.g. "A1", "A2", or None

    def __str__(self):
        return (
            f"SpecRequirement(rfc={self.rfc!r}, section={self.section!r}, "
            f"class={self.classification!r}, assumption={self.relevant_to_assumption!r}, "
            f"text={self.requirement_text[:60]!r}...)"
        )
