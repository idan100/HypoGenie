"""
Test fixtures for use in phase test gates.
Provides pre-parsed context and cached spec requirements to avoid
re-running LLM calls in tests.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from processor.yaml_parser import parse
from spec_processor.models import SpecRequirement

# ── QUIC Rapid Reset context (h2_rapid_reset.yaml) ─────────────────────────
_YAML_PATH = os.path.join(
    os.path.dirname(__file__), "yamls", "positive", "h2_rapid_reset.yaml"
)
quic_ctx = parse(_YAML_PATH)

# Pre-built spec requirements (avoids LLM calls in unit tests)
quic_spec_reqs = [
    SpecRequirement(
        rfc="RFC 7540",
        section="10.5",
        requirement_text=(
            "An endpoint SHOULD protect against RST_STREAM amplification."
        ),
        classification="should_deviation",
        dos_mechanism=(
            "No rate limit on stream resets allows rapid resource exhaustion"
        ),
        relevant_to_assumption="A3",
    ),
    SpecRequirement(
        rfc="RFC 7540",
        section="6.4",
        requirement_text=(
            "After sending the RST_STREAM, the sending endpoint MUST be prepared "
            "to receive and process additional frames sent by the peer on that stream."
        ),
        classification="must_violation",
        dos_mechanism=(
            "Server must keep accepting frames after RST_STREAM, creating "
            "continued resource usage during stream teardown"
        ),
        relevant_to_assumption="A1",
    ),
    SpecRequirement(
        rfc="RFC 7540",
        section="6.9",
        requirement_text=(
            "A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."
        ),
        classification="must_violation",
        dos_mechanism=(
            "No per-connection stream count limit means unlimited handler backlog"
        ),
        relevant_to_assumption="A2",
    ),
    SpecRequirement(
        rfc="RFC 7540",
        section="10.5",
        requirement_text=(
            "Every connection MUST bound outstanding stream-reset count or apply backoff."
        ),
        classification="implementation_invariant",
        dos_mechanism=(
            "Absence of this invariant allows unbounded goroutine accumulation"
        ),
        relevant_to_assumption="A3",
    ),
]
