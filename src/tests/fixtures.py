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
from gap_finder.models import AssumptionVerdict, ComplianceGap, SecurityDesignGap, ImplementationInvariantViolation

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

# ── Phase 2 output: verdicts + findings from Gap Finder on golang/net v0.17.0 ─
quic_verdicts = [
    AssumptionVerdict(
        assumption_id="A1",
        status="refuted",
        code_evidence="http2/server.go:1436 — RST_STREAM handler does not check sc.clientMaxStreams",
        reasoning="Server is not forced to keep accepting frames after RST_STREAM; clientMaxStreams controls concurrent streams",
    ),
    AssumptionVerdict(
        assumption_id="A2",
        status="confirmed",
        code_evidence="http2/server.go:1708 — no per-connection stream count limit beyond flow-control window",
        reasoning="No enforcement of a bound on the number of concurrent or accumulated stream resets",
    ),
    AssumptionVerdict(
        assumption_id="A3",
        status="refuted",
        code_evidence="http2/server.go:1434 — clientMaxStreams field present but no RST_STREAM rate limit",
        reasoning="clientMaxStreams limits concurrent streams but there is no rate limit on how fast RST_STREAM can be sent",
    ),
]

# Pre-built findings matching the Phase 2 run on golang/net v0.17.0
quic_findings = [
    ComplianceGap(
        requirement=quic_spec_reqs[0],  # §10.5 should_deviation
        gap_description=(
            "The server does not implement any rate limiting mechanisms for stream resets, "
            "allowing rapid resource exhaustion via repeated HEADERS+RST_STREAM cycles."
        ),
        code_location="http2/server.go:1434",
        code_snippet="// clientMaxStreams is set but no rate-limit counter exists here",
    ),
    ImplementationInvariantViolation(
        requirement=quic_spec_reqs[1],  # §6.4 must_violation
        invariant_description=(
            "There are no bounds or checks in place after sending RST_STREAM; "
            "the server continues processing queued frames without a cap."
        ),
        code_location="http2/server.go:1436",
        code_snippet="// no per-stream cleanup guard after RST_STREAM receipt",
    ),
    ImplementationInvariantViolation(
        requirement=quic_spec_reqs[2],  # §6.9 must_violation
        invariant_description=(
            "There is no enforcement of a limit on accumulated stream resets; "
            "the flow-control window (2^31-1) is unrelated to stream-reset count."
        ),
        code_location="http2/server.go:1708",
        code_snippet="// flow-control window update — no reset-count guard",
    ),
]

# ── Phase 3 output: pre-built ExploitPlan (avoids LLM calls in Phase 5 tests) ─
from exploit_planner.models import ExploitPlan, Step as ExploitStep

quic_plan = ExploitPlan(
    finding_type="ImplementationInvariantViolation",
    finding_ref="No RST_STREAM rate limit — unbounded goroutine accumulation",
    assumptions_relied_on=["A2"],
    attack_sequence=[
        ExploitStep(
            n=1,
            action="Establish TCP connection and send initial SETTINGS frame",
            quic_frame="SETTINGS: MAX_CONCURRENT_STREAMS=100",
            expected_server_response="Server sends SETTINGS ACK",
            rationale="Initialize the HTTP/2 connection with server stream limit",
        ),
        ExploitStep(
            n=2,
            action="Send HEADERS frame to open stream 1",
            quic_frame="HEADERS: stream_id=1, END_HEADERS=1",
            expected_server_response="Server allocates handler for stream 1",
            rationale="Open a stream that the server will track",
        ),
        ExploitStep(
            n=3,
            action="Immediately send RST_STREAM to cancel stream 1",
            quic_frame="RST_STREAM: stream_id=1, error_code=CANCEL",
            expected_server_response="Server tears down stream 1 handler (incomplete)",
            rationale="Trigger resource allocation then cancellation with no rate limit",
        ),
        ExploitStep(
            n=4,
            action="Repeat HEADERS+RST_STREAM on streams 3, 5, 7, ... in rapid succession",
            quic_frame="HEADERS: stream_id=N, END_HEADERS=1",
            expected_server_response="Server allocates goroutine per stream, never rate-limited",
            rationale="Flood the server event loop — no reset rate limit means unbounded goroutine growth",
        ),
        ExploitStep(
            n=5,
            action="Continue for 10,000+ cycles to exhaust CPU/memory",
            quic_frame="RST_STREAM: stream_id=N, error_code=CANCEL",
            expected_server_response="CPU spikes, memory grows, probe requests time out",
            rationale="Sustained attack confirms DoS once goroutine backlog exhausts resources",
        ),
    ],
    expected_effect="CPU exhaustion and goroutine accumulation leading to server unresponsiveness",
    severity="high",
    pivot_note=(
        "A1 (server must keep accepting frames) was refuted. Attack relies on A2 (confirmed): "
        "no per-connection stream count limit. Rapid HEADERS+RST_STREAM cycles still cause "
        "goroutine accumulation because there is no reset rate limit."
    ),
)
