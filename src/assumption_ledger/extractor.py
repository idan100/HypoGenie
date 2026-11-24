"""
Implicit assumption extractor.

Analyzes the hypothesis description and existing explicit assumptions to
identify additional implicit assumptions — claims required for the hypothesis
to hold that are NOT stated in the YAML.

One LLM call; returns empty list on any failure so it never blocks the pipeline.
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_client as _llm

from processor.models import Assumption


_SYSTEM = """You are a security hypothesis analyst.

Given a DoS hypothesis and its explicit assumptions, identify implicit assumptions
that are NOT stated but are required for the hypothesis to hold.

An implicit assumption is a claim about the target system that:
- Is not covered by any explicit assumption
- Must be true for the attack mechanism to work
- Is independently verifiable through source code analysis
- Could plausibly be false (i.e., is not a tautology)

Examples of implicit assumptions worth surfacing:
- "The server does not have a global per-connection rate limit on this operation"
- "Processing cost grows super-linearly with input size"
- "No upstream middleware strips or normalises the malicious field"
- "Buffers are heap-allocated per request, not pooled and reused"
- "The operation is synchronous, holding the handler goroutine for its full duration"

Rules:
- Do NOT repeat what is already covered in explicit_assumptions
- Do NOT fabricate implementation details — only observable, testable claims
- Limit output to at most 3 implicit assumptions
- If the explicit assumptions already cover all plausible attack prerequisites,
  return an empty list

Output JSON only:
{
  "implicit_assumptions": [
    {
      "id": "IMPL_1",
      "description": "precise, independently verifiable claim",
      "necessity": "required"
    }
  ]
}"""


_USER_TEMPLATE = """## Hypothesis

{description}

DoS class: {dos_class}
Protocol: {protocol}

## Explicit assumptions already stated

{explicit_assumptions}

Identify implicit assumptions not covered above. Output JSON only."""


def extract_implicit(ctx) -> list[Assumption]:
    """
    Extract implicit assumptions from hypothesis context.

    Returns a list of new Assumption objects with ids like IMPL_1, IMPL_2, ...
    Returns empty list if the LLM call fails or produces nothing useful.
    """
    explicit_text = "\n".join(
        f"- {a.id} ({a.necessity}): {a.description}"
        for a in ctx.assumptions
    )
    if not explicit_text:
        explicit_text = "(none)"

    user = _USER_TEMPLATE.format(
        description=ctx.description[:1000],
        dos_class=ctx.dos_class,
        protocol=ctx.protocol,
        explicit_assumptions=explicit_text,
    )

    try:
        raw = _llm.call_llm(
            _SYSTEM, user,
            role_env="GAP_FINDER_MODEL",
            max_tokens=512,
            json_mode=True,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw.strip())

        data = json.loads(raw)
        existing_ids = {a.id for a in ctx.assumptions}
        results: list[Assumption] = []

        for item in data.get("implicit_assumptions", []):
            aid = str(item.get("id", "")).strip()
            adesc = str(item.get("description", "")).strip()
            anec = str(item.get("necessity", "favorable")).strip()
            if not aid or not adesc:
                continue
            if anec not in ("required", "favorable"):
                anec = "favorable"
            # Avoid collisions with existing assumption IDs.
            if aid in existing_ids:
                aid = f"IMPL_{aid}"
            results.append(Assumption(id=aid, description=adesc, necessity=anec))

        return results

    except Exception as exc:
        print(f"  [assumption_extractor] Warning: {exc}")
        return []
