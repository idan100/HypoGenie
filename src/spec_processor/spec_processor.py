import json
import os
import re
import requests
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_client as _llm

from .models import SpecRequirement
from .prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE


def _fetch_rfc_section(rfc: str, section: str) -> str:
    """
    Fetch RFC section text from the IETF RFC editor (plain-text format).
    rfc example: "RFC 7540" → rfc number 7540
    section example: "10.5"
    Returns plain text of the section (best-effort).
    """
    rfc_num = re.sub(r"[^0-9]", "", rfc)
    url = f"https://www.rfc-editor.org/rfc/rfc{rfc_num}.txt"

    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        text = resp.text

        return _extract_section_from_plaintext(text, section, rfc_num)

    except Exception as e:
        return f"[Error fetching {rfc} §{section}: {e}]"


def _extract_section_from_plaintext(text: str, section: str, rfc_num: str) -> str:
    """
    Extract a section from RFC plain text format.

    RFC plain text has a table of contents near the top followed by the actual
    section content. TOC lines look like:
        10.5. Denial-of-Service Considerations .....70
    Actual section headings look like:
        10.5.  Denial-of-Service Considerations
    (no trailing page number, may have extra spaces between number and title)

    Strategy: skip the first occurrence (TOC entry) and collect from the second.
    """
    lines = text.split("\n")
    sec_prefix = re.escape(section)
    next_section_re = _build_next_section_re(section)

    # heading_re matches the actual section heading (not TOC entry)
    # TOC entries have trailing dots + page number; actual headings do not
    heading_re = re.compile(rf"^{sec_prefix}[.\s]")
    toc_re = re.compile(r"\.{3,}\s*\d+\s*$")  # ends with "...70" or "... 70"

    occurrences = 0
    collecting = False
    collected_lines = []

    for line in lines:
        stripped = line.strip()

        if not collecting:
            if heading_re.match(stripped):
                # Skip TOC entries
                if toc_re.search(stripped):
                    continue
                # This is the real section heading
                occurrences += 1
                collecting = True
                collected_lines.append(stripped)
        else:
            # Stop at the next section heading
            if next_section_re and re.match(next_section_re, stripped):
                # Confirm it's a real heading not a TOC reference
                if not toc_re.search(stripped):
                    break
            # Skip RFC page-break headers
            if re.match(r"^RFC\s+\d+\s+", stripped):
                continue
            # Skip author attribution lines
            if re.match(r"^[A-Z][a-z]+,\s+et al\.", stripped):
                continue
            collected_lines.append(stripped)
            if len(collected_lines) > 600:
                break

    if not collected_lines:
        return f"[Section {section} not found in RFC {rfc_num} plain text]"

    result = "\n".join(l for l in collected_lines if l)
    return result[:8000]


def _build_next_section_re(section: str) -> str:
    """Build a regex that matches the section that immediately follows `section`."""
    parts = section.split(".")
    # Try to find the next sibling or parent:
    # For "10.5" → next is "10.6" OR a new top-level section "11"
    # For "6.4" → next is "6.5" OR "7"
    try:
        last = int(parts[-1])
        parent = ".".join(parts[:-1])
        next_sibling = (parent + "." if parent else "") + str(last + 1)
        # Also match if section number goes up at any parent level
        top = int(parts[0])
        alt = str(top + 1) + r"[.\s]"
        if len(parts) == 1:
            return rf"^{re.escape(str(top + 1))}[.\s]"
        return rf"^({re.escape(next_sibling)}|{alt})[.\s]?"
    except ValueError:
        return ""


def _call_llm(system: str, user: str) -> str:
    return _llm.call_llm(system, user, role_env="SPEC_PROCESSOR_MODEL", json_mode=True)


def _parse_llm_output(raw: str, rfc: str, section: str) -> list[SpecRequirement]:
    """Parse JSON output from LLM into SpecRequirement objects."""
    # Strip markdown fences if present
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())

    # LLM might return a JSON object wrapping an array
    parsed = json.loads(raw)
    if isinstance(parsed, dict):
        # unwrap common wrapper keys
        for key in ("requirements", "result", "items", "data"):
            if key in parsed and isinstance(parsed[key], list):
                parsed = parsed[key]
                break
        else:
            # single object — wrap in list
            if "classification" in parsed:
                parsed = [parsed]
            else:
                return []

    valid_classes = {
        "must_violation", "should_deviation", "may_behavior",
        "security_consideration", "implementation_invariant",
    }

    results = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        classification = item.get("classification", "")
        if classification not in valid_classes:
            continue
        req = SpecRequirement(
            rfc=item.get("rfc", rfc),
            section=item.get("section", section),
            requirement_text=item.get("requirement_text", ""),
            classification=classification,
            dos_mechanism=item.get("dos_mechanism", ""),
            relevant_to_assumption=item.get("relevant_to_assumption"),
        )
        if req.requirement_text:
            results.append(req)

    return results


def run(ctx, rfc_text_override: Optional[dict] = None) -> list[SpecRequirement]:
    """
    For each rfc_sections entry in ctx, fetch the RFC text and call the LLM
    to extract DoS-relevant normative requirements.

    rfc_text_override: optional dict mapping (rfc, section) → text, used in tests.

    Returns a flat list of SpecRequirement objects across all sections.
    """
    all_requirements: list[SpecRequirement] = []

    assumptions_text = "\n".join(
        f"- {a.id} ({a.necessity}): {a.description}" for a in ctx.assumptions
    )
    suspected_mechanism_text = "\n".join(
        f"  {i+1}. {step}" if isinstance(step, str)
        else f"  {step.get('step', i+1)}. {step.get('action', '')}"
        for i, step in enumerate(
            getattr(ctx, "suspected_mechanism_raw", []) or []
        )
    )
    if not suspected_mechanism_text:
        suspected_mechanism_text = "(see hypothesis description)"

    for rfc_sec in ctx.rfc_sections:
        key = (rfc_sec.rfc, rfc_sec.section)

        if rfc_text_override and key in rfc_text_override:
            rfc_text = rfc_text_override[key]
        else:
            print(f"  [spec_processor] Fetching {rfc_sec.rfc} §{rfc_sec.section} ...")
            rfc_text = _fetch_rfc_section(rfc_sec.rfc, rfc_sec.section)

        if rfc_text.startswith("[Error") or rfc_text.startswith("[Could not"):
            print(f"  [spec_processor] WARNING: {rfc_text}")

        user = USER_PROMPT_TEMPLATE.format(
            description=ctx.description,
            dos_class=ctx.dos_class,
            assumptions=assumptions_text,
            suspected_mechanism=suspected_mechanism_text,
            rfc=rfc_sec.rfc,
            section=rfc_sec.section,
            dos_relevance=rfc_sec.dos_relevance,
            rfc_text=rfc_text,
        )

        try:
            raw = _call_llm(SYSTEM_PROMPT, user)
            reqs = _parse_llm_output(raw, rfc_sec.rfc, rfc_sec.section)
            print(
                f"  [spec_processor] {rfc_sec.rfc} §{rfc_sec.section}: "
                f"extracted {len(reqs)} requirement(s)"
            )
            all_requirements.extend(reqs)
        except Exception as e:
            print(f"  [spec_processor] ERROR on {rfc_sec.rfc} §{rfc_sec.section}: {e}")

    return all_requirements
