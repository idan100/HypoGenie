"""
Gap Finder — Developer + Critic loop (1 retry max).

Developer: LLM with file-reading tools explores the cloned repo,
           verifies assumptions and finds RFC compliance/design gaps.
Critic:    LLM with no tools reviews the developer's output for quality.
"""

import json
import os
import re
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_client as _llm
import cache as _cache

from .models import (
    AssumptionVerdict,
    ComplianceGap,
    SecurityDesignGap,
    ImplementationInvariantViolation,
    Finding,
)
from .prompts import (
    DEVELOPER_SYSTEM,
    DEVELOPER_USER_TEMPLATE,
    CRITIC_SYSTEM,
    CRITIC_USER_TEMPLATE,
)
from . import tools as _tools


def _llm_with_tools(system: str, user: str, repo_root: str) -> str:
    """
    Run the developer agent: LLM with file-reading tools.
    Implements a simple tool-call loop using the OpenAI function-calling API.
    """
    # Developer tool loop requires OpenAI function-calling API
    provider, client = _llm.get_client("openai")
    model = _llm.get_model(provider, "GAP_FINDER_MODEL")

    # Check cache
    cache_key_user = user + f"\n[repo_root={repo_root}]"

    cached = _cache.get(provider, model, system, cache_key_user)
    if cached is not None:
        print("  [gap_finder] developer (cache hit)")
        return cached

    _tools.set_repo_root(repo_root)

    tools_schema = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read file content with line numbers",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List directory contents",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "required": [],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_code",
                "description": "Search for a pattern in source files",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "file_pattern": {"type": "string", "default": "*.go"},
                        "path": {"type": "string", "default": "."},
                    },
                    "required": ["query"],
                },
            },
        },
    ]

    tool_map = {
        "read_file": _tools.read_file,
        "list_dir": _tools.list_dir,
        "search_code": _tools.search_code,
    }

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    max_iterations = 30
    for iteration in range(max_iterations):
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools_schema,
            tool_choice="auto",
            response_format={"type": "json_object"},
            max_tokens=8192,
        )
        msg = resp.choices[0].message

        if msg.tool_calls:
            messages.append(msg)
            for tc in msg.tool_calls:
                fn = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                    result = tool_map[fn](**args)
                except Exception as e:
                    result = f"[tool error] {e}"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result),
                })
            print(f"  [gap_finder] developer tool calls iteration {iteration+1}")
        else:
            # Final response
            result_text = msg.content or ""
            _cache.put(provider, model, system, cache_key_user, result_text)
            return result_text

    # Max iterations reached — return whatever we have
    final = messages[-1].get("content", "{}") if isinstance(messages[-1], dict) else "{}"
    _cache.put(provider, model, system, cache_key_user, final)
    return final


def _llm_no_tools(system: str, user: str) -> str:
    """Run the critic: LLM with no tools."""
    return _llm.call_llm(system, user, role_env="GAP_FINDER_CRITIC_MODEL", max_tokens=1024, json_mode=False)


def _parse_developer_output(raw: str, ctx, spec_reqs) -> tuple[list[AssumptionVerdict], list[Finding]]:
    """Parse JSON from the developer into typed objects."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  [gap_finder] JSON parse error: {e}")
        return [], []

    # Build requirement lookup
    req_lookup = {(r.rfc, r.section): r for r in spec_reqs}

    verdicts: list[AssumptionVerdict] = []
    for v in data.get("assumption_verdicts", []):
        status = v.get("status", "unclear")
        if status not in ("confirmed", "refuted", "unclear"):
            status = "unclear"
        verdicts.append(AssumptionVerdict(
            assumption_id=v.get("assumption_id", ""),
            status=status,
            code_evidence=v.get("code_evidence", ""),
            reasoning=v.get("reasoning", ""),
        ))

    findings: list[Finding] = []
    for f in data.get("findings", []):
        ftype = f.get("finding_type", "")
        rfc = f.get("requirement_rfc", "")
        sec = f.get("requirement_section", "")
        # Find matching spec requirement
        req = req_lookup.get((rfc, sec))
        if req is None:
            # Try subsection match
            for key, r in req_lookup.items():
                if sec.startswith(key[1] + ".") and key[0] == rfc:
                    req = r
                    break
        if req is None and spec_reqs:
            req = spec_reqs[0]  # fallback

        code_loc = f.get("code_location", "")
        code_snip = f.get("code_snippet", "")

        if ftype == "ComplianceGap" and req:
            findings.append(ComplianceGap(
                requirement=req,
                gap_description=f.get("gap_description", ""),
                code_location=code_loc,
                code_snippet=code_snip,
            ))
        elif ftype == "SecurityDesignGap" and req:
            findings.append(SecurityDesignGap(
                requirement=req,
                gap_description=f.get("gap_description", ""),
                code_location=code_loc,
                code_snippet=code_snip,
            ))
        elif ftype == "ImplementationInvariantViolation" and req:
            findings.append(ImplementationInvariantViolation(
                requirement=req,
                invariant_description=f.get("invariant_description",
                                           f.get("gap_description", "")),
                code_location=code_loc,
                code_snippet=code_snip,
            ))

    return verdicts, findings


def _parse_critic_output(raw: str) -> tuple[bool, str, str]:
    """Parse critic output. Returns (passed, reason, instruction)."""
    raw = raw.strip()
    if raw.upper().startswith("PASS"):
        return True, "", ""
    # RETRY
    reason = ""
    instruction = ""
    m = re.search(r"reason:\s*(.+?)(?=instruction:|$)", raw, re.DOTALL | re.IGNORECASE)
    if m:
        reason = m.group(1).strip()
    m = re.search(r"instruction:\s*(.+)", raw, re.DOTALL | re.IGNORECASE)
    if m:
        instruction = m.group(1).strip()
    return False, reason, instruction


def run(ctx, spec_reqs, repo_root: str) -> tuple[list[AssumptionVerdict], list[Finding]]:
    """
    Run the Gap Finder developer + critic loop.

    Args:
        ctx: HypothesisContext
        spec_reqs: list[SpecRequirement] from Spec Processor
        repo_root: path to the cloned target repository

    Returns:
        (verdicts, findings)
    """
    assumptions_text = "\n".join(
        f"- {a.id} ({a.necessity}): {a.description}" for a in ctx.assumptions
    )
    spec_reqs_text = "\n".join(
        f"- [{r.classification}] {r.rfc} §{r.section}: {r.requirement_text[:120]}"
        f"\n  dos_mechanism: {r.dos_mechanism}"
        f"\n  assumption: {r.relevant_to_assumption}"
        for r in spec_reqs
    )

    user = DEVELOPER_USER_TEMPLATE.format(
        description=ctx.description,
        dos_class=ctx.dos_class,
        assumptions=assumptions_text,
        spec_requirements=spec_reqs_text,
        repo_url=ctx.repo_url,
        version=ctx.version,
        protocol=ctx.protocol,
        repo_root=repo_root,
    )

    print("  [gap_finder] Running developer agent...")
    raw = _llm_with_tools(DEVELOPER_SYSTEM, user, repo_root)
    verdicts, findings = _parse_developer_output(raw, ctx, spec_reqs)
    print(f"  [gap_finder] Developer: {len(verdicts)} verdicts, {len(findings)} findings")

    if not verdicts and not findings:
        print("  [gap_finder] Empty developer output — skipping critic")
        return [], []

    # Build critic input
    verdicts_text = "\n".join(
        f"- {v.assumption_id}: {v.status}\n  evidence: {v.code_evidence[:120]}\n  reasoning: {v.reasoning[:120]}"
        for v in verdicts
    )
    findings_text = "\n".join(
        f"- {type(f).__name__}: {getattr(f, 'gap_description', getattr(f, 'invariant_description', ''))[:120]}"
        f"\n  location: {f.code_location}"
        for f in findings
    )
    citations = "\n".join(
        f.code_location for f in findings if f.code_location
    )

    critic_user = CRITIC_USER_TEMPLATE.format(
        description=ctx.description[:500],
        assumptions=assumptions_text,
        verdicts_text=verdicts_text,
        findings_text=findings_text,
        citations=citations,
    )

    print("  [gap_finder] Running critic...")
    critic_raw = _llm_no_tools(CRITIC_SYSTEM, critic_user)
    passed, reason, instruction = _parse_critic_output(critic_raw)

    if passed:
        print("  [gap_finder] Critic: PASS")
        return verdicts, findings

    print(f"  [gap_finder] Critic: RETRY — {reason}")
    print(f"  [gap_finder] Instruction: {instruction[:120]}")

    # Developer retry once — append critic feedback
    retry_user = user + (
        f"\n\n## Critic feedback (please address this in your revised output)\n"
        f"Reason: {reason}\n"
        f"Instruction: {instruction}\n"
        f"Provide a revised JSON output addressing the critique."
    )
    print("  [gap_finder] Running developer retry...")
    raw2 = _llm_with_tools(DEVELOPER_SYSTEM, retry_user, repo_root)
    verdicts2, findings2 = _parse_developer_output(raw2, ctx, spec_reqs)
    print(f"  [gap_finder] Retry: {len(verdicts2)} verdicts, {len(findings2)} findings")

    # Downgrade unclear findings that the critic flagged
    # (keep whatever the developer found on retry, mark previously failed ones as unclear)
    if verdicts2:
        return verdicts2, findings2

    # If retry also empty, downgrade originals to unclear
    for v in verdicts:
        if v.status == "confirmed":
            v.status = "unclear"
    return verdicts, findings
