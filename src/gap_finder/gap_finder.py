"""
Gap Finder — Developer + Critic loop (1 retry max).

Developer: LLM with file-reading tools explores the cloned repo,
           verifies assumptions and finds RFC compliance/design gaps.
Critic:    LLM with no tools reviews the developer's output for quality.

Returns (AssumptionLedger, list[Finding]).  Callers that need the old
list[AssumptionVerdict] API can call ledger.to_verdicts().
"""

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm_client as _llm
import cache as _cache
from run_context import run_id as _run_id

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

# Re-investigation system prompt for UNVERIFIED / AMBIGUOUS assumptions.
# Runs after the main developer pass to resolve initially unclear assumptions.
_REINVESTIGATION_SYSTEM = """You are a protocol security analyst.

A prior analysis pass left some assumptions UNVERIFIED or AMBIGUOUS.
Your task is to investigate ONLY the specific assumptions listed below.
Every other assumption has already been resolved — do not re-analyse them.

Investigation requirements:
1. For each compound assumption: decompose it into atomic sub-claims and
   verify each independently with targeted searches.
2. Run at least two searches per atomic claim before concluding UNVERIFIED.
3. Distinguish between:
   - Protocol/specification feasibility (can the RFC be satisfied?)
   - Target implementation behavior (does this implementation do it?)
   - Attacker-side feasibility (can an attacker achieve this in practice?)
   - Timing and state-reachability constraints
4. NEVER output UNVERIFIED without populating searches_attempted.
5. NEVER output INDETERMINATE without explaining what structural barrier
   prevents further investigation.
6. Favorable assumptions need the same evidence quality as required ones.

Output the SAME JSON structure as the main developer:
{
  "assumption_verdicts": [
    {
      "assumption_id": "...",
      "status": "SUPPORTED|REFUTED|CONFLICTING_EVIDENCE|UNVERIFIED|INDETERMINATE|AMBIGUOUS|NOT_APPLICABLE",
      "supporting_evidence": ["file:line: verbatim snippet"],
      "contradicting_evidence": ["file:line: verbatim snippet"],
      "reasoning": "...",
      "limitations": [...],
      "alternative_explanations": [...],
      "suggested_validation": "...",
      "source_refs": [...],
      "searches_attempted": [...]
    }
  ],
  "findings": []
}"""

# ---------------------------------------------------------------------------
# Pre-search scout — keyword→files map built before the LLM agent loop.
# ---------------------------------------------------------------------------

_STOPWORDS = frozenset({
    "about", "after", "all", "alloc", "also", "and", "another", "any",
    "are", "been", "before", "being", "bool", "byte", "bytes", "call",
    "check", "class", "close", "code", "could", "count", "data", "does",
    "during", "each", "every", "false", "field", "for", "frame", "free",
    "from", "func", "function", "have", "headers", "header", "here",
    "http", "init", "into", "just", "limit", "method", "more", "must",
    "none", "not", "null", "object", "open", "other", "over", "packets",
    "packet", "per", "rate", "read", "recv", "request", "response",
    "send", "should", "size", "some", "string", "struct", "table",
    "than", "that", "them", "then", "their", "there", "these", "they",
    "this", "those", "time", "true", "type", "under", "value", "values",
    "what", "when", "where", "which", "while", "will", "with", "would",
    "write",
})


def _detect_extensions(repo_root: str) -> list[str]:
    """Return glob patterns for the dominant source language in the repo."""
    try:
        r = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root, capture_output=True, text=True, timeout=10,
        )
        files = r.stdout.splitlines()
    except Exception:
        return ["*.cc", "*.h", "*.go", "*.py", "*.rs"]

    _src_exts = {"cc", "cpp", "cxx", "h", "hpp", "go", "py", "rs", "java", "js", "ts"}
    ext_counts: Counter = Counter()
    for f in files:
        if "." in f:
            ext = f.rsplit(".", 1)[1].lower()
            if ext in _src_exts:
                ext_counts[ext] += 1

    top = [f"*.{e}" for e, _ in ext_counts.most_common(4)]
    return top or ["*.cc", "*.h", "*.go", "*.py"]


def _grep_lines(repo_root: str, keyword: str, exts: list[str], use_rg: bool) -> list[str]:
    """
    Return repo-relative 'file:line' strings for each match of keyword.
    Returns at most 10 hits (first occurrence per file, up to 10 files).

    Uses rg when available (fastest), falls back to git grep (respects
    .gitignore, so won't scan .venv / node_modules), then grep -r.
    """
    root = repo_root.rstrip("/")
    try:
        if use_rg:
            glob_flags: list[str] = []
            for ext in exts:
                glob_flags += ["-g", ext]
            result = subprocess.run(
                ["rg", "--max-filesize=512K", "-i", "-n", "--max-count=1"]
                + glob_flags + ["--", keyword, root],
                capture_output=True, text=True, timeout=15,
            )
            # rg output: /abs/path/file.cc:42:content
            raw_lines = result.stdout.splitlines()
            hits, seen = [], set()
            for line in raw_lines:
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                abs_path, lineno = parts[0].strip(), parts[1].strip()
                if not lineno.isdigit():
                    continue
                rel = abs_path[len(root) + 1:] if abs_path.startswith(root + "/") else abs_path
                if rel in seen:
                    continue
                seen.add(rel)
                hits.append(f"{rel}:{lineno}")
                if len(hits) >= 10:
                    break
            return hits

        # git grep: searches only tracked files — fast and .gitignore-aware.
        # Output format: file.cc:42:content
        # Path specs come after "--": git grep <opts> keyword -- *.cc *.h ...
        path_specs = ["--"] + exts if exts else []
        result = subprocess.run(
            ["git", "grep", "-i", "-n", "--max-count=1", keyword] + path_specs,
            cwd=root, capture_output=True, text=True, timeout=15,
        )
        hits, seen = [], set()
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 2:
                continue
            rel_path, lineno = parts[0].strip(), parts[1].strip()
            if not lineno.isdigit():
                continue
            if rel_path in seen:
                continue
            seen.add(rel_path)
            hits.append(f"{rel_path}:{lineno}")
            if len(hits) >= 10:
                break
        return hits

    except Exception:
        return []


def _pre_search(repo_root: str, ctx) -> str:
    """
    Run targeted keyword searches against the cloned repo before the LLM
    agent loop starts.  Returns a formatted file-index block to inject into
    the developer prompt so the agent can open relevant files on iteration 1
    instead of spending the budget on directory traversal.
    """
    corpus = " ".join([
        ctx.description,
        ctx.protocol,
        " ".join(a.description for a in ctx.assumptions),
    ])
    tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9_]{3,}', corpus.lower())
    freq = Counter(tokens)
    keywords = [w for w, _ in freq.most_common(30) if w not in _STOPWORDS][:8]

    if not keywords:
        return ""

    exts = _detect_extensions(repo_root)
    use_rg = shutil.which("rg") is not None

    hits: dict[str, list[str]] = {}
    for kw in keywords:
        file_lines = _grep_lines(repo_root, kw, exts, use_rg)
        if file_lines:
            hits[kw] = file_lines

    if not hits:
        return ""

    lines = [
        "## Pre-indexed file map (keyword → file:line of first match)",
        "These locations were found by keyword search before the tool-call budget starts.",
        "Use read_file(path, start_line=N-10, end_line=N+60) on these line numbers directly.",
        "Do NOT use list_dir — open these files immediately.",
        "",
    ]
    for kw, file_lines in hits.items():
        lines.append(f"- **{kw}**: {', '.join(file_lines)}")
    lines.append("")
    return "\n".join(lines)


from assumption_ledger.models import (
    AssumptionStatus,
    AssumptionEvidence,
    AssumptionRecord,
    AssumptionLedger,
    LEGACY_TO_STATUS,
)
from assumption_ledger.extractor import extract_implicit
from processor.models import Assumption


def _llm_with_tools(system: str, user: str, repo_root: str) -> str:
    """
    Run the developer agent: LLM with file-reading tools.
    Implements a simple tool-call loop using the OpenAI function-calling API.
    """
    provider, client = _llm.get_client(_llm.get_provider(role_env="GAP_FINDER_MODEL"))
    model = _llm.get_model(provider, "GAP_FINDER_MODEL")

    cache_key_user = user + f"\n[repo_root={repo_root}]"

    cached = _cache.get(provider, model, system, cache_key_user)
    if cached is not None:
        print(f"  [gap_finder:{_run_id}] developer cache hit ({provider}/{model})")
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

        if resp.usage:
            _llm.track_usage(
                "GAP_FINDER_MODEL", provider, model,
                resp.usage.prompt_tokens, resp.usage.completion_tokens,
            )

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
            print(f"  [gap_finder:{_run_id}] developer tool calls iteration {iteration+1}")
        else:
            result_text = msg.content or ""
            _cache.put(provider, model, system, cache_key_user, result_text)
            return result_text

    final = messages[-1].get("content", "{}") if isinstance(messages[-1], dict) else "{}"
    _cache.put(provider, model, system, cache_key_user, final)
    return final


def _llm_no_tools(system: str, user: str) -> str:
    """Run the critic: LLM with no tools."""
    return _llm.call_llm(system, user, role_env="GAP_FINDER_CRITIC_MODEL", max_tokens=1024, json_mode=False)


def _parse_assumption_verdict(v: dict) -> tuple[AssumptionStatus, AssumptionEvidence]:
    """
    Parse one assumption_verdict dict from developer JSON output into
    (AssumptionStatus, AssumptionEvidence).

    Accepts both new-format (SUPPORTED / REFUTED / …) and old-format
    (confirmed / refuted / unclear) status values for backward compatibility
    with cached developer outputs.
    """
    raw_status = v.get("status", "UNVERIFIED")

    # New format — try direct enum parse.
    try:
        status = AssumptionStatus(raw_status.upper())
    except ValueError:
        # Old format — map legacy values.
        status = LEGACY_TO_STATUS.get(raw_status.lower(), AssumptionStatus.UNVERIFIED)

    # Collect evidence fields — handle both new and old schemas.
    supporting = []
    contradicting = []

    if isinstance(v.get("supporting_evidence"), list):
        supporting = [str(e) for e in v["supporting_evidence"] if e]
    if isinstance(v.get("contradicting_evidence"), list):
        contradicting = [str(e) for e in v["contradicting_evidence"] if e]

    # Old-format "code_evidence" field — fold into supporting/contradicting
    # based on the status.
    old_evidence = v.get("code_evidence", "")
    if old_evidence and not supporting and not contradicting:
        if status == AssumptionStatus.REFUTED:
            contradicting = [old_evidence]
        elif status == AssumptionStatus.SUPPORTED:
            supporting = [old_evidence]
        else:
            supporting = [old_evidence]

    evidence = AssumptionEvidence(
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        reasoning=v.get("reasoning", ""),
        limitations=[str(l) for l in v.get("limitations", []) if l],
        alternative_explanations=[str(a) for a in v.get("alternative_explanations", []) if a],
        suggested_validation=v.get("suggested_validation", ""),
        source_refs=[str(r) for r in v.get("source_refs", []) if r],
        searches_attempted=[str(s) for s in v.get("searches_attempted", []) if s],
    )
    return status, evidence


def _parse_developer_output(
    raw: str,
    ctx,
    spec_reqs,
    ledger: AssumptionLedger,
) -> tuple[AssumptionLedger, list[Finding]]:
    """
    Parse JSON from the developer and update the ledger + build findings.

    Returns the same ledger (mutated) and a list of Finding objects.
    """
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        # LLM sometimes appends prose after the closing brace.
        # Try extracting the first complete JSON object from the response.
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0))
                print(f"  [gap_finder] JSON recovered after parse error: {e}")
            except json.JSONDecodeError:
                print(f"  [gap_finder] JSON parse error (unrecoverable): {e}")
                return ledger, []
        else:
            print(f"  [gap_finder] JSON parse error: {e}")
            return ledger, []

    # Build requirement lookup for findings.
    req_lookup = {(r.rfc, r.section): r for r in spec_reqs}

    # ── update ledger from assumption_verdicts ────────────────────────────────
    evaluated_ids: set[str] = set()

    for v in data.get("assumption_verdicts", []):
        aid = v.get("assumption_id", "")
        if not aid:
            continue
        status, evidence = _parse_assumption_verdict(v)
        evaluated_ids.add(aid)

        existing = ledger.get(aid)
        if existing is not None:
            ledger.update_status(aid, status, evidence)
        else:
            # Assumption extracted implicitly and not yet in ledger.
            ledger.add(AssumptionRecord(
                assumption_id=aid,
                description=v.get("description", aid),
                necessity="inferred",
                status=status,
                evidence=evidence,
                is_critical=False,
                is_implicit=True,
            ))

    # Backfill: assumptions not evaluated by the developer keep NOT_STATED,
    # but we ensure they exist and log a warning so they don't slip through.
    for record in ledger.all():
        if record.assumption_id not in evaluated_ids:
            if record.status == AssumptionStatus.NOT_STATED:
                print(
                    f"  [gap_finder] WARNING: assumption {record.assumption_id!r} "
                    f"not evaluated by developer — staying NOT_STATED"
                )

    # ── parse findings ────────────────────────────────────────────────────────
    findings: list[Finding] = []
    for f in data.get("findings", []):
        ftype = f.get("finding_type", "")
        rfc = f.get("requirement_rfc", "")
        sec = f.get("requirement_section", "")
        req = req_lookup.get((rfc, sec))
        if req is None:
            for key, r in req_lookup.items():
                if sec.startswith(key[1] + ".") and key[0] == rfc:
                    req = r
                    break
        if req is None and spec_reqs:
            print(f"  [gap_finder] WARNING: finding cites {rfc!r} §{sec!r} which is not "
                  f"in spec_reqs — skipping (would have polluted spec_reqs[0])")
            continue

        code_loc = f.get("code_location", "")
        code_snip = f.get("code_snippet", "")
        cwes = [c for c in f.get("cwes", []) if isinstance(c, str) and c.startswith("CWE-")]

        if ftype == "ComplianceGap" and req:
            findings.append(ComplianceGap(
                requirement=req,
                gap_description=f.get("gap_description", ""),
                code_location=code_loc,
                code_snippet=code_snip,
                cwes=cwes,
            ))
        elif ftype == "SecurityDesignGap" and req:
            findings.append(SecurityDesignGap(
                requirement=req,
                gap_description=f.get("gap_description", ""),
                code_location=code_loc,
                code_snippet=code_snip,
                cwes=cwes,
            ))
        elif ftype == "ImplementationInvariantViolation" and req:
            findings.append(ImplementationInvariantViolation(
                requirement=req,
                invariant_description=f.get("invariant_description",
                                            f.get("gap_description", "")),
                code_location=code_loc,
                code_snippet=code_snip,
                cwes=cwes,
            ))

    return ledger, findings


def _reinvestigate_unclear(
    ledger: AssumptionLedger,
    repo_root: str,
    scout_text: str = "",
) -> AssumptionLedger:
    """
    Targeted re-investigation pass for UNVERIFIED and AMBIGUOUS assumptions.

    Runs a second LLM tool-call loop focused exclusively on the unclear
    assumptions.  Updates the ledger in place.  Returns the same ledger.
    """
    unclear = ledger.by_status(
        AssumptionStatus.UNVERIFIED, AssumptionStatus.AMBIGUOUS
    )
    if not unclear:
        return ledger

    assumptions_text = "\n".join(
        f"- {r.assumption_id} ({r.necessity}): {r.description}"
        f"\n  previous status: {r.status.value}"
        f"\n  searches already attempted: {'; '.join(r.evidence.searches_attempted)}"
        for r in unclear
    )

    user = (
        f"The following assumptions need deeper investigation:\n\n"
        f"{assumptions_text}\n\n"
        f"The repository is cloned at: {repo_root}\n\n"
        f"Use the tools to investigate each one.  Decompose compound claims into "
        f"atomic sub-claims and verify each independently.  "
        f"Output only the verdicts for these assumptions."
    )

    if scout_text:
        user = user + "\n\n" + scout_text

    print(f"  [gap_finder:{_run_id}] Re-investigating {len(unclear)} unclear assumption(s): "
          f"{[r.assumption_id for r in unclear]}")

    raw = _llm_with_tools(_REINVESTIGATION_SYSTEM, user, repo_root)

    # Parse the re-investigation output — only update assumptions in `unclear`.
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0))
                print(f"  [gap_finder] Re-investigation JSON recovered: {e}")
            except json.JSONDecodeError:
                print(f"  [gap_finder] Re-investigation JSON parse error (unrecoverable): {e}")
                return ledger
        else:
            print(f"  [gap_finder] Re-investigation JSON parse error: {e}")
            return ledger

    unclear_ids = {r.assumption_id for r in unclear}
    for v in data.get("assumption_verdicts", []):
        aid = v.get("assumption_id", "")
        if aid not in unclear_ids:
            continue
        status, evidence = _parse_assumption_verdict(v)
        ledger.update_status(aid, status, evidence)
        print(f"  [gap_finder] Re-investigation: {aid} → {status.value}")

    return ledger


def _parse_critic_output(raw: str) -> tuple[bool, str, str]:
    """Parse critic output.  Returns (passed, reason, instruction)."""
    raw = raw.strip()
    if raw.upper().startswith("PASS"):
        return True, "", ""
    reason = ""
    instruction = ""
    m = re.search(r"reason:\s*(.+?)(?=instruction:|$)", raw, re.DOTALL | re.IGNORECASE)
    if m:
        reason = m.group(1).strip()
    m = re.search(r"instruction:\s*(.+)", raw, re.DOTALL | re.IGNORECASE)
    if m:
        instruction = m.group(1).strip()
    return False, reason, instruction


def run(
    ctx,
    spec_reqs,
    repo_root: str,
    ledger: Optional[AssumptionLedger] = None,
) -> tuple[AssumptionLedger, list[Finding]]:
    """
    Run the Gap Finder developer + critic loop.

    1. Optionally extract implicit assumptions via LLM.
    2. Run developer (tool-using LLM) to verify all assumptions and find gaps.
    3. Run critic to validate evidence quality.
    4. Retry developer once if critic rejected.

    Args:
        ctx:       HypothesisContext
        spec_reqs: list[SpecRequirement] from Spec Processor
        repo_root: path to the cloned target repository
        ledger:    optional pre-populated AssumptionLedger; created from ctx if None

    Returns:
        (AssumptionLedger, list[Finding])
        Callers needing old list[AssumptionVerdict] can call ledger.to_verdicts().
    """
    # ── 0. Initialise ledger ──────────────────────────────────────────────────
    if ledger is None:
        ledger = AssumptionLedger.from_context(ctx)

    # ── 0b. Extract implicit assumptions ─────────────────────────────────────
    try:
        implicit = extract_implicit(ctx)
        for impl_a in implicit:
            if ledger.get(impl_a.id) is None:
                ledger.add(AssumptionRecord(
                    assumption_id=impl_a.id,
                    description=impl_a.description,
                    necessity=impl_a.necessity,
                    status=AssumptionStatus.NOT_STATED,
                    is_critical=(impl_a.necessity == "required"),
                    is_implicit=True,
                ))
                # Also append to ctx.assumptions so the developer prompt includes them.
                ctx.assumptions.append(impl_a)
        if implicit:
            print(f"  [gap_finder:{_run_id}] {len(implicit)} implicit assumption(s) extracted: "
                  f"{[a.id for a in implicit]}")
    except Exception as exc:
        print(f"  [gap_finder:{_run_id}] implicit extraction failed: {exc}")

    # ── 1. Build developer prompt ─────────────────────────────────────────────
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

    # ── 1b. Pre-search scout ──────────────────────────────────────────────────
    scout = _pre_search(repo_root, ctx)
    if scout:
        user = user + "\n\n" + scout
        kw_count = scout.count("\n- **")
        print(f"  [gap_finder:{_run_id}] Pre-search: {kw_count} keyword(s) indexed")
    else:
        print(f"  [gap_finder:{_run_id}] Pre-search: no hits")

    print(f"  [gap_finder:{_run_id}] Running developer agent...")
    raw = _llm_with_tools(DEVELOPER_SYSTEM, user, repo_root)
    ledger, findings = _parse_developer_output(raw, ctx, spec_reqs, ledger)
    n_resolved = sum(1 for r in ledger.all() if r.is_resolved)
    print(f"  [gap_finder] Developer: {n_resolved}/{len(ledger)} assumptions resolved, {len(findings)} findings")

    if not ledger.all() and not findings:
        print("  [gap_finder] Empty developer output — skipping critic")
        return ledger, []

    # ── 1b. Re-investigate any UNVERIFIED / AMBIGUOUS assumptions ─────────────
    _reinvestigate_unclear(ledger, repo_root, scout_text=scout)
    n_resolved_after = sum(1 for r in ledger.all() if r.is_resolved)
    if n_resolved_after > n_resolved:
        print(f"  [gap_finder] Re-investigation resolved "
              f"{n_resolved_after - n_resolved} additional assumption(s)")

    # ── 2. Build critic input ─────────────────────────────────────────────────
    verdicts_text = "\n".join(
        f"- {r.assumption_id}: {r.status.value}"
        f"\n  supporting: {'; '.join(r.evidence.supporting_evidence[:1])}"
        f"\n  contradicting: {'; '.join(r.evidence.contradicting_evidence[:1])}"
        f"\n  reasoning: {r.evidence.reasoning[:120]}"
        f"\n  alternatives: {'; '.join(r.evidence.alternative_explanations[:1])}"
        f"\n  searches: {'; '.join(r.evidence.searches_attempted[:2])}"
        for r in ledger.all()
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
        return ledger, findings

    print(f"  [gap_finder] Critic: RETRY — {reason}")
    print(f"  [gap_finder] Instruction: {instruction[:120]}")

    # ── 3. Developer retry once ───────────────────────────────────────────────
    retry_user = user + (
        f"\n\n## Critic feedback (please address this in your revised output)\n"
        f"Reason: {reason}\n"
        f"Instruction: {instruction}\n"
        f"Provide a revised JSON output addressing the critique."
    )
    # Reset ledger to initial state so retry starts fresh.
    ledger2 = AssumptionLedger.from_context(ctx)
    # Re-add implicit assumptions.
    for r in ledger.all():
        if r.is_implicit and ledger2.get(r.assumption_id) is None:
            ledger2.add(AssumptionRecord(
                assumption_id=r.assumption_id,
                description=r.description,
                necessity=r.necessity,
                status=AssumptionStatus.NOT_STATED,
                is_critical=r.is_critical,
                is_implicit=True,
            ))

    print("  [gap_finder] Running developer retry...")
    raw2 = _llm_with_tools(DEVELOPER_SYSTEM, retry_user, repo_root)
    ledger2, findings2 = _parse_developer_output(raw2, ctx, spec_reqs, ledger2)
    n_resolved2 = sum(1 for r in ledger2.all() if r.is_resolved)
    print(f"  [gap_finder] Retry: {n_resolved2}/{len(ledger2)} assumptions resolved, {len(findings2)} findings")

    if n_resolved2 > 0:
        return ledger2, findings2

    # Both passes produced no resolved assumptions — downgrade any SUPPORTED to
    # UNVERIFIED and clear findings: the critic rejected them and the retry
    # produced nothing, so forwarding the original would let the exploit planner
    # build an attack on evidence the critic already rejected.
    print("  [gap_finder] Both developer passes empty after critic rejection — downgrading")
    for record in ledger.all():
        if record.status == AssumptionStatus.SUPPORTED:
            record.status = AssumptionStatus.UNVERIFIED
    return ledger, []
