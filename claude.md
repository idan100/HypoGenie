# HypoGenie — CLAUDE.md

> Fork of CVE-Genie (https://github.com/BUseclab/cve-genie).  
> Goal: discover novel DoS vulnerabilities in protocol implementation code  
> from a YAML attack hypothesis, with no CVE ID required.  
> M.Sc. thesis project — Idan Efraim, Bar-Ilan University / TAU Deepness Lab (Prof. Anat Bremler-Barr).

---

## Table of Contents

1. [Quick-start order](#1-quick-start-order)
2. [Infrastructure setup](#2-infrastructure-setup)
3. [Model configuration](#3-model-configuration)
4. [YAML input format](#4-yaml-input-format)
5. [Ground-truth test suite](#5-ground-truth-test-suite)
6. [Pipeline overview — changes from CVE-Genie](#6-pipeline-overview)
7. [Module-by-module changes](#7-module-by-module-changes)
   - 7.1 Data Processor → YAML Parser
   - 7.2 Knowledge Builder → Spec Processor (NEW)
   - 7.3 Gap Finder (NEW)
   - 7.4 Exploit Planner (NEW)
   - 7.5 Builder — Docker changes
   - 7.6 Exploiter — protocol tools
   - 7.7 CTF Verifier → DoS Verifier
8. [Responsible disclosure](#8-responsible-disclosure)
9. [Validation strategy](#9-validation-strategy)
10. [Claude Code implementation order](#10-claude-code-implementation-order)

---

## 1. Quick-start order

```
Phase 0  Clone CVE-Genie; run one known CVE end-to-end as baseline.
Phase 1  YAML Parser + Spec Processor
Phase 2  Gap Finder
Phase 3  Exploit Planner
Phase 4  Builder — Docker rewrite
Phase 5  Exploiter — protocol tools
Phase 6  Wire together + DoS Verifier
Phase 7  Validate on ground-truth YAML suite
```

---

## 2. Infrastructure setup

Run `infra/setup.sh` once before any framework run. It is idempotent.

```bash
#!/usr/bin/env bash
# infra/setup.sh
set -euo pipefail

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

# ── TLS certs (self-signed, version-agnostic, mounted into every container) ──
if [[ ! -f "$CERTS_DIR/server.crt" ]]; then
  echo "[infra] Generating self-signed TLS cert..."
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERTS_DIR/server.key" \
    -out    "$CERTS_DIR/server.crt" \
    -days 3650 -nodes \
    -subj "/CN=localhost"
  echo "[infra] Certs written to $CERTS_DIR"
else
  echo "[infra] Certs already exist — skipping."
fi

# ── Python client-side attack tools (attacker env, NOT the server container) ──
pip install aioquic scapy h2 docker requests pyyaml

# ── Verify Docker daemon is reachable ──
docker info > /dev/null 2>&1 && echo "[infra] Docker daemon OK" \
  || { echo "[infra] ERROR: Docker daemon not running"; exit 1; }

# ── Verify IETF reachable (Spec Processor needs it) ──
curl -sf --max-time 5 https://www.rfc-editor.org/rfc/rfc9000 > /dev/null \
  && echo "[infra] IETF RFC server reachable" \
  || echo "[infra] WARNING: IETF RFC server unreachable — Spec Processor will fail"

echo "[infra] Setup complete."
```

After running setup:
- `infra/certs/server.crt` and `infra/certs/server.key` are ready.
- `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` must be set in a `.env` file at the project root.

---

## 3. Model configuration

Start with the cheapest models for iteration speed; upgrade later.

```yaml
# config/models.yaml
default_provider: anthropic      # or: openai

anthropic:
  model: claude-haiku-3-5        # cheapest Anthropic model at start
  api_key_env: ANTHROPIC_API_KEY

openai:
  model: gpt-4o-mini             # cheapest OpenAI model at start
  api_key_env: OPENAI_API_KEY
```

Every agent reads from this config. Switching to a stronger model later is a one-line change.  
Run the same ground-truth YAML suite on both providers to compare quality and cost.

---

## 4. YAML input format

```yaml
hypothesis:
  description: |
    [Rich prose — the richer the better. Include:]
    - RFC context: what the spec says about the mechanism
    - Analogies to known CVEs (e.g. HTTP/2 Rapid Reset CVE-2023-44487)
    - Suspected vulnerability mechanism step by step
    - Assumptions section: list each checkable property explicitly
    - Suspected mechanism: numbered trigger sequence

    Example (QUIC Rapid Reset variant via MAX_STREAMS credit granting):
    RFC 9000 §4.6 defines stream concurrency via a cumulative ceiling.
    In HTTP/2, RST_STREAM triggered rapid credit recycling (CVE-2023-44487).
    We suspect Caddy's HTTP/3 layer grants MAX_STREAMS credit on QUIC-layer
    stream closure, before application-level work completes.

  dos_class: resource_exhaustion
  # allowed: resource_exhaustion | recursion | regex | memory | cpu | resource_starvation

target:
  repo: https://github.com/caddyserver/caddy
  version: v2.7.6                      # exact tag or commit SHA
  protocol: QUIC
  entry_point: "UDP port 443, QUIC+HTTP/3"

assumptions:
  - id: A1
    description: "Server grants MAX_STREAMS credit on transport-level closure"
    necessity: required      # required | favorable
  - id: A2
    description: "Per-stream work not cancelled on RESET_STREAM"
    necessity: required
  - id: A3
    description: "No stream-churn rate limit"
    necessity: favorable

suspected_mechanism:
  - step: 1
    action: "Attacker opens N streams (server's current MAX_STREAMS limit)"
  - step: 2
    action: "Attacker sends RESET_STREAM on each immediately"
  - step: 3
    action: "Server increments MAX_STREAMS credit — attacker opens N more"
  - step: 4
    action: "Server accumulates goroutine / handler backlog → resource exhaustion"

rfc_sections:
  - rfc: RFC 9000
    section: "4.6"
    dos_relevance: "Stream concurrency ceiling and credit granting"
  - rfc: RFC 9114
    section: "6.4"
    dos_relevance: "HTTP/3 stream cancellation behaviour"

related_work:
  - type: cve
    id: CVE-2023-44487
  - type: writeup
    url: https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/
```

---

## 5. Ground-truth test suite

The test suite lives in `tests/yamls/`.

### 5a. Ground-truth POSITIVE (real DoS vulnerabilities, post-cutoff)

These should produce `CONFIRMED_DOS`. Use CVEs disclosed after August 2025 to avoid
training-data leakage influencing the LLM.

```
tests/yamls/positive/
  h2_rapid_reset.yaml
    — CVE-2023-44487 | HTTP/2 Rapid Reset | multiple servers (nginx, Apache,
      Go net/http, etc.) | FINDING_TYPE: SecurityDesignGap
      RST_STREAM is fully RFC-compliant behavior. RFC 7540 §10.5 warns of
      RST_STREAM amplification but does not mandate a rate-limit. The
      vulnerability is the absent defensive bound: no implementation rate-limited
      stream resets. Attacker rapidly opens + resets streams → server goroutine/
      handler backlog grows without bound → CPU/memory exhaustion.
      Reference case; known pre-cutoff baseline.

  golang_h2_double_flowcontrol.yaml
    — CVE-2026-78663 | golang.org/x/net HTTP/2 | FINDING_TYPE: ComplianceGap
      RFC 7540 §6.9 defines flow-control credit as a one-time grant per consumed
      byte. Implementation refunds connection-level credit twice for the same data
      — once on RST_STREAM (unread buffered bytes) and again when the handler reads
      them. This double-refund directly contradicts §6.9. Attacker bypasses
      MaxReceiveBufferPerConnection → unbounded buffer growth → memory exhaustion.
      CVSS 9.1 Critical. Post-cutoff.

  grpcgo_h2_data_fragmentation.yaml
    — CVE-2026-84304 | gRPC-Go < 1.83.1 | HTTP/2 over gRPC |
      FINDING_TYPE: ImplementationInvariantViolation
      RFC 7540 §6.9 governs payload byte accounting only — it sets no bound on
      per-frame struct overhead. gRPC-Go allocates a separate recvMsg per
      fragmented DATA frame in recvBuffer. Attacker sends millions of 1-byte DATA
      frames within flow-control limits → recvMsg struct metadata exhausts heap
      with zero RFC violation. The required invariant (per-connection recvMsg count
      or struct-overhead cap) was never mandated by the spec. Post-cutoff.

  coredns_grpc_no_limits.yaml
    — CVE-2025-68151 | CoreDNS < 1.14.0 | DNS-over-gRPC / DNS-over-HTTPS |
      FINDING_TYPE: SecurityDesignGap
      RFC 8484 (DoH) §5.1 recommends that servers apply "appropriate limits" on
      request sizes and rates but uses SHOULD language and gives no specific bound.
      CoreDNS gRPC, HTTPS and HTTP/3 listeners apply no connection limit, stream
      limit, or message-size cap. The spec permits this; CoreDNS chose not to add
      bounds. Attacker opens many concurrent streams or sends oversized DNS request
      bodies → memory exhaustion and crash. Published January 2026. Post-cutoff.

  quicgo_qpack_headers.yaml
    — CVE-2025-64702 | quic-go ≤ 0.56.0 | HTTP/3 over QUIC |
      FINDING_TYPE: ComplianceGap
      RFC 9114 §4.2.2 MUST: "An endpoint MUST NOT allow the peer to cause it to
      allocate an excessive amount of memory for field sections." Implementation
      enforces a limit on compressed frame length but NOT on decoded field section
      size. Attacker sends crafted QPACK headers with high compression ratio →
      ~15x wire-to-heap amplification → memory exhaustion. Fixed in v0.57.0.
      Post-cutoff.
```

Each YAML must have a matching `tests/yamls/positive/<name>.verdict` file:
```
EXPECTED: CONFIRMED_DOS
CVE: CVE-XXXX-XXXXX              # or PENDING if not yet assigned

# Attack summary
ATTACK: <one-line description of the triggering mechanism>
DOS_CLASS: resource_exhaustion   # matches hypothesis.dos_class

# Test lab
TARGET_IMAGE: caddy:2.7.6        # Docker image pulled at test time
TARGET_PORT: 443/udp
TLS: self-signed (infra/certs/)
CLIENT_TOOL: aioquic             # tool used by the Exploiter

# Finding classification (which Gap Finder type confirms the vulnerability)
FINDING_TYPE: ComplianceGap | SecurityDesignGap | ImplementationInvariantViolation

# Proof
PROOF_METHOD: metric             # metric | crash | unreachable
PROOF_METRIC: cpu_pct            # which metric crossed the threshold
PROOF_THRESHOLD: "+50pp for 5s" # what the verifier should observe
PROOF_NOTES: <how the attack was manually verified before adding this case>
```

### 5b. Ground-truth NEGATIVE (non-real / non-triggerable attacks)

These should produce `NO_DOS_EFFECT` or `INCONCLUSIVE`. Useful for checking
the system doesn't hallucinate confirmations.

```
tests/yamls/negative/
  quic_stream_limit_no_bug.yaml    — same mechanism, patched version
  h2_rst_patched.yaml              — CVE-2023-44487 on patched nginx
  fake_recursion_dos.yaml          — recursion assumption not reachable
  nonexistent_quic_bug.yaml        — plausible-sounding but fabricated
```

Each YAML must have a matching `tests/yamls/negative/<name>.verdict` file:
```
EXPECTED: NO_DOS_EFFECT

# Why the attack should not trigger
REASON: <one line summary>

# What was tested
TARGET_IMAGE: nginx:1.25.3          # exact Docker image used in manual test
TARGET_PORT: 443/tcp
CLIENT_TOOL: h2load                 # tool used to send the attack traffic

# How the attack was disproven
DISPROOF_METHOD: metric | gap_absent | assumption_refuted
DISPROOF_DETAIL: |
  <what was manually verified — e.g. "sent 10,000 RST_STREAM frames over 30s;
  CPU stayed below 5%, memory delta < 2MB, all probe requests succeeded.
  Server applies patch X which enforces Y limit per RFC Z §N.">
DISPROOF_NOTES: <which assumption failed or which fix closes the gap>
```

### 5c. Running the test suite

```bash
python hypogenie.py --test-suite tests/yamls/positive/ --expect CONFIRMED_DOS
python hypogenie.py --test-suite tests/yamls/negative/ --expect NO_DOS_EFFECT
```

Track: true-positive rate, false-positive rate, cost per run, agent token usage per module.

---

## 6. Pipeline overview

### CVE-Genie pipeline (unchanged modules in brackets)

```
[Processor]           Data Processor + Knowledge Builder
[Builder]             Prerequisite Developer + Setup Developer + Setup Critic
[Exploiter]           Exploit Developer + Exploit Critic
[CTF Verifier]        Verifier Developer + Flag Checker + Verifier Critic
```

### HypoGenie pipeline

```
YAML Parser           replaces CVE ID ingestion and Data Processor
Spec Processor        NEW — fetches RFC text, extracts DoS-relevant normative requirements
Gap Finder            NEW — verifies assumptions against implementation code (developer + critic)
Exploit Planner       NEW — translates Gap Finder output to concrete packet sequences (dev + critic, no loop)
Builder               MODIFIED — Docker Hub pull + source-build fallback; TLS cert mount
Exploiter             MODIFIED — aioquic / Scapy / h2 protocol tools; no HTTP payload generation
DoS Verifier          MODIFIED — metric-based (CPU / memory / latency / crash), not CTF flag
```

Modules that are **unchanged**: none. Every module has at least a small change.  
Modules that are **dropped**: Flag Checker (no CTF flag in protocol DoS).

---

## 7. Module-by-module changes

---

### 7.1 Data Processor → YAML Parser

**CVE-Genie behavior:**  
Fetches CVE metadata from NVD/MITRE, extracts affected product, version, patch diff URL.

**HypoGenie change:**  
Replace entirely. The YAML Parser reads the user-supplied YAML and populates a
structured `HypothesisContext` object passed through the pipeline:

```python
@dataclass
class HypothesisContext:
    description: str
    dos_class: str
    repo_url: str
    version: str
    protocol: str
    entry_point: str
    assumptions: list[Assumption]   # {id, description, necessity}
    rfc_sections: list[RFCSection]  # {rfc, section, dos_relevance}
    related_work: list[dict]
```

No LLM call in this module — pure parsing.

**Files to change:**
- `processor/data_processor.py` — replace CVE fetch logic with YAML load + validation
- `processor/models.py` — add `HypothesisContext`, `Assumption`, `RFCSection` dataclasses

---

### 7.2 Knowledge Builder → Spec Processor (NEW)

**CVE-Genie behavior:**  
Knowledge Builder builds exploit prerequisites from CVE description + patch diff.

**HypoGenie change:**  
Replace with Spec Processor. Single LLM call (developer only, no critic, no loop).

**Task:**  
For each `rfc_sections` entry in the YAML:
1. Fetch the RFC section text from `https://www.rfc-editor.org/rfc/rfcXXXX#section-Y`
2. Extract all normative statements (MUST / MUST NOT / SHALL / SHOULD) relevant to the
   `dos_relevance` annotation.
3. Output structured list of `SpecRequirement` objects:
   ```python
   @dataclass
   class SpecRequirement:
       rfc: str
       section: str
       requirement_text: str    # verbatim sentence, or paraphrase for invariants
       classification: Literal[
           "must_violation",           # MUST / SHALL / MUST NOT sentence
           "should_deviation",         # SHOULD / SHOULD NOT sentence
           "may_behavior",             # spec explicitly permits this — impl choice is dangerous
           "security_consideration",   # spec warns about this risk (e.g. §10.5 notes)
           "implementation_invariant", # property for safe operation; RFC may not mandate it
       ]
       dos_mechanism: str       # one-line: how this gap enables DoS
       relevant_to_assumption: str | None   # e.g. "A1", "A2"
   ```

   > **Important:** Not every DoS vulnerability is an RFC compliance violation.
   > An implementation can be fully spec-conformant and still be dangerously
   > exploitable. The five-way classification captures the full space:
   >
   > | Classification | Example |
   > |---|---|
   > | `must_violation` | quic-go ignores decoded header size limit (RFC 9114 §4.2.2) |
   > | `should_deviation` | gRPC-Go skips per-connection flow-control SHOULD bound |
   > | `may_behavior` | RESET_STREAM is permitted; impl chose not to rate-limit it |
   > | `security_consideration` | RFC 7540 §10.5 warns of RST_STREAM amplification |
   > | `implementation_invariant` | No per-frame metadata cap (RFC never mandated one) |

**Prompt guidance:**
- Classify each statement using the five-way `classification` field.
- For `must_violation` / `should_deviation`: quote the verbatim MUST/SHALL/SHOULD
  sentence as `requirement_text`.
- For `may_behavior`: describe the specific optional behavior the implementation
  chose, and explain why that choice enables DoS without a defensive bound.
- For `security_consideration`: quote or paraphrase the RFC security note (e.g.,
  "Implementations SHOULD protect against ... as described in §10.5").
- For `implementation_invariant`: derive the property from the hypothesis description
  and suspected mechanism — there may be **no RFC text** that mandates it. Set
  `rfc` / `section` to the closest related requirement, or `"N/A"` if none exists.
  `requirement_text` should state the invariant as a property: "Every connection MUST
  bound outstanding stream-reset count or apply a backoff."
- Do NOT extract generic security advice — only requirements directly relevant
  to the hypothesis `description` and the named `dos_class`.
- Each requirement must map to at least one assumption or to the suspected mechanism.
- If a section yields no relevant statements of any classification, output an empty list.

**Files to create:**
- `spec_processor/spec_processor.py`
- `spec_processor/models.py`
- `spec_processor/prompts.py`

---

### 7.3 Gap Finder (NEW)

**CVE-Genie behavior:** No equivalent.

**Task:**  
Verify whether each RFC normative requirement (from Spec Processor) is actually
enforced in the implementation code, and whether each user assumption holds.

**Agent structure:** Developer + Critic, 1 loop.

**Developer:**  
- Has file-reading tools (read_file, list_dir, search_code) targeting the cloned repo.
- For each `SpecRequirement`, traces the code path where the requirement should be enforced.
- For each `Assumption` (A1, A2, A3 …), reads the relevant code and returns:
  ```python
  @dataclass
  class AssumptionVerdict:
      assumption_id: str
      status: Literal["confirmed", "refuted", "unclear"]
      code_evidence: str      # verbatim snippet(s) + file:line
      reasoning: str
  ```
- For each gap found, emits one of three finding types keyed on
  `SpecRequirement.classification`:

  ```python
  # classification: must_violation | should_deviation
  @dataclass
  class ComplianceGap:
      requirement: SpecRequirement
      gap_description: str            # what the spec requires vs what the code does
      code_location: str              # file:line where enforcement is missing
      code_snippet: str               # surrounding code for context

  # classification: may_behavior | security_consideration
  @dataclass
  class SecurityDesignGap:
      requirement: SpecRequirement
      gap_description: str            # what defensive measure is absent
      code_location: str              # file:line of the unguarded code path
      code_snippet: str

  # classification: implementation_invariant  (no RFC mandate required)
  @dataclass
  class ImplementationInvariantViolation:
      requirement: SpecRequirement
      invariant_description: str      # the property that must hold for safe operation
      code_location: str              # file:line where the invariant is absent
      code_snippet: str

  # Union alias used throughout the pipeline
  Finding = ComplianceGap | SecurityDesignGap | ImplementationInvariantViolation
  ```

**Critic:**

The critic has **no file-reading tools**. It reasons only from what the developer
gave it and returns a binary verdict: `PASS` or `RETRY(<targeted instruction>)`.

*Input (exactly three things — nothing else):*
1. Original hypothesis text and assumptions list (from the YAML).
2. Developer's structured findings — `AssumptionVerdict` and `Finding` objects.
3. The file paths and line numbers cited in those findings — no code content.

*Responsibilities:*
1. **Challenge unsupported conclusions.**  
   Does the stated `gap_description` / `invariant_description` actually follow from
   the cited evidence? A finding that the code "has no rate limit" must cite the
   specific call path where a limit would live — not just the absence of a constant.

2. **Identify contradictions.**  
   Does a "confirmed" `AssumptionVerdict` contradict a `Finding` in the same run?
   Do two findings describe mutually exclusive code states? If so, the developer
   read the wrong version or confused two code paths.

3. **Reject evidence that doesn't prove the claim.**  
   Constant definitions, function signatures in isolation, and comments in source
   code are not evidence of behavior. A `ComplianceGap` requires the call site
   where enforcement should occur, not the definition of the limit variable.
   A `SecurityDesignGap` requires the unguarded code path, not the existence of
   the vulnerable behavior. An `ImplementationInvariantViolation` requires the
   absence of a check — showing a present check is the opposite of evidence.

4. **Request targeted additional evidence when necessary.**  
   When a finding is *almost* supported but one piece is missing, the critic names
   exactly what to fetch: a specific file path, a line range, or the call chain
   between two already-cited locations. The retry instruction is a concrete fetch
   request, not "look harder":
   > ✓ "Fetch lines 142–180 of internal/transport/http2_client.go and show  
   >    whether there is a counter decrement in the RST_STREAM handler."  
   > ✗ "Re-examine the stream handling code."

*Output:*
```
PASS
```
or
```
RETRY
reason: <one sentence: which responsibility failed and why>
instruction: <concrete fetch request or correction — file path and line range if known>
```

The developer may retry **once**. If the revised finding still fails the critic,
the finding is downgraded to `status: unclear` and passed to Exploit Planner with
that annotation — the critic does not block the pipeline indefinitely.

**Assumption gate (sequential):**  
Process assumptions in order. If a `required` assumption is `refuted`:
- Exploit Planner gets ONE pivot attempt: check if an alternative path exists
  using existing Gap Finder evidence only (no new tool calls).
- If no alternative supported by evidence → emit `INFEASIBLE` report and stop.
- If `favorable` assumption refuted → continue; Exploit Planner notes reduced severity.

**Files to create:**
- `gap_finder/gap_finder.py`
- `gap_finder/models.py`
- `gap_finder/prompts.py`
- `gap_finder/tools.py`   (file reading wrappers)

---

### 7.4 Exploit Planner (NEW)

**CVE-Genie behavior:** No equivalent (Exploiter generates exploit code directly).

**Task:**  
Bridge between static analysis (Gap Finder) and dynamic exploitation (Exploiter).
Pure reasoning — no tool calls. Takes Gap Finder structured output and produces a
concrete packet sequence specification.

**Agent structure:** Single developer call + single critic call. No loop.

**Developer output:**
```python
@dataclass
class ExploitPlan:
    finding_type: Literal["ComplianceGap", "SecurityDesignGap", "ImplementationInvariantViolation"]
    finding_ref: str                 # brief label matching the Gap Finder finding
    assumptions_relied_on: list[str] # A1, A2, ...
    attack_sequence: list[Step]      # numbered steps
    expected_effect: str             # what resource is exhausted / what crashes
    severity: Literal["critical", "high", "medium", "low"]
    pivot_note: str | None           # set if a required assumption was refuted
```

```python
@dataclass
class Step:
    n: int
    action: str          # e.g. "Send STREAM frame on stream_id=4"
    quic_frame: str      # frame type + fields
    expected_server_response: str
    rationale: str
```

**Critic:**  
- Cross-references every factual claim in the plan against Gap Finder's raw output.
- No new tool calls — pure cross-referencing.
- Verifies: each `quic_frame` field names a real QUIC frame type from RFC 9000.
- Returns pass / correction. If correction: developer revises once (no second critic call).

**Files to create:**
- `exploit_planner/exploit_planner.py`
- `exploit_planner/models.py`
- `exploit_planner/prompts.py`

---

### 7.5 Builder — Docker changes

**CVE-Genie behavior:**  
Writes a Dockerfile, builds from source, runs the container. Setup Developer + Critic
pattern already handles arbitrary repos. Reuse all of this unchanged.

**HypoGenie change — minimal diff only:**

Three additions on top of CVE-Genie's Builder:

1. **Prepend a Docker Hub pull attempt** before the source build.  
   If `docker pull {product}:{version}` succeeds → skip the Dockerfile/build step entirely.  
   If it fails → fall through to CVE-Genie's existing source build logic unchanged.

2. **Change input type** — Builder receives `HypothesisContext` instead of CVE metadata.  
   `target.repo`, `target.version`, and `target.entry_point` replace the CVE fields.

3. **Add TLS cert mount** to the `docker run` call.  
   The cert destination is always `/certs/` — fixed, product-independent.  
   The config file destination is determined by the Setup Developer for each product
   and returned as `config_path` (e.g. `/etc/nginx/nginx.conf`, `/etc/caddy/Caddyfile`,
   `/etc/coredns/Corefile` — whatever the target server expects):
   ```python
   docker run \
     -v ./infra/certs/server.crt:/certs/server.crt:ro \
     -v ./infra/certs/server.key:/certs/server.key:ro \
     -v ./workspace/{run_id}/server.conf:{config_path}:ro \
     -p {ports} \
     {image}:{version}
   ```
   The Setup Developer prompt must:
   - Write the server config using `/certs/server.crt` and `/certs/server.key` for TLS,
     regardless of the product.
   - Return `config_path` (the in-container path where the product reads its config)
     and `ports` (the host:container port mappings needed for the protocol) alongside
     the config file content. The Builder fills these into the `docker run` call.

**Files to change:**
- `builder/builder.py` — add Hub pull attempt before source build; swap input type
- `builder/setup_developer.py` — pass `target.entry_point` as the port/protocol hint; add cert path instruction to prompt
- `builder/setup_critic.py` — add check: config references fixed cert mount paths
- Remove: `builder/prerequisite_developer.py` (prerequisites encoded in `infra/setup.sh`)

---

### 7.6 Exploiter — protocol tools

**CVE-Genie behavior:**  
Exploiter Developer writes Python exploit code (HTTP requests, library calls).
Exploit Critic reviews and runs it.

**HypoGenie change — what stays:**  
Developer + Critic loop (N iterations) is kept exactly as in CVE-Genie.

**HypoGenie change — what changes:**

1. **Input:** Exploiter receives `ExploitPlan` (from Exploit Planner) not a free-form
   exploit description. The plan specifies the exact packet sequence; the Exploiter
   translates it to working code.

2. **Protocol tools pre-installed (not discovered by agent):**
   | Protocol | Tool | Notes |
   |----------|------|-------|
   | QUIC     | aioquic | QUIC packets are AEAD-encrypted — Scapy cannot craft them post-handshake |
   | HTTP/2   | h2 (hyper) | raw frame-level control |
   | DNS      | Scapy or dnspython | |
   | TLS      | tlslite-ng | |
   | other    | Scapy | raw packet crafting |

3. **Target:** Protocol-level packet sequences, not HTTP application payloads.
   The agent sends QUIC frames / HTTP/2 frames / DNS messages, not `requests.get()`.

4. **Metric collection:** Exploiter also monitors server-side metrics during the attack:
   ```python
   # Collect every 1 second during attack
   metrics = {
       "cpu_pct": [],       # via docker stats
       "mem_mb": [],        # via docker stats
       "latency_ms": [],    # probe request RTT
       "alive": []          # bool — did probe request succeed
   }
   ```

**Files to change:**
- `exploiter/exploit_developer.py` — input is now `ExploitPlan`, not free-form description
- `exploiter/exploit_critic.py` — verify protocol frame fields against RFC; verify metric collection code
- `exploiter/tools.py` — add metric collection helpers

---

### 7.7 CTF Verifier → DoS Verifier

**CVE-Genie behavior:**  
CTF Verifier looks for a flag string in exploit output. Uses Flag Checker + Verifier Developer + Verifier Critic.

**HypoGenie change:**  
Replace flag-based verification with metric-based. Drop Flag Checker.

**Verification protocol — three phases, in order:**

**Phase 1 — Baseline** *(10 seconds, no attack traffic)*  
Record resource consumption before the experiment. The isolated Docker environment
makes this especially reliable — the container has no background workload.
```python
baseline = {
    "cpu_pct":    [],   # via docker stats, 1-second samples
    "mem_mb":     [],   # via docker stats
    "latency_ms": [],   # probe request RTT (10 sequential probes)
    "alive":      [],   # all must be True — if not, server failed to start
}
# Baseline is healthy only if: all alive=True AND cpu_pct mean < 20%
# If baseline is unhealthy → abort with ENVIRONMENT_ERROR, do not proceed.
```

**Phase 2 — Attack + Attribution**  
Run the exploit from `ExploitPlan`. Collect metrics at 1-second resolution throughout.
```python
attack_metrics = {
    "cpu_pct": [], "mem_mb": [], "latency_ms": [], "alive": []
}
```
Attribution checks (all three must hold for a threshold crossing to count):
1. Baseline was healthy (Phase 1 passed).
2. The metric spike is **temporally correlated with attack traffic** — onset must
   occur within 10 seconds of the first attack packet, not before.
3. Probe requests answered normally during baseline but degrade during the attack.
   (Rules out a pre-existing condition unrelated to the exploit.)

**Verdict thresholds (applied to attack_metrics relative to baseline):**
```
CPU:         (attack mean) − (baseline mean) ≥ 50pp, sustained ≥5 consecutive seconds
Memory:      (attack peak) − (baseline mean) ≥ 100 MB RSS
Latency:     (attack mean) ≥ 5 × (baseline mean RTT)
Crash:       container exited unexpectedly (docker inspect exit code ≠ 0)
Unreachable: probe alive=False for ≥3 consecutive seconds during attack
```
Any one threshold crossed + all three attribution checks → **tentative** `CONFIRMED_DOS`.

**Phase 3 — Repeatability**  
A single metric spike is not sufficient. If Phase 2 yields tentative `CONFIRMED_DOS`:
1. Cold restart the container (stop → remove → fresh pull/start → wait for healthy baseline).
2. Re-run the identical exploit from a clean state.
3. If the second run also crosses a threshold with attribution → **final** `CONFIRMED_DOS`.
4. If the second run does not confirm → downgrade to `INCONCLUSIVE`.

**Verdict flow:**
```
CONFIRMED_DOS (final)
  → auto-generate responsible disclosure draft (see §8)

INCONCLUSIVE (Phase 2 threshold not met, or Phase 3 not confirmed)
  → cold restart + re-run at escalated intensity (once)
  → if threshold met → enter Phase 3 repeatability check
  → if still not confirmed → NO_DOS_EFFECT

NO_DOS_EFFECT
  → emit report noting which assumption was most likely wrong
  → include baseline and attack metric time-series for manual review

ENVIRONMENT_ERROR (baseline unhealthy)
  → emit error; do not emit a verdict; fix the environment and re-run
```

**Files to change:**
- `verifier/verifier_developer.py` — implement three-phase protocol; baseline health check; attribution checks; repeatability loop; emit verdict
- `verifier/verifier_critic.py`    — verify baseline was recorded before attack; verify attribution checks are applied; verify repeatability ran before final CONFIRMED_DOS
- Remove: `verifier/flag_checker.py`

---

## 8. Responsible disclosure

On `CONFIRMED_DOS`, auto-generate a draft in `output/<run_id>/disclosure_draft.md`:

```markdown
# Responsible Disclosure Draft

**Product:** {target.repo} @ {target.version}
**Protocol:** {target.protocol}
**DoS class:** {hypothesis.dos_class}
**Discovered by:** Idan Efraim (Bar-Ilan University / TAU Deepness Lab)

## Summary
[one paragraph from ExploitPlan.expected_effect]

## Technical details
[ExploitPlan.attack_sequence rendered as steps]

## Evidence
[metric summary: peak CPU, peak memory, latency spike, crash info]

## Findings
[ComplianceGaps — RFC MUST/SHALL requirements violated]
[SecurityDesignGaps — spec-permitted behaviors with no defensive bound]
[ImplementationInvariantViolations — properties absent that safe operation requires]

## Suggested fix
[Verifier Developer's recommendation]

## Timeline
- Discovered: {date}
- Draft: {date}
- Disclosed to vendor: [PENDING]
```

---

## 9. Validation strategy

### Phase 7 checklist

- [ ] Run all positive YAMLs → all emit `CONFIRMED_DOS`
- [ ] Run all negative YAMLs → all emit `NO_DOS_EFFECT` or `INCONCLUSIVE`
- [ ] Run same YAML on `claude-haiku-3-5` and `gpt-4o-mini` — compare verdicts + cost
- [ ] Run same YAML on stronger model (claude-sonnet / gpt-4o) — check if verdict improves
- [ ] Check disclosure drafts are coherent and accurate
- [ ] Check Gap Finder never cites a constant definition as enforcement evidence (ComplianceGap)
- [ ] Check SecurityDesignGap findings name the absent defensive measure, not just the vulnerable path
- [ ] Check ImplementationInvariantViolation findings show the missing bound/check, not an existing one
- [ ] Confirm all three finding types (ComplianceGap, SecurityDesignGap, ImplementationInvariantViolation) are exercised across the positive suite
- [ ] Check Exploit Planner never invents QUIC frame types not in RFC 9000

### Cost tracking

Log per-run token usage by module. Target: Gap Finder should dominate (most file reads).
If Exploiter dominates, the Exploit Plan is probably underspecified.

---

## Notes

- **Language:** CVE-Genie is Python. All new modules are Python. Keep consistent.
- **Repo clone:** YAML Parser clones the target repo at `workspace/{run_id}/target/`
  at the specified version/tag. All Gap Finder file reads are rooted here.
- **Run isolation:** Each hypothesis run gets its own `workspace/{run_id}/` directory.
- **No CVE ID required:** This framework is for pre-disclosure discovery. The CVE field
  in positive YAMLs is for test-suite bookkeeping only.
- **Scope (current):** Protocol specification implementation DoS only. Web-app DoS
  (taint-analysis path) is deferred to a later phase.

---

## 10. Claude Code implementation order

Work through phases in order. Do not start the next phase until the test gate for the current one passes.

---

### Phase 0 — Baseline: run a known CVE on the existing fork

The repo is already forked and cloned with no changes applied yet.

**Tasks:**
```bash
# run one known CVE end-to-end (pick a simple web CVE from CVE-Genie's examples)
# read the code as it runs: entry point, agent loop, context passing between modules
```

**Understand before moving on:**
- Where does each agent live? What is the developer+critic loop pattern?
- How does the pipeline pass context between modules?
- What does a successful run look like in the logs?

**Test gate:**
```
[ ] One CVE runs end-to-end without errors
[ ] You can identify the file/class for: Data Processor, Builder, Exploiter, Verifier
[ ] You understand how agent prompts are structured and how tool calls are made
```

---

### Phase 1 — YAML Parser + Spec Processor

**Tasks:**
1. Create `processor/models.py` — `HypothesisContext`, `Assumption`, `RFCSection` dataclasses
2. Create `processor/yaml_parser.py` — load and validate the YAML; populate `HypothesisContext`
3. Replace `processor/data_processor.py` logic with YAML Parser (keep same interface so rest of pipeline is untouched)
4. Create `spec_processor/spec_processor.py` — single LLM call; fetch RFC section from IETF, extract normative DoS-relevant requirements
5. Create `spec_processor/models.py` — `SpecRequirement` dataclass
6. Create `spec_processor/prompts.py`

**Test gate:**
```bash
# Parse the QUIC Rapid Reset example YAML — no errors, all fields populated
python -c "from processor.yaml_parser import parse; ctx = parse('tests/yamls/positive/h2_rapid_reset.yaml'); print(ctx)"

# Spec Processor fetches and parses RFC 9000 §4.6
python -c "
from spec_processor.spec_processor import run
reqs = run(ctx)
assert len(reqs) > 0, 'no requirements extracted'
for r in reqs: print(r.requirement_text[:80])
"
[ ] At least 2 MUST/SHALL requirements extracted for each rfc_sections entry
[ ] Requirements map to at least one assumption or suspected_mechanism step
[ ] No hallucinated RFC section numbers in output
```

---

### Phase 2 — Gap Finder

**Tasks:**
1. Create `gap_finder/tools.py` — `read_file`, `list_dir`, `search_code` wrappers rooted at `workspace/{run_id}/target/`
2. Create `gap_finder/models.py` — `AssumptionVerdict`, `ComplianceGap`, `SecurityDesignGap`, `ImplementationInvariantViolation`, `Finding` dataclasses
3. Create `gap_finder/prompts.py` — developer prompt (verify each assumption + find each gap); critic prompt (reject constant-only citations)
4. Create `gap_finder/gap_finder.py` — developer+critic loop, 1 iteration max

**Test gate:**
```bash
# Clone Caddy v2.7.6 into workspace/test/target/
git clone --depth 1 --branch v2.7.6 https://github.com/caddyserver/caddy workspace/test/target/

# Run Gap Finder on the QUIC Rapid Reset hypothesis
python -c "
from gap_finder.gap_finder import run
from tests.fixtures import quic_ctx, quic_spec_reqs
verdicts, findings = run(quic_ctx, quic_spec_reqs, repo_root='workspace/test/target/')
for v in verdicts: print(v.assumption_id, v.status, v.code_evidence[:60])
for f in findings:
    desc = getattr(f, 'gap_description', getattr(f, 'invariant_description', ''))
    print(type(f).__name__, desc[:80])
"
[ ] A1, A2, A3 each return a verdict (confirmed / refuted / unclear)
[ ] Each verdict cites a file:line, not just a variable name
[ ] Critic does NOT pass a ComplianceGap that only cites a constant definition
[ ] Critic does NOT pass a SecurityDesignGap that only identifies vulnerable behavior without naming the absent defensive bound
[ ] Critic does NOT pass an ImplementationInvariantViolation that shows an existing check rather than a missing one
[ ] At least one Finding of each type (ComplianceGap, SecurityDesignGap, ImplementationInvariantViolation) exercised across the full positive test suite
```

---

### Phase 3 — Exploit Planner

**Tasks:**
1. Create `exploit_planner/models.py` — `ExploitPlan`, `Step` dataclasses
2. Create `exploit_planner/prompts.py` — developer prompt (severity, reachability, packet sequence); critic prompt (cross-reference against Gap Finder raw output; validate frame types)
3. Create `exploit_planner/exploit_planner.py` — single dev call + single critic call, no loop; pivot logic if required assumption refuted

**Test gate:**
```bash
python -c "
from exploit_planner.exploit_planner import run
from tests.fixtures import quic_ctx, quic_verdicts, quic_findings
plan = run(quic_ctx, quic_verdicts, quic_findings)
print(plan.severity, plan.expected_effect)
for s in plan.attack_sequence: print(s.n, s.quic_frame)
"
[ ] Plan contains ≥ 3 steps
[ ] Every quic_frame field names a real RFC 9000 frame type
[ ] No step references a file or function name (Gap Finder already did that)
[ ] If a required assumption is refuted → plan.pivot_note is set, not None
[ ] Critic passes without requesting a revision on a valid Gap Finder output
```

---

### Phase 4 — Builder (Docker rewrite)

**Tasks:**
1. Rewrite `builder/builder.py` — implement three-case Docker strategy (Hub pull → source build fallback → Dockerfile write); fill `{config_path}` and `{ports}` from Setup Developer output
2. Rewrite `builder/setup_developer.py` — generate server config from `target.entry_point` for any product; return `config_path` (product-specific in-container path) and `ports` alongside config content; always reference `/certs/server.crt` and `/certs/server.key` for TLS
3. Update `builder/setup_critic.py` — verify config references `/certs/server.crt` and `/certs/server.key` (not any product-specific path); verify `config_path` and `ports` are returned
4. Remove `builder/prerequisite_developer.py`

**Test gate:**
```bash
# Case 1: image available on Hub (use any image with a known tag)
python -c "from builder.builder import build; build('nginx', '1.25.3', entry_point='TCP port 443, HTTPS')"
docker ps | grep nginx
openssl s_client -connect localhost:443 -brief   # should show self-signed cert

# Case 2: tag not on Hub → source build fallback
python -c "from builder.builder import build; build('nginx', '1.25.3-nonexistent', entry_point='TCP port 443, HTTPS')"
# should fall back to source build without crashing

[ ] Container starts and is reachable on the configured port
[ ] TLS cert mounted at /certs/ inside the container (openssl s_client confirms self-signed cert)
[ ] Server config references /certs/server.crt and /certs/server.key — not any product-specific path
[ ] config_path and ports are returned by Setup Developer and used in docker run, not hardcoded
[ ] docker stop + docker rm cleanup runs on teardown
```

---

### Phase 5 — Exploiter (protocol tools)

**Tasks:**
1. Update `exploiter/exploit_developer.py` — accept `ExploitPlan` as input; generate aioquic / h2 / Scapy code from the plan's `attack_sequence`
2. Update `exploiter/exploit_critic.py` — verify protocol frame fields against RFC; verify metric collection code present
3. Update `exploiter/tools.py` — add `collect_metrics()` helper (docker stats + probe RTT)

**Test gate:**
```bash
# Run Exploiter against live Caddy container with the QUIC Rapid Reset plan
python -c "
from exploiter.exploiter import run
from tests.fixtures import quic_plan
metrics = run(quic_plan, container_id='<caddy_container_id>')
print(metrics)
"
[ ] Exploit script runs without import errors (aioquic, h2, scapy all available)
[ ] Metrics dict populated: cpu_pct, mem_mb, latency_ms, alive all have entries
[ ] No HTTP payload generation — only QUIC / HTTP/2 / DNS frame calls
[ ] Critic passes the generated exploit code on a valid plan
```

---

### Phase 6 — Wire together + DoS Verifier

**Tasks:**
1. Update `verifier/verifier_developer.py` — read metrics dict, apply CONFIRMED_DOS thresholds, emit verdict
2. Update `verifier/verifier_critic.py` — verify threshold logic
3. Remove `verifier/flag_checker.py`
4. Create `hypogenie.py` — main entry point; wire YAML Parser → Spec Processor → Gap Finder → Exploit Planner → Builder → Exploiter → DoS Verifier → disclosure draft
5. Add `--test-suite` mode to `hypogenie.py`

**Test gate:**
```bash
# Full end-to-end run on QUIC Rapid Reset YAML (known-vulnerable Caddy version)
python hypogenie.py --input tests/yamls/positive/h2_rapid_reset.yaml

[ ] Run completes without unhandled exceptions
[ ] output/<run_id>/verdict.json exists and contains CONFIRMED_DOS or NO_DOS_EFFECT
[ ] output/<run_id>/disclosure_draft.md generated on CONFIRMED_DOS
[ ] output/<run_id>/metrics.json contains time-series CPU, memory, latency
[ ] Pipeline logs show each module completing in order
[ ] Token usage logged per module
```

---

### Phase 7 — Validate on ground-truth test suite

**Tasks:**
1. Write all 5 positive YAMLs (see §5a) with correct fields
2. Write all 4 negative YAMLs (see §5b) with correct fields
3. Run full test suite on both model providers

**Test gate:**
```bash
python hypogenie.py --test-suite tests/yamls/positive/ --expect CONFIRMED_DOS
python hypogenie.py --test-suite tests/yamls/negative/ --expect NO_DOS_EFFECT

[ ] True-positive rate = 5/5
[ ] False-positive rate = 0/4
[ ] Both anthropic (claude-haiku-3-5) and openai (gpt-4o-mini) pass
[ ] Cost per run logged and within acceptable range
[ ] Gap Finder token usage > Exploiter token usage (plan is sufficiently specified)
```
