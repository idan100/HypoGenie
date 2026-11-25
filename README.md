# HypoGenie

An LLM-based multi-agent framework for **discovering novel DoS vulnerabilities** in protocol implementation code — no CVE ID required.

HypoGenie is a fork of [CVE-Genie](https://github.com/BUseclab/cve-genie), redesigned for pre-disclosure discovery. You supply a structured YAML attack hypothesis and the framework verifies it end-to-end: from RFC analysis and static code review through live exploit execution and reproducibility confirmation.

> M.Sc. Thesis Research — Idan Efraim, Bar-Ilan University, under the supervision of Dr. Ariel Nof, in collaboration with TAU Deepness Lab (Prof. Anat Bremler-Barr).

---

## What it does

HypoGenie takes a structured hypothesis YAML describing a suspected DoS vulnerability and runs a 7-stage pipeline to confirm or refute it:

```
YAML Parser       → parses the hypothesis, target, assumptions, and RFC sections
Spec Processor    → fetches RFC text, extracts MUST/SHALL/SHOULD requirements
Gap Finder        → verifies each assumption against the implementation source code
                    └─ Assumption Ledger gate: INFEASIBLE if all required assumptions refuted
Exploit Planner   → translates Gap Finder findings into a concrete packet sequence
                    └─ generates base_attack_sequence + amplified_attack_sequence independently
Builder           → pulls or builds the target server in Docker, mounts TLS certs
Exploiter         → executes the protocol-level exploit (aioquic / h2 / Scapy)
DoS Verifier      → 4-phase verification: baseline → attack → attribution → repeatability
                    └─ lifecycle validation: resource accumulation across batched operations
```

**Measurement verdicts:** `CONFIRMED_DOS` · `NO_DOS_EFFECT` · `INCONCLUSIVE` · `INFEASIBLE` · `DEFECT` · `REJECTED` · `ENVIRONMENT_ERROR`

**Hypothesis verdicts:** `DOS_CONFIRMED` · `HYPOTHESIS_DISPROVEN` · `HYPOTHESIS_PARTIALLY_DISPROVEN` · `HYPOTHESIS_INCONCLUSIVE`

On `CONFIRMED_DOS`, the framework auto-generates a `disclosure_draft.md` with product details, attack steps, metric evidence, and a suggested fix.

---

## Results

See [results/RESULTS.md](results/RESULTS.md) for details on the ground-truth test suite outcomes.

---

## Requirements

- Python ≥ 3.12
- Docker (daemon running)
- `openssl` CLI (for cert generation)
- `git`
- An Anthropic API key and/or OpenAI API key

---

## Setup

### 1. Clone and create a virtual environment

```bash
git clone https://github.com/idan100/HypoGenie
cd HypoGenie
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install the agentlib and project dependencies

```bash
pip install -e src/agentlib/
pip install aioquic scapy h2 docker requests pyyaml anthropic openai
```

### 3. Configure API keys

Create a `.env` file at the project root:

```bash
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...          # optional if using Anthropic only
```

### 4. Configure the LLM

Edit [`config/models.yaml`](config/models.yaml) to choose your cost/quality profile:

```yaml
active_profile: cheap   # cheap | medium | strong

profiles:
  cheap:   { openai: "gpt-4o-mini",   anthropic: "claude-haiku-4-5"  }
  medium:  { openai: "gpt-4o",        anthropic: "claude-haiku-4-5"  }
  strong:  { openai: "gpt-4o",        anthropic: "claude-sonnet-4-5" }

# Optional per-role overrides (take precedence over active_profile):
# role_overrides:
#   EXPLOITER_MODEL: "anthropic:claude-opus-4-5"
```

`openai` roles: Spec Processor, Gap Finder, Gap Finder Critic, Exploit Planner.
`anthropic` roles: Builder, Exploiter.

Start with `cheap` for iteration speed; use `strong` for final validation runs.

### 5. Run infrastructure setup (once)

```bash
bash infra/setup.sh
```

This generates a self-signed TLS certificate in `infra/certs/` and verifies that Docker and the IETF RFC server are reachable. It is idempotent — safe to re-run.

---

## Running HypoGenie

### Single hypothesis

```bash
source .venv/bin/activate
python hypogenie.py --input src/tests/yamls/positive/h2_rapid_reset.yaml
```

Output is written to `output/<run_id>/`:

| File | Contents |
|------|----------|
| `verdict.json` | Final verdict, hypothesis verdict, evidence tier, triggered thresholds, assumption ledger, exploit plan, lifecycle validation |
| `metrics.json` | CPU, memory, latency time-series (baseline + attack) |
| `token_usage.json` | Token usage per pipeline module |
| `run_report.md` | Human-readable pipeline report with phase-by-phase evidence |
| `disclosure_draft.md` | Auto-generated responsible disclosure (only on `CONFIRMED_DOS`) |

### Test suite

Run all positive cases (should produce `CONFIRMED_DOS`):

```bash
python hypogenie.py --test-suite src/tests/yamls/positive/ --expect CONFIRMED_DOS
```

Run all negative cases (should produce `NO_DOS_EFFECT` or `INCONCLUSIVE`):

```bash
python hypogenie.py --test-suite src/tests/yamls/negative/ --expect NO_DOS_EFFECT
```

---

## Writing a hypothesis YAML

```yaml
hypothesis:
  description: |
    Rich prose describing the suspected vulnerability. Include:
    - RFC context: what the spec says about the mechanism
    - Analogies to known CVEs
    - Assumptions section: each checkable property explicitly listed
    - Suspected mechanism: numbered trigger sequence

  dos_class: resource_exhaustion
  # allowed: memory | cpu | connection | bandwidth | resource_exhaustion

target:
  repo: https://github.com/caddyserver/caddy
  version: v2.7.5                   # exact tag or commit SHA
  protocol: HTTP/2
  entry_point: "TCP port 443, HTTP/2 over TLS"
  docker_image: "caddy:2.7.5"       # optional: skip Docker Hub lookup if known
  server_config: |                  # optional: paste nginx.conf, Corefile, etc.
    ...

assumptions:
  - id: A1
    description: "Server allocates per-stream handler on HEADERS frame"
    necessity: required             # required | favorable
  - id: A2
    description: "No rate-limit on stream resets per connection"
    necessity: favorable

suspected_mechanism:
  - step: 1
    action: "Attacker opens N HEADERS frames (filling MAX_CONCURRENT_STREAMS)"
  - step: 2
    action: "Attacker immediately sends RST_STREAM on all N streams"
  - step: 3
    action: "Handler backlog accumulates → CPU exhaustion"

rfc_sections:
  - rfc: RFC 7540
    section: "10.5"
    dos_relevance: "RST_STREAM amplification and denial-of-service protections"

related_work:
  - type: cve
    id: CVE-2023-44487
  - type: writeup
    url: https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/
```

A complete annotated template is at [`src/tests/yamls/hypothesis_template.yaml`](src/tests/yamls/hypothesis_template.yaml). See [`src/tests/yamls/positive/`](src/tests/yamls/positive/) for working examples.

---

## Ground-truth test suite

The test suite lives in [`src/tests/yamls/`](src/tests/yamls/):

**Positive cases** (`CONFIRMED_DOS` expected):
- `h2_rapid_reset.yaml` — CVE-2023-44487, HTTP/2 Rapid Reset
- `h2_window_update_flood.yaml` — 821K WINDOW_UPDATE/s triggers CPU exhaustion
- `golang_h2_double_flowcontrol.yaml` — CVE-2026-78663, double flow-control credit refund
- `grpcgo_h2_data_fragmentation.yaml` — CVE-2026-84304, per-frame struct overhead exhaustion
- `coredns_grpc_no_limits.yaml` — CVE-2025-68151, CoreDNS gRPC with no connection limits
- `quicgo_qpack_headers.yaml` — CVE-2025-64702, QPACK header decompression amplification

**Negative cases** (`NO_DOS_EFFECT` or `INFEASIBLE` expected):
- `h2_rst_patched.yaml` — CVE-2023-44487 on a patched nginx version
- `h2_continuation_patched.yaml` — continuation flood on a patched server (INFEASIBLE)
- `h2_max_concurrent_streams.yaml` — stream-limit memory hypothesis; server enforces the cap
- `h2_settings_cycling.yaml` — settings flood on a rate-limited implementation
- `quic_reset_rate_limited.yaml` — same mechanism on a rate-limited implementation
- `quic_window_bounded.yaml` — bounded flow control, attack does not trigger
- `dns_recursion_limited.yaml` — recursion assumption not reachable in the target

**Broad hypotheses** (21 experimental cases across HTTP, QUIC, gRPC, DNS, MQTT, AMQP, SQL, LDAP, Redis, etc.):
- Located in [`src/tests/yamls/broad/`](src/tests/yamls/broad/)
- Cover Envoy, HAProxy, Traefik, Varnish, Nginx, CoreDNS, Unbound, Mosquitto, RabbitMQ, MySQL, PostgreSQL, OpenLDAP, Redis, Node.js, Consul, etcd, Kamailio, Apache

---

## Pipeline details

### Assumption Ledger

The Gap Finder maintains an `AssumptionLedger` — a single source of truth threaded through the entire pipeline. Each assumption accumulates evidence from code analysis and re-investigation loops.

**Assumption statuses (8 values):**

| Status | Meaning |
|--------|---------|
| `SUPPORTED` | Direct evidence confirms the claim |
| `REFUTED` | Direct evidence contradicts the claim |
| `CONFLICTING_EVIDENCE` | Both supporting and contradicting evidence found |
| `UNVERIFIED` | Investigation attempted; no conclusive evidence |
| `AMBIGUOUS` | Claim too vague to verify |
| `INDETERMINATE` | Irreducible uncertainty; no investigation path available |
| `NOT_APPLICABLE` | Assumption does not apply to this target/version |
| `NOT_STATED` | Investigation has not started |

**Assumption gate:** if ALL `required` assumptions are `REFUTED`, the pipeline stops at stage 4 and returns `INFEASIBLE` without running the exploit. `favorable` assumptions amplify the attack when `SUPPORTED` but do not block it when `UNVERIFIED`.

**Re-investigation:** `UNVERIFIED` or `AMBIGUOUS` assumptions automatically trigger a second investigation pass (`_reinvestigate_unclear`) before the gate decision.

**Exploit Planner output:** two independent attack sequences:
- `base_attack_sequence` — relies only on `required` assumptions
- `amplified_attack_sequence` — adds amplification from `SUPPORTED` favorable assumptions

### DoS Verifier — 4-phase protocol

1. **Phase 1 — Baseline** (10 s, no attack): records CPU, memory, latency. Aborts with `ENVIRONMENT_ERROR` if the server is unhealthy. CPU settle-wait (up to 120 s, target < 15%) precedes baseline measurement.
2. **Phase 2 — Attack**: runs the exploit from the Exploit Plan. Checks whether thresholds are crossed.
3. **Phase 2c — Differential Attribution**: re-runs the exploit against a benign control container. Computes `cpu_ratio = control_delta / target_delta`. Ratio < 0.50 → attributed to application layer; ≥ 0.80 → transport overhead only; in between → `INCONCLUSIVE`.
4. **Phase 2d — Benign Comparison**: runs benign equivalent traffic at the same stream/request rate. `benign_ratio = benign_delta / attack_delta`. Ratio ≥ 0.80 → attack is not disproportionate → `DEFECT`.
5. **Phase 3 — Repeatability**: cold-restarts the container and re-runs. `CONFIRMED_DOS` requires two independent confirmations.

**Verdict thresholds (attack vs. baseline):**

| Metric | Threshold |
|--------|-----------|
| CPU | Δ ≥ 50 pp sustained ≥ 5 s |
| Memory | Δ ≥ 100 MB RSS |
| Latency | attack mean ≥ 5× baseline mean RTT |
| Crash | container exit code ≠ 0 |
| Unreachable | probe `alive=False` for ≥ 3 consecutive seconds |

**Dynamic Baseline & Attribution Engine** (`src/verifier/dynamic_baseline.py`): for high-throughput protocols (AMQP, MQTT, raw TCP) where I/O volume alone can saturate CPU, the `AttributionEngine` intercepts the Phase 3 `CONFIRMED_DOS` path. Without a matched control, those protocols return `INCONCLUSIVE` rather than a false positive. HTTP/2, gRPC, and QUIC have matched controls and receive `CONFIRMED_DOS` normally.

### Gap Finder — finding types

| Type | When used |
|------|-----------|
| `ComplianceGap` | MUST / SHALL requirement not enforced in code |
| `SecurityDesignGap` | Spec-permitted behavior with no defensive bound |
| `ImplementationInvariantViolation` | Property required for safe operation, absent in code |

### Evidence tiers

Each completed run is assigned an evidence tier:

| Tier | Meaning |
|------|---------|
| Source-code weakness identified | Gap Finder found at least one finding |
| Theoretically exploitable | Plan exists and no required assumption is refuted |
| Reproduced resource exhaustion | `CONFIRMED_DOS` from DoS Verifier |
| Externally observable availability impact | Latency spike or service unreachable during attack |

Tiers are cumulative: reaching tier 3 implies tiers 1 and 2.

### Lifecycle Validation

For memory-class hypotheses where resource accumulation across batched operations is the concern, a separate lifecycle experiment runs after the DoS Verifier:

- Sends multiple batches of operations with varying cancellation timing (before dispatch, on start signal, 300 ms after start)
- Measures `outstanding_cleanups` (live operations not yet released) across batches
- Tracks recovery: how quickly outstanding operations drain back to baseline after the attack ends
- Reports one of: `NO_RESOURCE_RETENTION` · `BOUNDED_RETENTION` · `RESOURCE_ACCUMULATION` · `CONFIRMED_RESOURCE_EXHAUSTION`

Lifecycle mode is controlled per-hypothesis via `validation.resource_lifecycle.mode`: `auto` (default, infers applicability from hypothesis signals), `enabled`, or `disabled`.

---

## Visualizer

To explore a completed run interactively:

```bash
# Copy run output to results/
cp -r output/<run_id> results/reproduced_cve/

cd visualizer/
python3 serve.py
```

Open the URL printed by `serve.py`, enter a run ID, and navigate agent conversations, tool calls, and intermediate artifacts.

---

## Project structure

```
hypogenie.py                   main entry point
config/models.yaml             LLM profile and per-role model selection
infra/certs/                   self-signed TLS certs (generated by setup.sh)
infra/grpcgo-server/           Go gRPC server used by grpc hypotheses
infra/http3-server/            Go HTTP/3 server used by QUIC hypotheses
src/
  processor/                   YAML parser → HypothesisContext
  spec_processor/              RFC section fetch + normative requirement extraction
  gap_finder/                  developer + critic loop, assumption + code gap analysis
  assumption_ledger/           8-status ledger threaded through pipeline stages
    models.py                  AssumptionStatus, AssumptionRecord, AssumptionLedger
    extractor.py               LLM-based implicit assumption extraction
  exploit_planner/             Gap Finder output → base + amplified attack sequences
  builder/                     Docker Hub pull / source-build, TLS cert mount
  exploiter/                   aioquic / h2 / Scapy protocol exploit execution
  verifier/
    verifier.py                4-phase metric-based DoS verification
    dynamic_baseline.py        AttributionEngine + WorkloadMatcher for AMQP/MQTT/TCP
  lifecycle/                   resource accumulation experiment (cancel-timing batches)
    model.py                   LifecycleMode, LifecycleResult, RetentionSample
    scenarios.py               LifecycleRunner (gRPC backend + sidecar)
    applicability.py           pre-run applicability scoring
  agentlib/                    base agent framework (developer/critic loop primitives)
  tests/
    yamls/positive/            ground-truth positive YAML test suite
    yamls/negative/            ground-truth negative YAML test suite
    yamls/broad/               21 experimental hypotheses across protocols
    test_exploit_validation.py 86 exploit validation tests
    test_assumption_reasoning.py  55 assumption ledger / reasoning tests
    test_lifecycle_applicability.py  lifecycle applicability tests
output/                        per-run results (verdict, metrics, disclosure draft)
visualizer/                    web UI for exploring run artifacts
```

---

## License

[LICENSE](LICENSE)
