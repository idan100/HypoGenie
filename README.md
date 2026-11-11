# HypoGenie

An LLM-based multi-agent framework for **discovering novel DoS vulnerabilities** in protocol implementation code — no CVE ID required.

HypoGenie is a fork of [CVE-Genie](https://github.com/BUseclab/cve-genie), redesigned for pre-disclosure discovery. You supply a structured YAML attack hypothesis and the framework verifies it end-to-end: from RFC analysis and static code review through live exploit execution and reproducibility confirmation.

> M.Sc. thesis project — Idan Efraim, Bar-Ilan University / TAU Deepness Lab (Prof. Anat Bremler-Barr).

---

## What it does

HypoGenie takes a structured hypothesis YAML describing a suspected DoS vulnerability and runs a 7-stage pipeline to confirm or refute it:

```
YAML Parser       → parses the hypothesis, target, assumptions, and RFC sections
Spec Processor    → fetches RFC text, extracts MUST/SHALL/SHOULD requirements
Gap Finder        → verifies each assumption against the implementation source code
Exploit Planner   → translates Gap Finder findings into a concrete packet sequence
Builder           → pulls or builds the target server in Docker, mounts TLS certs
Exploiter         → executes the protocol-level exploit (aioquic / h2 / Scapy)
DoS Verifier      → 3-phase verification: baseline → attack → repeatability
```

**Verdict options:** `CONFIRMED_DOS` · `NO_DOS_EFFECT` · `INCONCLUSIVE` · `INFEASIBLE` · `ENVIRONMENT_ERROR`

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

Edit [`config/models.yaml`](config/models.yaml) to choose your provider and model:

```yaml
default_provider: anthropic      # or: openai

anthropic:
  model: claude-haiku-4-5
  api_key_env: ANTHROPIC_API_KEY

openai:
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
```

Start with the cheapest models for iteration speed; switch to a stronger model for final validation.

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
| `verdict.json` | Final verdict, triggered thresholds, target metadata |
| `metrics.json` | CPU, memory, latency time-series (baseline + attack) |
| `token_usage.json` | Token usage per pipeline module |
| `disclosure_draft.md` | Auto-generated disclosure (only on `CONFIRMED_DOS`) |

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
  # allowed: resource_exhaustion | recursion | regex | memory | cpu | resource_starvation

target:
  repo: https://github.com/caddyserver/caddy
  version: v2.7.5                   # exact tag or commit SHA
  protocol: HTTP/2
  entry_point: "TCP port 443, HTTP/2 over TLS"
  docker_image: "caddy:2.7.5"       # optional: skip Docker Hub lookup if known

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

See [`src/tests/yamls/positive/`](src/tests/yamls/positive/) for complete working examples.

---

## Ground-truth test suite

The test suite lives in [`src/tests/yamls/`](src/tests/yamls/):

**Positive cases** (real vulnerabilities, `CONFIRMED_DOS` expected):
- `h2_rapid_reset.yaml` — CVE-2023-44487, HTTP/2 Rapid Reset
- `golang_h2_double_flowcontrol.yaml` — CVE-2026-78663, double flow-control credit refund
- `grpcgo_h2_data_fragmentation.yaml` — CVE-2026-84304, per-frame struct overhead exhaustion
- `coredns_grpc_no_limits.yaml` — CVE-2025-68151, CoreDNS gRPC with no connection limits
- `quicgo_qpack_headers.yaml` — CVE-2025-64702, QPACK header decompression amplification

**Negative cases** (`NO_DOS_EFFECT` expected):
- `h2_rst_patched.yaml` — CVE-2023-44487 on a patched nginx version
- `quic_reset_rate_limited.yaml` — same mechanism on a rate-limited implementation
- `quic_window_bounded.yaml` — bounded flow control, attack does not trigger
- `dns_recursion_limited.yaml` — recursion assumption not reachable

---

## Pipeline details

### DoS Verifier — 3-phase protocol

1. **Baseline** (10 s, no attack) — records CPU, memory, latency. Aborts with `ENVIRONMENT_ERROR` if the server is unhealthy before the attack.
2. **Attack** — runs the exploit from the Exploit Plan. Checks attribution (spike onset within 10 s of first packet, probe requests degraded).
3. **Repeatability** — cold-restarts the container and re-runs. `CONFIRMED_DOS` requires two independent confirmations.

Verdict thresholds (attack vs. baseline):

| Metric | Threshold |
|--------|-----------|
| CPU | Δ ≥ 50 pp sustained ≥ 5 s |
| Memory | Δ ≥ 100 MB RSS |
| Latency | attack mean ≥ 5× baseline mean RTT |
| Crash | container exit code ≠ 0 |
| Unreachable | probe `alive=False` for ≥ 3 consecutive seconds |

### Gap Finder — finding types

| Type | When used |
|------|-----------|
| `ComplianceGap` | MUST / SHALL requirement not enforced in code |
| `SecurityDesignGap` | Spec-permitted behavior with no defensive bound |
| `ImplementationInvariantViolation` | Property required for safe operation, absent in code |

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
hypogenie.py              main entry point
config/models.yaml        LLM provider and model selection
infra/certs/              self-signed TLS certs (generated by setup.sh)
src/
  processor/              YAML parser → HypothesisContext
  spec_processor/         RFC section fetch + normative requirement extraction
  gap_finder/             developer + critic loop, assumption + code gap analysis
  exploit_planner/        Gap Finder output → concrete packet sequence
  builder/                Docker Hub pull / source-build, TLS cert mount
  exploiter/              aioquic / h2 / Scapy protocol exploit execution
  verifier/               3-phase metric-based DoS verification
  agentlib/               base agent framework (developer/critic loop primitives)
  tests/yamls/            ground-truth positive and negative YAML test suite
output/                   per-run results (verdict, metrics, disclosure draft)
visualizer/               web UI for exploring run artifacts
```

---

## License

[LICENSE](LICENSE)
