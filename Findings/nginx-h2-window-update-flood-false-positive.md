Security Research · nginx/nginx release-1.26.0 · November 2026

# nginx HTTP/2 WINDOW_UPDATE Flood — Conformance Gap, Not Exploitable DoS

Idan Efraim · Bar-Ilan University / TAU Deepness Lab

---

**No vulnerability — not CVE-worthy**  
HypoGenie returned CONFIRMED_DOS. It was wrong. The CPU signal, the unreachable trigger, and the apparent crash were all artefacts of running in a `--cpus=1` cgroup, not nginx behaviour under WINDOW_UPDATE load. A conformance gap is real — nginx has no dedicated per-connection WINDOW_UPDATE frame counter — but it does not translate to exploitable DoS under any realistic deployment. F5 closed the HackerOne submission Informative. Self-retracted to LOW before they did.

---

## Getting the Run to Work

Four attempts on the same day failed before the pipeline produced a usable result.

Runs `160724`, `161306`, and `163730` all returned `INVALID_TEST` with "Sent 0 WINDOW_UPDATE frames." The root cause was ALPN: without `ctx.set_alpn_protocols(["h2"])` the TLS handshake negotiated HTTP/1.1, the h2 library's send path silently produced nothing, and the footer rule (`PROTOCOL_NEGOTIATED` must be "h2") correctly rejected all three as invalid. Run `171616` fixed the ALPN but hit `ENVIRONMENT_ERROR` because the YAML was still in `negative/` and the path resolution failed. Attempt 5 at `171641` corrected both: ALPN set, path moved to `positive/`. That run produced numbers.

---

## What the Pipeline Saw

| Phase | CPU mean | Δ from baseline | Triggered |
|---|---|---|---|
| Baseline (10s) | 0.0% | — | — |
| Attack (30s) | 179.9% | +179.9pp | cpu |
| Repeatability | 162.3% | +162.3pp | cpu, unreachable, crash |

The CPU crossed the 50pp threshold and sustained it for the full window in both Phase 2 and Phase 3. Phase 3 also saw `unreachable` (3 consecutive seconds of no response) and `crash` ("container exited unexpectedly"). The pipeline issued CONFIRMED_DOS. On the same day, commit `64e63d8` removed `negative/h2_window_update_flood.yaml` and promoted the hypothesis to `positive/` on the basis of this result.

The source analysis had confirmed two assumptions cleanly:

**A1** — nginx processes every WINDOW_UPDATE frame without rate limiting, incrementing `h2c->send_window` unconditionally per frame:

```c
/* src/http/v2/ngx_http_v2.c:2480 */
h2c->send_window += window;
```

**A2** — the handler is O(1): one overflow check, one addition, no queued ACK. The `h2c->frames` pool that throttles other frame types never fires for WINDOW_UPDATE because there is nothing to acknowledge. Confirmed at lines 2411–2413.

Both confirmed. CPU triggered. Container crashed. The pipeline called it a confirmed DoS.

---

## What the Pipeline Got Wrong

**The CPU was cgroup noise, not WINDOW_UPDATE handler cost.**

nginx was running with `--cpus=1` in a container on a 7-core host. The normalisation factor is 7: raw cgroup CPU × 7 = host-equivalent CPU. At 821 K WINDOW_UPDATE frames/s the network I/O and TLS decryption inside the cgroup saturated the single allowed core. The handler at `ngx_http_v2.c:2480` is one integer addition behind a TLS record boundary — it is not the bottleneck.

The confirmation came from the HackerOne follow-up: a PING frame control test produced an identical CPU profile. PING frames are 8 bytes, require an immediate PING ACK, and have nothing to do with the WINDOW_UPDATE handler. If flooding with PING produces the same 170–180pp cgroup CPU as flooding with WINDOW_UPDATE, the signal is frame-volume TLS overhead, not handler cost. It was.

**The "crash" was a cgroup kill, not a DoS crash.**

When the cgroup's single CPU core is saturated by network I/O, the Linux kernel's cgroup scheduler will throttle and eventually kill the heaviest process. The nginx worker that was handling the flood was that process. `container exited unexpectedly` in the pipeline's output is the master process removing the killed worker — a normal response to a cgroup-throttled OOM-adjacent situation, not a worker crash caused by the WINDOW_UPDATE flood itself. Run the same test on a host without `--cpus=1` and the container stays alive while consuming proportionally more CPU.

**The differential control was not run.**

This run predates the Phase 2c differential control and Phase 2d benign comparison logic. If the pipeline had run a benign frame-flood control at the same frame rate, it would have shown the same CPU profile from PING or any other O(1) frame type. That would have set `transport_overhead_confirmed = true` and cleared `cpu_attributed`. The false positive happened because the verifier at the time only checked whether CPU crossed a threshold, not whether the attack mechanism specifically drove it.

---

## The Real Conformance Gap

The Gap Finder's finding is correct on its own terms. RFC 7540 §6.9.1 requires a sender to terminate the stream or connection if a WINDOW_UPDATE would cause the flow-control window to exceed 2^31−1. nginx checks for that overflow. What it does not have is any per-connection counter for the rate of incoming WINDOW_UPDATE frames — no token bucket, no frame counter, no equivalent to the `refused_streams` guard that limits RST_STREAM floods.

The `h2c->frames` pool that sits between frame receipt and processing for most frame types never fires for WINDOW_UPDATE because the handler queues no outbound ACK. Every WINDOW_UPDATE delivered to nginx is processed inline, synchronously, with no throttle path available short of the overflow check.

This is a real design asymmetry: an attacker can send WINDOW_UPDATE at wire rate and nginx will process every frame. The question is what "process every frame" costs — and the answer, empirically, is one integer addition per frame. At 821 K frames/s that is 821 K integer additions per second. On any server with a real CPU budget, that is not measurable above background.

---

## Why It Is Not Exploitable

The WINDOW_UPDATE handler is too cheap. The O(1) cost confirmed by A2 is not a theoretical property — it is the reason the handler scales. An attacker sending WINDOW_UPDATE at maximum link rate produces less CPU load on the server than the TLS decryption required to unwrap the frames containing them. The bottleneck is always the network layer, not the handler, which means the server's CPU budget for WINDOW_UPDATE processing grows with link capacity rather than outrunning it.

The absence of a frame counter matters for defence-in-depth — a future handler change that made WINDOW_UPDATE more expensive would have no throttle to fall back on — but absent such a change the gap has no exploitable consequence.

---

## What Should Have Happened

The commit `64e63d8` that promoted this hypothesis to `positive/` should not have been made on the basis of this run. The CONFIRMED_DOS verdict was a false positive driven by cgroup CPU measurement without a differential control. The correct action after getting a clean run was to run a Phase 2c benign control before reclassifying the hypothesis. The reclassification to `positive/` has since been reverted.

---

HypoGenie security research · run 20261112-171641-425a · CONFIRMED_DOS (false positive)  
nginx/nginx@release-1.26.0 · HTTP/2 · 2026-11-12 · HackerOne submission: closed Informative
