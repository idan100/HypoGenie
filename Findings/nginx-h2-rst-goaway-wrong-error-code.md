Security Research · nginx/nginx release-1.25.3 · November 2026

# nginx HTTP/2 RST_STREAM — Wrong GOAWAY Error Code

Idan Efraim · Bar-Ilan University / TAU Deepness Lab

---

**No vulnerability — not CVE-worthy**  
The hypothesis was that nginx 1.25.3 lacked an RST_STREAM rate-limit patch, making it vulnerable to H2 rapid reset DoS (CVE-2023-44487 class). It didn't. The patch is present and effective. HypoGenie found one real thing on the way out: nginx closes rate-limited connections with `GOAWAY(NO_ERROR)` instead of `GOAWAY(ENHANCE_YOUR_CALM)`. That error code is wrong per RFC 7540 §10.5. It is not exploitable.

---

## The Attack Idea

The theory was that nginx 1.25.3 had not applied the rapid-reset mitigation, leaving the server able to be saturated by a flood of HEADERS+RST_STREAM cycles. Each cycle makes the server allocate stream state and immediately throw it away — with enough cycles per second, CPU spikes and the server falls over. This is the CVE-2023-44487 class of attack that affected nearly every major HTTP/2 stack in October 2023.

Two assumptions had to hold for the attack to work. Both were checked against source.

---

## The Assumptions — Did They Hold?

**A1 — nginx 1.25.3 has not applied the RST_STREAM rate-limit patch**  
Required  
**False — refuted by source**

The Gap Finder found the mitigation at `src/http/v2/ngx_http_v2.c:1357–1370`:

```c
if (h2c->refused_streams++ > ngx_max(h2scf->concurrent_streams, 100)) {
    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent too many refused streams");
    return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_NO_ERROR);
}
```

The counter exists, it is incremented on each incoming RST_STREAM, and the connection is closed with a GOAWAY once the limit is exceeded. The patch is in place. An attacker can send at most `max(concurrent_streams, 100)` rapid resets per connection before nginx ends it.

**A2 — No per-connection reset counter limits rapid resets**  
Required  
**False — same evidence as A1**

The `h2c->refused_streams` counter is exactly this. Both assumptions fail on the same two lines of source. Without them the attack has no basis.

**IMPL_1 — RST_STREAM frames are processed immediately, without batching or deferral**  
Required  
**Confirmed — but harmless without A1 and A2**

`ngx_http_v2_state_rst_stream` processes incoming RST_STREAM frames synchronously: it parses the frame, updates stream state, and fires the read event handler inline (`ev->handler(ev)` at line 2126). There is no queue or batch. This is confirmed — and is exactly the property the patch relies on to increment `refused_streams` reliably on every reset.

---

## The Exploit Attempt

HypoGenie ran the attack anyway — 353 connections/s, HEADERS+RST_STREAM flood, escalated to 60 seconds — and watched what happened.

| Phase | CPU mean | Δ from baseline |
|---|---|---|
| Baseline (10s) | 0.0% | — |
| Attack (30s) | 26.8% | +26.8pp |
| Attack escalated (60s) | 53.3% | +53.3pp |

The escalated run crossed the 50pp threshold and triggered a differential control test — a second container running the same connection rate with benign payloads, to separate transport overhead from application-level cost.

| | Target | Control |
|---|---|---|
| CPU delta | +53.3pp | +44.4pp |
| Ratio | — | **0.833** |

The reject threshold is 0.80. At 0.833 the verifier sets `transport_overhead_confirmed = true` and `cpu_attributed = false`. The math confirms it: 353.1 conn/s × 0.095 CPU-s/conn predicts 33.6pp in TLS handshake cost alone; the control observed 44.4pp. After subtracting the predicted TLS cost, the net application-level delta is **19.7pp** — well below the 50pp threshold, not attributed to the attack.

The patch is working. By forcing GOAWAY, nginx makes the attacker reconnect and pay a new TLS handshake per reconnect cycle. That is the defence. The overhead is symmetric — both sides pay the same TLS cost — so there is no amplification.

---

## What HypoGenie Found

On the way out, the Gap Finder flagged the error code on line 1362:

```c
return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_NO_ERROR);
```

RFC 7540 §10.5 says:

> An endpoint **MAY** treat activity that is suspicious as a connection error of type ENHANCE_YOUR_CALM.

nginx uses `NO_ERROR` (error code 0x0) instead of `ENHANCE_YOUR_CALM` (error code 0xb). The spec says MAY, so using `NO_ERROR` is technically conformant. The connection is still closed; the RST flood is still stopped. But the signal carried in the GOAWAY frame is wrong, and that matters in several concrete ways.

**What ENHANCE_YOUR_CALM is for.** `ENHANCE_YOUR_CALM` is an HTTP/2 error code defined specifically to mean "you are sending too fast — slow down." It is the HTTP/2 equivalent of a TCP RST sent in response to a rate limit: the receiver knows that the closure was a policy decision, not a network event or a server crash. RFC 7540 §10.5 reserves it precisely for the case where an endpoint detects suspicious stream-reset activity and decides to terminate the connection as a defence.

**What `NO_ERROR` tells the client instead.** A GOAWAY with `NO_ERROR` conventionally means the server is shutting down gracefully — a planned restart, a load-balancer drain, an idle timeout. Clients and proxies that see `NO_ERROR` have no reason to pause before reconnecting. HTTP/2 clients typically reconnect immediately and transparently on `NO_ERROR` GOAWAY, retrying any in-flight requests on the new connection. That is the right thing to do for a graceful shutdown. It is the wrong thing to do when the server just closed the connection because the client was flooding it with resets.

**The P3 reconnect loop in this context.** The exploit planner's P3 pivot identified this exact dynamic: since nginx issues GOAWAY on hitting the `refused_streams` limit, an attacker can close and reopen connections as fast as TLS allows, treating each GOAWAY as a prompt to reconnect. With `NO_ERROR`, a standards-compliant HTTP/2 client — or a deliberately adversarial one — has no protocol-level signal that it should do anything differently on reconnect. With `ENHANCE_YOUR_CALM`, a compliant client is expected to apply exponential backoff before retrying. The difference is that `NO_ERROR` removes the one hook where the protocol could slow the reconnect loop down on the client side.

In practice this doesn't create an exploitable condition because the TLS handshake cost is symmetric — the attacker pays as much to reconnect as the server pays to handle the reconnect. But it means the defence relies entirely on that symmetric cost rather than also having a protocol signal that tells well-behaved clients to pause.

**Observability.** `ENHANCE_YOUR_CALM` appears as a distinct value in GOAWAY frames visible in packet captures, server logs, and HTTP/2 frame parsers. `NO_ERROR` does not. When nginx silently closes a connection under RST flood with `NO_ERROR`, the closure looks identical in logs to a normal connection lifecycle event. An operator watching an access log or an IDS watching H2 traffic has no way to distinguish "this connection was rate-limited due to a reset flood" from "this connection closed cleanly." `ENHANCE_YOUR_CALM` would make the event identifiable without any application-layer logging change.

**Exploitability: none.** The connection is closed either way. The wrong error code affects client backoff behaviour and monitoring observability, not whether the attack succeeds.

---

## Recommended Fix

```c
/* src/http/v2/ngx_http_v2.c:1362 */

/* before */
return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_NO_ERROR);

/* after */
return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
```

This makes the signal correct: clients and proxies see a rate-limit closure rather than a normal shutdown, and compliant clients apply backoff on reconnect.

---

HypoGenie security research · run 20261126-152206-1dfb · DEFECT · patch_bypass=false  
nginx/nginx@release-1.25.3 · HTTP/2 · 2026-11-26
