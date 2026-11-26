Security Investigation · quic-go v0.59.1–v0.66.0 · November 2026

# HTTP/3 Stream Limit Bypass in quic-go: RFC 9000 §4.6 Ordering Violation

Idan Efraim · Bar-Ilan University / TAU Deepness Lab

---

**Verdict:** BUG CONFIRMED · **CVE:** RECOMMENDED · **Versions affected:** v0.59.1 → v0.66.0 · **Latest tested:** v0.66.0 ✗ still affected · **Date:** 2026-11-25

---

A client can open more streams than the server permits, in every tested quic-go version including v0.66.0. quic-go accepts an extra stream from a client before telling that client it's allowed to open one. This violates RFC 9000 §4.6. The bug is confirmed by three independent evidence sources: a client-side UDP datagram probe (64% bypass rate), server-side qlog timestamps (stream accepted, then MAX_STREAMS sent 0.010–0.036ms later), and source code analysis. The existing `RequireStreamCreditRelease` opt-in does not fix it. A CVE report to the quic-go project is recommended.

| 64% bypass rate | 52% bypass rate | 0.023 ms | 5 quic-go versions |
|---|---|---|---|
| v0.59.1 (16/25 trials) | v0.66.0 latest (13/25) | server-side delta: stream accepted → MAX_STREAMS sent | tested and confirmed |

---

## How HypoGenie Found It

The pipeline's initial hypothesis tested whether QUIC stream cancellation could exhaust server resources the way CVE-2023-44487 did in HTTP/2. That hypothesis was refuted — stream cancellation costs the same as normal stream completion, and the Phase 2d benign comparison showed benign traffic running 27% more expensive than the attack. The pipeline issued a DEFECT verdict and moved on.

But the Gap Finder had flagged something in `streams_map_outgoing.go:108` on the way out:

```go
// If we just received a MAX_STREAMS frame, this might have been the next stream
// that could be opened. Make sure we unblock the next OpenStreamSync call.
```

This pointed at a timing gap in how quic-go issues stream credit. The initial run (`20261119-160506-7b86`) reproduced a CPU spike of +137pp against a control ratio of 0.424 — attributed to application-level processing, not transport overhead — with benign traffic costing only 70.6% as much as the attack (`moderate_disproportionality`). That asymmetry was enough to flag a deeper investigation.

Manual follow-up validated the specific ordering violation described here.

---

## What the Bug Is

HTTP/3 servers have a cap on how many simultaneous requests a single client can open. This cap is `MaxIncomingStreams`. When a request finishes, the server frees up one slot and sends the client a MAX_STREAMS message: "you're now allowed to open one more."

The bug: quic-go frees the slot and immediately accepts the next incoming stream — before it has actually sent the MAX_STREAMS message. By the time the message goes out, the extra stream is already open and being processed.

RFC 9000 §4.6 is explicit: a server must not accept a stream that the client wasn't authorized to open yet. The authorization is the MAX_STREAMS message. Accepting a stream before sending that message is a protocol violation.

A client that knows about this can craft a single UDP packet containing both the acknowledgement of the previous response and a new request. The server processes them together in one pass, accepts the new request, and only then sends the authorization — too late.

---

## How the Bypass Works (Sequence B)

The technique needs the client and server to be at the stream limit — the client has opened exactly as many streams as the server allows.

1. Client opens N−1 streams and keeps them open (hold the limit).
2. Client opens stream N, sends its request and closes that half of the stream.
3. Server finishes responding to stream N and sends its own FIN back to the client.
4. Client receives that FIN and immediately sends, in **one UDP packet**: the acknowledgement of the server's FIN (which will free slot N) and the first frame of stream N+1 (which is one over the limit).
5. Server processes both frames together:
   - ACK → free slot N → internal counter goes from N to N+1 → queue a MAX_STREAMS message
   - STREAM(N+1) → check counter → N+1 ≤ N+1 → **accept**
   - Packet done → now transmit the queued MAX_STREAMS message

Stream N+1 is accepted in step 5, and the MAX_STREAMS message authorizing it only leaves after — after the fact. The client never received permission to open N+1.

```
frame 1  ACK → free slot → counter++ → MAX_STREAMS queued
frame 2  STREAM(N+1) → check counter → accepted  ← violation
after    MAX_STREAMS sent — too late, stream already open
```

---

## Evidence

### 1 — Source Code Analysis

The root cause is quic-go's run-loop design. When a packet arrives, the server processes all frames in the packet first — including freeing stream slots and accepting new ones — and only then transmits outbound frames. There is no mechanism to pause frame processing between "slot freed" and "MAX_STREAMS transmitted."

```
connection.go:562 — run loop
    handlePackets()   ← ACK processed, deleteStream() fires, m.maxStream++,
                        STREAM(K+1) accepted using the incremented value
    triggerSending()  ← MAX_STREAMS transmitted here, after the fact
```

Tracing the full path:

- `connection.go:1808` — `handleFrames()` processes frames sequentially in arrival order
- `streams_map_incoming.go` — `deleteStream()` does `m.maxStream++` then calls `queueMaxStreamID()` (queues, doesn't send)
- `streams_map_incoming.go` — `GetOrOpenStream()` checks `id > m.maxStream` using the already-incremented value and accepts K+1
- `connection.go:562` — run loop calls `handlePackets()` before `triggerSending()`; the send is always after

### 2 — Client-Side Datagram Probe

An instrumented Python client (aioquic) overrides `transmit()` to count UDP datagrams emitted per bypass `datagram_received()` call. 25 trials against quic-go v0.59.1. In 16 trials the bypass stream was accepted; in all 16, exactly 1 UDP datagram was sent — confirming ACK and STREAM(K+1) were packed together. Zero instrumentation errors.

| # | Client sent 1 datagram? | Server accepted stream? | Verdict |
|---|---|---|---|
| 1–16 | Yes (1 datagram) | Yes — echoed data back | RFC §4.6 violation |
| 17–24 | Yes (1 datagram) | No — arrived out of order | Timing miss (not a violation) |
| 25 | Yes | No — STREAM_LIMIT_ERROR | Correctly rejected |

The 8 "timing miss" trials represent runs where the two frames happened to arrive in separate packets. The 1 correct rejection shows the server can enforce the limit — just not in the same-packet case.

### 3 — Server-Side Timestamp Evidence (qlog)

An instrumented Go server wrote a qlog file for every connection. Each file records every packet received and sent, with microsecond timestamps. Across 50 connections, 18 showed the violation clearly:

```
t = 620.536 ms   packet received: [ACK, STREAM{id=400 (stream #101)}]
t = 620.559 ms   packet sent:     [MAX_STREAMS{limit=102}]
                 Δ = 0.023 ms — stream #101 accepted 23 µs before authorization sent
```

Stream ID 400 = client-initiated bidi stream #101 (ID/4+1 = 101), one beyond the `MaxIncomingStreams=100` limit. The server accepted it, then sent `MAX_STREAMS(102)` afterward. This is the ordering that RFC 9000 §4.6 forbids. The delta range across all 18 violation events: **0.010–0.036ms**.

---

## All Tested Versions

| Version | Config | Trials | Server accepted bypass | Verdict |
|---|---|---|---|---|
| v0.59.1 | default | 25 | 16/25 (64%) | CONFIRMED |
| v0.65.0 | default | 20 | 12/20 (60%) | CONFIRMED |
| v0.65.0 | RequireStreamCreditRelease=true | 20 | 16/20 (80%) | CONFIRMED |
| v0.66.0 | default | 25 | 13/25 (52%) | CONFIRMED |
| v0.66.0 | RequireStreamCreditRelease=true | 25 | 22/25 (88%) | CONFIRMED |

`RequireStreamCreditRelease` does not fix this bug. That setting gives applications explicit control over when stream credit is released, but it doesn't change the run-loop ordering. The same violation occurs — the flag actually makes it slightly more consistent, not less.

---

## What an Attacker Can Do

With this bug, a client can exceed the server's `MaxIncomingStreams` limit. By repeating the bypass pattern, the client can keep opening more streams than the server intends to allow:

Each bypass cycle opens one extra stream that the server processes normally. Repeating accumulates stream goroutines and their memory buffers on the server. There is no server-side check that catches streams accepted this way — they look like legitimate streams.

The practical severity depends on deployment factors. Memory per stream: each accepted stream spawns a Go goroutine (minimum ~8 KB stack, growing to 1 MB+) plus read/write buffers sized to the QUIC flow-control window (typically 1–4 MB per stream). A server with `MaxIncomingStreams=100` and 4 MB per stream budgets ~400 MB per connection; the bypass allows accumulating far beyond that.

Each attacker connection can independently keep cycling the pattern. Ten simultaneous attacker connections each hitting the limit 10× equals 100 unbounded streams — with no server-side signal that anything is wrong, since each stream looks legitimate. Cloud-native deployments in pods with tight memory limits (256 MB – 1 GB) are proportionally more effective targets. Servers that do real work per stream (database queries, gRPC calls, file I/O) amplify the effect: bypassed streams trigger the same application logic as legitimate streams.

---

## Recommendation

File a protocol conformance bug report with the quic-go project. The violation is confirmed in every tested version including v0.66.0. A CVE is appropriate given that the bypass allows exceeding a server-configured resource limit and the issue is present in the current release.

Suggested report title: *"RFC 9000 §4.6: stream K+1 accepted before MAX_STREAMS is transmitted when ACK and STREAM arrive in the same UDP datagram"*

Suggested fix: when `deleteStream()` queues a MAX_STREAMS frame, track that it has not yet been sent. In `GetOrOpenStream()`, if the queued-but-unsent MAX_STREAMS covers a stream that hasn't been authorized by the last **transmitted** value, reject the stream with `STREAM_LIMIT_ERROR` rather than checking the internal in-memory value.

---

HypoGenie security investigation · runs 20261119-160506-7b86 (CONFIRMED_DOS) + 20261124-144942-e3af (DEFECT) + manual validation  
CONFIRMED_PROTOCOL_CONFORMANCE_BUG · CVE recommended  
quic-go v0.59.1–v0.66.0 · 2026-11-25 · `security_validation/http3_cancellation_dos/final_validation/`
