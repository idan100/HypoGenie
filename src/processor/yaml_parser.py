import warnings
import yaml
from pathlib import Path
from .models import HypothesisContext, Assumption, RFCSection, ServiceSpec

VALID_DOS_CLASSES = {
    "resource_exhaustion",   # CWE-400, CWE-770, CWE-774 — connection/fd/thread pool limits
    "recursion",             # CWE-674, CWE-776 — recursive parsing, entity expansion
    "regex",                 # CWE-407, CWE-1333 — ReDoS specifically
    "memory",                # CWE-401, CWE-771, CWE-789 — memory leaks, excessive allocation
    "cpu",                   # CWE-834, CWE-1050 — CPU spin, high-rate computation
    "resource_starvation",   # CWE-410, CWE-664 — thread/lock starvation
    # ── additions ────────────────────────────────────────────────────────────
    "connection",            # CWE-400 (Slowloris/slow-drain subtype) — hold connections open
                             #   to exhaust server worker pool without completing requests
    "algorithmic_complexity",# CWE-407 (broader than regex) — hash collision, parser quadratic
                             #   blowup, JWT algorithm confusion; exploits asymmetric processing
    "decompression_bomb",    # CWE-409 — send highly compressed payloads (gzip/zlib/brotli)
                             #   that expand 100–1000× on the server, exhausting memory/CPU
    "infinite_loop",         # CWE-835 — crafted protocol messages that trap the server in a
                             #   loop with no reachable exit condition; different from cpu
                             #   (high-rate) because a single message suffices
    "disk_exhaustion",       # CWE-779 — trigger excessive logging or file writes to fill the
                             #   server's disk, causing crashes or write failures
    "resource_lifecycle",    # CWE-401, CWE-772 — resource not properly released on connection
                             #   teardown or cancellation; accumulates across requests
    "missing_throttling",    # CWE-770, CWE-307 — absent rate limit on a computationally
                             #   expensive operation; attacker can invoke it without bound
    "state_machine_abuse",   # CWE-706, CWE-394 — crafted message sequence drives the server
                             #   state machine to unexpected states, consuming CPU or memory
    "excessive_iteration",   # CWE-834, CWE-400 — attacker-controlled input causes the server
                             #   to iterate N times proportional to input size with no cap
}

VALID_NECESSITY = {"required", "favorable"}

# Canonical protocol identifiers used throughout the pipeline for skeleton
# injection, control-test selection, and validator rules.
_KNOWN_PROTOCOLS = {
    "HTTP/2", "gRPC", "QUIC", "DNS-over-TLS", "DNS/TLS", "DNS-over-QUIC", "MQTT", "TCP",
}

# Lowercase alias → canonical.  Applied before the unknown-protocol warning so
# common case-variations and abbreviations normalise silently.
_PROTOCOL_ALIASES: dict[str, str] = {
    "http/2":     "HTTP/2",
    "http2":      "HTTP/2",
    "h2":         "HTTP/2",
    "grpc":       "gRPC",
    "grpc/http2": "gRPC",
    "grpc/h2":    "gRPC",
    "quic":       "QUIC",
    "quic/http3": "QUIC",
    "http/3":     "QUIC",
    "h3":         "QUIC",
    "dns-over-tls": "DNS-over-TLS",
    "dot":        "DNS-over-TLS",
    "dns-over-quic": "DNS-over-QUIC",
    "doq":        "DNS-over-QUIC",
    "dns/tls":    "DNS/TLS",
    "mqtt":       "MQTT",
    "amqp":       "TCP",
    "amqp 1.0":   "TCP",
    "amqp1.0":    "TCP",
    "tcp":        "TCP",
    # HTTP/1.x and raw TLS map to TCP — no h2/QUIC skeleton injection applies
    "http/1.1":   "TCP",
    "http/1":     "TCP",
    "http1":      "TCP",
    "http1.1":    "TCP",
    "tls":        "TCP",
    "ssl":        "TCP",
    "tls/tcp":    "TCP",
}


def parse(yaml_path: str) -> HypothesisContext:
    """Load and validate a hypothesis YAML file; return HypothesisContext."""
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"YAML file not found: {yaml_path}")

    with open(path, "r") as f:
        data = yaml.safe_load(f)

    # ── hypothesis ─────────────────────────────────────────────────────────────
    hyp = data.get("hypothesis", {})
    description = hyp.get("description", "").strip()
    if not description:
        raise ValueError("hypothesis.description is required")

    dos_class = hyp.get("dos_class", "").strip()
    if dos_class not in VALID_DOS_CLASSES:
        raise ValueError(
            f"hypothesis.dos_class must be one of {VALID_DOS_CLASSES}, got {dos_class!r}"
        )

    # ── target ─────────────────────────────────────────────────────────────────
    tgt = data.get("target", {})
    repo_url = tgt.get("repo", "").strip()
    if not repo_url:
        raise ValueError("target.repo is required")
    version = str(tgt.get("version", "")).strip()
    if not version:
        raise ValueError("target.version is required")
    protocol_raw = tgt.get("protocol", "").strip()
    if not protocol_raw:
        raise ValueError("target.protocol is required")
    protocol = _PROTOCOL_ALIASES.get(protocol_raw.lower(), protocol_raw)
    if protocol not in _KNOWN_PROTOCOLS:
        warnings.warn(
            f"target.protocol {protocol_raw!r} is not a known protocol; "
            f"skeleton injection, control tests, and validator rules will not apply. "
            f"Known protocols: {sorted(_KNOWN_PROTOCOLS)}",
            stacklevel=2,
        )
    entry_point = tgt.get("entry_point", "").strip()
    if not entry_point:
        raise ValueError("target.entry_point is required")

    # ── assumptions ────────────────────────────────────────────────────────────
    assumptions = []
    for raw in data.get("assumptions", []):
        aid = raw.get("id", "").strip()
        adesc = raw.get("description", "").strip()
        anec = raw.get("necessity", "required").strip()
        if not aid:
            raise ValueError("Each assumption must have an id")
        if anec not in VALID_NECESSITY:
            raise ValueError(
                f"assumption necessity must be 'required' or 'favorable', got {anec!r}"
            )
        assumptions.append(Assumption(id=aid, description=adesc, necessity=anec))

    # ── rfc_sections ───────────────────────────────────────────────────────────
    rfc_sections = []
    for raw in data.get("rfc_sections", []):
        rfc = raw.get("rfc", "").strip()
        section = str(raw.get("section", "")).strip()
        relevance = raw.get("dos_relevance", "").strip()
        if not rfc or not section:
            raise ValueError("Each rfc_sections entry must have rfc and section")
        rfc_sections.append(RFCSection(rfc=rfc, section=section, dos_relevance=relevance))

    # ── related_work ───────────────────────────────────────────────────────────
    related_work = data.get("related_work", [])

    docker_image = tgt.get("docker_image", None)
    server_config = tgt.get("server_config", "") or ""

    # ── services (multi-container topology) ────────────────────────────────────
    services_raw = tgt.get("services", []) or []
    services: list[ServiceSpec] = []
    if services_raw:
        for i, svc in enumerate(services_raw):
            if not isinstance(svc, dict):
                raise ValueError(f"target.services[{i}] must be a mapping")
            svc_name = str(svc.get("name", "")).strip()
            svc_image = str(svc.get("docker_image", "")).strip()
            svc_role = str(svc.get("role", "")).strip()
            if not svc_name:
                raise ValueError(f"target.services[{i}] is missing 'name'")
            if not svc_image:
                raise ValueError(f"target.services[{i}] ({svc_name!r}) is missing 'docker_image'")
            if not svc_role:
                raise ValueError(f"target.services[{i}] ({svc_name!r}) is missing 'role'")
            raw_cmd = svc.get("command", []) or []
            if isinstance(raw_cmd, str):
                raw_cmd = [raw_cmd]
            services.append(ServiceSpec(
                name=svc_name,
                docker_image=svc_image,
                role=svc_role,
                server_config=str(svc.get("server_config", "") or ""),
                command=list(raw_cmd),
                env_vars=dict(svc.get("env", {}) or {}),
                ports=str(svc.get("ports", "") or ""),
            ))
        target_roles = [s for s in services if s.role == "target"]
        if len(target_roles) != 1:
            raise ValueError(
                f"target.services must have exactly one entry with role=target, "
                f"got {len(target_roles)}"
            )

    # ── suspected_mechanism ────────────────────────────────────────────────────
    # list of {step: int, action: str} dicts; silently ignored if absent or malformed
    suspected_mechanism = []
    for raw in data.get("suspected_mechanism", []):
        if isinstance(raw, dict):
            suspected_mechanism.append(raw)

    # ── validation ─────────────────────────────────────────────────────────────
    # Optional block; only validation.resource_lifecycle.mode is consumed currently.
    # Defaults to mode="auto" so existing YAMLs without the block are unaffected.
    validation_raw = data.get("validation", {}) or {}
    rl = validation_raw.get("resource_lifecycle", {}) or {}
    mode = str(rl.get("mode", "auto")).strip()
    if mode not in ("auto", "enabled", "disabled"):
        mode = "auto"
    validation = {"resource_lifecycle": {"mode": mode}}

    return HypothesisContext(
        description=description,
        dos_class=dos_class,
        repo_url=repo_url,
        version=version,
        protocol=protocol,
        entry_point=entry_point,
        assumptions=assumptions,
        rfc_sections=rfc_sections,
        related_work=related_work,
        docker_image=docker_image,
        server_config=server_config,
        services=services,
        suspected_mechanism=suspected_mechanism,
        validation=validation,
    )
