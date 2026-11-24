import warnings
import yaml
from pathlib import Path
from .models import HypothesisContext, Assumption, RFCSection

VALID_DOS_CLASSES = {
    "resource_exhaustion",
    "recursion",
    "regex",
    "memory",
    "cpu",
    "resource_starvation",
}

VALID_NECESSITY = {"required", "favorable"}

# Canonical protocol identifiers used throughout the pipeline for skeleton
# injection, control-test selection, and validator rules.
_KNOWN_PROTOCOLS = {
    "HTTP/2", "gRPC", "QUIC", "DNS-over-TLS", "DNS/TLS", "MQTT", "TCP",
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
    "dns/tls":    "DNS/TLS",
    "mqtt":       "MQTT",
    "amqp":       "TCP",
    "amqp 1.0":   "TCP",
    "amqp1.0":    "TCP",
    "tcp":        "TCP",
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
        suspected_mechanism=suspected_mechanism,
        validation=validation,
    )
