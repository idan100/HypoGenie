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
    protocol = tgt.get("protocol", "").strip()
    if not protocol:
        raise ValueError("target.protocol is required")
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
    )
