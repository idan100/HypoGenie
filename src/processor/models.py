from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Assumption:
    id: str
    description: str
    necessity: str  # "required" | "favorable"


@dataclass
class RFCSection:
    rfc: str
    section: str
    dos_relevance: str


@dataclass
class HypothesisContext:
    description: str
    dos_class: str
    repo_url: str
    version: str
    protocol: str
    entry_point: str
    assumptions: list[Assumption] = field(default_factory=list)
    rfc_sections: list[RFCSection] = field(default_factory=list)
    related_work: list[dict] = field(default_factory=list)
    docker_image: Optional[str] = None   # optional override; skips Hub pull + source build

    def __str__(self):
        lines = [
            f"HypothesisContext(",
            f"  description={self.description[:80]!r}...",
            f"  dos_class={self.dos_class!r}",
            f"  repo_url={self.repo_url!r}",
            f"  version={self.version!r}",
            f"  protocol={self.protocol!r}",
            f"  entry_point={self.entry_point!r}",
            f"  assumptions=[{', '.join(a.id for a in self.assumptions)}]",
            f"  rfc_sections=[{', '.join(r.rfc + ' §' + r.section for r in self.rfc_sections)}]",
            f"  related_work={len(self.related_work)} items",
            f")",
        ]
        return "\n".join(lines)
