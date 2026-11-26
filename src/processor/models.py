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
class ServiceSpec:
    name: str              # container hostname on the shared Docker network
    docker_image: str
    role: str              # "target" = DoS target (CPU measured, ports exposed); any other = supporting
    server_config: str = ""             # config hint passed to Setup Developer LLM (target only)
    command: list[str] = field(default_factory=list)        # overrides Docker CMD if non-empty
    env_vars: dict[str, str] = field(default_factory=dict)  # additional env vars
    ports: str = ""        # space-separated "host:container/proto" mappings, e.g. "18080:8080/tcp"


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
    docker_image: Optional[str] = None   # single-container override; ignored when services is set
    server_config: str = ""              # single-container config hint; ignored when services is set
    # multi-container topology; when non-empty, docker_image and server_config are ignored
    services: list[ServiceSpec] = field(default_factory=list)
    # list[dict] from YAML suspected_mechanism block (step + action keys)
    suspected_mechanism: list[dict] = field(default_factory=list)
    # validation.resource_lifecycle.mode: "auto" | "enabled" | "disabled"
    validation: dict = field(default_factory=dict)

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
