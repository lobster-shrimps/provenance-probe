"""Evidence model for fleet findings — tiers, classification, and the record.

Evidence tiers separate what we actually observed (Codex #4: "configured" is not
"effective traffic path"). The wedge only produces CONFIGURED evidence (reading
config files / env); ACTIVE_PROCESS and OBSERVED are B-phase but the field exists
so a finding never overstates what it rests on.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- Evidence tiers (weakest to strongest) ---------------------------------- #
CONFIGURED = "configured"          # found in a config file / env var (may be stale)
ACTIVE_PROCESS = "active-process"  # a running process is using it (B-phase)
OBSERVED = "observed"              # observed egress on the wire (B-phase)
IMPORTED_LOG = "imported-log"      # a log the operator handed over; not a socket table

# --- Classification states (exhaustive) ------------------------------------- #
SANCTIONED = "sanctioned"                          # on the allowlist
OFF_ALLOWLIST_ATTRIBUTED = "off-allowlist-attributed"
OFF_ALLOWLIST_UNATTRIBUTED = "off-allowlist-unattributed"
AGGREGATOR_UNRESOLVABLE = "aggregator-unresolvable"
GATEWAY_UPSTREAM_UNRESOLVED = "gateway-upstream-unresolved"


@dataclass(frozen=True)
class Attribution:
    """A SUB-CONFIRMED static-lookup pointer, NEVER a measured provenance verdict.

    `operator`/`origin` come from the bundled corpus.py endpoint intelligence; a
    domain match tells you who a host is *registered to*, not what model actually
    served (that needs a tokenizer fingerprint). `measured` is always False here
    to keep "two verdicts, never collapse them" honest (guardrail 2).
    """
    operator: str
    origin: str                     # e.g. "PRC", "PRC-operator", "US", "EU"
    confidence: float               # from corpus.py; 0..1
    source: str = "corpus"
    measured: bool = False          # invariant: registry attribution is never measured


@dataclass(frozen=True)
class Finding:
    """One discovered endpoint and how it was classified."""
    source: str                     # where found, e.g. "~/.codex/config.toml" or "env:OPENAI_BASE_URL"
    base_url: str                   # the raw configured base_url
    host: str                       # parsed hostname (or "" if unparseable)
    evidence_tier: str              # CONFIGURED / ...
    classification: str             # SANCTIONED / ...
    via_gateway: str = ""           # gateway name if this upstream was resolved through one
    attribution: Attribution | None = None
    notes: list[str] = field(default_factory=list)
    client: str = ""                # workstation or id.orig_h, when a log row had one
    seen_at: str = ""               # row timestamp, when the log had one


@dataclass(frozen=True)
class ScanResult:
    """The private local report payload."""
    findings: list[Finding]
    sanctioned: int
    drifted: int                    # anything not sanctioned
    unresolved: int                 # gateway-upstream-unresolved + aggregator-unresolvable
    unattributed_names: int = 0     # unique log names with no corpus hit; not findings

    @property
    def headline(self) -> str:
        total = self.sanctioned + self.drifted
        line = (f"allowlist holding: {self.sanctioned}/{total} sanctioned, "
                f"{self.drifted} drifted ({self.unresolved} unresolved)")
        if self.unattributed_names:
            line += f"; {self.unattributed_names} unattributed names"
        return line
