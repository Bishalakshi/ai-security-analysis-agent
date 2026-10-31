"""Unified finding model produced by every analysis agent (Milestone 2)."""
from dataclasses import dataclass, asdict
from typing import Optional

# 5-tier severity pyramid
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
DEBT_MINUTES = {"CRITICAL": 120, "HIGH": 60, "MEDIUM": 30, "LOW": 15, "INFORMATIONAL": 5}   # estimated fix effort
QUALITY_PENALTY = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1.5, "INFORMATIONAL": 0.5}


def band(score: float) -> str:
    """CVSS-style bands: 9-10 critical, 7-8.9 high, 4-6.9 medium, 2-3.9 low, below 2 informational."""
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score >= 2 else "INFORMATIONAL"


@dataclass
class AgentFinding:
    agent: str                 # "Code Analysis" | "Security"
    type: str                  # e.g. SQL_INJECTION, HIGH_COMPLEXITY
    title: str
    line: int                  # 1-based, where the issue is flagged
    score: float               # 0-10
    message: str               # explanation
    category: str = "quality"  # quality | style | security
    snippet: str = ""          # evidence
    end_line: Optional[int] = None
    owasp: str = ""            # e.g. "A05:2025 Injection"
    cwe: str = ""              # e.g. "CWE-89"
    tainted: bool = False      # user-controlled data reaches the sink
    fix_hint: str = ""         # suggested remediation
    scored: bool = True        # counted in accuracy validation (style-tier findings are not)
    language: str = ""
    confidence: str = "High"   # High = confirmed pattern, Medium = potential risk

    @property
    def severity(self) -> str:
        return band(self.score)

    @property
    def rule_id(self) -> str:
        return f"{'PY' if self.language == 'python' else 'JAVA'}-{self.type.replace('_', '-')}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(severity=self.severity, rule_id=self.rule_id)
        return d
