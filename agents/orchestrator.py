"""Multi-agent orchestration: Code Analysis and Security agents run in parallel (thread pool),
their outputs are merged into one unified, de-duplicated, severity-sorted findings list,
then scored (risk score, code-quality score, technical debt)."""
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List

from agents import code_analysis, security
from models.findings import AgentFinding, DEBT_MINUTES, QUALITY_PENALTY, SEVERITY_ORDER

AGENTS: Dict[str, Callable[[str, str], List[AgentFinding]]] = {
    "Code Analysis": code_analysis.run,
    "Security": security.run,
}
AGENT_LABEL = {"Code Analysis": "Code Analysis Agent", "Security": "Security Vulnerability Agent"}


@dataclass
class ReviewResult:
    language: str
    findings: List[AgentFinding] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)   # seconds per agent
    errors: Dict[str, str] = field(default_factory=dict)      # agent -> error text (one failing agent must not kill the review)
    total_seconds: float = 0.0

    @property
    def status(self) -> Dict[str, str]:
        return {a: ("Failed" if a in self.errors else "Complete") for a in self.timings}

    @property
    def by_severity(self) -> Dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {k: c.get(k, 0) for k in SEVERITY_ORDER}

    @property
    def by_agent(self) -> Dict[str, int]:
        c = Counter(f.agent for f in self.findings)
        return {k: c.get(k, 0) for k in AGENTS}

    @property
    def risk_score(self) -> float:
        """0-10 overall risk: the worst finding plus a small bonus for volume (capped)."""
        if not self.findings:
            return 0.0
        return round(min(10.0, max(f.score for f in self.findings) + min(1.0, 0.1 * len(self.findings))), 1)

    @property
    def quality_score(self) -> int:
        """0-100 code-quality assessment: 100 minus a penalty per finding (heavier for severe ones)."""
        return max(0, round(100 - sum(QUALITY_PENALTY[f.severity] for f in self.findings)))

    @property
    def technical_debt_minutes(self) -> int:
        return sum(DEBT_MINUTES[f.severity] for f in self.findings)


def _timed(name, fn, code, lang):
    t = time.perf_counter()
    try:
        return name, fn(code, lang), time.perf_counter() - t, None
    except Exception as e:                                   # isolate agent failures
        return name, [], time.perf_counter() - t, f"{type(e).__name__}: {e}"


def review(code: str, language: str, agents=None) -> ReviewResult:
    names = agents or list(AGENTS)
    t0 = time.perf_counter()
    res = ReviewResult(language)
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        futures = [pool.submit(_timed, n, AGENTS[n], code, language) for n in names]
        for fut in futures:
            name, found, secs, err = fut.result()
            res.timings[name] = round(secs, 4)
            if err:
                res.errors[name] = err
            res.findings += found
    best: Dict[tuple, AgentFinding] = {}                     # same issue type on the same line: keep the higher score
    for f in res.findings:
        f.language = language
        k = (f.type, f.line)
        if k not in best or f.score > best[k].score:
            best[k] = f
    res.findings = sorted(best.values(), key=lambda f: (SEVERITY_ORDER[f.severity], -f.score, f.line))
    for i, f in enumerate(res.findings, 1):
        f.id = f"F-{i:03d}"                                   # type: ignore[attr-defined]
    res.total_seconds = round(time.perf_counter() - t0, 4)
    return res
