from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Submission:
    code: str
    language: str
    source: str = "paste"            # "paste" | "upload"
    filename: str | None = None
    is_valid: bool = False
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class KBHit:
    source: str
    title: str
    category: str
    language: str
    score: float
    text: str
