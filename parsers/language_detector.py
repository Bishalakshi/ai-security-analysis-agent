"""Detect whether submitted code is Python or Java (or something unsupported)."""
import re

_JAVA = [r"\bpublic\s+(static\s+)?(class|interface|enum)\b", r"\bpublic\s+static\s+void\s+main\b", r"System\.out\.print",
         r"^\s*import\s+java\.", r"^\s*package\s+[\w.]+;", r"\b(String|int|boolean|double|long)\s+\w+\s*[=;(]",
         r"\bnew\s+\w+\s*\(", r"\b(private|protected)\s+\w", r"@Override", r";\s*$"]
_PY = [r"^\s*def\s+\w+\s*\(.*\)\s*(->.*)?:", r"^\s*import\s+\w+\s*$", r"^\s*from\s+[\w.]+\s+import\s+",
       r"^\s*class\s+\w+(\(.*\))?:", r"\bprint\(", r"^\s*(if|elif|else|for|while|try|except|with)\b.*:\s*$",
       r"\bself\.", r"^\s*#.*$", r":\s*$", r"\bNone\b|\bTrue\b|\bFalse\b"]
_OTHER = {"C/C++": [r"#include\s*<", r"\bstd::", r"using\s+namespace", r"\bcout\s*<<"],
          "JavaScript": [r"\bconsole\.log\(", r"\bfunction\s+\w+\s*\(", r"=>\s*\{", r"\b(let|const)\s+\w+\s*="],
          "C#": [r"\busing\s+System", r"Console\.Write", r"\bnamespace\s+\w+"]}
EXT = {".py": "python", ".java": "java"}


def detect_language(code: str, filename: str | None = None) -> dict:
    """Returns {"language": "python"|"java"|"unsupported"|"unknown", "reason": str, "confidence": float}."""
    if filename and "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()
        if ext in EXT:
            return {"language": EXT[ext], "reason": f"file extension {ext}", "confidence": 1.0}
        return {"language": "unsupported", "reason": f"extension {ext} is not .py or .java", "confidence": 1.0}
    if not code or not code.strip():
        return {"language": "unknown", "reason": "no code provided", "confidence": 0.0}
    for lang, pats in _OTHER.items():
        if sum(bool(re.search(p, code, re.M)) for p in pats) >= 1:
            return {"language": "unsupported", "reason": f"looks like {lang}", "confidence": 0.9}
    java = sum(bool(re.search(p, code, re.M)) for p in _JAVA)
    py = sum(bool(re.search(p, code, re.M)) for p in _PY)
    braces = code.count("{") + code.count("}")
    if braces >= 2 and java >= py:
        java += 2
    if "def " in code and braces == 0:
        py += 2
    if java == py == 0:
        return {"language": "unknown", "reason": "could not recognise Python or Java", "confidence": 0.0}
    lang = "java" if java > py else "python"
    conf = round(max(java, py) / (java + py), 2)
    return {"language": lang, "reason": "keyword and syntax patterns", "confidence": conf}
