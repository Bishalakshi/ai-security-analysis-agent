"""Retrieve guidance for a question, or for risky patterns found in submitted code."""
import re
from rag.embeddings import BACKENDS
from rag.ingestion import index_path
from rag.vector_store import VectorStore

# (regex, label, retrieval query). Heuristic hints only - the full analysis agents come in Milestone 2.
PATTERNS = {
    "python": [
        (r"\b(eval|exec)\s*\(", "Use of eval()/exec()", "code injection eval exec untrusted input"),
        (r"pickle\.loads?\(|yaml\.load\(|marshal\.loads?\(", "Unsafe deserialization", "insecure deserialization untrusted data"),
        (r"os\.system\(|os\.popen\(|shell\s*=\s*True", "Possible OS command injection", "OS command injection prevention"),
        (r"(execute|executemany)\(\s*(f[\"']|[\"'].*[\"']\s*(\+|%))|SELECT .*['\"]\s*\+", "SQL built from strings", "SQL injection prevention parameterized queries"),
        (r"(password|passwd|secret|api_?key|token)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded secret", "hardcoded secrets credentials management"),
        (r"hashlib\.(md5|sha1)\(", "Weak hash function", "password storage hashing algorithm"),
        (r"verify\s*=\s*False", "TLS verification disabled", "cryptographic failures TLS certificate validation"),
        (r"except\s*:\s*(pass)?|except\s+Exception\s*:\s*pass", "Broad/silent exception handling", "error handling exceptional conditions"),
        (r"def\s+\w+\(.*=\s*(\[\]|\{\})", "Mutable default argument", "mutable default arguments python code quality"),
        (r"\bdebug\s*=\s*True", "Debug mode enabled", "security misconfiguration debug mode"),
    ],
    "java": [
        (r"createStatement\(|Statement\s+\w+\s*=|executeQuery\(.*\+|\"\s*\+\s*\w+.*(SELECT|WHERE)|(SELECT|WHERE).*\"\s*\+", "SQL built from strings", "SQL injection prevention PreparedStatement"),
        (r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder", "Possible OS command injection", "OS command injection prevention"),
        (r"ObjectInputStream|readObject\(", "Unsafe deserialization", "Java deserialization untrusted data"),
        (r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", "Weak hash function", "password storage hashing algorithm"),
        (r"new\s+Random\(", "Predictable random numbers", "Java SecureRandom cryptographic randomness"),
        (r"(password|passwd|secret|apiKey|token)\s*=\s*\"[^\"]+\"", "Hardcoded secret", "hardcoded secrets credentials management"),
        (r"printStackTrace\(\)", "Stack trace printed", "error handling information leakage"),
        (r"catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)\s*\{\s*\}", "Empty catch block", "error handling exceptional conditions"),
        (r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory", "XML parser (check XXE)", "XML external entity XXE Java"),
        (r"\"[^\"]*\"\s*==\s*\w+|\w+\s*==\s*\"[^\"]*\"", "String compared with ==", "Java string equals comparison code quality"),
    ],
}


class Retriever:
    def __init__(self, backend: str = BACKENDS[0]):
        self.store = VectorStore(index_path(backend))
        self.ready = self.store.load()

    def search(self, query, k=5, language=None, category=None):
        return self.store.search(query, k, language, category) if self.ready else []

    def analyze_code(self, code: str, language: str, k: int = 2):
        """Find risky patterns line by line and fetch matching guidance for each."""
        found, lines = [], code.splitlines()
        for rx, label, query in PATTERNS.get(language, []):
            hit_lines = [i + 1 for i, ln in enumerate(lines) if re.search(rx, ln, re.I)]
            if hit_lines:
                found.append({"issue": label, "lines": hit_lines[:8], "query": query,
                              "guidance": self.search(query, k, language)})
        return found
