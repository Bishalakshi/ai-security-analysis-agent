import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from rag.ingestion import ingest_knowledge_base
from rag.retriever import Retriever
from rag.chunking import split_text
from rag.loader import parse_front_matter

TF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_files")


@pytest.fixture(scope="module")
def retriever():
    info = ingest_knowledge_base()
    assert info["status"] == "ok" and info["chunks_created"] > 100
    return Retriever()

def test_front_matter_parsed():
    meta, body = parse_front_matter('---\ntitle: "T"\nlanguage: "java"\n---\n\nHello')
    assert meta["language"] == "java" and body.strip() == "Hello"

def test_chunks_are_bounded():
    chunks = split_text(("word " * 200 + "\n\n") * 10, size=900)
    assert chunks and all(len(c) <= 1100 for c in chunks)

def test_sql_injection_query(retriever):
    top = retriever.search("how to prevent SQL injection", 3)
    assert any("SQL" in h["title"] or "Injection" in h["title"] for h in top)

def test_language_filter(retriever):
    hits = retriever.search("code style naming conventions", 5, language="java")
    assert hits and all(h["language"] in ("java", "general") for h in hits)

def test_python_quality_doc_found(retriever):
    hits = retriever.search("PEP 8 naming conventions snake_case", 3, language="python")
    assert any(h["source"].startswith("python/") for h in hits)

def test_vulnerable_python_patterns(retriever):
    code = open(os.path.join(TF, "vulnerable.py")).read()
    labels = {i["issue"] for i in retriever.analyze_code(code, "python")}
    assert {"Hardcoded secret", "Weak hash function", "SQL built from strings"} <= labels

def test_vulnerable_java_patterns(retriever):
    code = open(os.path.join(TF, "Vulnerable.java")).read()
    labels = {i["issue"] for i in retriever.analyze_code(code, "java")}
    assert {"SQL built from strings", "Weak hash function", "Hardcoded secret", "Possible OS command injection"} <= labels
