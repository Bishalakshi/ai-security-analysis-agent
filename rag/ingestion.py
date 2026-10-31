"""Build the knowledge-base index: load -> chunk -> embed -> store."""
import os
from collections import Counter
from rag.loader import load_documents
from rag.chunking import split_documents
from rag.embeddings import Embedder, BACKENDS
from rag.vector_store import VectorStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KB_DIR = os.path.join(ROOT, "knowledge_base")


def index_path(backend: str) -> str:
    return os.path.join(ROOT, "data", "kb_index_" + ("sbert" if backend.startswith("Sentence") else "tfidf") + ".pkl")


def ingest_knowledge_base(kb_dir: str = KB_DIR, backend: str = BACKENDS[0]) -> dict:
    docs = load_documents(kb_dir)
    if not docs:
        return {"status": "empty", "docs_loaded": 0, "chunks_created": 0, "files": []}
    chunks = split_documents(docs)
    store = VectorStore(index_path(backend))
    store.embedder = Embedder(backend)
    store.vectors = store.embedder.fit_transform([c["text"] for c in chunks])
    store.records = chunks
    store.save()
    return {"status": "ok", "backend": backend, "docs_loaded": len(docs), "chunks_created": len(chunks),
            "by_category": dict(Counter(d["category"] for d in docs)), "by_language": dict(Counter(d["language"] for d in docs)),
            "files": sorted(d["source"] for d in docs)}


if __name__ == "__main__":
    r = ingest_knowledge_base()
    print({k: v for k, v in r.items() if k != "files"})
