"""A small persistent vector store: vectors + metadata on disk, cosine-similarity search."""
import os
import pickle
import numpy as np


class VectorStore:
    def __init__(self, path: str):
        self.path, self.vectors, self.records, self.embedder = path, None, [], None

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "wb") as f:
            pickle.dump({"vectors": self.vectors, "records": self.records, "embedder": self.embedder}, f)

    def load(self) -> bool:
        if not os.path.exists(self.path):
            return False
        with open(self.path, "rb") as f:
            d = pickle.load(f)
        self.vectors, self.records, self.embedder = d["vectors"], d["records"], d["embedder"]
        return True

    def search(self, query: str, k: int = 5, language: str | None = None, category: str | None = None):
        q = self.embedder.transform([query])
        scores = self.vectors @ q.T
        scores = np.asarray(scores.todense()).ravel() if hasattr(scores, "todense") else np.asarray(scores).ravel()
        order, hits = np.argsort(scores)[::-1], []
        for i in order:
            r = self.records[i]
            if language and r["language"] not in (language, "general"):
                continue
            if category and r["category"] != category:
                continue
            if scores[i] <= 0:
                break
            hits.append({**r, "score": round(float(scores[i]), 3)})
            if len(hits) >= k:
                break
        return hits
