"""Embedding backends: TF-IDF (offline, instant) or sentence-transformers (semantic)."""
import numpy as np

BACKENDS = ["TF-IDF (offline)", "Sentence-Transformers (semantic)"]


class Embedder:
    def __init__(self, backend: str = BACKENDS[0]):
        self.backend, self.model = backend, None
        if backend.startswith("Sentence"):
            from sentence_transformers import SentenceTransformer   # raises ImportError if missing
            self.model = SentenceTransformer("all-MiniLM-L6-v2")
        else:
            from sklearn.feature_extraction.text import TfidfVectorizer
            self.model = TfidfVectorizer(stop_words="english", sublinear_tf=True, ngram_range=(1, 2), max_features=60000)

    def fit_transform(self, texts):
        if self.backend.startswith("Sentence"):
            return np.asarray(self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False))
        return self.model.fit_transform(texts)          # sparse, L2-normalised by default

    def transform(self, texts):
        if self.backend.startswith("Sentence"):
            return np.asarray(self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False))
        return self.model.transform(texts)
