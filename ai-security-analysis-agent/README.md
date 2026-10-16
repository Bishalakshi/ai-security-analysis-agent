# AI Code Review & Security Analysis Agent - Milestone 1

Code Submission Module + Secure Coding Knowledge Base (RAG) with a Streamlit dashboard.

## Run it (Windows PowerShell or any terminal, from this folder)
```
python -m venv venv
venv\Scripts\activate            # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python -m rag.ingestion          # builds the knowledge-base index (about 1,475 chunks)
pytest -q                        # 22 tests should pass
streamlit run ui/app.py          # opens http://localhost:8501
```
In the dashboard: click **Index Knowledge Base** (sidebar) once, then paste code or upload a file
from `test_files/` (correct / wrong / vulnerable, Python and Java).

## Structure
- `knowledge_base/` OWASP Top 10:2025, OWASP cheat sheets, PEP 8/257/20, Google style guides, original Python/Java security and quality guides (`sources.md` lists sources and licences)
- `parsers/` language detector, Python validator (compile), Java validator (javalang)
- `rag/` loader, chunking, embeddings (TF-IDF or sentence-transformers), vector store, ingestion, retriever
- `ui/app.py` dashboard, `models/`, `utils/`, `tests/`, `test_files/`
- `agile_docs/` Agile template, unit test plan and defect tracker for Milestone 1

Optional better semantic search: `pip install sentence-transformers`, then choose it in the sidebar and re-index.
