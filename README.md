# AI Code Review & Security Analysis Agent - Milestone 2

Milestone 1: code submission (paste / upload `.py` `.java`), language detection, syntax gatekeeper, secure-coding knowledge base (RAG).
Milestone 2: **Code Analysis Agent** + **Security Vulnerability Agent**, run in parallel and merged into one scored report.

## Run it (Windows PowerShell or any terminal, from this folder)
```
python -m venv venv
venv\Scripts\activate            # Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python -m rag.ingestion          # builds the knowledge-base index (about 1,475 chunks)
pytest -q                        # 47 tests should pass
python evaluation/evaluate.py    # accuracy validation -> docs/validation_report.md
streamlit run ui/app.py          # opens http://localhost:8501
```
Step-by-step demo script with expected results: `docs/MILESTONE2_GUIDE.md`.

## Workflow (Milestone 2)
```
Stage 1  Developer submits code (paste or .py / .java upload)
Stage 2  Auto language detection + syntax gatekeeper      -> invalid syntax: pipeline blocked, exact line highlighted
Stage 3  Orchestrator starts both agents in parallel (thread pool)
           |-- Code Analysis Agent      (complexity, smells, anti-patterns)      Python: ast   Java: javalang
           '-- Security Vulnerability Agent (taint tracking + OWASP / CWE rules)
Stage 4  Fan-in: merge, de-duplicate, sort by severity score
Stage 5  Scoring: severity pyramid (Critical / High / Medium / Low / Informational),
         risk score 0-10, code-quality score 0-100, technical debt (hours)
Stage 6  Dashboard report: findings with rule id, evidence, OWASP / CWE, remediation; RAG guideline per finding; JSON export
```
Design details: `docs/milestone2_design.md`. Accuracy results and limitations: `docs/validation_report.md`.

## Structure
- `agents/` `code_analysis.py`, `security.py`, `orchestrator.py`, `common.py`
- `models/` `submission.py` (Milestone 1), `findings.py` (unified finding, severity bands)
- `knowledge_base/` OWASP Top 10:2025, OWASP cheat sheets, PEP 8/257/20, Google style guides, original Python/Java security and quality guides (`sources.md` lists sources and licences)
- `parsers/` language detector, Python validator (compile), Java validator (javalang)
- `rag/` loader, chunking, embeddings (TF-IDF or sentence-transformers), vector store, ingestion, retriever
- `samples/`, `samples_holdout/` labelled Python / Java code (`EXPECT:` comments mark the known issues)
- `evaluation/` accuracy script (precision / recall) and `results.json`
- `ui/app.py` dashboard, `utils/`, `tests/`, `test_files/`
- `agile_docs/` Agile template, unit test plan and defect tracker (Milestone 1 and Milestone 2)

Optional better semantic search: `pip install sentence-transformers`, then choose it in the sidebar and re-index.
