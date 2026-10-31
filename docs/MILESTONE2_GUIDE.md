# Milestone 2 - step-by-step execution guide

Goal of the milestone: a **Code Analysis Agent** and a **Security Vulnerability Agent** that run in parallel, their findings merged
into one report, and detection accuracy validated on sample Python and Java code with known issues.
All numbers below come from real runs of this repository.

## Step 0 - set up (once)
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m rag.ingestion          # {'status': 'ok', 'docs_loaded': 43, 'chunks_created': 1475, ...}
```

## Step 1 - run all tests          **[Screenshot 1: terminal]**
```
pytest -q
```
Expected: `47 passed` (22 from Milestone 1 + 25 new: agents, orchestrator, accuracy gate, dashboard).
Useful extra shots: `pytest -q tests/test_agents.py -k "parallel or failing"` shows parallel execution and failure isolation.

## Step 2 - start the dashboard
```
streamlit run ui/app.py
```
In the sidebar click **Index Knowledge Base** (needed only for the "Retrieved guidelines" tab).

## Step 3 - demo the syntax gatekeeper (Milestone 1 behaviour still works)     **[Screenshot 2]**
Upload `test_files/wrong.py` -> red error on line 3, the **Validate Code & Run Analysis Agents** button stays disabled.
The agents never run on code that does not parse.

## Step 4 - run the agents on vulnerable code
Upload the file, then press **Validate Code & Run Analysis Agents**.

| Demo file | Findings | Severity mix | Risk | Quality | Tech debt |
|---|---|---|---|---|---|
| `test_files/vulnerable.py` | 9 (3 Code Analysis, 6 Security) | 5 High, 1 Medium, 1 Low, 2 Info | 9.7/10 | 54/100 | 5h 55m |
| `test_files/Vulnerable.java` | 10 (6 Code Analysis, 4 Security) | 3 High, 1 Medium, 3 Low, 3 Info | 9.8/10 | 66/100 | 4h 30m |
| `samples/python/vulnerable_flask_app.py` | 21 | 8 Critical, 7 High, 5 Medium, 1 Info | 10.0/10 | 0/100 | 25h 35m |
| `samples/java/UserServlet.java` | 17 | 2 Critical, 5 High, 3 Medium, 2 Low, 5 Info | 10.0/10 | 12/100 | 11h 25m |

What to show on screen **[Screenshot 3: findings, Screenshot 4: agent status]**:
* the two status lines `Code Analysis Agent - Complete` and `Security Vulnerability Agent - Complete` with timings (agents ran in parallel);
* the metric cards (risk, quality, technical debt, findings) and the severity counts;
* an expanded finding: rule id (for example `PY-SQL-INJECTION`), line, OWASP 2025 category, CWE, evidence, suggested remediation;
* **Code view with line numbers** - flagged lines are coloured by severity (hover shows the finding);
* tab **Retrieved guidelines (RAG)** - the knowledge-base passage matched to each finding type;
* **Export findings (JSON)**.

## Step 5 - code-smell demo (Code Analysis Agent only)       **[Screenshot 5]**
`samples/python/legacy_report_generator.py` -> 27 findings (10 Medium, 16 Low, 1 Info), all from the Code Analysis Agent:
long parameter list, mutable default, high complexity, deep nesting, long function, bare / empty / broad except, duplicate code, god class.
`samples/java/LegacyInventory.java` -> 20 findings.

## Step 6 - clean code demo (no false alarms)
`samples/python/secure_service.py` -> 0 findings, quality 100/100.

## Step 7 - accuracy validation         **[Screenshot 6: terminal, Screenshot 7: docs/validation_report.md]**
```
python evaluation/evaluate.py
```
Prints precision / recall per agent on `samples_holdout/` (first, realistic) and `samples/` (tuning set), with every miss and
false positive listed. Current held-out result: Code Analysis 92% precision / 100% recall, Security 100% / 100%.
Read the "Honest limitations" section of the report before presenting - small sample set, rule-based detection.

## Step 8 - show the documents
* `README.md` - 6-stage workflow, structure, run commands
* `docs/milestone2_design.md` - agents, scoring model, finding schema
* `agile_docs/*Milestone2*` - Agile template, unit test plan, defect tracker

## Suggested screenshot list (same style as your peers)
1. `pytest -q` -> 47 passed
2. Syntax error blocks the pipeline (wrong.py)
3. Dashboard: agent status + metrics + findings for `vulnerable.py`
4. Expanded finding with evidence and remediation
5. Java result (`Vulnerable.java`) with `JAVA-HARDCODED-SECRET` and `JAVA-SQL-INJECTION`
6. Code view with coloured flagged lines
7. `python evaluation/evaluate.py` output
8. VS Code: `agents/` folder (`code_analysis.py`, `security.py`, `orchestrator.py`) and README workflow
9. The three Excel files (backlog, unit test plan, defect tracker)
