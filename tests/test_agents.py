import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest  # noqa: E402
from agents import review  # noqa: E402
from agents import code_analysis, security  # noqa: E402

types = lambda fs: {f.type for f in fs}  # noqa: E731


def sec(code, lang="python"):
    return security.run(code, lang)


# ---------------- Code Analysis Agent
def test_python_complexity_and_nesting():
    code = "def f(a):\n" + "".join("    " * (i + 1) + f"if a > {i}:\n" for i in range(6)) + "    " * 7 + "return a\n"
    t = types(code_analysis.run(code, "python"))
    assert "DEEP_NESTING" in t and "HIGH_COMPLEXITY" not in t
    many = "def g(x):\n" + "".join(f"    if x == {i}:\n        return {i}\n" for i in range(12)) + "    return -1\n"
    assert "HIGH_COMPLEXITY" in types(code_analysis.run(many, "python"))


def test_python_smells():
    code = "import os\ndef f(a, items=[]):\n    try:\n        pass\n    except:\n        pass\n"
    t = types(code_analysis.run(code, "python"))
    assert {"UNUSED_IMPORT", "MUTABLE_DEFAULT", "BARE_EXCEPT", "EMPTY_EXCEPT"} <= t


def test_java_smells():
    code = 'import java.util.*;\npublic class A {\n  public int x;\n  boolean f(String s) {\n    try { g(); } catch (Exception e) { }\n    return s == "a";\n  }\n}\n'
    t = types(code_analysis.run(code, "java"))
    assert {"WILDCARD_IMPORT", "PUBLIC_FIELD", "EMPTY_EXCEPT", "STRING_EQUALITY"} <= t


def test_severity_scores_follow_metric_size():
    small = code_analysis.run("def f(a):\n" + "".join(f"    if a == {i}:\n        return {i}\n" for i in range(11)), "python")
    big = code_analysis.run("def f(a):\n" + "".join(f"    if a == {i}:\n        return {i}\n" for i in range(25)), "python")
    s1 = max(f.score for f in small if f.type == "HIGH_COMPLEXITY"); s2 = max(f.score for f in big if f.type == "HIGH_COMPLEXITY")
    assert s2 > s1


# ---------------- Security Agent
def test_sql_injection_tainted_is_critical():
    code = 'def v(request, cur):\n    n = request.args.get("n")\n    cur.execute("SELECT * FROM t WHERE n=\'" + n + "\'")\n'
    f = [x for x in sec(code) if x.type == "SQL_INJECTION"][0]
    assert f.tainted and f.severity == "CRITICAL" and f.line == 3 and f.cwe == "CWE-89"


def test_parameterised_query_is_not_flagged():
    code = 'def v(request, cur):\n    n = request.args.get("n")\n    cur.execute("SELECT * FROM t WHERE n = ?", (n,))\n'
    assert "SQL_INJECTION" not in types(sec(code))


def test_sanitised_input_is_not_flagged():
    code = 'import os\ndef v(request):\n    host = request.args.get("h")\n    os.system("ping " + shlex.quote(host))\n'
    assert "COMMAND_INJECTION" not in types(sec(code))


def test_comments_and_string_words_do_not_trigger():
    code = '# password = "hunter2"\nx = "cur.execute(\'SELECT * FROM t\' + y)"\n'
    assert not sec(code)


def test_java_taint_through_variable():
    code = 'class A { void f(javax.servlet.http.HttpServletRequest request, java.sql.Statement st) throws Exception {\n String n = request.getParameter("n");\n String q = "SELECT * FROM t WHERE n=\'" + n + "\'";\n st.executeQuery(q);\n}}'
    f = [x for x in sec(code, "java") if x.type == "SQL_INJECTION"]
    assert f and f[0].line == 4 and f[0].tainted


def test_java_secure_code_is_clean():
    code = 'class A { void f(java.sql.Connection c, String n) throws Exception {\n var p = c.prepareStatement("SELECT * FROM t WHERE n = ?");\n p.setString(1, n);\n}}'
    assert not sec(code, "java")


def test_owasp_and_cwe_mapping_present():
    f = sec('import hashlib\nh = hashlib.md5(b"x")\n')[0]
    assert f.owasp.startswith("A04:2025") and f.cwe == "CWE-327"


# ---------------- Orchestrator
def test_orchestrator_merges_both_agents_sorted_by_severity():
    code = 'import os\nPASSWORD = "abcd1234"\ndef f():\n    pass\n'
    r = review(code, "python")
    assert {"Code Analysis", "Security"} <= {f.agent for f in r.findings}
    scores = [f.score for f in r.findings]
    assert scores == sorted(scores, reverse=True) or [f.severity for f in r.findings][0] in ("CRITICAL", "HIGH")
    assert r.findings[0].type == "HARDCODED_SECRET" and r.findings[0].id == "F-001"


def test_orchestrator_runs_agents_in_parallel(monkeypatch):
    import time
    from agents import orchestrator

    def slow(code, lang):
        time.sleep(0.3)
        return []
    monkeypatch.setitem(orchestrator.AGENTS, "Code Analysis", slow)
    monkeypatch.setitem(orchestrator.AGENTS, "Security", slow)
    r = review("x = 1\n", "python")
    assert r.total_seconds < 0.55            # two 0.3 s agents finished in about 0.3 s, not 0.6 s


def test_one_failing_agent_does_not_stop_the_review(monkeypatch):
    from agents import orchestrator

    def boom(code, lang):
        raise RuntimeError("agent crashed")
    monkeypatch.setitem(orchestrator.AGENTS, "Code Analysis", boom)
    r = review('PASSWORD = "abcd1234"\n', "python")
    assert "Code Analysis" in r.errors and any(f.type == "HARDCODED_SECRET" for f in r.findings)


def test_duplicates_across_agents_are_merged():
    from agents import orchestrator
    from models.findings import AgentFinding
    mk = lambda ag, sc: AgentFinding(ag, "X", "x", 3, sc, "m")  # noqa: E731
    orchestrator.AGENTS["A"] = lambda c, l: [mk("A", 4.0)]
    orchestrator.AGENTS["B"] = lambda c, l: [mk("B", 6.0)]
    try:
        r = review("x", "python", agents=["A", "B"])
        assert len(r.findings) == 1 and r.findings[0].score == 6.0
    finally:
        del orchestrator.AGENTS["A"], orchestrator.AGENTS["B"]


# ---------------- Milestone 2 additions (scoring, rule ids, peers' 5-tier pyramid)
def test_rule_id_and_confidence():
    r = review('import os\ndef f(cmd):\n    os.system(cmd)\nPASSWORD = "abcd1234"\n', "python")
    by = {f.type: f for f in r.findings}
    assert by["HARDCODED_SECRET"].rule_id == "PY-HARDCODED-SECRET" and by["HARDCODED_SECRET"].confidence == "High"
    assert by["COMMAND_INJECTION"].confidence == "Medium"          # variable command, no proven user input


def test_variable_command_is_reported_in_both_languages():
    assert "COMMAND_INJECTION" in types(sec("import os\ndef run(cmd):\n    os.system(cmd)\n"))
    java = "class A { void run(String cmd) throws Exception {\n Runtime.getRuntime().exec(cmd);\n}}"
    assert "COMMAND_INJECTION" in types(sec(java, "java"))
    assert "COMMAND_INJECTION" not in types(sec('import os\nos.system("ls -l")\n'))


def test_severity_pyramid_has_five_tiers():
    from models.findings import band
    assert [band(s) for s in (9.8, 7.5, 5, 3, 1.5)] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def test_quality_score_and_technical_debt():
    clean = review('"""doc."""\n\n\ndef f(a):\n    """doc."""\n    return a\n', "python")
    dirty = review(open(Path(__file__).resolve().parent.parent / "test_files" / "vulnerable.py").read(), "python")
    assert clean.quality_score == 100 and clean.technical_debt_minutes == 0
    assert dirty.quality_score < 80 and dirty.technical_debt_minutes > 120


def test_java_unreachable_statement_right_after_method_start():
    java = "class A {\n int f(int x) {\n  return x;\n  x++;\n }\n}"
    assert "UNREACHABLE_CODE" in types(code_analysis.run(java, "java"))


def test_agent_status_shows_complete_or_failed(monkeypatch):
    from agents import orchestrator
    monkeypatch.setitem(orchestrator.AGENTS, "Code Analysis", lambda c, l: 1 / 0)
    r = review("x = 1\n", "python")
    assert r.status == {"Code Analysis": "Failed", "Security": "Complete"}


# ---------------- Accuracy gate (Milestone 2 acceptance criteria)
def test_accuracy_on_labelled_samples():
    from evaluation.evaluate import evaluate
    r = evaluate(Path(__file__).resolve().parent.parent / "samples_holdout")
    for agent, v in r["agents"].items():
        assert v["recall"] >= 0.9, (agent, v)
        assert v["precision"] >= 0.8, (agent, v)


def test_no_findings_on_clean_samples():
    root = Path(__file__).resolve().parent.parent / "samples"
    for name, lang in (("python/secure_service.py", "python"), ("java/SecureAccountRepository.java", "java")):
        r = review((root / name).read_text(), lang)
        assert [f for f in r.findings if f.scored] == [], name
