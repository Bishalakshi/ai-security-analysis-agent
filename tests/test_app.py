import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from streamlit.testing.v1 import AppTest
APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "app.py")


def test_dashboard_blocks_submit_on_syntax_error():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.text_area[0].set_value("def f(:\n    pass").run()
    assert at.error and "line 1" in at.error[0].value
    assert [b for b in at.button if "Validate Code" in b.label][0].disabled

def test_dashboard_accepts_valid_java():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.text_area[0].set_value("public class A { void f() { int x = 1; } }").run()
    assert at.success
    assert not [b for b in at.button if "Validate Code" in b.label][0].disabled


def _run_review(path):
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.text_area[0].set_value(open(os.path.join(os.path.dirname(APP), "..", "test_files", path), encoding="utf-8").read()).run()
    [b for b in at.button if "Validate Code" in b.label][0].click().run()
    return at


def test_dashboard_runs_both_agents_on_vulnerable_python():
    at = _run_review("vulnerable.py")
    assert not at.exception
    assert sum("Complete" in m.value for m in at.markdown if "Agent" in m.value) == 2
    assert any("PY-SQL-INJECTION" in e.label for e in at.expander)
    assert {m.label for m in at.metric} >= {"Risk score", "Code quality", "Technical debt", "Findings"}


def test_dashboard_runs_both_agents_on_vulnerable_java():
    at = _run_review("Vulnerable.java")
    assert not at.exception
    assert any("JAVA-HARDCODED-SECRET" in e.label for e in at.expander)
