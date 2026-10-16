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
