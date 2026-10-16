import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsers.validate import validate_code, validate_file
from parsers.language_detector import detect_language

TF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_files")
rd = lambda n: open(os.path.join(TF, n), encoding="utf-8").read()


def test_correct_python_file():
    assert validate_code(rd("correct.py"), filename="correct.py")["valid"]

def test_python_indentation_error_line():
    r = validate_code(rd("wrong.py"), filename="wrong.py")
    assert not r["valid"] and r["line"] == 5

def test_python_return_outside_function_caught():
    r = validate_code("x = 1\nreturn x\n", "python")
    assert not r["valid"]

def test_correct_java_file():
    assert validate_code(rd("Correct.java"), filename="Correct.java")["valid"]

def test_java_missing_semicolon_points_to_right_line():
    r = validate_code(rd("Wrong.java"), filename="Wrong.java")
    assert not r["valid"] and r["line"] == 3

def test_autodetect_pasted_java_method():
    assert detect_language("public class A { void f() { int x = 1; } }")["language"] == "java"

def test_autodetect_pasted_python():
    assert detect_language("def f(x):\n    return x + 1\n")["language"] == "python"

def test_cpp_not_detected_as_java():
    assert detect_language('#include <iostream>\nint main(){ std::cout << 1; }')["language"] == "unsupported"

def test_empty_code_rejected():
    assert not validate_code("   ")["valid"]

def test_upload_wrong_extension():
    assert not validate_file("notes.txt", b"hello")["valid"]

def test_upload_binary_rejected():
    assert not validate_file("a.py", b"\x00\x01\x02")["valid"]

def test_upload_too_large():
    assert not validate_file("a.py", b"x = 1\n" * 200000)["valid"]

def test_upload_valid_returns_code():
    r = validate_file("ok.py", b"print(1)")
    assert r["valid"] and r["code"] == "print(1)"
