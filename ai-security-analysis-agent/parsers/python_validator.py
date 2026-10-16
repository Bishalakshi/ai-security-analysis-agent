"""Python syntax validation. Uses compile() (not ast.parse) so errors such as
'return' outside a function are also caught. The code is never executed."""


def validate_python(code: str) -> dict:
    try:
        compile(code, "<submission>", "exec")
        return {"valid": True, "language": "python", "error": None, "line": None, "column": None}
    except SyntaxError as e:
        return {"valid": False, "language": "python", "error": e.msg,
                "line": e.lineno, "column": e.offset}
    except (ValueError, OverflowError, MemoryError) as e:  # e.g. null bytes
        return {"valid": False, "language": "python", "error": str(e), "line": None, "column": None}
