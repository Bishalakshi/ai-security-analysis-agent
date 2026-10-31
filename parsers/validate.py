"""Single entry point used by the dashboard and the API."""
from parsers.python_validator import validate_python
from parsers.java_validator import validate_java
from parsers.language_detector import detect_language

MAX_BYTES = 500 * 1024  # 500 KB limit (same as the upload hint in the UI)
EXT = {".py": "python", ".java": "java"}


def validate_code(code: str, language: str | None = None, filename: str | None = None) -> dict:
    """Validate pasted code or file content. If language is None it is auto-detected."""
    det = detect_language(code, filename) if not language else {"language": language.lower(), "reason": "chosen by caller", "confidence": 1.0}
    lang = det["language"]
    base = {"language": lang, "detected_by": det["reason"], "confidence": det["confidence"]}
    if not code or not code.strip():
        return {**base, "valid": False, "error": "Code is empty.", "line": None, "column": None}
    if len(code.encode("utf-8")) > MAX_BYTES:
        return {**base, "valid": False, "error": "Code exceeds the 500 KB limit.", "line": None, "column": None}
    if lang == "python":
        return {**base, **validate_python(code)}
    if lang == "java":
        return {**base, **validate_java(code)}
    msg = "Unsupported language: only Python and Java are supported." if lang == "unsupported" else \
          "Could not detect the language. Use a .py / .java file or paste Python / Java code."
    return {**base, "valid": False, "error": msg + f" ({det['reason']})", "line": None, "column": None}


def validate_file(filename: str, content: bytes) -> dict:
    """Validate an uploaded file: extension, size, binary / UTF-8, empty, then syntax."""
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in EXT:
        return {"valid": False, "language": None, "error": "Only .py and .java files are allowed.", "line": None, "column": None, "code": ""}
    if len(content) > MAX_BYTES:
        return {"valid": False, "language": EXT[ext], "error": "File exceeds the 500 KB limit.", "line": None, "column": None, "code": ""}
    if b"\x00" in content:
        return {"valid": False, "language": EXT[ext], "error": "File looks binary (contains null bytes).", "line": None, "column": None, "code": ""}
    try:
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        return {"valid": False, "language": EXT[ext], "error": "File is not valid UTF-8 text.", "line": None, "column": None, "code": ""}
    res = validate_code(code, EXT[ext], filename)
    res["code"] = code
    return res
