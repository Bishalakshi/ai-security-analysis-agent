"""Java syntax validation using the javalang parser (pure Python, no JDK needed)."""
import javalang

_OK_ENDINGS = (";", "{", "}", ")", ",", ":", "->", "(", "&&", "||", "+", "-", "*", "/", "=", ".", "@")


def _strip_comment(line: str) -> str:
    return line.split("//")[0].rstrip()


def _previous_code_line(lines, lineno):
    """Return (index, text) of the nearest non-empty line before lineno (1-based)."""
    i = lineno - 2
    while i >= 0:
        txt = _strip_comment(lines[i]).strip()
        if txt and not txt.startswith(("*", "/*", "//")):
            return i + 1, txt
        i -= 1
    return None, None


def validate_java(code: str) -> dict:
    try:
        javalang.parse.parse(code)
        return {"valid": True, "language": "java", "error": None, "line": None, "column": None}
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
        pos = getattr(getattr(e, "at", None), "position", None)
        line, col = (pos[0], pos[1]) if pos else (None, None)
        msg = getattr(e, "description", None) or str(e)
        # A missing ';' is detected on the NEXT token, i.e. the following line.
        # Point at the line that is really missing the semicolon.
        if line and line > 1:
            prev_no, prev_txt = _previous_code_line(code.splitlines(), line)
            if prev_txt and not prev_txt.endswith(_OK_ENDINGS):
                line, msg = prev_no, "Missing ';' at the end of this line"
        return {"valid": False, "language": "java", "error": msg, "line": line, "column": col}
