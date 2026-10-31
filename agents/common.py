"""Helpers shared by the agents: comment stripping, logical lines, taint propagation."""
import io
import re
import tokenize
from typing import List, Set, Tuple


def strip_comments_py(code: str) -> str:
    """Blank out # comments (line numbers preserved)."""
    lines = code.splitlines()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type == tokenize.COMMENT:
                (r, c), (_, e) = tok.start, tok.end
                lines[r - 1] = lines[r - 1][:c] + " " * (e - c) + lines[r - 1][e:]
    except (tokenize.TokenError, IndentationError):
        pass
    return "\n".join(lines)


def strip_comments_java(code: str) -> str:
    """Blank out // and /* */ comments but keep strings and newlines."""
    out, i, n, mode = [], 0, len(code), None
    while i < n:
        c, d = code[i], code[i:i + 2]
        if mode is None:
            if d == "//": mode = "line"; out.append("  "); i += 2; continue
            if d == "/*": mode = "block"; out.append("  "); i += 2; continue
            if c in "\"'": mode = c
            out.append(c)
        elif mode == "line":
            if c == "\n": mode = None; out.append(c)
            else: out.append(" ")
        elif mode == "block":
            if d == "*/": mode = None; out.append("  "); i += 2; continue
            out.append("\n" if c == "\n" else " ")
        else:                                   # inside a string / char literal
            out.append(c)
            if c == "\\" and i + 1 < n: out.append(code[i + 1]); i += 2; continue
            if c == mode or c == "\n": mode = None
        i += 1
    return "".join(out)


def logical_lines(code: str, braces: bool = False) -> List[Tuple[int, str]]:
    """Join statements that span several lines (open brackets / trailing operators).
    Returns (first_line_number, joined_text)."""
    out, buf, start, depth = [], [], 0, 0
    for no, line in enumerate(code.splitlines(), 1):
        if not buf:
            start = no
        buf.append(line.strip() if buf else line)
        s = re.sub(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", '""', line)   # ignore brackets in strings
        opens, closes = ("([{", ")]}") if braces else ("([", ")]")
        depth += sum(s.count(c) for c in opens) - sum(s.count(c) for c in closes)
        cont = s.rstrip().endswith(("\\", "+", ",", "&&", "||")) and not s.strip().startswith(("@", "case ", "default"))
        if depth <= 0 and not cont:
            out.append((start, " ".join(buf)))
            buf, depth = [], 0
    if buf:
        out.append((start, " ".join(buf)))
    return out


SANITIZERS = re.compile(r"\b(?:int|float|bool|escape|quote|quote_plus|secure_filename|parseInt|parseLong|parseDouble|valueOf|"
                        r"encodeForHTML|encodeForSQL|escapeHtml\w*|escapeXml\w*|sanitize\w*|clean|urlsafe_b64encode|"
                        r"URLEncoder\.encode|basename|getName|abs)\s*\((?:[^()]|\([^()]*\))*\)")


def _blank_strings(expr: str) -> str:
    """Empty string literals so words inside them are not mistaken for variables;
    f-string {interpolations} are kept because they do reference variables."""
    def repl(m):
        body = m.group(2)[1:-1]
        return " " + " ".join(re.findall(r"\{([^}]*)\}", body)) + " " if m.group(1) else '""'
    return re.sub(r"(\bf)?(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", repl, expr)


def has_taint(expr: str, tainted: Set[str], sources: "re.Pattern") -> bool:
    expr = SANITIZERS.sub("SAFE", expr)
    if sources.search(expr):
        return True
    code = _blank_strings(expr)
    return any(re.search(rf"(?<![\w.]){re.escape(v)}(?!\w)", code) for v in tainted)


def is_dynamic(expr: str) -> bool:
    """Is a string being built at run time (concatenation, f-string, format, %)?"""
    if re.search(r"\bf\"[^\"]*\{|\bf'[^']*\{", expr) or ".format(" in expr or "String.format(" in expr or ".concat(" in expr:
        return True
    stripped = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", '""', expr)
    return bool(re.search(r"\"\"\s*(\+|%)\s*[\w(]|[\w)\]]\s*\+\s*\"\"", stripped) or re.search(r"\"\"\s*%\s*[\w(]", stripped))


def first_arg(rest: str) -> str:
    """Text of the first call argument: `rest` is everything after the opening '('."""
    depth, q = 0, None
    for i, c in enumerate(rest):
        if q:
            if c == q and rest[i - 1] != "\\": q = None
            continue
        if c in "\"'": q = c
        elif c in "([{": depth += 1
        elif c in ")]}":
            if depth == 0: return rest[:i]
            depth -= 1
        elif c == "," and depth == 0:
            return rest[:i]
    return rest
