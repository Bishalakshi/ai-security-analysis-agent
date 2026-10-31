"""Code Analysis Agent: code smells, complexity, design anti-patterns and poor practices.
Python is analysed with the `ast` module, Java with tree-sitter. Every finding gets a 0-10 score."""
import ast
import re
from typing import Callable, Dict, List

from agents.common import strip_comments_java, strip_comments_py
from models.findings import AgentFinding
import javalang
from javalang import tree as jt
from javalang.tokenizer import tokenize

# type -> (title, fix hint, scored, owasp)
CATALOG: Dict[str, tuple] = {
    "HIGH_COMPLEXITY":     ("High cyclomatic complexity", "Split the function into smaller functions; replace nested conditionals with guard clauses.", True, ""),
    "LONG_FUNCTION":       ("Long function / method", "Extract cohesive blocks into helper functions.", True, ""),
    "LONG_PARAMETER_LIST": ("Too many parameters", "Group related parameters into an object / dataclass.", True, ""),
    "DEEP_NESTING":        ("Deeply nested control flow", "Use early returns and extract inner blocks.", True, ""),
    "GOD_CLASS":           ("Class is too large (god class)", "Split responsibilities into smaller, focused classes.", True, ""),
    "DUPLICATE_CODE":      ("Duplicated code block", "Extract the repeated block into one reusable function.", True, ""),
    "MAGIC_NUMBER":        ("Magic number", "Replace the literal by a named constant.", True, ""),
    "UNUSED_IMPORT":       ("Unused import", "Remove the import.", True, ""),
    "WILDCARD_IMPORT":     ("Wildcard import", "Import only the names you use.", True, ""),
    "MUTABLE_DEFAULT":     ("Mutable default argument", "Use None as the default and create the object inside the function.", True, ""),
    "BARE_EXCEPT":         ("Bare except", "Catch specific exception types.", True, "A10:2025 Mishandling of Exceptional Conditions"),
    "EMPTY_EXCEPT":        ("Exception silently swallowed", "Log or handle the exception, or re-raise it.", True, "A10:2025 Mishandling of Exceptional Conditions"),
    "BROAD_EXCEPT":        ("Overly broad exception handler", "Catch the narrowest exception you can handle.", True, "A10:2025 Mishandling of Exceptional Conditions"),
    "GLOBAL_STATE":        ("Global state modified", "Pass state explicitly or encapsulate it in a class.", True, ""),
    "COMPARE_NONE":        ("Comparison to None with ==", "Use 'is None' / 'is not None'.", True, ""),
    "STRING_EQUALITY":     ("Strings compared with ==", "Use equals() - == compares references, not content.", True, ""),
    "UNREACHABLE_CODE":    ("Unreachable code", "Remove the statements after return / raise / break / continue.", True, ""),
    "PUBLIC_FIELD":        ("Public mutable field", "Make the field private and expose it through methods.", True, ""),
    # style tier - reported, but not counted in accuracy validation
    "NO_DOCSTRING":        ("Missing documentation", "Add a docstring / Javadoc describing purpose, parameters and result.", False, ""),
    "NAMING":              ("Naming convention", "Follow PEP 8 / Google Java naming rules.", False, ""),
    "CONSOLE_OUTPUT":      ("Console output instead of logging", "Use the logging framework.", False, ""),
    "LONG_LINE":           ("Line too long", "Wrap the line (100 characters max).", False, ""),
    "TODO_COMMENT":        ("Unresolved TODO / FIXME", "Resolve it or track it in the issue tracker.", False, ""),
}
MAX_COMPLEXITY, MAX_LINES, MAX_PARAMS, MAX_DEPTH, MAX_METHODS, MAX_CLASS_LINES = 10, 40, 5, 4, 20, 300
OK_NUMBERS = {0, 1, 2, -1, 10, 100, 1000, 0.5}


def _f(t: str, line: int, score: float, msg: str, code_lines: List[str], end=None) -> AgentFinding:
    title, hint, scored, owasp = CATALOG[t]
    snip = code_lines[line - 1].strip()[:160] if 0 < line <= len(code_lines) else ""
    return AgentFinding("Code Analysis", t, title, line, round(score, 1), msg,
                        "quality" if scored else "style", snip, end, owasp, "", False, hint, scored)


def _cx_score(c): return 4.5 if c <= 15 else 5.5 if c <= 20 else 6.5 if c <= 30 else 7.5
def _len_score(n): return 4.0 if n <= 80 else 5.5
def _nest_score(d): return 4.5 if d == MAX_DEPTH + 1 else 5.5
def _param_score(n): return min(4.0 + 0.3 * (n - MAX_PARAMS - 1), 5.5)


# ------------------------------------------------------------------ language independent
def _duplicates(code: str, lines: List[str]) -> List[AgentFinding]:
    W, seen, out, last_end = 5, {}, [], 0
    norm = [(i + 1, re.sub(r"\s+", " ", l.strip())) for i, l in enumerate(lines)]
    norm = [(i, t) for i, t in norm if len(t) > 6 and not t.startswith(("import ", "from ", "@", "package ", "#", "}", "else", "//"))]
    for k in range(len(norm) - W + 1):
        win = tuple(t for _, t in norm[k:k + W])
        if len(set(win)) < 3:
            continue
        start, end = norm[k][0], norm[k + W - 1][0]
        if win in seen and seen[win][1] < start:
            if start > last_end:
                out.append(_f("DUPLICATE_CODE", start, 4.5, f"Block repeats lines {seen[win][0]}-{seen[win][1]}.", lines, end))
            last_end = max(last_end, end)
        else:
            seen.setdefault(win, (start, end))
    return out


def _style(raw: str, lines: List[str], maxlen: int) -> List[AgentFinding]:
    out = []
    for i, l in enumerate(raw.splitlines(), 1):
        if len(l.rstrip()) > maxlen:
            out.append(_f("LONG_LINE", i, 1.0, f"Line has {len(l.rstrip())} characters (limit {maxlen}).", lines))
        if re.search(r"(#|//|/\*|\*)\s*(TODO|FIXME|XXX)\b", l):
            out.append(_f("TODO_COMMENT", i, 1.0, "Unresolved TODO / FIXME comment.", lines))
    return out


# ------------------------------------------------------------------ Python
class _Cx(ast.NodeVisitor):
    """McCabe complexity of one function (nested defs are analysed on their own)."""
    def __init__(self): self.n = 1
    def generic_visit(self, node):
        if isinstance(node, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.match_case)):
            self.n += 1
        elif isinstance(node, ast.BoolOp):
            self.n += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            self.n += 1 + len(node.ifs)
        super().generic_visit(node)
    def visit_FunctionDef(self, node): pass
    visit_AsyncFunctionDef = visit_ClassDef = visit_Lambda = visit_FunctionDef


def _depth(stmts, d=0) -> int:
    best = d
    for s in stmts:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(s, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)):
            subs = []
            if isinstance(s, ast.Try):
                subs = [s.body, s.orelse, s.finalbody] + [h.body for h in s.handlers]
            elif isinstance(s, ast.Match):
                subs = [c.body for c in s.cases]
            else:
                subs = [s.body, getattr(s, "orelse", [])]
            for b in subs:
                best = max(best, _depth(b, d + 1))
    return best


def _dead(stmts, lines, out):
    for i, s in enumerate(stmts):
        if isinstance(s, (ast.Return, ast.Raise, ast.Continue, ast.Break)) and i + 1 < len(stmts):
            out.append(_f("UNREACHABLE_CODE", stmts[i + 1].lineno, 3.5, "Statement can never run: it follows a return/raise/break/continue.", lines))
            break
    for s in stmts:
        for attr in ("body", "orelse", "finalbody"):
            if isinstance(getattr(s, attr, None), list) and not isinstance(s, (ast.Expr,)):
                _dead(getattr(s, attr), lines, out)
        for h in getattr(s, "handlers", []):
            _dead(h.body, lines, out)


def analyse_python(code: str) -> List[AgentFinding]:
    clean = strip_comments_py(code)
    lines = code.splitlines()
    out: List[AgentFinding] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return out
    out += _duplicates(clean, clean.splitlines()) + _style(code, lines, 100)

    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = n.end_lineno or n.lineno
            cx = _Cx()
            for s in n.body: cx.visit(s)
            if cx.n > MAX_COMPLEXITY:
                out.append(_f("HIGH_COMPLEXITY", n.lineno, _cx_score(cx.n), f"'{n.name}' has cyclomatic complexity {cx.n} (limit {MAX_COMPLEXITY}).", lines, end))
            size = end - n.lineno + 1
            if size > MAX_LINES:
                out.append(_f("LONG_FUNCTION", n.lineno, _len_score(size), f"'{n.name}' is {size} lines long (limit {MAX_LINES}).", lines, end))
            params = [a.arg for a in n.args.posonlyargs + n.args.args + n.args.kwonlyargs if a.arg not in ("self", "cls")]
            if len(params) > MAX_PARAMS:
                out.append(_f("LONG_PARAMETER_LIST", n.lineno, _param_score(len(params)), f"'{n.name}' takes {len(params)} parameters (limit {MAX_PARAMS}).", lines))
            d = _depth(n.body)
            if d > MAX_DEPTH:
                out.append(_f("DEEP_NESTING", n.lineno, _nest_score(d), f"'{n.name}' nests control flow {d} levels deep (limit {MAX_DEPTH}).", lines, end))
            for dflt in n.args.defaults + [k for k in n.args.kw_defaults if k]:
                if isinstance(dflt, (ast.List, ast.Dict, ast.Set)) or (isinstance(dflt, ast.Call) and getattr(dflt.func, "id", "") in ("list", "dict", "set")):
                    out.append(_f("MUTABLE_DEFAULT", n.lineno, 5.0, f"'{n.name}' has a mutable default argument shared between calls.", lines))
            if not n.name.startswith("_") and not ast.get_docstring(n):
                out.append(_f("NO_DOCSTRING", n.lineno, 1.5, f"'{n.name}' has no docstring.", lines))
            if not re.fullmatch(r"_{0,2}[a-z][a-z0-9_]*_{0,2}", n.name):
                out.append(_f("NAMING", n.lineno, 1.5, f"Function '{n.name}' should be snake_case.", lines))
            _dead(n.body, lines, out)
            for m in ast.walk(n):                                         # magic numbers
                if isinstance(m, ast.Return) and isinstance(m.value, ast.Constant) and type(m.value.value) in (int, float) and m.value.value not in OK_NUMBERS:
                    out.append(_f("MAGIC_NUMBER", m.lineno, 2.5, f"Unnamed numeric literal {m.value.value}.", lines))
                if isinstance(m, (ast.Compare, ast.BinOp)):
                    for c in ast.walk(m):
                        if isinstance(c, ast.Constant) and type(c.value) in (int, float) and c.value not in OK_NUMBERS:
                            out.append(_f("MAGIC_NUMBER", c.lineno, 2.5, f"Unnamed numeric literal {c.value}.", lines)); break
        elif isinstance(n, ast.ClassDef):
            methods = sum(isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) for b in n.body)
            size = (n.end_lineno or n.lineno) - n.lineno + 1
            if methods > MAX_METHODS or size > MAX_CLASS_LINES:
                out.append(_f("GOD_CLASS", n.lineno, 6.0, f"Class '{n.name}' has {methods} methods and {size} lines.", lines, n.end_lineno))
            if not re.fullmatch(r"_?[A-Z][A-Za-z0-9]*", n.name):
                out.append(_f("NAMING", n.lineno, 1.5, f"Class '{n.name}' should be CapWords.", lines))
            if not ast.get_docstring(n) and not n.name.startswith("_"):
                out.append(_f("NO_DOCSTRING", n.lineno, 1.5, f"Class '{n.name}' has no docstring.", lines))
        elif isinstance(n, ast.ExceptHandler):
            body_pass = all(isinstance(b, ast.Pass) or (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant)) for b in n.body)
            reraises = any(isinstance(x, ast.Raise) for b in n.body for x in ast.walk(b))
            if n.type is None:
                out.append(_f("BARE_EXCEPT", n.lineno, 4.5, "Bare 'except:' also catches KeyboardInterrupt and hides bugs.", lines))
            if body_pass:
                out.append(_f("EMPTY_EXCEPT", n.lineno, 5.0, "The exception is swallowed without any handling.", lines))
            elif n.type is not None and getattr(n.type, "id", "") in ("Exception", "BaseException") and not reraises:
                out.append(_f("BROAD_EXCEPT", n.lineno, 3.0, "Catching Exception is too broad.", lines))
        elif isinstance(n, ast.Global):
            out.append(_f("GLOBAL_STATE", n.lineno, 3.5, f"'global {', '.join(n.names)}' modifies shared state.", lines))
        elif isinstance(n, ast.Compare):
            for op, c in zip(n.ops, n.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(c, ast.Constant) and c.value is None:
                    out.append(_f("COMPARE_NONE", n.lineno, 2.5, "Use 'is None' instead of '== None'.", lines))
        elif isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
            out.append(_f("WILDCARD_IMPORT", n.lineno, 3.0, f"'from {n.module} import *' pollutes the namespace.", lines))
        elif isinstance(n, ast.Call) and getattr(n.func, "id", "") == "print":
            out.append(_f("CONSOLE_OUTPUT", n.lineno, 2.0, "print() used instead of logging.", lines))

    # unused imports
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    exported = set(re.findall(r"[\"'](\w+)[\"']", " ".join(l for l in clean.splitlines() if "__all__" in l)))
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)) and not (isinstance(n, ast.ImportFrom) and n.module == "__future__"):
            for a in n.names:
                if a.name == "*": continue
                nm = a.asname or a.name.split(".")[0]
                if nm not in used and nm not in exported and nm != "_":
                    out.append(_f("UNUSED_IMPORT", n.lineno, 2.0, f"'{nm}' is imported but never used.", lines))
    return out


# ------------------------------------------------------------------ Java (javalang AST + token stream)
_KEY_BRANCH = {"if", "for", "while", "case", "catch"}
_KEY_NEST = {"if", "for", "while", "try", "switch", "synchronized", "do", "else", "catch", "finally"}
_NUM = ("DecimalInteger", "DecimalFloatingPoint")


def _match(toks, i, open_c="{", close_c="}"):
    """Index of the token closing the bracket that opens at toks[i]."""
    depth = 0
    for j in range(i, len(toks)):
        v = toks[j].value
        if toks[j].__class__.__name__ == "Separator":
            if v == open_c: depth += 1
            elif v == close_c:
                depth -= 1
                if depth == 0: return j
    return len(toks) - 1


def _name_index(toks, name, pos):
    for i, t in enumerate(toks):
        if t.value == name and t.__class__.__name__ == "Identifier" and (t.position.line, t.position.column) >= (pos.line, pos.column) \
                and i + 1 < len(toks) and toks[i + 1].value in ("(", "{", "extends", "implements", "<"):
            return i
    return None


def _body_open(toks, i):
    """First '{' after the name at toks[i] (skipping the parameter list / throws), or None for abstract methods."""
    paren = 0
    for j in range(i, len(toks)):
        v, k = toks[j].value, toks[j].__class__.__name__
        if k == "Separator":
            if v == "(": paren += 1
            elif v == ")": paren -= 1
            elif v == ";" and paren == 0: return None
            elif v == "{" and paren == 0: return j
    return None


def _jcx(body) -> int:
    n = 1
    for k, t in enumerate(body):
        v, c = t.value, t.__class__.__name__
        if c == "Keyword" and v in _KEY_BRANCH: n += 1
        elif c == "Operator" and v in ("&&", "||"): n += 1
        elif c == "Operator" and v == "?" and k > 0 and body[k - 1].value not in ("<", ",") and (k + 1 >= len(body) or body[k + 1].value != ">"): n += 1
    return n


def _jdepth(body) -> int:
    stack, pending, paren, best, prev = [], False, 0, 0, None
    for t in body:
        v, c = t.value, t.__class__.__name__
        if c == "Keyword" and v in _KEY_NEST:
            pending = True
        elif c == "Separator":
            if v == "(": paren += 1
            elif v == ")": paren -= 1
            elif v == ";" and paren == 0: pending = False
            elif v == "{":
                stack.append(1 if pending else 0); pending = False
                best = max(best, sum(stack))
            elif v == "}" and stack: stack.pop()
        prev = t
    return best


def _unreachable(toks, base_idx, lines, out):
    for k, t in enumerate(toks):
        if t.__class__.__name__ == "Keyword" and t.value in ("return", "throw", "break", "continue") and (k == 0 or toks[k - 1].value in (";", "{", "}")):
            depth, j = 0, k
            while j < len(toks):
                v = toks[j].value
                if toks[j].__class__.__name__ == "Separator":
                    if v in "({[": depth += 1
                    elif v in ")}]": depth -= 1
                    elif v == ";" and depth == 0: break
                j += 1
            nxt = toks[j + 1] if j + 1 < len(toks) else None
            if nxt is not None and nxt.value not in ("}", "case", "default"):
                out.append(_f("UNREACHABLE_CODE", nxt.position.line, 3.5, "Statement can never run: it follows a return/throw/break/continue.", lines))
                return


def _decl_final(toks, k) -> bool:
    j = k
    while j > 0 and toks[j - 1].value not in (";", "{", "}"):
        j -= 1
    return any(t.__class__.__name__ == "Modifier" and t.value == "final" for t in toks[j:k])


def analyse_java(code: str) -> List[AgentFinding]:
    clean = strip_comments_java(code)
    lines = code.splitlines()
    out: List[AgentFinding] = _duplicates(clean, clean.splitlines()) + _style(code, lines, 100)
    try:
        tree = javalang.parse.parse(code)
        toks = list(tokenize(code))
    except Exception:                                  # unsupported syntax: structure checks are skipped
        return out
    L = lambda t: t.position.line                      # noqa: E731

    # ---- methods and constructors
    for node in [n for _, n in tree.filter(jt.MethodDeclaration)] + [n for _, n in tree.filter(jt.ConstructorDeclaration)]:
        i = _name_index(toks, node.name, node.position)
        if i is None: continue
        op = _body_open(toks, i)
        if op is None: continue
        cl = _match(toks, op)
        body = toks[op + 1:cl]
        line, end = L(toks[i]), L(toks[cl])
        cx = _jcx(body)
        if cx > MAX_COMPLEXITY:
            out.append(_f("HIGH_COMPLEXITY", line, _cx_score(cx), f"'{node.name}' has cyclomatic complexity {cx} (limit {MAX_COMPLEXITY}).", lines, end))
        size = end - node.position.line + 1
        if size > MAX_LINES:
            out.append(_f("LONG_FUNCTION", line, _len_score(size), f"'{node.name}' is {size} lines long (limit {MAX_LINES}).", lines, end))
        if len(node.parameters) > MAX_PARAMS:
            out.append(_f("LONG_PARAMETER_LIST", line, _param_score(len(node.parameters)), f"'{node.name}' takes {len(node.parameters)} parameters (limit {MAX_PARAMS}).", lines))
        d = _jdepth(body)
        if d > MAX_DEPTH:
            out.append(_f("DEEP_NESTING", line, _nest_score(d), f"'{node.name}' nests control flow {d} levels deep (limit {MAX_DEPTH}).", lines, end))
        if isinstance(node, jt.MethodDeclaration):
            if not re.fullmatch(r"[a-z][A-Za-z0-9]*", node.name):
                out.append(_f("NAMING", line, 1.5, f"Method '{node.name}' should be lowerCamelCase.", lines))
            if "public" in node.modifiers and not node.documentation:
                out.append(_f("NO_DOCSTRING", line, 1.5, f"Public method '{node.name}' has no Javadoc.", lines))
        _unreachable(body, op, lines, out)
        for k, t in enumerate(body):                   # magic numbers
            if t.__class__.__name__ in _NUM:
                prev = body[k - 1].value if k else ""
                if prev in ("case", "[", "@") or _decl_final(body, k):
                    continue
                try: num = float(t.value.rstrip("lLfFdD").replace("_", ""))
                except ValueError: continue
                if num not in OK_NUMBERS:
                    out.append(_f("MAGIC_NUMBER", L(t), 2.5, f"Unnamed numeric literal {t.value}.", lines))

    # ---- classes and fields
    for _, node in tree.filter(jt.ClassDeclaration):
        i = _name_index(toks, node.name, node.position)
        if i is None: continue
        op = _body_open(toks, i)
        cl = _match(toks, op) if op is not None else i
        methods = sum(isinstance(m, jt.MethodDeclaration) for m in node.body)
        size = L(toks[cl]) - node.position.line + 1
        if methods > MAX_METHODS or size > MAX_CLASS_LINES:
            out.append(_f("GOD_CLASS", L(toks[i]), 6.0, f"Class '{node.name}' has {methods} methods and {size} lines.", lines, L(toks[cl])))
        if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", node.name):
            out.append(_f("NAMING", L(toks[i]), 1.5, f"Class '{node.name}' should be UpperCamelCase.", lines))
        for m in node.body:
            if isinstance(m, jt.FieldDeclaration):
                if "public" in m.modifiers and "final" not in m.modifiers:
                    out.append(_f("PUBLIC_FIELD", m.position.line, 3.0, "Public non-final field breaks encapsulation.", lines))
                if {"static", "final"} <= set(m.modifiers):
                    for dcl in m.declarators:
                        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", dcl.name):
                            out.append(_f("NAMING", m.position.line, 1.5, "Constants should be UPPER_SNAKE_CASE.", lines))

    # ---- whole-file token checks
    for k, t in enumerate(toks):
        v, c = t.value, t.__class__.__name__
        if c == "Keyword" and v == "catch" and k + 1 < len(toks):
            close_p = _match(toks, k + 1, "(", ")")
            seg = toks[k + 2:close_p]
            ctype = "".join(x.value for x in seg[:-1] if x.value != "final")
            op = close_p + 1
            if op < len(toks) and toks[op].value == "{":
                cl = _match(toks, op)
                inner = toks[op + 1:cl]
                commented = False
                if not inner:
                    o, e = toks[op].position, toks[cl].position
                    text = lines[o.line - 1][o.column:e.column - 1] if e.line == o.line else "\n".join(lines[o.line:e.line - 1])
                    commented = "//" in text or "/*" in text
                if not inner and not commented:
                    out.append(_f("EMPTY_EXCEPT", L(t), 5.0, "Empty catch block swallows the exception.", lines))
                elif ctype in ("Exception", "Throwable") and not any(x.value == "throw" for x in inner):
                    out.append(_f("BROAD_EXCEPT", L(t), 3.0, f"Catching {ctype} is too broad.", lines))
        elif c == "Operator" and v in ("==", "!=") and (toks[k - 1].__class__.__name__ == "String" or (k + 1 < len(toks) and toks[k + 1].__class__.__name__ == "String")):
            out.append(_f("STRING_EQUALITY", L(t), 5.5, "Strings compared with == / != (reference comparison).", lines))
        elif c == "Identifier" and v == "System" and k + 4 < len(toks) and toks[k + 2].value in ("out", "err") and toks[k + 4].value.startswith("print"):
            out.append(_f("CONSOLE_OUTPUT", L(t), 2.0, "Console output instead of a logger.", lines))
        elif c == "Identifier" and v == "printStackTrace":
            out.append(_f("CONSOLE_OUTPUT", L(t), 2.0, "printStackTrace() instead of a logger.", lines))

    # ---- imports
    rest = "\n".join(l for l in clean.splitlines() if not l.strip().startswith("import "))
    for imp in tree.imports:
        line = imp.position.line if imp.position else 1
        if imp.wildcard:
            out.append(_f("WILDCARD_IMPORT", line, 3.0, "Wildcard imports are discouraged.", lines))
        else:
            nm = imp.path.split(".")[-1]
            if not re.search(rf"(?<![\w.]){re.escape(nm)}\b", rest):
                out.append(_f("UNUSED_IMPORT", line, 2.0, f"'{nm}' is imported but never used.", lines))
    seen, uniq = set(), []
    for f in out:
        if (f.type, f.line) not in seen:
            seen.add((f.type, f.line)); uniq.append(f)
    return uniq


def run(code: str, language: str) -> List[AgentFinding]:
    return (analyse_python if language == "python" else analyse_java)(code)
