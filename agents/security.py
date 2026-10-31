"""Security Vulnerability Agent: OWASP-mapped detection with simple taint tracking.
Pipeline per file: strip comments -> join multi-line statements -> propagate taint from
user-controlled sources through assignments -> test sinks -> score (higher if tainted)."""
import re
from typing import Dict, List, Set

from agents.common import (SANITIZERS, first_arg, has_taint, is_dynamic, logical_lines, strip_comments_java, strip_comments_py)
from models.findings import AgentFinding

A01, A02, A04, A05 = ("A01:2025 Broken Access Control", "A02:2025 Security Misconfiguration",
                      "A04:2025 Cryptographic Failures", "A05:2025 Injection")
A07, A08, A09, A10 = ("A07:2025 Authentication Failures", "A08:2025 Software or Data Integrity Failures",
                      "A09:2025 Security Logging and Alerting Failures", "A10:2025 Mishandling of Exceptional Conditions")

# type -> (title, cwe, owasp, base score, score if tainted, fix hint)
CATALOG: Dict[str, tuple] = {
    "SQL_INJECTION":    ("SQL injection", "CWE-89", A05, 8.6, 9.8, "Use parameterised queries / PreparedStatement; never build SQL from strings."),
    "COMMAND_INJECTION":("OS command injection", "CWE-78", A05, 8.8, 9.8, "Pass an argument list without a shell; validate against an allow-list."),
    "CODE_INJECTION":   ("Code injection (eval / exec)", "CWE-95", A05, 8.5, 9.8, "Remove eval/exec; use ast.literal_eval or explicit parsing."),
    "XSS":              ("Cross-site scripting", "CWE-79", A05, 6.1, 7.5, "Encode output for its context; use auto-escaping templates."),
    "SSTI":             ("Server-side template injection", "CWE-1336", A05, 8.0, 9.0, "Render fixed templates and pass user data as variables."),
    "PATH_TRAVERSAL":   ("Path traversal", "CWE-22", A01, 6.5, 7.7, "Normalise the path and check it stays inside the base directory."),
    "SSRF":             ("Server-side request forgery", "CWE-918", A01, 6.5, 8.0, "Validate URLs against an allow-list of hosts."),
    "OPEN_REDIRECT":    ("Open redirect", "CWE-601", A01, 4.7, 6.1, "Redirect only to relative paths or allow-listed hosts."),
    "INSECURE_DESERIALIZATION": ("Insecure deserialization", "CWE-502", A08, 8.0, 9.8, "Use a safe format (JSON) or a safe loader; never deserialize untrusted data."),
    "HARDCODED_SECRET": ("Hard-coded credential", "CWE-798", A07, 7.5, 7.5, "Load secrets from environment variables or a secrets manager."),
    "WEAK_CRYPTO":      ("Weak cryptographic algorithm", "CWE-327", A04, 5.9, 5.9, "Use SHA-256+ / bcrypt / argon2 for hashing and AES-GCM for encryption."),
    "INSECURE_RANDOM":  ("Insecure random number generator", "CWE-330", A04, 5.3, 5.3, "Use secrets (Python) or SecureRandom (Java) for security values."),
    "TLS_VERIFY_DISABLED": ("TLS certificate validation disabled", "CWE-295", A07, 7.4, 7.4, "Keep certificate and hostname verification enabled."),
    "DEBUG_ENABLED":    ("Debug mode enabled", "CWE-489", A02, 5.4, 5.4, "Disable debug mode in production."),
    "CSRF_DISABLED":    ("CSRF protection disabled", "CWE-352", A01, 6.5, 6.5, "Keep CSRF protection on for state-changing requests."),
    "BROKEN_ACCESS_CONTROL": ("Sensitive endpoint without access control", "CWE-862", A01, 7.2, 7.2, "Require authentication and an authorization check on the endpoint."),
    "INSECURE_AUTH":    ("Insecure authentication", "CWE-287", A07, 6.0, 6.0, "Hash passwords and compare in constant time; always verify tokens."),
    "SENSITIVE_LOGGING":("Sensitive data written to logs", "CWE-532", A09, 4.3, 4.3, "Never log passwords, tokens or secrets."),
    "XXE":              ("XML external entity processing", "CWE-611", A02, 7.5, 7.5, "Disable DTDs and external entities on the XML parser."),
    "INSECURE_COOKIE":  ("Cookie without Secure / HttpOnly", "CWE-614", A02, 4.3, 4.3, "Set Secure, HttpOnly and SameSite on session cookies."),
    "PERMISSIVE_CORS":  ("Overly permissive CORS", "CWE-942", A02, 5.0, 5.0, "Allow only specific trusted origins."),
    "INSECURE_TEMPFILE":("Insecure temporary file", "CWE-377", A01, 4.0, 4.0, "Use tempfile.NamedTemporaryFile / Files.createTempFile."),
    "INSECURE_PERMISSIONS": ("World-writable permissions", "CWE-732", A01, 5.5, 5.5, "Use the least privilege (e.g. 0o600 / 0o640)."),
}

SECRET_NAME = r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|access[_-]?key|auth[_-]?key|credentials?)"
SECRET_LIT = re.compile(rf"(?i)[\"']?\b\w*{SECRET_NAME}\w*[\"']?\]?\s*(?::|=|=>)\s*(?:\w+\s+)?[\"']([^\"'\s]{{4,}})[\"']")
SECRET_ARG = re.compile(rf"(?i)\b(?:set\w*(?:password|secret|token|key)|PasswordAuthentication)\w*\(\s*(?:[^\"'(),]*,\s*)?\"([^\"]{{3,}})\"")
SECRET_TOKENS = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9-]{10,}")
PLACEHOLDER = re.compile(r"(?i)^(?:<.*>|\$\{.*\}|\{\{.*\}\}|x{3,}|\*{3,}|none|null|changeme_?|your[_-].*|example.*|todo)$")
SEC_CTX = re.compile(r"(?i)token|password|passwd|secret|\bkey\b|otp|session|salt|nonce|csrf|reset|api_?key|iv\b")
SQL_WORD = re.compile(r"(?i)\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|exec\s)")
HTML_WORD = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>?")
ROUTE_DEC = re.compile(r"@\w+(?:\.\w+)*\.(?:route|get|post|put|delete|patch)\(|@(?:Get|Post|Put|Delete|Patch|Request)Mapping|@(?:GET|POST|PUT|DELETE)\b")
SENSITIVE_PATH = re.compile(r"(?i)admin|delete|remove|promote|reset|export|backup|users?/\d|internal|config|grant|role")
AUTH_WORD = re.compile(r"(?i)login_required|jwt_required|requires?_auth|auth\w*required|permission|roles?_required|admin_required|@PreAuthorize|@Secured|@RolesAllowed|@PermitAll|hasRole|hasAuthority|isUserInRole|current_user|g\.user|session\[|check_auth|verify_token|is_admin|is_authenticated|has_perm|abort\(40[13]")

PY_SOURCES = re.compile(r"\brequest\.(?:args|form|values|json|cookies|headers|data|files|GET|POST|COOKIES|META|body)\b|\brequest\.get_json\(|\binput\(|\bsys\.argv\b|\bself\.request\b|\bos\.environ\.get\([^)]*\)\s*or\s+request")
JAVA_SOURCES = re.compile(r"\b(?:request|req)\.(?:getParameter|getParameterValues|getHeader|getCookies|getQueryString|getInputStream|getReader|getRequestURI|getPathInfo)\(|\bargs\[\d+\]|\b\w*[Ss]canner\w*\.next\w*\(|\.readLine\(\)")



_STR = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")


def _sx(pat: str, s: str):
    """Like re.search but ignores matches that sit inside a string literal."""
    spans = [(m.start(), m.end()) for m in _STR.finditer(s)]
    for m in re.finditer(pat, s):
        if not any(a < m.start() < b for a, b in spans):
            return m
    return None


def _f(t: str, line: int, snippet: str, msg: str, tainted=False, score=None) -> AgentFinding:
    title, cwe, owasp, base, hi, hint = CATALOG[t]
    s = score if score is not None else (hi if tainted else base)
    heuristic = (t in ("SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION", "XSS", "SSTI", "PATH_TRAVERSAL", "SSRF", "OPEN_REDIRECT",
                       "INSECURE_DESERIALIZATION") and not tainted) or t in ("BROKEN_ACCESS_CONTROL", "INSECURE_RANDOM", "INSECURE_AUTH")
    return AgentFinding("Security", t, title, line, round(s, 1), msg + (" User-controlled data reaches this call." if tainted else ""),
                        "security", snippet.strip()[:160], None, owasp, cwe, tainted, hint, True,
                        confidence="Medium" if heuristic else "High")


def _args(text: str, m: "re.Match") -> str:
    return text[m.end():]


def _scan(code: str, lang: str) -> List[AgentFinding]:
    py = lang == "python"
    clean = strip_comments_py(code) if py else strip_comments_java(code)
    stmts = logical_lines(clean, braces=py)
    SRC = PY_SOURCES if py else JAVA_SOURCES
    tainted: Set[str] = set()
    sqlvars: Set[str] = set()
    path_vars: Set[str] = set()
    out: List[AgentFinding] = []
    add = lambda *a, **k: out.append(_f(*a, **k))  # noqa: E731
    file_has = lambda p: re.search(p, clean) is not None  # noqa: E731
    assign = re.compile(r"^\s*(?:final\s+)?(?:[\w<>\[\],.?]+\s+)?(\w+)\s*(\+?=)(?!=)\s*(.+)$", re.S)

    # route / controller handler parameters are user controlled
    for i, (ln, text) in enumerate(stmts):
        if py and re.match(r"\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)", text):
            prev = [s for _, s in stmts[max(0, i - 3):i] if s.strip().startswith("@")]
            if any(ROUTE_DEC.search(p) for p in prev):
                for a in re.match(r"\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)", text).group(1).split(","):
                    a = a.split(":")[0].split("=")[0].strip()
                    if a and a not in ("self", "cls"):
                        tainted.add(a)
        if not py:
            for m in re.finditer(r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|QueryParam|PathParam|FormParam|CookieValue)(?:\([^)]*\))?\s+(?:final\s+)?[\w<>\[\],.?]+\s+(\w+)", text):
                tainted.add(m.group(1))

    # access control: route handlers on sensitive paths with no auth check
    for i, (ln, text) in enumerate(stmts):
        if ROUTE_DEC.search(text) and SENSITIVE_PATH.search(text):
            k = i - 1
            before = []                                     # annotations stacked above the route annotation
            while k >= 0 and stmts[k][1].strip().startswith("@"):
                before.append(stmts[k][1]); k -= 1
            j, block = i + 1, [text] + before
            while j < len(stmts) and stmts[j][1].strip().startswith("@"):
                block.append(stmts[j][1]); j += 1
            sig = stmts[j][1] if j < len(stmts) else ""
            body = " ".join(s for _, s in stmts[j + 1:j + 12])
            if not AUTH_WORD.search(" ".join(block) + sig + body):
                add("BROKEN_ACCESS_CONTROL", ln, text, "Route looks sensitive but no authentication / authorization check was found.")

    cur_fn = ""
    for ln, text in stmts:
        s = text.strip()
        if not s:
            continue
        fm = re.match(r"(?:async\s+)?def\s+(\w+)", s) if py else re.match(r"(?:(?:public|private|protected|static|final|synchronized)\s+)*[\w<>\[\],.?]+\s+(\w+)\s*\([^)]*\)\s*(?:throws[^{]*)?\{", s)
        if fm and not re.match(r"(?:return|new|else|if|for|while|switch)\b", s):
            cur_fn = fm.group(1)
        # ---- taint propagation
        m = assign.match(s)
        if m and not s.startswith(("if ", "if(", "return", "for ", "while ", "elif ", "else")):
            name, op, rhs = m.groups()
            if has_taint(rhs, tainted, SRC):
                tainted.add(name)
            elif op == "=" and name in tainted:
                tainted.discard(name)
            if SQL_WORD.search(rhs) and is_dynamic(rhs):
                sqlvars.add(name)
            elif op == "+=" and name in sqlvars:
                pass
            elif op == "+=" and re.search(r"(?i)\b(select|insert|update|delete|where|and|or|from)\b", rhs) and re.search(r"\b(sql|query|stmt|statement|q)\b", name, re.I) and is_dynamic(rhs):
                sqlvars.add(name)
        tn = lambda expr: has_taint(expr, tainted, SRC)  # noqa: E731

        # ---- SQL injection
        sink = _sx(r"(?:\.|\b)(?P<fn>execute|executemany|executescript|raw|read_sql(?:_query)?|executeQuery|executeUpdate|executeLargeUpdate|prepareStatement|createQuery|createNativeQuery|queryForObject|queryForList|update|query)\s*\(", s)
        if sink and not re.match(r"\s*(?:def|public|private|protected)\b", s) and not (py and sink.group("fn") in ("update", "query")):
            first = first_arg(_args(s, sink))
            generic = sink.group("fn") in ("update", "query")
            var_hit = any(re.search(rf"(?<![\w.]){v}(?!\w)", first) for v in sqlvars)
            sql_text = bool(SQL_WORD.search(first))
            if (is_dynamic(first) and sql_text) or var_hit or (sql_text and tn(first)) or (not generic and tn(first) and re.fullmatch(r"\s*[\w.]+\s*", first)):
                add("SQL_INJECTION", ln, s, "SQL statement is assembled from variable data.", tainted=tn(first) or (var_hit and bool(tainted & sqlvars)))
        # ---- command injection
        m = _sx(r"\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:run|call|Popen|check_output|check_call|getoutput)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(", s)
        if m:
            rest = _args(s, m)
            shell = "shell=True" in rest.replace(" ", "")
            non_literal = not re.match(r"\s*[\"'][^\"']*[\"']\s*[,)]", rest)
            if py and m.group(0).startswith("os."):
                if (is_dynamic(rest) and not (SANITIZERS.search(rest) and not tn(rest))) or tn(rest) or shell or (non_literal and not SANITIZERS.search(rest)):
                    add("COMMAND_INJECTION", ln, s, "Shell command built from variable data.", tainted=tn(rest))
            elif not py and "exec" in m.group(0) and non_literal and not tn(rest) and not is_dynamic(rest):
                add("COMMAND_INJECTION", ln, s, "Runtime.exec() called with a variable command.")
            elif (shell and (is_dynamic(rest) or tn(rest))) or (not py and (is_dynamic(rest) or tn(rest))) or (py and not shell and tn(rest) and "[" not in rest.split(")")[0][:1]):
                add("COMMAND_INJECTION", ln, s, "Process started with variable data.", tainted=tn(rest))
            elif shell:
                add("COMMAND_INJECTION", ln, s, "shell=True runs the command through a shell.", score=6.5)
        # ---- code injection
        m = _sx(r"(?<![\w.])(?:eval|exec)\s*\(", s) if py else None
        if m and not s.startswith("def "):
            add("CODE_INJECTION", ln, s, f"{m.group(0).strip('( ')}() executes dynamic code.", tainted=tn(_args(s, m)))
        # ---- XSS / SSTI
        if py:
            m = _sx(r"\brender_template_string\s*\(", s)
            if m and (tn(_args(s, m)) or is_dynamic(_args(s, m))):
                add("SSTI", ln, s, "Template string built from variable data.", tainted=tn(_args(s, m)))
            m = _sx(r"\b(?:Markup|mark_safe|HttpResponse|make_response|Response)\s*\(|\|\s*safe\b", s)
            if m and HTML_WORD.search(s) and (is_dynamic(s) or tn(_args(s, m))) and tn(s):
                add("XSS", ln, s, "HTML response contains unescaped variable data.", tainted=True)
            elif re.match(r"\s*return\s", s) and HTML_WORD.search(s) and (is_dynamic(s)) and tn(s):
                add("XSS", ln, s, "HTML returned with unescaped variable data.", tainted=True)
        else:
            m = _sx(r"(?:getWriter\(\)|(?<![\w.])out|(?<![\w.])writer|getOutputStream\(\))\s*\.\s*(?:println|print|write|append|printf|format)\s*\(", s)
            if m and (tn(_args(s, m)) or (is_dynamic(_args(s, m)) and HTML_WORD.search(s))):
                add("XSS", ln, s, "Response written with unescaped variable data.", tainted=tn(_args(s, m)))
            elif re.match(r"\s*return\s", s) and HTML_WORD.search(s) and is_dynamic(s) and tn(s):
                add("XSS", ln, s, "HTML returned with unescaped variable data.", tainted=True)
        # ---- path traversal (a variable built from an already-flagged path is not reported twice)
        m = _sx(r"(?<![\w.])open\s*\(|\bsend_file\s*\(|\bsend_from_directory\s*\(|\bos\.path\.join\s*\(|\bPath\s*\(|new\s+File(?:InputStream|OutputStream|Reader|Writer)?\s*\(|\bPaths\.get\s*\(|\bFiles\.\w+\s*\(", s)
        if m and not re.match(r"\s*(?:def|public|private)\b", s):
            rest = _args(s, m)
            only_derived = bool(path_vars) and any(re.search(rf"(?<![\w.]){v}(?!\w)", rest) for v in path_vars) \
                and not SRC.search(rest) and not any(re.search(rf"(?<![\w.]){v}(?!\w)", rest) for v in tainted - path_vars)
            if not only_derived and (tn(rest) or (is_dynamic(rest) and "request" in rest)):
                add("PATH_TRAVERSAL", ln, s, "File path built from variable data.", tainted=True)
                am = assign.match(s)
                if am:
                    path_vars.add(am.group(1))
        # ---- SSRF & open redirect
        m = _sx(r"\b(?:requests|httpx|session)\.(?:get|post|put|delete|head|request)\s*\(|\burlopen\s*\(|\burllib\.request\.\w+\(|new\s+URL\s*\(|URI\.create\s*\(|HttpRequest\.newBuilder\(", s)
        if m and tn(_args(s, m)):
            add("SSRF", ln, s, "Outgoing request to a URL derived from variable data.", tainted=True)
        m = _sx(r"\bredirect\s*\(|sendRedirect\s*\(|RedirectView\s*\(", s)
        if m and tn(_args(s, m)):
            add("OPEN_REDIRECT", ln, s, "Redirect target derived from variable data.", tainted=True)
        # ---- deserialization
        if py:
            m = _sx(r"\b(?:pickle|cPickle|_pickle|dill|marshal|shelve)\.loads?\s*\(|\bjsonpickle\.decode\s*\(|\byaml\.(?:load|load_all|unsafe_load)\s*\(", s)
            if m and not (("yaml" in m.group(0)) and re.search(r"Safe\w*Loader|safe_load", s)):
                add("INSECURE_DESERIALIZATION", ln, s, "Untrusted data may be deserialized into objects.", tainted=tn(_args(s, m)))
        else:
            m = _sx(r"new\s+ObjectInputStream\s*\(|new\s+XMLDecoder\s*\(|new\s+Yaml\s*\(\s*\)\s*\.load|enableDefaultTyping\s*\(", s)
            if not m and re.search(r"\.readObject\s*\(\s*\)", s) and not file_has(r"new\s+ObjectInputStream"):
                m = _sx(r"\.readObject", s)          # stream created elsewhere (e.g. passed in)
            if m:
                add("INSECURE_DESERIALIZATION", ln, s, "Java deserialization of possibly untrusted data.", tainted=tn(s))
        # ---- hard-coded secrets
        m = SECRET_LIT.search(s) or SECRET_ARG.search(s)
        if m and not PLACEHOLDER.match(m.group(1)) and not re.search(r"os\.environ|getenv|getpass|System\.getenv|config\.", s) and not re.match(r"\s*(?:def|class|import)\b", s) \
           and not re.search(rf"(?i){SECRET_NAME}\w*\s*(?:==|!=)", s) and not re.search(r"(?i)(?:url|uri|path|file|name|header|field|prefix|param|label|type|endpoint)\w*\s*=", s.split("=")[0] + "=") :
            add("HARDCODED_SECRET", ln, s, "Credential is written into the source code.")
        elif SECRET_TOKENS.search(s):
            add("HARDCODED_SECRET", ln, s, "Key or token pattern found in the source code.")
        # ---- weak crypto
        if re.search(r"\bhashlib\.(?:md5|sha1)\s*\(|hashlib\.new\(\s*[\"'](?:md5|sha1)|MessageDigest\.getInstance\(\s*\"(?:MD5|MD2|SHA-?1)\"|Cipher\.getInstance\(\s*\"(?:DES|DESede|RC4|RC2|Blowfish|AES)(?:/ECB[^\"]*)?\"|AES\.MODE_ECB|\bDES\.new\(|\bARC4\.new\(|ARC4\.", s, re.I if False else 0):
            add("WEAK_CRYPTO", ln, s, "Broken or weak cryptographic primitive.")
        # ---- insecure random
        if re.search(r"\brandom\.(?:random|randint|choice|choices|randrange|getrandbits|sample)\s*\(|\bnew\s+Random\s*\(|\bMath\.random\s*\(", s) and SEC_CTX.search((s.split("=")[0] if "=" in s else s) + " " + cur_fn):
            add("INSECURE_RANDOM", ln, s, "Predictable random numbers used for a security value.")
        # ---- TLS
        if re.search(r"verify\s*=\s*False|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\(\s*\([^)]*\)\s*->\s*true|TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}", s):
            add("TLS_VERIFY_DISABLED", ln, s, "Certificate or hostname verification is turned off.")
        # ---- debug / csrf / cors / cookies
        if re.search(r"\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True|app\.debug\s*=\s*True|setDebug\(\s*true", s):
            add("DEBUG_ENABLED", ln, s, "Debug mode exposes internals and an interactive console.")
        if re.search(r"@csrf_exempt|WTF_CSRF_ENABLED[\"']?\s*(?:\]\s*)?=\s*False|csrf\.exempt|\.csrf\(\)\s*\.\s*disable\(\)|csrf\s*->\s*\w+\.disable\(\)|csrf\(\s*AbstractHttpConfigurer::disable\)|csrf\(\)\.disable", s):
            add("CSRF_DISABLED", ln, s, "CSRF protection is switched off.")
        if re.search(r"@CrossOrigin\s*(?:\(\s*\))?\s*$|origins\s*=\s*\"\*\"|allowedOrigins\(\s*\"\*\"|Access-Control-Allow-Origin[\"']?\s*[,:=]\s*[\"']\*|CORS\(\s*\w+\s*\)|origins\s*=\s*[\"']\*[\"']", s):
            add("PERMISSIVE_CORS", ln, s, "Any website may call this API from a browser.")
        if re.search(r"setHttpOnly\(\s*false|setSecure\(\s*false|(?:httponly|secure)\s*=\s*False|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False", s):
            add("INSECURE_COOKIE", ln, s, "Cookie flag disables a browser protection.")
        # ---- authentication
        if re.search(r"jwt\.decode\([^)]*(?:verify\s*=\s*False|verify_signature[\"']?\s*:\s*False)|algorithms\s*=\s*\[\s*[\"']none[\"']", s, re.I):
            add("INSECURE_AUTH", ln, s, "JWT signature is not verified.", score=9.1)
        elif re.search(r"(?i)\bpassword\w*\s*(?:==|!=)\s*[\w.]*(?:password|passwd|pwd)\w*|\bpassword\w*\.equals\(|\.equals\(\s*\w*(?:password|passwd|pwd)\w*\s*\)|\.getPassword\(\)\s*\.equals\(|(?:password|passwd|pwd)\w*\s*(?:==|!=)\s*\w+\.\w*(?:password|passwd|pwd)", s):
            add("INSECURE_AUTH", ln, s, "Password compared as plain text (not hashed / not constant time).")
        # ---- logging secrets
        if re.search(rf"(?i)\b(?:logging|logger|log|LOG|LOGGER)\.\w+\s*\(.*{SECRET_NAME}|\bprint\s*\(.*(?:password|passwd|secret|token)|System\.(?:out|err)\.print\w*\(.*(?:password|passwd|secret|token)", s) and not re.search(r"(?i)(?:invalid|missing|expired|reset|refresh)\s+token", s):
            add("SENSITIVE_LOGGING", ln, s, "A secret value is written to logs / console.")
        # ---- XXE
        m = re.search(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\s*\(|XMLReaderFactory\.createXMLReader|etree\.XMLParser\([^)]*resolve_entities\s*=\s*True", s)
        if m and not file_has(r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|ACCESS_EXTERNAL_DTD|setExpandEntityReferences\(\s*false|external-general-entities"):
            add("XXE", ln, s, "XML parser created without disabling external entities / DTDs.")
        # ---- misc
        if re.search(r"\btempfile\.mktemp\s*\(|File\.createTempFile\([^)]*\)\s*;?\s*$(?<!x)" if False else r"\btempfile\.mktemp\s*\(", s):
            add("INSECURE_TEMPFILE", ln, s, "mktemp() is vulnerable to race conditions.")
        if re.search(r"os\.chmod\([^)]*0o?777|chmod\([^)]*0o?666|PosixFilePermissions\.fromString\(\s*\"rwxrwxrwx\"|setWritable\(\s*true\s*,\s*false\s*\)", s):
            add("INSECURE_PERMISSIONS", ln, s, "File is writable by every user.")
    # dedupe (type, line)
    seen, uniq = set(), []
    for f in sorted(out, key=lambda f: -f.score):
        if (f.type, f.line) not in seen:
            seen.add((f.type, f.line)); uniq.append(f)
    return sorted(uniq, key=lambda f: f.line)


def run(code: str, language: str) -> List[AgentFinding]:
    return _scan(code, language)
