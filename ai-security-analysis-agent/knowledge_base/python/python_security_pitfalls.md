---
title: "Python Security Pitfalls for Code Review"
publisher: "Project team (original summary)"
source_url: "n/a - written for this project; informed by OWASP, PEP 8 and common static-analysis rules"
license: "Project documentation"
retrieved: "2026-10-15"
category: "security_pitfalls"
language: "python"
---

# Python Security Pitfalls for Code Review

## Code injection with eval and exec
Calling eval() or exec() on text that comes from a user, file or network lets an attacker run arbitrary Python. Use ast.literal_eval() for literal values, or parse input explicitly. Never build executable code from strings.

## Insecure deserialization (pickle, yaml, marshal)
pickle.load, pickle.loads and marshal can execute code while loading data. yaml.load() without a safe loader can also construct arbitrary objects. Use yaml.safe_load(), JSON, or a schema-validated format for untrusted data, and never unpickle data you did not create.

## OS command injection
os.system(), os.popen() and subprocess calls with shell=True combined with user input allow command injection. Pass the command as a list of arguments, keep shell=False, validate input against an allow-list, and use shlex.quote only as a last resort.

## SQL injection
Building SQL with f-strings, string concatenation or % formatting lets input change the query. Use parameterized queries: cursor.execute("SELECT * FROM users WHERE name = %s", (name,)). ORMs are safe only when values are bound as parameters.

## Hardcoded secrets
Passwords, API keys and tokens assigned to variables in source code leak through repositories and logs. Read them from environment variables or a secrets manager, never commit .env files, and rotate any secret that was committed.

## Weak hashing and randomness
hashlib.md5 and hashlib.sha1 are broken for security use. Store passwords with bcrypt, Argon2 or scrypt, never a plain fast hash. The random module is predictable; use the secrets module for tokens, session IDs and password reset links.

## Disabled certificate verification
requests.get(url, verify=False) turns off TLS certificate checks and exposes the connection to man-in-the-middle attacks. Keep verification on and supply a CA bundle if needed.

## Debug mode and assert
Running Flask or Django with debug enabled in production exposes an interactive debugger. Do not use assert for security or input validation: assertions are removed when Python runs with the -O flag.

## Insecure temporary files and paths
tempfile.mktemp() is race-prone; use tempfile.mkstemp() or NamedTemporaryFile(). For user-supplied file names, resolve the path and confirm it stays inside the intended directory to prevent path traversal.

## Swallowed exceptions
A bare except: or except Exception: pass hides failures, including security failures. Catch specific exceptions, log them without leaking sensitive data, and fail safely.
