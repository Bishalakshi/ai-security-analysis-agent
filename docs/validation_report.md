# Detection accuracy validation - Milestone 2

Method: the Code Analysis and Security agents are run (through the orchestrator) over labelled Python and Java files.
Ground truth is an `EXPECT:` comment on the issue line. A finding is a true positive when its type matches and the labelled
line lies inside the finding's line span (+/- 1). Files without labels are clean negatives, so any finding there counts as a
false positive. Style-tier findings (missing docstrings, naming, console output, long lines, TODOs) are reported by the
agents but are not scored.

## Held-out set (`samples_holdout/`) - first run of the prototype, before any rule was changed

| Agent | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Code Analysis | 11 | 2 | 0 | 85% | 100% | 0.92 |
| Security | 12 | 1 | 0 | 92% | 100% | 0.96 |

The one Security false positive was a real bug (a protecting `@PreAuthorize` placed *above* the route annotation was ignored) and is fixed.
In this repository the Java analysis was ported from tree-sitter to `javalang` (already a project dependency). First run after the port:
Code Analysis 11 TP / 1 FP / 0 FN, Security 12 / 0 / 0. Two more gaps were then fixed (see the history table).

## Held-out set - current

| Agent | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Code Analysis | 12 | 1 | 0 | 92% | 100% | 0.96 |
| Security | 12 | 0 | 0 | 100% | 100% | 1.00 |

<details><summary>details</summary>

| File | Language | Labelled | TP | FP | FN |
|---|---|---|---|---|---|
| OrderApi.java | java | 4 | 4 | 1 | 0 |
| ReportService.java | java | 5 | 5 | 0 | 0 |
| batch_jobs.py | python | 7 | 7 | 0 | 0 |
| inventory_api.py | python | 8 | 8 | 0 | 0 |

| Agent : Type | TP | FP | FN |
|---|---|---|---|
| Code Analysis:BROAD_EXCEPT | 2 | 0 | 0 |
| Code Analysis:COMPARE_NONE | 1 | 0 | 0 |
| Code Analysis:DEEP_NESTING | 2 | 0 | 0 |
| Code Analysis:EMPTY_EXCEPT | 1 | 0 | 0 |
| Code Analysis:LONG_PARAMETER_LIST | 2 | 0 | 0 |
| Code Analysis:MAGIC_NUMBER | 2 | 1 | 0 |
| Code Analysis:MUTABLE_DEFAULT | 1 | 0 | 0 |
| Code Analysis:STRING_EQUALITY | 1 | 0 | 0 |
| Security:BROKEN_ACCESS_CONTROL | 1 | 0 | 0 |
| Security:COMMAND_INJECTION | 1 | 0 | 0 |
| Security:CSRF_DISABLED | 1 | 0 | 0 |
| Security:HARDCODED_SECRET | 1 | 0 | 0 |
| Security:INSECURE_DESERIALIZATION | 1 | 0 | 0 |
| Security:INSECURE_RANDOM | 2 | 0 | 0 |
| Security:SQL_INJECTION | 2 | 0 | 0 |
| Security:WEAK_CRYPTO | 2 | 0 | 0 |
| Security:XSS | 1 | 0 | 0 |

Misses: none

Wrong detections: `OrderApi.java`:59 MAGIC_NUMBER

</details>

## Tuning set (`samples/`) - current

| Agent | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Code Analysis | 44 | 0 | 0 | 100% | 100% | 1.00 |
| Security | 38 | 0 | 0 | 100% | 100% | 1.00 |

<details><summary>details</summary>

| File | Language | Labelled | TP | FP | FN |
|---|---|---|---|---|---|
| AdminController.java | java | 9 | 9 | 0 | 0 |
| LegacyInventory.java | java | 17 | 17 | 0 | 0 |
| SecureAccountRepository.java | java | 0 | 0 | 0 | 0 |
| UserServlet.java | java | 11 | 11 | 0 | 0 |
| legacy_report_generator.py | python | 23 | 23 | 0 | 0 |
| order_processing.py | python | 2 | 2 | 0 | 0 |
| secure_service.py | python | 0 | 0 | 0 | 0 |
| vulnerable_flask_app.py | python | 20 | 20 | 0 | 0 |

| Agent : Type | TP | FP | FN |
|---|---|---|---|
| Code Analysis:BARE_EXCEPT | 1 | 0 | 0 |
| Code Analysis:BROAD_EXCEPT | 3 | 0 | 0 |
| Code Analysis:COMPARE_NONE | 1 | 0 | 0 |
| Code Analysis:DEEP_NESTING | 2 | 0 | 0 |
| Code Analysis:DUPLICATE_CODE | 2 | 0 | 0 |
| Code Analysis:EMPTY_EXCEPT | 2 | 0 | 0 |
| Code Analysis:GLOBAL_STATE | 1 | 0 | 0 |
| Code Analysis:GOD_CLASS | 2 | 0 | 0 |
| Code Analysis:HIGH_COMPLEXITY | 3 | 0 | 0 |
| Code Analysis:LONG_FUNCTION | 1 | 0 | 0 |
| Code Analysis:LONG_PARAMETER_LIST | 2 | 0 | 0 |
| Code Analysis:MAGIC_NUMBER | 13 | 0 | 0 |
| Code Analysis:MUTABLE_DEFAULT | 1 | 0 | 0 |
| Code Analysis:PUBLIC_FIELD | 1 | 0 | 0 |
| Code Analysis:STRING_EQUALITY | 1 | 0 | 0 |
| Code Analysis:UNREACHABLE_CODE | 1 | 0 | 0 |
| Code Analysis:UNUSED_IMPORT | 5 | 0 | 0 |
| Code Analysis:WILDCARD_IMPORT | 2 | 0 | 0 |
| Security:BROKEN_ACCESS_CONTROL | 2 | 0 | 0 |
| Security:CODE_INJECTION | 1 | 0 | 0 |
| Security:COMMAND_INJECTION | 3 | 0 | 0 |
| Security:DEBUG_ENABLED | 1 | 0 | 0 |
| Security:HARDCODED_SECRET | 2 | 0 | 0 |
| Security:INSECURE_AUTH | 2 | 0 | 0 |
| Security:INSECURE_COOKIE | 1 | 0 | 0 |
| Security:INSECURE_DESERIALIZATION | 3 | 0 | 0 |
| Security:INSECURE_RANDOM | 2 | 0 | 0 |
| Security:OPEN_REDIRECT | 2 | 0 | 0 |
| Security:PATH_TRAVERSAL | 2 | 0 | 0 |
| Security:PERMISSIVE_CORS | 1 | 0 | 0 |
| Security:SENSITIVE_LOGGING | 2 | 0 | 0 |
| Security:SQL_INJECTION | 4 | 0 | 0 |
| Security:SSRF | 1 | 0 | 0 |
| Security:SSTI | 1 | 0 | 0 |
| Security:TLS_VERIFY_DISABLED | 2 | 0 | 0 |
| Security:WEAK_CRYPTO | 2 | 0 | 0 |
| Security:XSS | 3 | 0 | 0 |
| Security:XXE | 1 | 0 | 0 |

Misses: none

Wrong detections: none

</details>

## How the agents improved while validating

| Run | Code Analysis (TP / FP / FN) | Security (TP / FP / FN) | What was fixed |
|---|---|---|---|
| 1st run | 33 / 48 / 5 | 18 / 11 / 19 | - |
| 2nd run | 42 / 1 / 1 | 38 / 4 / 0 | Java class bodies were merged into one statement (wrong line numbers); f-strings containing quotes; secret in `config["KEY"]`; context of the enclosing function for random numbers; Java `.equals(password)`; bare `return 4.99` literals; wrong tolerance when matching nearest line |
| 3rd run | 44 / 0 / 0 | 38 / 0 / 0 | Tainted value used as a *bound parameter* was reported as SQL injection; `System.out` matched the XSS writer pattern; follow-on sinks of an already flagged path / deserialization were reported twice; words inside string literals counted as tainted variables |

| Port to this repo | 43 / 0 / 1 | 38 / 0 / 0 | `os.system(cmd)` / `Runtime.exec(cmd)` with a variable command were not reported; an unreachable statement directly after a method's opening brace was missed; a `catch (Exception e)` holding only a comment is now reported as a broad catch |
| Unit tests | - | - | Sanitised values (`shlex.quote`) inside a built string were still flagged; code-looking text *inside a string literal* triggered sinks |

Some labels and fixtures were corrected after review because the *fixture* was wrong, not the agent (for example code after a
non-returning `if` labelled as unreachable, accidental extra magic numbers in generated filler methods, a genuinely unused
import left unlabelled). Each of those edits was made after checking the code by hand, not to hide a miss.

## Honest limitations

* The tuning set (`samples/`) was written by the team and the agents were improved against it, so its 100% is **optimistic**.
  The held-out set (`samples_holdout/`) was written afterwards and first run without changes - treat it as the realistic figure.
* Both sets are small (about 80 labelled issues). Rules are pattern + light taint based: no inter-procedural analysis, no
  type information, no framework models. Obfuscated or cross-file flows are missed.
* Debatable calls: a radix literal such as `Long.toString(x, 36)` is reported as a magic number; `catch (Exception e)` with only a
  comment is reported as a broad catch.
* Recommended next step: validate on public labelled projects (e.g. OWASP Benchmark for Java, intentionally vulnerable Flask apps).
