---
title: "Python Code Quality Checklist"
publisher: "Project team (original summary)"
source_url: "n/a - written for this project; informed by OWASP, PEP 8 and common static-analysis rules"
license: "Project documentation"
retrieved: "2026-10-15"
category: "code_quality"
language: "python"
---

# Python Code Quality Checklist

## Naming and style (PEP 8)
Use snake_case for functions and variables, PascalCase for classes, and UPPER_CASE for constants. Use 4 spaces per indent and keep lines near 79-99 characters. Choose descriptive names instead of single letters or abbreviations.

## Mutable default arguments
A default such as def add(item, items=[]) is created once and shared between calls. Use None as the default and create the list inside the function.

## Resource handling
Open files with a with statement so they are always closed. Use context managers for locks, connections and temporary resources.

## Exceptions
Avoid bare except: clauses and broad except Exception that hide bugs. Catch specific exceptions, and raise meaningful errors. Do not use exceptions for ordinary control flow.

## Comparisons and idioms
Compare to None with is None, not == None. Use enumerate() instead of manual index counters, zip() to iterate in parallel, and join() instead of concatenating strings in a loop. Prefer comprehensions when they stay readable.

## Function design
Keep functions short and focused on one job. Avoid more than about four or five parameters, deep nesting and flag arguments. Return early to reduce nesting. Avoid hidden global state.

## Documentation and typing
Write docstrings for public modules, classes and functions (PEP 257). Add type hints to make interfaces clear and let tools catch mistakes.

## Imports and dead code
Remove unused imports and variables. Group imports as standard library, third party, then local. Avoid wildcard imports such as from module import *.

## Logging
Use the logging module instead of print() for diagnostics, with appropriate levels, and do not log secrets.
