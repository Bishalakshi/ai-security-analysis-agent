---
title: "Java Code Quality Checklist"
publisher: "Project team (original summary)"
source_url: "n/a - written for this project; informed by OWASP, PEP 8 and common static-analysis rules"
license: "Project documentation"
retrieved: "2026-10-15"
category: "code_quality"
language: "java"
---

# Java Code Quality Checklist

## Naming and formatting
Use PascalCase for classes, camelCase for methods and variables, and UPPER_SNAKE_CASE for constants. Keep one top-level class per file and use consistent braces and indentation. Choose names that describe intent.

## String comparison and equality
Compare strings with equals(), not ==. When overriding equals(), also override hashCode() so objects behave correctly in hash-based collections.

## Resource management
Use try-with-resources for streams, connections and statements so they close automatically. Unclosed resources cause leaks.

## Null handling
Return empty collections instead of null. Use Optional for values that may be absent, and check parameters with Objects.requireNonNull. Avoid chains of calls that can throw NullPointerException.

## Exceptions
Do not catch Exception or Throwable broadly, and never leave a catch block empty. Preserve the cause when wrapping exceptions. Do not use exceptions for normal control flow.

## Performance and readability
Use StringBuilder instead of string concatenation inside loops. Avoid magic numbers by using named constants. Prefer interfaces such as List over concrete types in declarations.

## Class and method design
Keep methods short and focused. Reduce the number of parameters and the depth of nesting. Prefer composition over inheritance, keep fields private, and make classes immutable where possible with final fields.

## Switch statements and flow
Always include a default case or exhaustive handling in switch statements. Avoid fall-through unless clearly commented.

## Dead code and warnings
Remove unused imports, variables and private methods. Fix compiler and static-analysis warnings (for example from PMD or SpotBugs) rather than suppressing them.

## Documentation
Write Javadoc for public classes and methods that explains behavior, parameters and exceptions.
