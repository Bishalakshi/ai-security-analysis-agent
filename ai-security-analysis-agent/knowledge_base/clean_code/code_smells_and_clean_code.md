---
title: "Code Smells and Clean Code Principles"
publisher: "Project team (original summary)"
source_url: "n/a - written for this project; informed by OWASP, PEP 8 and common static-analysis rules"
license: "Project documentation"
retrieved: "2026-10-15"
category: "code_quality"
language: "general"
---

# Code Smells and Clean Code Principles

## What a code smell is
A code smell is a surface sign in code that usually points to a deeper design problem. Smells are not bugs, but they make code harder to read, test and change.

## Common smells and fixes
Long method: a function that does too many things. Split it into smaller, well-named functions.
Duplicate code: the same logic copied in several places. Extract a shared function or class.
Large class (god object): one class with too many responsibilities. Split it by responsibility.
Long parameter list: many parameters are hard to use correctly. Group related values into an object.
Magic numbers and strings: unexplained literals. Replace them with named constants.
Deep nesting: many levels of if and loops. Use early returns and helper functions.
Dead code: unused variables, methods and imports. Delete them.
Poor naming: unclear names hide intent. Rename to describe purpose.
Feature envy: a method uses another class's data more than its own. Move it to that class.
Primitive obsession: using raw strings and numbers for domain concepts. Introduce small value types.

## Core principles
DRY: do not repeat yourself. KISS: keep it simple. YAGNI: do not build what you do not need yet.
SOLID: single responsibility, open for extension but closed for modification, Liskov substitution, interface segregation, and dependency inversion.

## Complexity guidance
Cyclomatic complexity counts independent paths through a function. Values above about 10 suggest the function should be simplified or split. Smaller functions are easier to test.

## Secure and clean together
Clear code is easier to audit for security. Validate input at boundaries, keep error handling explicit, and separate configuration and secrets from logic.
