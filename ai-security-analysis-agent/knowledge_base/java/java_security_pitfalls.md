---
title: "Java Security Pitfalls for Code Review"
publisher: "Project team (original summary)"
source_url: "n/a - written for this project; informed by OWASP, PEP 8 and common static-analysis rules"
license: "Project documentation"
retrieved: "2026-10-15"
category: "security_pitfalls"
language: "java"
---

# Java Security Pitfalls for Code Review

## SQL injection through Statement
Concatenating input into a query passed to java.sql.Statement lets an attacker change the SQL. Use PreparedStatement with ? placeholders and setString()/setInt(), or a JPA query with named parameters.

## OS command injection
Runtime.getRuntime().exec(command) and ProcessBuilder with user-controlled strings can run unintended commands. Avoid shelling out, pass arguments as separate list items, and validate input against an allow-list.

## Insecure deserialization
ObjectInputStream.readObject() on untrusted data can lead to remote code execution through gadget chains. Prefer JSON with explicit types, or configure an ObjectInputFilter allow-list.

## XML external entity (XXE) attacks
DocumentBuilderFactory, SAXParserFactory and XMLInputFactory may resolve external entities by default. Disable DTDs (for example, set the disallow-doctype-decl feature) and external entity processing.

## Weak hashing, ciphers and randomness
MessageDigest.getInstance("MD5") and "SHA-1" are weak. Store passwords with bcrypt, Argon2 or PBKDF2 with a salt. Avoid DES and AES in ECB mode; use AES-GCM. java.util.Random is predictable, so use java.security.SecureRandom for tokens and keys.

## Hardcoded credentials
String password = "..." or API keys inside source or properties files in the repository are exposed to anyone with code access. Load them from environment variables or a secrets manager.

## Trust-all TLS settings
A TrustManager that accepts every certificate, or a HostnameVerifier that always returns true, disables TLS protection. Use the default trust store.

## Information leakage and poor error handling
e.printStackTrace() and returning raw exception messages to users reveals internal details. Log errors with a logger, show generic messages to users, and never leave a catch block empty.

## Path traversal and file handling
Building file paths from user input allows ../ escapes. Normalize the path, check it starts with the allowed base directory, and validate uploaded file names and types.

## Resource leaks
Streams, connections and statements that are not closed can be abused for denial of service. Use try-with-resources so they are always closed.
