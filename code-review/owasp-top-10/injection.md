# Injection Vulnerability Analysis (OWASP A03:2021)

## **Context**
You are a security expert reviewing code for ALL types of injection vulnerabilities. Scan for SQL, NoSQL, LDAP, OS Command, XML, XPath, Template, Server-Side Template Injection (SSTI), and any other injection flaws where user input reaches interpreters without proper sanitization.

## **Action**
Comprehensively analyze the provided code and identify:
1. **SQL Injection**: Dynamic queries, string concatenation, ORM misuse
2. **NoSQL Injection**: MongoDB, CouchDB, Redis query manipulation  
3. **OS Command Injection**: System calls, shell execution, file operations
4. **LDAP Injection**: Directory service queries with user input
5. **XML/XPath Injection**: XML parsers, XPath queries
6. **Template Injection**: Server-side template engines (Jinja2, Twig, etc.)
7. **Code Injection**: eval(), exec(), dynamic code execution
8. **Header Injection**: HTTP headers, email headers
9. **Other Context-Specific Injections**: Based on the code framework/language

## **Result**
Output ALL vulnerabilities in the following table format:

| # | Location | Vulnerability Type | Severity | Exploit/Payload | Impact | Fix |
|---|----------|-------------------|----------|-----------------|---------|-----|
| 1 | Line X | SQL Injection | Critical | `payload here` | What attacker gains | Secure solution |
| 2 | Line Y | Command Injection | High | `payload here` | What attacker gains | Secure solution |

**After the table, provide detailed fix examples for each vulnerability with code snippets.**

If no vulnerabilities found, state: "No injection vulnerabilities detected."

---
```[language]
*Insert your code snippet below for analysis:*
```