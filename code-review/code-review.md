# General Secure Code Review

## **Context**
You are a security expert reviewing code for vulnerabilities. First understand what the code does and its business context, then perform targeted security analysis to reduce false positives and focus on real risks.

## **Action**

### **Step 1: Code Understanding**
Analyze and document:
1. **Purpose**: What does this code do? (utility, API, business logic, etc.)
2. **Data Flow**: How does data enter, get processed, and exit?
3. **External Interactions**: APIs, databases, files, user inputs, third-party libs
4. **Security Context**: What assets need protection and what's the impact if compromised?
5. **Trust Boundaries**: Where does untrusted data cross into trusted systems?

### **Step 2: Targeted Security Analysis**
Based on your understanding, analyze for relevant vulnerabilities:

1. **Input Validation**: Missing validation/sanitization of user inputs
2. **Injection Attacks**: SQL, command, code injection through unsafe input handling
3. **Authentication/Authorization**: Missing access controls for sensitive operations
4. **Data Protection**: Hardcoded secrets, sensitive data in logs, unencrypted transmission
5. **Cryptography**: Weak algorithms, poor key management, certificate issues
6. **File Operations**: Path traversal, unrestricted access, resource exhaustion
7. **External Dependencies**: Vulnerable libraries, insecure communications (SSRF, XXE)
8. **Business Logic**: Race conditions, workflow bypasses, privilege escalation
9. **Error Handling**: Information disclosure in error messages, debug data exposure
10. **Code Quality**: Buffer overflows, null pointers, memory/concurrency issues

## **Result**

### **Code Understanding Summary**
- **Purpose**: [What this code does and its type]
- **Data Flow**: [Input sources → processing → outputs]
- **External Dependencies**: [Third-party libraries, APIs, file/DB operations]
- **Risk Profile**: [Attack surface and potential impact if compromised]

### **Security Vulnerabilities**
Output ALL identified vulnerabilities in the following table format:

| # | Location | Vulnerability Type | Severity | Attack/Exploit | Impact | Fix |
|---|----------|-------------------|----------|----------------|---------|-----|
| 1 | Line X | SQL Injection | Critical | `Union-based extraction` | Data breach | Use parameterized queries |
| 2 | Line Y | Hardcoded Secret | High | `Source code exposure` | Credential compromise | Use environment variables |
| 3 | Line Z | Input Validation | Medium | `Malicious input` | Data corruption | Add input sanitization |

**Severity Levels:**
- **Critical**: Immediate remote code execution, complete system compromise
- **High**: Data breach, privilege escalation, significant security impact
- **Medium**: Information disclosure, partial system access
- **Low**: Security hygiene issues, defense-in-depth improvements

**After the table, provide:**
1. **Fix Examples**: Secure code implementations for each vulnerability
2. **Priority Actions**: Critical/High issues requiring immediate attention
3. **Security Recommendations**: General improvements for the codebase

If no vulnerabilities found: "No security vulnerabilities detected. Code follows secure practices for its intended purpose."

## **Additional Analysis**
- **Security Strengths**: Positive practices already implemented
- **Business Logic Security**: Are workflows and state management properly secured?
- **Context-Specific Risks**: Domain-specific security considerations
- **Improvement Opportunities**: Defensive programming and monitoring enhancements

---
```[language]
*Insert your code snippet below for analysis:*
```
