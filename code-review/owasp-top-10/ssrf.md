# Server-Side Request Forgery (SSRF) Analysis (OWASP A10:2021)

## **Context**
You are a security expert reviewing code for Server-Side Request Forgery (SSRF) vulnerabilities. Focus on server-side HTTP requests that can be manipulated by attackers to access internal resources, cloud metadata, or perform port scanning and network reconnaissance.

## **Action**
Comprehensively analyze the provided code and identify:
1. **URL Parameter Manipulation**: User-controlled URLs in server-side requests
2. **Internal Resource Access**: Requests that can target internal/private IP ranges
3. **Cloud Metadata Access**: Access to cloud provider metadata services (AWS, GCP, Azure)
4. **Port Scanning**: Using the server to scan internal network ports
5. **File Protocol Abuse**: Local file access through file:// protocol
6. **Redirect Following**: Unvalidated redirect following leading to SSRF
7. **DNS Rebinding**: Attacks using DNS resolution manipulation
8. **Blind SSRF**: No direct response but server-side effects (timing, errors)
9. **Protocol Smuggling**: Using different protocols (ftp, gopher, dict) for attacks
10. **Webhook/Callback SSRF**: User-controlled webhook URLs without validation

## **Result**
Output ALL vulnerabilities in the following table format:

| # | Location | Vulnerability Type | Severity | Attack/Exploit | Impact | Fix |
|---|----------|-------------------|----------|----------------|---------|-----|
| 1 | Line X | URL Parameter SSRF | Critical | `Internal service access` | Data exposure, RCE | URL validation and whitelist |
| 2 | Line Y | Cloud Metadata SSRF | Critical | `AWS metadata access` | Credential theft | Block metadata IPs |

**After the table, provide detailed fix examples for each vulnerability with secure implementations.**

If no vulnerabilities found, state: "No SSRF vulnerabilities detected."


---
```[language]
*Insert your code snippet below for analysis:*
```
