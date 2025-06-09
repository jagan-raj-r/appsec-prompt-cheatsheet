# AppSec AI Prompt Cheat Sheet

As a Prompt Engineer specializing in Application Security (AppSec), here's a comprehensive cheat sheet of high-quality prompts that AppSec engineers can use to leverage AI in security assessments. These prompts are designed to enhance speed, depth, and accuracy, align with OWASP Top 10, and support both offensive (finding vulnerabilities) and defensive (remediation) approaches.

---

## General Principles for Effective Prompting:

* **Be Specific**: Vague prompts lead to generic and potentially insecure responses. Provide as much context as possible.
* **Define Role and Persona**: Tell the AI what role it should adopt (e.g., "You are an experienced AppSec engineer," "You are a malicious attacker").
* **Specify Output Format**: Clearly define how you want the response structured (e.g., "Provide a detailed report in markdown format," "List vulnerabilities with severity and remediation steps").
* **Provide Examples (Few-Shot Prompting)**: For complex tasks, including a few examples of desired input/output pairs can significantly improve the AI's accuracy and adherence to your style.
* **Iterate and Refine**: Start with a broad prompt and refine it based on the AI's initial responses.
* **Emphasize Security Requirements**: Explicitly mention secure coding best practices, OWASP Top 10, and relevant standards (e.g., PCI-DSS, SOC 2).
* **Context is King**: Provide snippets of code, system architecture diagrams (described in text), data flow, and business context.
* **Focus on Actionable Insights**: Request concrete findings, impact analysis, and clear remediation steps.

---

## 1. Code Review (Offensive & Defensive)

**Goal**: Identify vulnerabilities in source code and suggest secure coding practices.

### Offensive Prompts (Finding Vulnerabilities):

* **Prompt**: "Act as a penetration tester specializing in web application security. Analyze the following Java code snippet for potential vulnerabilities, focusing on OWASP Top 10 risks, specifically Injection, Broken Access Control, and Cross-Site Scripting (XSS). For each identified vulnerability, provide:
    1.  A brief description of the vulnerability.
    2.  The line number(s) in the code where it occurs.
    3.  A realistic exploitation scenario.
    4.  The potential impact on the application and user data.

    ```java
    // [Insert Java code snippet here, e.g., a servlet handling user input]
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'");
    ```
    **Scenario**: Login functionality where user input is directly concatenated into a SQL query."

* **Prompt**: "Review this Python Flask application code for potential insecure deserialization vulnerabilities (OWASP A8:2021 - Software and Data Integrity Failures) and suggest attack vectors. Pay close attention to any use of `pickle` or `yaml.load()`.

    ```python
    # [Insert Python Flask code snippet, e.g., a route handling serialized data]
    import pickle
    from flask import Flask, request
    app = Flask(__name__)

    @app.route('/deserialize', methods=['POST'])
    def deserialize_data():
        data = request.get_data()
        obj = pickle.loads(data)
        return "Deserialized object: " + str(obj)
    ```
    **Scenario**: An API endpoint that accepts serialized data from untrusted sources."

### Defensive Prompts (Remediation & Secure Coding):

* **Prompt**: "You are an experienced AppSec engineer. Given the following vulnerable PHP code snippet that is susceptible to SQL Injection, refactor it to implement secure coding practices using prepared statements and parameterized queries. Explain the security improvements.

    ```php
    // [Insert vulnerable PHP code snippet, e.g., a database query]
    $username = $_POST['username'];
    $password = $_POST['password'];
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = mysqli_query($conn, $query);
    ```
    **Explanation**: The current code directly interpolates user input into the SQL query, making it vulnerable to injection."

* **Prompt**: "Analyze the provided JavaScript code for client-side input validation and suggest improvements to prevent Cross-Site Scripting (XSS) attacks. Ensure that any suggested changes align with OWASP XSS Prevention Cheat Sheet guidelines (e.g., output encoding, input sanitization).

    ```javascript
    // [Insert JavaScript code snippet, e.g., a display function]
    function displayComment(comment) {
        document.getElementById('comments').innerHTML += '<p>' + comment + '</p>';
    }
    // Assume 'comment' comes from user input
    ```
    **Context**: A comment section where user-submitted content is displayed on the webpage."

* **Prompt**: "Review the following C# code for potential insecure direct object references (IDOR) (OWASP A4:2021 - Insecure Design). Propose a secure design pattern, such as using indirect references or proper authorization checks, to mitigate this vulnerability.

    ```csharp
    // [Insert C# code snippet, e.g., an API endpoint to retrieve user data]
    public ActionResult GetUserProfile(int userId)
    {
        // Directly fetching user profile based on user-supplied ID
        var userProfile = _dbContext.UserProfiles.FirstOrDefault(p => p.Id == userId);
        if (userProfile != null)
        {
            return View(userProfile);
        }
        return HttpNotFound();
    }
    ```
    **Scenario**: A web application where `userId` can be manipulated by an attacker to access other users' profiles."

---

## 2. Threat Modeling (Defensive)

**Goal**: Identify potential threats to a system during the design phase and propose mitigation strategies.

* **Prompt**: "You are a security architect. Perform a STRIDE threat model on the following system description. For each identified threat, suggest at least one mitigation strategy. Focus on the core components and data flows.
    **System Description**:
    A new e-commerce platform with the following components:
    * **Frontend**: ReactJS single-page application (SPA)
    * **Backend API**: Node.js Express application (RESTful)
    * **Database**: PostgreSQL (stores user data, product information, orders)
    * **Payment Gateway Integration**: Third-party API
    * **User Authentication**: JWT-based authentication
    * **Data Flow**: User interacts with SPA -> SPA calls Backend API -> Backend API interacts with Database and Payment Gateway.

    **Focus**: Identify threats related to Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege."

* **Prompt**: "Given the following user story, identify potential security risks from an attacker's perspective (offensive approach) and propose corresponding secure design principles (defensive approach).
    **User Story**: 'As a registered user, I want to be able to upload profile pictures to my account so that I can personalize my profile.'
    **Consider**: File upload vulnerabilities (e.g., malicious file types, oversized files), storage security, and privacy implications. Structure your response with identified risks and proposed mitigations."

* **Prompt**: "Analyze the data flow diagram described below and identify potential trust boundaries. For each trust boundary, enumerate possible security risks and suggest appropriate security controls based on the principle of least privilege and defense-in-depth.
    **Data Flow Description**:
    1.  User uploads a document through a web browser to a web server.
    2.  The web server validates the file type and size.
    3.  The validated file is then stored in an S3 bucket.
    4.  A separate microservice processes the file from the S3 bucket.
    5.  The processing microservice stores metadata about the file in a NoSQL database.

    **Considerations**: Network access, API access, storage access, and inter-service communication."

---

## 3. Vulnerability Analysis (Offensive & Defensive)

**Goal**: Analyze reported vulnerabilities, assess their impact, and provide remediation guidance.

### Offensive Prompts (Understanding Exploitation):

* **Prompt**: "Explain how a successful 'Broken Authentication' vulnerability (OWASP A7:2021) could be exploited in an application using session tokens. Provide a step-by-step attack scenario and the potential impact on user accounts and system integrity."

* **Prompt**: "Describe a 'Server-Side Request Forgery (SSRF)' vulnerability (OWASP A10:2021) in the context of a web application that fetches external resources. Provide an example of a malicious URL that an attacker might use and explain what kind of internal resources could be targeted.
    **Scenario**: An image resizing service that takes a URL as input."

### Defensive Prompts (Assessment & Remediation):

* **Prompt**: "You have been given a finding from a security scanner: 'CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting').' Provide a detailed analysis of this finding, including:
    1.  What is XSS and how does it manifest?
    2.  What is the potential impact if exploited (e.g., cookie theft, defacement)?
    3.  How can this vulnerability be remediated in a general web application context (e.g., input validation, output encoding, Content Security Policy)?
    4.  List common libraries or frameworks that offer built-in protections against XSS."

* **Prompt**: "An external penetration test report states a 'Critical' finding of 'Insecure Cryptographic Storage' (OWASP A2:2021 - Cryptographic Failures) related to password hashing. Advise on best practices for securely storing user passwords, considering salting, iteration count, and strong hashing algorithms. Suggest specific algorithms and their benefits."

* **Prompt**: "Given a vulnerability description indicating 'Insufficient Logging & Monitoring' (OWASP A9:2021), outline the key elements of a robust logging and monitoring strategy for a critical production application. Include types of events to log, where to store logs securely, and how to monitor for anomalous activities."

---

## 4. Secure Design (Defensive)

**Goal**: Integrate security principles into the software development lifecycle (SDLC) from the outset.

* **Prompt**: "You are designing a new microservice that will handle sensitive customer PII. Outline the secure design principles you would incorporate from the ground up to ensure data confidentiality, integrity, and availability. Focus on aspects like data encryption (at rest and in transit), access control mechanisms, input validation, and secure API design. Refer to relevant OWASP principles like 'Security by Design' and 'Least Privilege'."

* **Prompt**: "Propose a secure architecture for a new multi-tenant SaaS application. Address considerations for tenant isolation, data segregation, authentication, authorization, and secure communication channels between tenants and the platform. Emphasize how you would prevent one tenant from affecting or accessing another's data (OWASP A4:2021 - Insecure Design)."

* **Prompt**: "Describe the process for incorporating security requirements into the early stages of the SDLC for a new mobile application. How would you ensure security is 'shifted left' and not an afterthought? Include steps like security training for developers, threat modeling, and defining security acceptance criteria."

* **Prompt**: "Imagine you are building a new authentication service. Detail a secure authentication and session management design, focusing on mitigating common vulnerabilities like credential stuffing, brute-force attacks, and session hijacking (OWASP A7:2021 - Identification and Authentication Failures). Include elements like multi-factor authentication (MFA), strong password policies, secure cookie flags, and session invalidation."

---

## 5. SCA / Dependency Analysis (Offensive & Defensive)

**Goal**: Identify and manage risks associated with open-source and third-party components (libraries, frameworks, packages) in the software supply chain. Aligns with OWASP A6:2021 - Vulnerable and Outdated Components and A8:2021 - Software and Data Integrity Failures.

### Offensive Prompts (Finding Supply Chain Vulnerabilities):

* **Prompt**: "You are an attacker aiming to compromise an application by exploiting its supply chain. Given a `package.json` (Node.js) file, identify potential vulnerabilities related to outdated or known-vulnerable dependencies (OWASP A6:2021). Suggest specific dependencies that might be exploitable, their known CVEs, and a hypothetical attack vector.
    **`package.json` snippet**:
    ```json
    {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.20",
        "express": "^4.17.1",
        "moment": "^2.29.1",
        "json-schema": "0.2.3"
      }
    }
    ```
    **Context**: This is a simplified `package.json` from a web application."

* **Prompt**: "As a malicious actor, how would you attempt to inject a backdoor or malware into an application through a compromised open-source dependency? Describe the typical steps involved in such a 'Software and Data Integrity Failure' (OWASP A8:2021) attack, from compromising the legitimate dependency to the impact on the target application."

### Defensive Prompts (Mitigation & Best Practices):

* **Prompt**: "You are an AppSec engineer responsible for managing software supply chain risks. Outline a strategy for continuously identifying and remediating vulnerabilities in third-party and open-source components used in a CI/CD pipeline. Address how to:
    1.  Automate SCA scanning early in the SDLC ('shift left').
    2.  Prioritize findings based on exploitability and reachability (not just CVSS score).
    3.  Generate and maintain a Software Bill of Materials (SBOM).
    4.  Manage transitive dependencies.
    5.  Respond to newly disclosed CVEs for already deployed components.

    **Consider**: Tools like OWASP Dependency-Check, Snyk, Mend, JFrog Xray, etc."

* **Prompt**: "A recent critical vulnerability (e.g., Log4Shell - CVE-2021-44228) has been disclosed in a widely used Java library. As an AppSec professional, describe the immediate steps your team should take to identify if this vulnerability affects your applications, assess its impact, and implement remediation measures. Focus on processes that align with mitigating 'Vulnerable and Outdated Components' (OWASP A6:2021) and 'Software and Data Integrity Failures' (OWASP A8:2021)."

* **Prompt**: "Explain the importance of 'integrity verification' for downloaded software updates, libraries, and container images in the context of preventing supply chain attacks (OWASP A8:2021). Describe common methods for verifying integrity (e.g., digital signatures, cryptographic hashes) and how they should be integrated into a secure CI/CD pipeline and deployment process."

---

## 6. Policy, Documentation & Awareness (Defensive)

**Goal**: Establish and enforce security policies, create useful documentation, and foster a security-aware culture.

* **Prompt**: "You are an AppSec lead tasked with creating a new 'Secure Coding Policy' for your development teams. Outline the key sections and topics that this policy should cover, focusing on practical guidelines that align with OWASP Top 10 and secure by design principles. Include guidance on input validation, error handling, authentication, authorization, and cryptographic practices."

* **Prompt**: "Describe how to effectively integrate security documentation (e.g., threat models, security requirements, architecture diagrams with security zones) into existing development workflows and tools (e.g., Confluence, Jira, GitHub Wiki). What are the best practices to ensure this documentation remains current and accessible to both developers and security engineers?"

* **Prompt**: "Design a curriculum for a mandatory AppSec awareness training program for all software developers. What are the top 5 most critical AppSec concepts or vulnerabilities you would prioritize, and how would you make the training engaging and relevant to their daily work? Provide specific examples of how to explain complex vulnerabilities like SQL Injection or XSS in an understandable way."

* **Prompt**: "Draft a 'Security Incident Response Plan' snippet specifically for an application-level security breach (e.g., data exfiltration due to a web vulnerability). Focus on the initial detection, containment, eradication, recovery, and post-incident analysis steps, outlining who is responsible for each phase."

---

## 7. Fix and Hardening Guidance (Defensive)

**Goal**: Provide actionable guidance for fixing identified vulnerabilities and hardening application environments beyond code.

* **Prompt**: "A recent penetration test identified 'Insecure Configuration' (OWASP A5:2021) related to sensitive data exposure in your Nginx web server configuration. Provide precise Nginx configuration snippets and explanations to address common insecure configurations such as:
    1.  Directory listing enabled.
    2.  Missing security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options).
    3.  Weak TLS/SSL settings (outdated protocols, weak ciphers).
    4.  Overly permissive access to sensitive directories.

    **Context**: The application serves static files and acts as a reverse proxy for a backend API."

* **Prompt**: "You need to harden a Linux server running a critical web application. Provide a checklist of essential hardening steps, covering:
    1.  Operating system updates and patching.
    2.  User and access management (least privilege).
    3.  Network configurations (firewall rules).
    4.  Logging and auditing.
    5.  Service hardening (e.g., SSH, database).

    **Focus**: Practical, implementable steps that align with general security best practices."

* **Prompt**: "Describe the process for securely managing secrets (API keys, database credentials) within a cloud-native application deployed on Kubernetes. Focus on solutions like Kubernetes Secrets, Vault, or AWS Secrets Manager. Explain why storing secrets directly in code or environment variables is insecure and how these solutions provide better protection."

* **Prompt**: "Outline a strategy for securely patching and updating dependencies and application code in a production environment with minimal downtime. Include considerations for testing, rollback procedures, and communication with stakeholders. Emphasize how this mitigates 'Vulnerable and Outdated Components' (OWASP A6:2021)."

---

## 8. DAST / API Security (Offensive & Defensive)

**Goal**: Leverage AI for dynamic application security testing (DAST) insights and specific API security challenges.

### Offensive Prompts (Finding DAST/API Vulnerabilities):

* **Prompt**: "You are simulating a DAST scanner. Given the OpenAPI/Swagger definition of a REST API, identify potential attack surface areas for common API vulnerabilities (OWASP API Security Top 10, e.g., Broken Object Level Authorization, Broken Function Level Authorization, Mass Assignment, Excessive Data Exposure). For each identified area, describe a potential test case/payload.
    **OpenAPI Snippet (example)**:
    ```yaml
    paths:
      /users/{userId}:
        get:
          summary: Get user profile by ID
          parameters:
            - name: userId
              in: path
              required: true
              schema:
                type: integer
          responses:
            '200':
              description: User profile
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: integer
                      username:
                        type: string
                      email:
                        type: string
                      isAdmin: # Potential excessive data exposure or privilege escalation
                        type: boolean
    ```
    **Context**: Focus on common API logic flaws."

* **Prompt**: "As a DAST expert, explain how to automatically test a web application for 'Broken Access Control' (OWASP A1:2021) vulnerabilities, specifically focusing on horizontal and vertical privilege escalation. Describe the methodology, including how to manipulate session tokens, user IDs, and roles to bypass authorization checks. Provide a simplified pseudo-code example of a test scenario."

* **Prompt**: "Describe how to probe an API for 'NoSQL Injection' vulnerabilities, given that it interacts with a MongoDB backend. Provide examples of common NoSQL injection payloads that could bypass authentication or extract data, and explain the underlying principles."

### Defensive Prompts (DAST/API Remediation & Best Practices):

* **Prompt**: "You are designing a new RESTful API. Outline the essential security considerations for 'API Security' (referencing OWASP API Security Top 10). Cover topics such as:
    1.  Authentication and Authorization mechanisms (e.g., OAuth 2.0, JWT validation).
    2.  Input validation and sanitization for all API endpoints.
    3.  Rate limiting and throttling to prevent abuse.
    4.  Data encryption in transit (TLS) and at rest.
    5.  Logging and monitoring of API calls for suspicious activity.

    **Focus**: Preventative measures from the design phase."

* **Prompt**: "Explain the role of DAST (Dynamic Application Security Testing) in an AppSec program. What types of vulnerabilities is DAST best suited to find, and what are its limitations? How can DAST be integrated into a CI/CD pipeline to provide continuous security feedback without slowing down development?"

* **Prompt**: "Given an API endpoint that processes financial transactions, detail how to implement robust 'Broken Object Level Authorization' (OWASP API1:2023) and 'Broken Function Level Authorization' (OWASP API5:2023) controls. Provide a clear distinction between the two and present secure coding patterns (e.g., attribute-based access control, resource ownership checks) to prevent these flaws."

---

## 9. Bug Bounty / Offensive Use Cases (Offensive)

**Goal**: Generate prompts for offensive security research, bug bounty hunting, and advanced attack simulations.

* **Prompt**: "You are a bug bounty hunter targeting a modern web application that uses a GraphQL API. Suggest advanced enumeration and exploitation techniques for GraphQL, focusing on potential vulnerabilities like:
    1.  Information disclosure via introspection.
    2.  Rate limiting bypasses.
    3.  Mass assignment through mutations.
    4.  SQL Injection or other backend injection attacks via GraphQL arguments.

    Provide specific GraphQL query examples for each scenario."

* **Prompt**: "Given the following application description, identify uncommon or niche attack vectors that might lead to a high-severity bug in a bug bounty program. Think beyond OWASP Top 10 for novel attack paths.
    **Application Description**: A cloud-based image processing service that allows users to upload images, apply filters, and share them. It integrates with several third-party image libraries and uses a serverless architecture (AWS Lambda, S3, API Gateway).

    **Consider**: Image parsing vulnerabilities, serverless misconfigurations, side-channel attacks, or race conditions."

* **Prompt**: "You are conducting a red team exercise against an organization. The primary goal is to achieve remote code execution (RCE) on any internal server. Describe a multi-stage attack chain that starts from a typical web vulnerability (e.g., SSRF, file upload vulnerability) and escalates to RCE. Include potential pivots, lateral movement techniques, and post-exploitation steps."

* **Prompt**: "Generate a list of advanced reconnaissance techniques a bug bounty hunter could use to discover hidden API endpoints, subdomains, or unlisted functionalities of a target web application. Include methods like JavaScript analysis, WAF bypass techniques for enumeration, and open-source intelligence (OSINT) gathering."

---

## 10. Compliance & Policy Mapping (Defensive)

**Goal**: Leverage AI to assist in understanding, mapping, and demonstrating adherence to security standards and regulations.

* **Prompt**: "You are an AppSec compliance specialist. Given a set of security requirements from NIST SP 800-53 (e.g., AC-3 Access Enforcement, AU-2 Event Logging), explain how a modern microservices-based web application implemented in Node.js and deployed on AWS could meet these controls. Provide specific examples of code patterns, AWS services, and configurations that would satisfy each control."

* **Prompt**: "Our organization needs to achieve PCI-DSS compliance for a new payment processing module. Describe how AI can assist in the process of mapping application security controls (e.g., secure coding practices, vulnerability management) to specific PCI-DSS requirements (e.g., Requirement 6: Develop and Maintain Secure Systems and Software). How can AI help generate a compliance matrix or identify gaps?"

* **Prompt**: "Draft a high-level summary explaining the key differences and overlaps between the security requirements of GDPR and CCPA from an application development perspective. Focus on aspects like data privacy, consent management, data deletion, and data breach notification within the application logic itself."

* **Prompt**: "Given a set of application security findings from a recent penetration test, categorize and prioritize them based on their relevance and impact on achieving SOC 2 Type 2 compliance. For each critical finding, suggest remediation strategies that would specifically satisfy SOC 2 Trust Services Criteria (e.g., Security, Availability, Confidentiality)."

---

## 11. Vulnerability Prioritization & Remediation Planning (Defensive)

**Goal**: Use AI to intelligently prioritize vulnerabilities and create effective remediation plans.

* **Prompt**: "You are an AppSec analyst. Given the following list of vulnerabilities with their CVSS scores, provide a prioritized remediation plan. For each vulnerability, consider:
    1.  Its CVSS Base Score.
    2.  Its exploitability (simple vs. complex).
    3.  Its business impact (critical data, core functionality).
    4.  Whether it's reachable from an unauthenticated user.
    5.  Suggest specific, actionable remediation steps and the effort level (low, medium, high).

    **Vulnerability List**:
    -   SQL Injection (CVSS 9.8) in admin login page
    -   Reflected XSS (CVSS 6.1) in search function
    -   Outdated `lodash` library (CVSS 7.5, CVE-2020-28500)
    -   Missing HSTS header (CVSS 2.6)
    -   Insecure Direct Object Reference (CVSS 7.7) on user profile API (allows viewing other users' public profiles)

    **Output Format**: Prioritized list with rationale and remediation actions."

* **Prompt**: "Describe how AI can enhance a traditional vulnerability management program by providing context-aware prioritization. Specifically, how can an LLM incorporate factors beyond a standard CVSS score, such as attacker likelihood, asset criticality, and existing compensating controls, to offer a more nuanced risk assessment?"

* **Prompt**: "Given a detailed report for a critical server-side vulnerability (e.g., an RCE flaw), generate a comprehensive remediation plan that includes not only code fixes but also recommendations for:
    1.  Testing (unit, integration, security).
    2.  Deployment considerations (e.g., canary deployment, rollback).
    3.  Post-deployment monitoring.
    4.  Documentation updates.
    5.  Preventative measures to avoid similar issues in the future.

    **Context**: Assume a typical CI/CD environment."

---

## 12. Security Architecture Review & Pattern Analysis (Defensive)

**Goal**: Leverage AI to review and analyze system architectures for security weaknesses and recommend secure patterns.

* **Prompt**: "You are a cloud security architect. Analyze the following high-level architectural description for potential security flaws. Focus on common cloud security pitfalls related to network segmentation, access control, data storage, and inter-service communication. For each identified flaw, suggest a secure architectural pattern or AWS service to mitigate it.
    **Architecture Description**:
    A web application hosted on AWS. Frontend on S3/CloudFront. Backend API on EC2 instances in a public subnet with a public IP. RDS database also in a public subnet. No explicit network ACLs or security groups between components beyond default. API uses basic authentication.

    **Consider**: OWASP A5:2021 (Security Misconfiguration) and general cloud security best practices."

* **Prompt**: "Explain the concept of 'Zero Trust Architecture' in the context of a modern enterprise application moving from an on-premise monolithic application to a microservices architecture in the cloud. How would you apply Zero Trust principles to:
    1.  User and device authentication.
    2.  Network segmentation.
    3.  API authorization.
    4.  Data access.

    Provide practical examples."

* **Prompt**: "Given a description of a sensitive data flow through an application (e.g., processing credit card information), identify potential points of data exposure or tampering. Suggest secure design patterns and cryptographic controls (e.g., encryption, tokenization, secure multi-party computation) to protect the data at each stage (at rest, in transit, in use)."

* **Prompt**: "Analyze the provided diagram describing a secure software development lifecycle (SSDLC) and identify any missing security activities or potential bottlenecks. Suggest improvements to enhance the 'shift left' security posture.
    **SSDLC Description**:
    -   Requirements -> Design (Functional only) -> Coding -> Testing (Functional + QA) -> Deployment -> Pentest (one-off) -> Production.
    -   Security is primarily handled by the pentest team at the end.

    **Focus**: Incorporating security earlier and more continuously."

---

## 13. Secure SDLC Orchestration & Automation (AI-assisted)

**Goal**: Explore how AI can integrate and automate security processes within the Software Development Lifecycle.

* **Prompt**: "You are an expert in DevSecOps. Propose ways that AI/ML could be integrated into a CI/CD pipeline to enhance application security automation. Focus on:
    1.  Automated PR/code review for security flaws.
    2.  Intelligent vulnerability correlation and false positive reduction from SAST/DAST/SCA tools.
    3.  Automated generation of remediation code snippets for common vulnerabilities.
    4.  Predictive analysis of security risks based on code changes.

    **Consider**: How AI can augment existing tools, not replace them."

* **Prompt**: "Describe how AI can help customize and optimize static application security testing (SAST) rules for a specific codebase written in Java, reducing noise and improving accuracy. How can AI learn from previous false positives and true positives to refine future scan results?"

* **Prompt**: "Outline a process for using AI to monitor security configurations and policies across a fleet of cloud resources (e.g., AWS S3 buckets, EC2 security groups, Lambda functions) and automatically flag or even remediate deviations from established baselines. How can AI help in continuous compliance enforcement?"

* **Prompt**: "Explain how AI could be used to generate secure test cases or fuzzing inputs for APIs, beyond simple permutations. How can AI learn from API specifications (e.g., OpenAPI) and observed traffic to identify complex, multi-step attack scenarios or logic flaws that traditional fuzzing might miss?"

---

## 14. Privacy by Design & Data Protection (Defensive)

**Goal**: Integrate AI to assist in implementing privacy principles throughout the application lifecycle.

* **Prompt**: "You are a privacy engineer. Given a user story that involves collecting new personally identifiable information (PII) from users (e.g., 'As a user, I want to upload my government ID for verification'), identify the key 'Privacy by Design' principles that must be considered. For each principle (e.g., Data Minimization, Purpose Limitation, Transparency, Security), explain how it should be implemented in the application's design and code."

* **Prompt**: "Describe how an application can securely implement 'the right to be forgotten' (data erasure) as required by GDPR. Focus on the technical challenges for distributed systems and databases, and suggest a secure, auditable process for data deletion. Consider edge cases like backups and logs."

* **Prompt**: "Outline a strategy for automated data classification and labeling within an application's data stores (e.g., identifying PII, sensitive financial data, health data). How can AI help in this process, and how does accurate classification contribute to better data protection and access control policies?"

* **Prompt**: "Given a data breach scenario involving the exposure of user PII, how would an AI system assist the incident response team in assessing the scope of the breach, identifying affected users, and generating the necessary data breach notification reports, while adhering to regulatory requirements (e.g., GDPR, CCPA)?"

---

### How to use this `.md` file:

1.  **Copy the entire content** within the ````markdown` and ```` tags above.
2.  **Open a plain text editor** on your computer (e.g., Notepad, TextEdit, VS Code, Sublime Text).
3.  **Paste the copied content** into the editor.
4.  **Save the file** with a `.md` extension (e.g., `AppSec_AI_Prompts_Extended.md`).
5.  **Ensure you save it as "Plain Text"** to prevent any unwanted formatting.

This comprehensive version should provide a wealth of high-quality prompts for a wide range of AppSec activities!
