# AppSec AI Prompt Cheat Sheet

As a Prompt Engineer specializing in Application Security (AppSec), here's a comprehensive cheat sheet of high-quality prompts to leverage AI in security assessments. These prompts are designed to enhance speed, depth, and accuracy, align with OWASP Top 10, and support both offensive (finding vulnerabilities) and defensive (remediation) approaches.

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
* **Prompt**: "You are an attacker aiming to compromise an application by exploiting its supply chain. Given a package.json (Node.js) file, identify potential vulnerabilities related to outdated or known-vulnerable dependencies (OWASP A6:2021). Suggest specific dependencies that might be exploitable, their known CVEs, and a hypothetical attack vector.
package.json snippet:

    ```JSON
    {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.20",
        "express": "^4.17.1",
        "moment": "^2.29.1",
        "json-schema": "0.2.3"
      }
    }```
* **Context**: This is a simplified package.json from a web application."

* **Prompt**: "As a malicious actor, how would you attempt to inject a backdoor or malware into an application through a compromised open-source dependency? Describe the typical steps involved in such a 'Software and Data Integrity Failure' (OWASP A8:2021) attack, from compromising the legitimate dependency to the impact on the target application."

### Defensive Prompts (Mitigation & Best Practices):
* **Prompt**: "You are an AppSec engineer responsible for managing software supply chain risks. Outline a strategy for continuously identifying and remediating vulnerabilities in third-party and open-source components used in a CI/CD pipeline. Address how to:

Automate SCA scanning early in the SDLC ('shift left').
Prioritize findings based on exploitability and reachability (not just CVSS score).
Generate and maintain a Software Bill of Materials (SBOM).
Manage transitive dependencies.
Respond to newly disclosed CVEs for already deployed components.
Consider: Tools like OWASP Dependency-Check, Snyk, Mend, JFrog Xray, etc."

* **Prompt**: "A recent critical vulnerability (e.g., Log4Shell - CVE-2021-44228) has been disclosed in a widely used Java library. As an AppSec professional, describe the immediate steps your team should take to identify if this vulnerability affects your applications, assess its impact, and implement remediation measures. Focus on processes that align with mitigating 'Vulnerable and Outdated Components' (OWASP A6:2021) and 'Software and Data Integrity Failures' (OWASP A8:2021)."

* **Prompt**: "Explain the importance of 'integrity verification' for downloaded software updates, libraries, and container images in the context of preventing supply chain attacks (OWASP A8:2021). Describe common methods for verifying integrity (e.g., digital signatures, cryptographic hashes) and how they should be integrated into a secure CI/CD pipeline and deployment process."

---
