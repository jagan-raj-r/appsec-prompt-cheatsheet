# AppSec Code Review Prompts

Welcome to the **AppSec Code Review Prompts** — a collection of ready-to-use security analysis prompts for comprehensive code reviews.

These prompts are designed to help **security engineers, developers, and analysts** conduct thorough, context-aware security reviews using AI (e.g., GPT-4, Claude, or other LLMs).

---

## 🔧 How to Use

1. **Choose a Prompt**: Select from general code review or OWASP Top 10 specific prompts
2. **Copy the Prompt**: Each `.md` file contains a complete, ready-to-use prompt
3. **Add Your Code**: Paste your code snippet in the designated section at the bottom
4. **Run Analysis**: Send the complete prompt + code to your preferred LLM (ChatGPT, Claude, etc.)
5. **Review Results**: Get structured vulnerability analysis with fixes and recommendations
6. **Apply Fixes**: Implement the suggested security improvements

---

## 🧠 Why This is Helpful

- ✅ **Context-Aware Analysis**: Understands code purpose first, then performs targeted security review
- ✅ **Reduced False Positives**: Focuses only on relevant vulnerabilities based on code functionality
- ✅ **Structured Output**: Consistent vulnerability tables with severity, impact, and fixes
- ✅ **Comprehensive Coverage**: Both general security and OWASP Top 10 specific analysis
- ✅ **Easy to Use**: Copy-paste prompts that work with any major LLM
- ✅ **Actionable Results**: Detailed remediation guidance and secure code examples

---

## 📦 Available Prompts

### 🔍 General Security Review
- [`code-review.md`](./code-review.md): **Context-aware comprehensive security analysis**
  - Understands code purpose before analyzing for vulnerabilities
  - Covers 10 major vulnerability categories
  - Reduces false positives through targeted analysis
  - Perfect for any codebase regardless of domain

### 🏆 OWASP Top 10 Specific
- [`owasp-top-10/`](./owasp-top-10): **Specialized prompts for specific vulnerability types**
  - Injection vulnerabilities (SQL, Command, etc.)
  - Cross-Site Scripting (XSS)
  - Broken Authentication & Authorization
  - Server-Side Request Forgery (SSRF)
  - Cryptographic Failures
  - Security Misconfiguration
  - And more...

---

## 🚀 Contribute

Want to improve security workflows using AI? 

- **Add new vulnerability-specific prompts** to the OWASP Top 10 collection
- **Enhance the general code review prompt** with additional security categories
- **Create domain-specific prompts** for mobile, cloud, or IoT security
- **Improve prompt effectiveness** through testing and community feedback

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for help getting started.

---

## 💡 Usage Tips

**For Best Results:**
- Provide context about your code's purpose when using the general prompt
- Use specific OWASP prompts when you suspect a particular vulnerability type
- Combine multiple prompts for comprehensive coverage of complex applications
- Review and verify all AI-generated findings before implementing fixes

**Token Optimization:**
- The general prompt is optimized for minimal token usage while maintaining thoroughness
- For large codebases, break into smaller, logical chunks for analysis
- Use the most specific prompt available for your use case

---

Secure smarter, not harder. 🔐🤖
