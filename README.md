# AppSec Prompt Cheatsheet

A comprehensive collection of ready-to-use security analysis prompts for AI-powered code reviews and vulnerability assessments. This repository provides both general security analysis and OWASP Top 10 specific prompts designed to help security engineers, developers, and analysts conduct thorough, context-aware security reviews.

## 🚀 Quick Start

### **For Code Reviews**
1. **General Analysis**: Use [`code-review/code-review.md`](./code-review/code-review.md) for comprehensive, context-aware security analysis
2. **Specific Vulnerabilities**: Use prompts in [`code-review/owasp-top-10/`](./code-review/owasp-top-10/) for targeted analysis
3. **Copy & Paste**: Each prompt is ready to use with any major LLM (ChatGPT, Claude, etc.)

### **Key Features**
- ✅ **Context-Aware Analysis**: Understands code purpose before analyzing for vulnerabilities
- ✅ **Reduced False Positives**: Focuses only on relevant risks for the code type
- ✅ **Structured Output**: Consistent vulnerability tables with severity and fixes
- ✅ **Token Optimized**: Efficient prompts that minimize cost while maintaining quality
- ✅ **Comprehensive Coverage**: Both general security and OWASP Top 10 specific analysis

---

## 📦 Available Prompt Collections

### 🔍 **General Security Code Review**
**File**: [`code-review/code-review.md`](./code-review/code-review.md)

The flagship prompt that provides comprehensive security analysis through a two-step approach:
1. **Understanding Phase**: Analyzes code purpose, business logic, and data flow
2. **Security Analysis**: Performs targeted vulnerability assessment based on context

**Best For**: Any codebase, any programming language, reducing false positives

### 🏆 **OWASP Top 10 Specific Prompts**
**Folder**: [`code-review/owasp-top-10/`](./code-review/owasp-top-10/)

Specialized prompts for deep-dive analysis of specific vulnerability types:
- Injection Vulnerabilities (SQL, Command, etc.)
- Cross-Site Scripting (XSS)
- Broken Authentication & Authorization
- Server-Side Request Forgery (SSRF)
- Cryptographic Failures
- Security Misconfiguration
- And more...

**Best For**: When you suspect specific vulnerability types or need focused analysis

---

## 💡 Usage Examples

### **General Code Review**
```markdown
# Copy the entire content from code-review/code-review.md
# Add your code snippet at the bottom
# Send to your preferred LLM
```

### **Specific Vulnerability Analysis**
```markdown
# Copy content from code-review/owasp-top-10/injection.md
# Add your code snippet
# Get targeted injection vulnerability analysis
```

---

## 🎯 Best Practices

* **Be Specific**: Provide as much context as possible about your code's purpose and environment
* **Define Clear Roles**: Tell the AI what perspective to take (security expert, penetration tester, etc.)
* **Request Structured Output**: Use the provided table formats for consistent, actionable results
* **Provide Context**: Include information about the application domain and business logic
* **Iterate and Refine**: Start with the general prompt, then use specific OWASP prompts for deep dives
* **Verify Results**: Always review and validate AI-generated security findings

---

## 🚀 Contributing

We welcome contributions! See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for guidelines on:
- Adding new vulnerability-specific prompts
- Enhancing existing prompts for better accuracy
- Creating domain-specific security analysis prompts
- Improving documentation and examples

**Priority Areas**: Mobile security, cloud configuration analysis, GraphQL security, modern frameworks

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

## 🌟 Community & Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Join community discussions for prompt engineering tips
- **Pull Requests**: Contribute new prompts or improvements
- **Security Research**: Share findings and improvements

---

<div align="center">

**Star ⭐ this repository if you find it helpful!**

Made with ❤️ for the AppSec community

[🚀 Get Started](./code-review/code-review.md) | [📖 Documentation](./code-review/README.md) | [🤝 Contribute](./CONTRIBUTING.md)

</div>