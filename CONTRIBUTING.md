# Contributing to AppSec Prompt Cheatsheet

Thank you for your interest in contributing to the AppSec Prompt Cheatsheet! This project aims to provide high-quality, context-aware security analysis prompts for the community.

## 🚀 Ways to Contribute

### 1. **New Security Prompts**
- Add prompts for specific vulnerability types
- Create domain-specific security analysis prompts (mobile, cloud, IoT)
- Develop specialized prompts for different programming languages

### 2. **Improve Existing Prompts**
- Enhance prompt clarity and effectiveness
- Add more comprehensive vulnerability coverage
- Optimize prompts for better token efficiency
- Fix bugs or inaccuracies in existing prompts

### 3. **Documentation & Examples**
- Add usage examples and case studies
- Improve README files and documentation
- Create guides for specific use cases
- Add screenshots or demo videos

### 4. **Testing & Validation**
- Test prompts against real-world code samples
- Validate prompt effectiveness and accuracy
- Report false positives or missed vulnerabilities
- Share feedback on prompt performance

## 📝 Contribution Guidelines

### **Creating New Prompts**

#### Structure Requirements
All security analysis prompts should follow this structure:

```markdown
# [Vulnerability Type] Analysis

## **Context**
Brief description of the security expert role and focus area.

## **Action** 
Clear instructions on what to analyze and look for.

## **Result**
Expected output format with structured table and additional analysis.

---
```[language]
*Insert your code snippet below for analysis:*
```
```

#### Quality Standards
- **Context-Aware**: Prompts should understand code purpose before analysis
- **Specific & Actionable**: Clear vulnerability identification and fix guidance  
- **False Positive Reduction**: Focus only on relevant risks for the code type
- **Consistent Format**: Use standardized vulnerability tables and severity levels
- **Token Efficient**: Optimize for minimal token usage while maintaining quality

### **OWASP Top 10 Specific Prompts**

When adding OWASP-specific prompts:
- Follow the existing format in `/code-review/owasp-top-10/`
- Focus on one specific vulnerability category per prompt
- Include comprehensive coverage of sub-types (e.g., SQL injection, NoSQL injection)
- Provide detailed attack scenarios and remediation examples

### **General Code Review Enhancements**

For improvements to the main code review prompt:
- Maintain the two-step approach (understand first, then analyze)
- Keep the 10 core vulnerability categories balanced
- Ensure cross-language applicability
- Test against diverse code samples

## 🔧 Getting Started

### **1. Fork & Clone**
```bash
git clone https://github.com/[your-username]/appsec-prompt-cheatsheet.git
cd appsec-prompt-cheatsheet
```

### **2. Create Your Changes**
- Create a new branch: `git checkout -b feature/new-prompt-name`
- Add your prompt following the structure guidelines
- Update relevant README files
- Test your prompt with real code samples

### **3. Submit Your Contribution**
- Commit with clear messages: `git commit -m "Add: XSS analysis prompt for React applications"`
- Push to your fork: `git push origin feature/new-prompt-name`
- Create a Pull Request with detailed description

## ✅ Pull Request Checklist

Before submitting, ensure:

- [ ] **Prompt follows standard structure** (Context → Action → Result)
- [ ] **Includes comprehensive vulnerability coverage** for the target area
- [ ] **Provides clear, actionable remediation guidance**
- [ ] **Is tested against sample code** and produces relevant results
- [ ] **README files are updated** to include the new prompt
- [ ] **Commit messages are descriptive** and follow conventional format
- [ ] **No sensitive information** is included in examples

## 📊 Testing Your Prompts

### **Quality Validation**
Test your prompts against:
- **Vulnerable code samples** (should detect issues)
- **Secure code samples** (should have minimal false positives)
- **Edge cases** (unusual but valid code patterns)
- **Different programming languages** (if applicable)

### **Effectiveness Metrics**
Consider these when evaluating prompt quality:
- **True Positive Rate**: Correctly identifies real vulnerabilities
- **False Positive Rate**: Minimizes incorrect vulnerability reports
- **Actionability**: Provides useful, implementable fixes
- **Coverage**: Comprehensive analysis of the security domain

## 🎯 Current Priorities

We're particularly interested in contributions for:

### **High Priority**
- Mobile application security prompts (iOS/Android)
- Cloud security configuration analysis
- Container and Kubernetes security
- GraphQL security analysis
- Modern framework-specific prompts (React, Vue, Angular)

### **Medium Priority**
- Legacy system security analysis
- Infrastructure as Code (IaC) security
- Blockchain/Smart contract security
- API security beyond REST

### **Documentation**
- Usage examples for complex scenarios
- Integration guides for CI/CD pipelines
- Best practices for prompt engineering in security

## 💬 Community & Support

### **Getting Help**
- Open an issue for questions about contributing
- Check existing issues before creating new ones
- Tag issues appropriately (`enhancement`, `bug`, `documentation`, etc.)

### **Code of Conduct**
- Be respectful and constructive in all interactions
- Focus on the security value and technical merit of contributions
- Help newcomers learn and contribute effectively
- Maintain professional, collaborative communication

## 🏆 Recognition

Contributors will be:
- Listed in repository contributors
- Credited in relevant documentation
- Recognized for significant contributions in release notes

## 📈 Roadmap Contributions

Interested in larger contributions? Check our roadmap for:
- Integration with popular security tools
- Automated testing frameworks for prompts
- Multi-language support and localization
- Enterprise-focused security analysis prompts

---

**Ready to contribute?** Start with a small improvement or new prompt, and help make application security analysis more effective for everyone! 🔐

For questions, open an issue or reach out to the maintainers.
