# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-09-29

### Added
- **General Security Code Review Prompt** - Context-aware comprehensive security analysis
  - Two-step approach: understand code first, then analyze for vulnerabilities
  - Covers 10 major vulnerability categories
  - Token-optimized for cost efficiency
  - Reduces false positives through targeted analysis
- **OWASP Top 10 Specific Prompts** collection for deep-dive vulnerability analysis
  - Injection vulnerabilities (SQL, Command, etc.)
  - Cross-Site Scripting (XSS)
  - Broken Authentication & Authorization  
  - Server-Side Request Forgery (SSRF)
  - Cryptographic Failures
  - Security Misconfiguration
  - And more specialized prompts
- **Comprehensive Documentation**
  - Updated README with quick start guide
  - Code review specific documentation
  - Contribution guidelines
  - MIT License
- **Repository Structure**
  - Organized code-review/ folder with general and OWASP-specific prompts
  - Clear separation between general analysis and targeted vulnerability assessment

### Changed
- **Restructured Repository** from comprehensive prompt examples to focused code review tools
- **Updated Main README** to highlight new structure and key features
- **Optimized Prompts** for better token efficiency while maintaining quality

### Documentation
- Added CONTRIBUTING.md with detailed contribution guidelines
- Created structured prompt format requirements
- Added usage examples and best practices
- Included community guidelines and support information

---

## Release Notes

### v1.0.0 - Initial Release
This release marks the transformation of the AppSec Prompt Cheatsheet into a focused, production-ready collection of security analysis prompts. The repository now provides:

1. **Ready-to-Use Prompts**: Copy-paste prompts that work with any major LLM
2. **Context-Aware Analysis**: Intelligent prompting that understands code purpose
3. **Structured Output**: Consistent vulnerability reporting with severity and fixes
4. **Comprehensive Coverage**: Both general security and OWASP Top 10 specific analysis
5. **Community-Ready**: Complete documentation, contribution guidelines, and licensing

Perfect for security engineers, developers, and analysts who want to leverage AI for thorough, accurate security code reviews.
