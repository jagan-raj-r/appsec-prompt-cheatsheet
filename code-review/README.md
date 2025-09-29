# AppSec Prompt Packs

Welcome to the **AppSec Prompt Packs** — a modular collection of ready-to-use POML prompts tailored for common application security use cases.

These prompt packs are designed to help **security engineers, developers, red teamers, and bug bounty hunters** automate and scale their security reviews using AI (e.g., GPT-4, Claude, or open-source LLMs).

---

## 🔧 How to Use

1. **Pick a Prompt Pack**: Each folder in `prompt-packs/` focuses on a security domain (e.g., `owasp-top-10`, `cloud-threats`, `auth-flows`).
2. **Load a Prompt**: Each `.poml` file follows the [POML (Prompt Orchestration Markup Language)](https://github.com/microsoft/poml) format.
3. **Inject Context**: Replace the `<code>` or `<context>` content with real code snippets, configurations, or threat models.
4. **Send to LLM**: Use any POML-compatible runner (e.g., Python SDK, VS Code extension, CLI) to render and send the prompt to your preferred language model.
5. **Interpret & Remediate**: Review the output and apply the insights to strengthen your application security posture.

---

## 🧠 Why This is Helpful

- ✅ **Consistent Prompting**: Reduces prompt variability and improves response quality
- ✅ **Actionable Outputs**: Prompts request structured output: vulnerabilities, severity, impact, and fix
- ✅ **Modular & Reusable**: Works across languages, threat types, and environments
- ✅ **Works in CI/CD or IDEs**: Compatible with CLI tools and developer workflows
- ✅ **Community-Extendable**: Anyone can add new prompts, extend packs, or integrate with other tools

---

## 📦 Available Packs

- [`owasp-top-10/`](./owasp-top-10): Prompts for Injection, XSS, and Broken Authentication (more coming soon)
- `cloud-threats/`: (coming soon)
- `auth-flows/`: (coming soon)
- `threat-modeling/`: (coming soon)

---

## 🧩 Dependencies

Most prompts reference a shared output style block:

> Be sure to include: `/shared/output_format.let`

You can load this into your POML renderer so prompts using `<use name="standard_output"/>` resolve correctly.

---

## 🚀 Contribute

Want to improve security workflows using AI? Add your own prompts, use-cases, or language coverage.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for help getting started.

---

Secure smarter, not harder. 🔐🤖
