# OWASP Top 10 Prompt Pack

This prompt pack helps security engineers analyze and improve code according to OWASP Top 10 risks.

## Included Prompts

- `injection.poml` – Detect SQL injection and unsafe query patterns.
- `xss.poml` – Identify DOM-based and reflected/stored XSS.
- `broken-auth.poml` – Analyze authentication and session vulnerabilities.

## Usage

These prompts are written in POML and ready to integrate into:
- LLM chat interfaces
- CLI tools
- CI pipelines
- IDEs (e.g., via extensions)

Each prompt uses `<use name="standard_output"/>`, so ensure you include the shared `/shared/output_format.let` when rendering.
