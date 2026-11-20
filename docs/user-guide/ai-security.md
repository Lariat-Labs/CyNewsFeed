# AI security

The **AI security** page brings together threats to AI/LLM systems and your AI software supply chain.

## Sources

Built-in AI-security sources: OWASP GenAI Security Project, MITRE ATLAS releases, AI Incident Database, arXiv
LLM-security papers, Embrace The Red, Simon Willison (prompt injection), NVIDIA AI Red Team, plus Google Security Blog and
JFrog Security Research. OpenAI and Hugging Face blogs are included but disabled by default.

## Framework mappings

| Framework | Where it appears |
|---|---|
| **OWASP Top 10 for LLM Applications (2025)** | AI security page grid (LLM01–LLM10), story tags |
| **MITRE ATLAS** | AI security page heatmap by tactic, story tags |
| **MITRE ATT&CK Enterprise** | Dashboard heatmap by tactic, story tags |

Mappings come from AI summaries, plus IDs written literally in articles (e.g. `T1190`, `AML.T0051`, `LLM01`), which are
extracted for free. Summarise more stories, or enable auto-summarise, for fuller coverage. Click any technique or
category to see its stories.

## AI supply-chain watch

Maintain the list of packages your AI stack depends on (PyPI, npm, Go, crates.io, Maven, NuGet, RubyGems, Packagist).
The default list covers LangChain, LlamaIndex, Transformers, PyTorch, vLLM, llama.cpp, MLflow, Gradio, Ray, LiteLLM, the
OpenAI/Anthropic SDKs and Ollama.

- Each hourly run queries **OSV.dev** and turns newly published advisories (vulnerabilities and `MAL-` malicious packages)
  into stories tagged `ai-supply-chain` and OWASP **LLM03 (Supply Chain)**.
- **Pin a version** to see only advisories that affect it. The live check shows counts, worst severity, malicious-package
  flags, fixed versions and links to osv.dev.
